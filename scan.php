<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Error;

class SecurityValidator extends NodeVisitorAbstract
{
    public array $issues = [];
    private array $taintedVariables = [];
    private array $memoizationCache = [];

    // --- CONSTANTES DE CONFIGURAÇÃO ---
    private const USER_INPUT_SOURCES = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES'];
    private const DANGEROUS_EXEC_FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'assert'];
    private const SANITIZING_FUNCTIONS = ['htmlspecialchars', 'htmlentities', 'strip_tags', 'intval', 'floatval', '(int)', '(float)', 'mysqli_real_escape_string', 'escapeshellarg', 'escapeshellcmd', 'basename'];
    private const XSS_SINK_NODES = [Node\Stmt\Echo_::class, Node\Expr\Print_::class, Node\Expr\FuncCall::class];
    private const XSS_SINK_FUNCTIONS = ['die', 'exit', 'printf'];
    private const SSRF_SINK_FUNCTIONS = ['file_get_contents', 'fopen', 'fsockopen', 'curl_exec'];

    private array $checksToRun;

    public function __construct()
    {
        $this->checksToRun = [
            [$this, 'trackTaintedAssignments'],
            [$this, 'validateDangerousFunctionCall'],
            [$this, 'validateXssSinks'],
            [$this, 'validateShellExecution'],
            [$this, 'validateInclude'],
            [$this, 'validateDatabaseCall'],
            [$this, 'validateDeserialization'],
            [$this, 'validateHeaderInjection'],
            [$this, 'validatePregReplaceEModifier'],
            [$this, 'validateInsecureFileUpload'],
            [$this, 'validateEvalConstruct'],
            [$this, 'validateSsrf'],
        ];
    }
    
    public function enterNode(Node $node): void
    {
        foreach ($this->checksToRun as $check) {
            $check($node);
        }
    }
    
    public function beforeTraverse(array $nodes): ?array
    {
        $this->memoizationCache = [];
        return null;
    }

    private function trackTaintedAssignments(Node $node): void
    {
        if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
            if ($this->isTainted($node->expr)) {
                if (!in_array($node->var->name, $this->taintedVariables)) { $this->taintedVariables[] = $node->var->name; }
            }
            elseif (in_array($node->var->name, $this->taintedVariables)) {
                if (!$this->isTainted($node->expr)) {
                    $this->taintedVariables = array_diff($this->taintedVariables, [$node->var->name]);
                }
            }
        }
    }

    private function isTainted(Node $node): bool
    {
        $nodeHash = spl_object_hash($node);
        if (isset($this->memoizationCache[$nodeHash])) {
            return $this->memoizationCache[$nodeHash];
        }

        // Funções de sanitização
        if (
            ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && in_array(strtolower((string)$node->name), self::SANITIZING_FUNCTIONS, true)) ||
            ($node instanceof Node\Expr\Cast && in_array(strtolower($node->getAttribute('kind')), self::SANITIZING_FUNCTIONS, true))
        ) {
            return $this->memoizationCache[$nodeHash] = false;
        }

        // NOVO: Detecta qualquer acesso a superglobal, mesmo em profundidade (ex: $_FILES['file']['name'])
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            $var = $node->var;
            while ($var instanceof Node\Expr\ArrayDimFetch) {
                $var = $var->var;
            }
            if ($var instanceof Node\Expr\Variable && is_string($var->name) && in_array($var->name, self::USER_INPUT_SOURCES, true)) {
                return $this->memoizationCache[$nodeHash] = true;
            }
            // Recursivo: se qualquer parte do acesso for tainted
            if ($this->isTainted($node->var) || ($node->dim && $this->isTainted($node->dim))) {
                return $this->memoizationCache[$nodeHash] = true;
            }
        }

        if ($node instanceof Node\Expr\Variable && is_string($node->name) && in_array($node->name, $this->taintedVariables, true)) {
            return $this->memoizationCache[$nodeHash] = true;
        }

        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            return $this->memoizationCache[$nodeHash] = ($this->isTainted($node->left) || $this->isTainted($node->right));
        }
        
        if ($node instanceof Node\Expr\FuncCall) {
             foreach ($node->args as $arg) {
                 if ($this->isTainted($arg->value)) {
                     return $this->memoizationCache[$nodeHash] = true;
                 }
             }
        }

        return $this->memoizationCache[$nodeHash] = false;
    }

    private function addIssue(Node $node, string $message, string $suggestion, string $severity): void
    {
        $issue = [
            'line' => $node->getStartLine(),
            'message' => $message,
            'suggestion' => $suggestion,
            'severity' => $severity,
        ];
        if (!in_array($issue, $this->issues, true)) {
            $this->issues[] = $issue;
        }
    }
    
    // --- MÉTODOS DE VALIDAÇÃO ---

    private function validateEvalConstruct(Node $node): void
    {
        if ($node instanceof Node\Expr\Eval_) {
            $this->addIssue($node, 'Uso crítico do construtor eval() (RCE)', 'Eval é extremamente perigoso. Refatore o código para evitar seu uso.', 'CRITICAL');
        }
    }

    private function validatePregReplaceEModifier(Node $node): void
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower((string)$node->name) === 'preg_replace' && isset($node->getArgs()[0])) {
            $patternArg = $node->getArgs()[0]->value;
            if ($patternArg instanceof Node\Scalar\String_) {
                $pattern = $patternArg->value;
                $lastDelimiterPos = strrpos($pattern, $pattern[0]);
                if ($lastDelimiterPos !== false && $lastDelimiterPos > 0) {
                    $modifiers = substr($pattern, $lastDelimiterPos + 1);
                    if (str_contains($modifiers, 'e')) {
                        $this->addIssue($node, 'Uso crítico de preg_replace com modificador /e (RCE)', 'Substitua imediatamente por preg_replace_callback().', 'CRITICAL');
                    }
                }
            }
        }
    }

    private function validateInsecureFileUpload(Node $node): void
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower((string)$node->name) === 'move_uploaded_file' && isset($node->getArgs()[1])) {
            if ($this->isTainted($node->getArgs()[1]->value)) {
                 $this->addIssue($node, 'Upload de arquivo inseguro', 'O destino do arquivo parece usar dados do usuário (como o nome original do arquivo). Gere um nome novo e seguro no servidor e valide a extensão.', 'HIGH');
            }
        }
    }

    private function validateDatabaseCall(Node $node): void
    {
        if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\FuncCall) {
            $isDbCall = ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && in_array(strtolower((string)$node->name), ['mysqli_query', 'mysql_query'])) ||
                        ($node->name instanceof Node\Identifier && in_array(strtolower($node->name->name), ['query', 'exec']));
            if ($isDbCall && (isset($node->args[0]) || isset($node->args[1]))) {
                $queryArg = ($node instanceof Node\Expr\FuncCall) ? ($node->args[1]->value ?? null) : ($node->args[0]->value ?? null);
                if ($queryArg && $queryArg instanceof Node\Expr\BinaryOp\Concat && $this->isTainted($queryArg)) {
                    $this->addIssue($node, 'Potencial SQL Injection', 'Use Prepared Statements com bind de parâmetros (bindParam, bindValue).', 'HIGH');
                }
            }
        }
    }

    private function validateInclude(Node $node): void
    {
        if ($node instanceof Node\Expr\Include_) {
            if ($node->expr instanceof Node\Expr\Variable) {
                 $this->addIssue($node, 'Include/require com variável (Potencial LFI)', 'Evite usar variáveis em includes. Use caminhos de arquivo fixos ou uma lista de permissões.', 'HIGH');
            } elseif ($this->isTainted($node->expr)) {
                $this->addIssue($node, 'Potencial Path Traversal em include/require', 'Evite usar dados do usuário para construir caminhos de arquivos.', 'HIGH');
            }
        }
    }
    
    private function validateDeserialization(Node $node): void
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower((string)$node->name) === 'unserialize') {
            if (isset($node->args[0]) && $this->isTainted($node->args[0]->value)) {
                $this->addIssue($node, 'Desserialização insegura de dados do usuário', 'Nunca use unserialize() em dados não confiáveis. Prefira JSON (json_decode).', 'HIGH');
            }
        }
    }

    private function validateXssSinks(Node $node): void
    {
        if (!in_array(get_class($node), self::XSS_SINK_NODES, true)) return;
        $expressions = [];
        if ($node instanceof Node\Stmt\Echo_) { $expressions = $node->exprs; } 
        elseif ($node instanceof Node\Expr\Print_) { $expressions = [$node->expr]; } 
        elseif ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && in_array(strtolower((string)$node->name), self::XSS_SINK_FUNCTIONS, true)) {
            foreach($node->getArgs() as $arg) { $expressions[] = $arg->value; }
        }
        foreach ($expressions as $expr) {
            if ($this->isTainted($expr)) {
                $this->addIssue($node, 'Potencial XSS (Cross-Site Scripting)', 'Utilize htmlspecialchars() ou outra função de escape para sanitizar a saída.', 'MEDIUM');
                break;
            }
        }
    }
    
    private function validateDangerousFunctionCall(Node $node): void
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $funcName = strtolower((string) $node->name);
            if (in_array($funcName, self::DANGEROUS_EXEC_FUNCTIONS, true)) {
                $isTainted = false;
                foreach($node->args as $arg) { if ($this->isTainted($arg->value)) { $isTainted = true; break; } }
                $context = $isTainted ? "com dados do usuário" : "de forma estática";
                $this->addIssue($node, "Uso da função perigosa {$funcName}() {$context}", "Evite o uso desta função. Se for essencial, valide e sanitize rigorosamente todas as entradas.", 'MEDIUM');
            }
        }
    }
    
    private function validateHeaderInjection(Node $node): void
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower((string)$node->name) === 'header') {
            if (isset($node->args[0]) && $this->isTainted($node->args[0]->value)) {
                 $this->addIssue($node, 'Potencial injeção de cabeçalho HTTP', 'Sanitize os dados passados para a função header() para remover caracteres de nova linha.', 'MEDIUM');
            }
        }
    }

    private function validateShellExecution(Node $node): void
    {
        if ($node instanceof Node\Expr\ShellExec) {
            $this->addIssue($node, 'Execução de comando de shell via backticks (`...`)', 'Utilize funções seguras e validadas, como escapeshellarg().', 'MEDIUM');
        }
    }
    
    private function validateSsrf(Node $node): void
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && in_array(strtolower((string)$node->name), self::SSRF_SINK_FUNCTIONS, true) && isset($node->getArgs()[0])) {
            $arg = $node->getArgs()[0]->value;
            if ($this->isTainted($arg)) {
                $this->addIssue($node, 'Potencial SSRF com dados do usuário', 'Valide a URL contra uma lista de permissões estrita antes de fazer a requisição.', 'MEDIUM');
            } elseif ($arg instanceof Node\Scalar\String_ && preg_match('#^(https|http|ftp)://#i', $arg->value)) {
                $this->addIssue($node, 'Requisição a URL externa estática', 'Acessar recursos remotos pode expor informações ou causar lentidão. Verifique se é necessário.', 'LOW');
            }
        }
    }
}

function scanFile(string $path): array
{
    if (!is_file($path) || !is_readable($path)) {
        return ["Erro: Arquivo não encontrado ou sem permissão: {$path}"];
    }
    $code = file_get_contents($path);
    if (empty($code)) return [];
    $parser = (new ParserFactory)->createForNewestSupportedVersion();
    try {
        $ast = $parser->parse($code);
        if ($ast === null) return [];
    } catch (Error $e) {
        return ["Erro de parse no arquivo {$path}: {$e->getMessage()}"];
    }
    $traverser = new NodeTraverser();
    $validator = new SecurityValidator();
    $traverser->addVisitor($validator);
    $traverser->traverse($ast);
    return $validator->issues;
}