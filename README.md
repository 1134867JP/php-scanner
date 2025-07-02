# PHP Security Scanner

Um scanner de vulnerabilidades de segurança para código PHP, construído com análise estática de AST (Abstract Syntax Tree). A ferramenta possui uma interface web moderna com suporte a upload de múltiplos arquivos via drag-and-drop, e também pode ser utilizada via linha de comando (CLI).

Este projeto foi desenvolvido como uma ferramenta educativa para demonstrar a detecção de vulnerabilidades comuns do PHP e a aplicação de boas práticas de arquitetura de software, como Separação de Responsabilidades e otimização de performance.

## ✨ Funcionalidades

- **Análise Estática com AST:** Utiliza a biblioteca `nikic/php-parser` para analisar o código em um nível estrutural, permitindo a criação de regras de detecção complexas.
- **Rastreamento de Dados ("Taint Analysis"):** Rastreia a origem de dados vindos de superglobais (`$_GET`, `$_POST`, etc.) para identificar quando são usados em funções sensíveis ("sinks") sem a devida sanitização.
- **Interface Moderna e Responsiva:** UI com efeito de "Glassmorphism", gradientes animados e micro-interações para uma experiência de usuário agradável.
- **Upload Simplificado:** Suporte a upload de múltiplos arquivos via drag-and-drop.
- **Resultados Detalhados:** Exibe as vulnerabilidades encontradas com o nome do arquivo, linha do código, descrição, sugestão de correção e nível de severidade (Crítico, Alto, Médio, Baixo).
- **Dupla Interface:** Funciona tanto com a interface web quanto via linha de comando (CLI).

## 🛠️ Tecnologias Utilizadas

- **Backend:** PHP 8.2
- **Dependências:** `nikic/php-parser`
- **Frontend:** HTML5, CSS3 (Flexbox, Grid, Variáveis CSS, Animações), JavaScript (ES6)
- **Ambiente:** Docker, Docker Compose, Apache

## 🚀 Instalação e Execução Local

Para rodar este projeto localmente com todas as funcionalidades, você precisará ter o **Docker** e o **Docker Compose** instalados.

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/seu-usuario/php-security-scanner.git](https://github.com/seu-usuario/php-security-scanner.git)
    cd php-security-scanner
    ```

2.  **Construa e inicie os containers Docker:**
    Este comando irá construir a imagem PHP/Apache e iniciar o ambiente em segundo plano.
    ```bash
    docker-compose up --build -d
    ```

3.  **Instale as dependências do PHP:**
    Este comando executa o `composer update` dentro do container para baixar as bibliotecas necessárias.
    ```bash
    docker-compose exec web composer update
    ```

4.  **Acesse a aplicação:**
    Pronto! Abra seu navegador e acesse:
    [**http://localhost:8080**](http://localhost:8080)

## Como Usar

### Demo Online (Capacidade Limitada)

Uma versão de demonstração está disponível publicamente no seguinte endereço:

[**https://php-security-scanner.onrender.com**](https://php-security-scanner.onrender.com)

**Aviso Importante:** Esta versão online é protegida por um Web Application Firewall (WAF). Por isso, o upload de arquivos que contêm código deliberadamente vulnerável (como `SQL Injection`, `XSS`, `eval()`, etc.) será **bloqueado** com um erro `403 - Forbidden`.

A demo online é ideal para testar a interface e escanear arquivos PHP simples e benignos.

### Teste Completo (Interface Web Local)

Para testar todo o poder de detecção do scanner, utilize o ambiente Docker local.

1.  Acesse `http://localhost:8080`.
2.  Arraste e solte os arquivos `.php` que deseja analisar, incluindo arquivos de teste com vulnerabilidades.
3.  Clique no botão "Scanear".
4.  Os resultados aparecerão na parte inferior, sem o bloqueio do WAF.
