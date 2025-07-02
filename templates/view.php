<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PHP Security Scanner</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

  <header>
    <h1>PHP Security Scanner</h1>
  </header>

  <main>
    <form method="post" enctype="multipart/form-data" action="index.php">
      <div class="drop-zone" id="dropZone">
        <span id="dropText">Arraste & solte ou clique para selecionar arquivos .php</span>
        <input type="file" id="phpfile" name="phpfile[]" accept=".php,.phtml,.txt,.html" multiple required>
      </div>
      <button type="submit">Scanear</button>
    </form>

    <?php if (!empty($issues)): ?>
      <div class="results">
        <h2>Resultados</h2>
        <?php foreach ($issues as $fileName => $fileIssues): ?>
          <h3><?= htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8') ?> (Erros: <?= count($fileIssues) ?>)</h3>
          
          <?php if (empty($fileIssues)): ?>
            <p class="ok">Nenhuma vulnerabilidade detectada!</p>
          <?php else: ?>
            <?php uasort($fileIssues, function ($a, $b) {
                $order = ['CRITICAL' => 4, 'HIGH' => 3, 'MEDIUM' => 2, 'LOW' => 1];
                return ($order[$b['severity']] ?? 0) <=> ($order[$a['severity']] ?? 0);
            }); ?>
            <?php foreach ($fileIssues as $issue): ?>
              <?php
                $severity = strtolower($issue['severity']);
                $message = "[Linha {$issue['line']}] {$issue['message']}";
                $suggestion = $issue['suggestion'];
              ?>
              <div class="issue issue-<?= htmlspecialchars($severity, ENT_QUOTES, 'UTF-8') ?>">
                <div class="error-text">
                  <span class="severity-tag"><?= htmlspecialchars($issue['severity'], ENT_QUOTES, 'UTF-8') ?></span>
                  <?= htmlspecialchars($issue['message'], ENT_QUOTES, 'UTF-8') ?>
                </div>
                <?php if ($suggestion): ?>
                  <div class="suggestion"><?= htmlspecialchars($suggestion, ENT_QUOTES, 'UTF-8') ?></div>
                <?php endif; ?>
              </div>
            <?php endforeach; ?>
          <?php endif; ?>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </main>

  <footer>&copy; <?= date('Y') ?> PHP Security Scanner</footer>
  <script src="assets/js/script.js"></script>
</body>
</html>