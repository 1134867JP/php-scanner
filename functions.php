<?php
// functions.php

declare(strict_types=1);

/**
 * Realiza o upload seguro de um único arquivo e retorna seu caminho de destino.
 *
 * @param array $file O array do arquivo vindo de $_FILES.
 * @return string|null O caminho completo para o arquivo salvo em caso de sucesso, ou null em caso de falha.
 */
function secureFileUpload(array $file): ?string
{
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }

    $allowedExtensions = ['php', 'phtml', 'php5', 'txt', 'html'];
    $uploadDir = __DIR__ . '/upload/';

    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $originalName = $file['name'];
    $fileTmp = $file['tmp_name'];
    $fileInfo = pathinfo($originalName);
    $extension = strtolower($fileInfo['extension'] ?? '');

    if (!in_array($extension, $allowedExtensions, true)) {
        error_log("Tentativa de upload de extensão não permitida: {$extension}");
        return null;
    }

    // Gera um nome seguro para evitar conflitos e Path Traversal.
    $safeName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . $safeName;

    if (move_uploaded_file($fileTmp, $destination)) {
        return $destination;
    }

    return null;
}