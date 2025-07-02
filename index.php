<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/scan.php';

$issues = [];
$uploadPath = __DIR__ . '/upload/';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['phpfile'])) {
    
    if (!is_dir($uploadPath)) {
        mkdir($uploadPath, 0755, true);
    }

    $uploadedFiles = $_FILES['phpfile'];
    
    $filesToProcess = [];
    if (is_array($uploadedFiles['name'])) {
        for ($i = 0; $i < count($uploadedFiles['name']); $i++) {
            $filesToProcess[] = [
                'name' => $uploadedFiles['name'][$i],
                'tmp_name' => $uploadedFiles['tmp_name'][$i],
                'error' => $uploadedFiles['error'][$i]
            ];
        }
    } else {
        $filesToProcess[] = $uploadedFiles;
    }

    foreach ($filesToProcess as $file) {
        if ($file['error'] === UPLOAD_ERR_OK) {
            $fileName = basename($file['name']);
            $destination = $uploadPath . $fileName;
            
            if (move_uploaded_file($file['tmp_name'], $destination)) {
                $issues[$fileName] = scanFile($destination);
            }
        }
    }
}

require __DIR__ . '/templates/view.php';