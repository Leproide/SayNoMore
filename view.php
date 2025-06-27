<?php
// view.php: mostra e decripta segreto una sola volta con AES-256-CBC e zero-fill prima dell’eliminazione
session_start();
$storage = __DIR__ . '/data';

$token     = $_GET['token'] ?? '';
$aesKey    = $_GET['key']   ?? '';
$decrypted = null;

if ($token) {
    $filePath = "{$storage}/{$token}";
    if (file_exists($filePath)) {
        // Leggi e decodifica
        $raw  = file_get_contents($filePath);
        $data = base64_decode($raw);

        // Prova decriptazione solo se la chiave è valida
        if ($aesKey && ctype_xdigit($aesKey) && strlen($aesKey) === 64) {
            $cipher = 'aes-256-cbc';
            $ivLen  = openssl_cipher_iv_length($cipher);
            $iv     = substr($data, 0, $ivLen);
            $ct     = substr($data, $ivLen);
            $decrypted = openssl_decrypt(
                $ct,
                $cipher,
                hex2bin($aesKey),
                OPENSSL_RAW_DATA,
                $iv
            );
        }

        // Zero-fill
        $fp = fopen($filePath, 'r+');
        if ($fp) {
            $size = filesize($filePath);
            rewind($fp);
            $chunk = str_repeat("\0", 1024 * 1024);
            $written = 0;
            while ($written < $size) {
                $toWrite = min(1024 * 1024, $size - $written);
                fwrite($fp, substr($chunk, 0, $toWrite));
                $written += $toWrite;
            }
            fflush($fp);
            fclose($fp);
        }

        // Rimuovi sempre il file, anche se il segreto non è stato decriptato correttamente
        unlink($filePath);
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SayNoMore - Visualizza</title>
  <link rel="stylesheet" href="style.css">
  <link rel="icon" href="favicon.ico" type="image/x-icon">
</head>
<body>
  <div class="container">
    <?php if ($decrypted !== null): ?>
      <h1>SayNoMore</h1>
      <br>
      <h2>Il tuo segreto:</h2>
      <br>
      <textarea class="secret-text" readonly><?php
        echo htmlspecialchars($decrypted, ENT_QUOTES, 'UTF-8');
      ?></textarea>
    <?php else: ?>
      <h1>Secret non disponibile</h1>
      <p>Link già usato o invalido.</p>
    <?php endif; ?>

    <div class="actions">
      <form action="index.php" method="get">
        <button type="submit" class="generate">Home</button>
      </form>
    </div>
  </div>

  <footer>
    <div class="footer-content">
      <p>Offerto con 💀 da Leprechaun — <a href="https://github.com/leproide" target="_blank">GitHub</a></p>
    </div>
  </footer>
</body>
</html>
