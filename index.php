<!--
    Simple One Time Secret
    Created by Leproide – https://github.com/Leproide/SimpleOneTimeSecret

    This project is distributed under the terms of the GNU General Public License v2.
    You are free to redistribute and/or modify it under the conditions of the license.

    No warranty is provided
-->


<?php
// index.php: inoltra segreto e mostra link, AES-256-CBC client-side, no redirect
session_start();

$storage = __DIR__ . '/data';
if (!file_exists($storage)) mkdir($storage, 0700, true);

$link = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['secret'])) {
    $secret = trim($_POST['secret']);
    $token   = bin2hex(random_bytes(16));
    // AES-256 key: 32 bytes
    $aesKey  = bin2hex(random_bytes(32));

    // Cifra con AES-256-CBC
    $cipher = 'aes-256-cbc';
    $iv     = random_bytes(openssl_cipher_iv_length($cipher));
    $encrypted = openssl_encrypt(
        $secret,
        $cipher,
        hex2bin($aesKey),
        OPENSSL_RAW_DATA,
        $iv
    );
    $payload = base64_encode($iv . $encrypted);
    file_put_contents("{$storage}/{$token}", $payload);

    // Costruisci link
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'];
    $path     = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
    $link     = "{$protocol}://{$host}{$path}/view.php?token={$token}&key={$aesKey}";
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SayNoMore</title>
  <link rel="stylesheet" href="style.css">
  <link rel="icon" href="favicon.ico" type="image/x-icon">
</head>
<body>
  <div class="container">
    <h1>SayNoMore</h1>

    <?php if ($link): ?>
      <p class="info-text">Link generato (copia e invia):</p>
	  <br>
      <div class="link-box">
        <input id="secretLink" type="text" readonly value="<?php echo htmlspecialchars($link); ?>">
        <button id="copyBtn" type="button">Copia</button>
      </div>
    <?php else: ?>
      <form method="POST">
        <textarea name="secret" placeholder="Inserisci il tuo segreto..." required class="secret-input"></textarea>
        <button type="submit" class="generate">Genera link</button>
      </form>
    <?php endif; ?>

  </div>

  <script src="script.js"></script>

  <footer>
    <div class="footer-content">
      <p>Offerto con 💀 da Leprechaun — <a href="https://github.com/leproide" target="_blank">GitHub</a></p>
    </div>
  </footer>
</body>
</html>
