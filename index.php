<!--
    SayNoMore
    Created by Leproide – https://github.com/Leproide/SayNoMore

    This project is distributed under the terms of the GNU General Public License v2.
    You are free to redistribute and/or modify it under the conditions of the license.

    No warranty is provided
-->


<?php
// index.php – genera link con segreto e passphrase hashed SHA-512

session_start();
$storage = __DIR__ . '/data';
if (!file_exists($storage)) mkdir($storage, 0700, true);

$link = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['secret']) && !empty($_POST['passphrase'])) {
    $secret     = trim($_POST['secret']);
    $passphrase = trim($_POST['passphrase']);
    $token      = bin2hex(random_bytes(16));
    $aesKey     = bin2hex(random_bytes(32));
    $hashPass   = hash('sha512', $passphrase);

    // cifro il segreto
    $cipher   = 'aes-256-cbc';
    $iv       = random_bytes(openssl_cipher_iv_length($cipher));
    $enc      = openssl_encrypt($secret, $cipher, hex2bin($aesKey), OPENSSL_RAW_DATA, $iv);

    // memorizzo IV + ciphertext + :: + passhash
    $payload = base64_encode($iv . $enc . '::' . $hashPass);
    file_put_contents("{$storage}/{$token}", $payload);

    // costruisco link
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']==='on') ? 'https' : 'http';
    $host  = $_SERVER['HTTP_HOST'];
    $path  = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
    $link  = "{$proto}://{$host}{$path}/view.php?token={$token}&key={$aesKey}";
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SayNoMore</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="container">
    <h1>SayNoMore</h1>

    <?php if ($link): ?>
      <p class="info-text">Link generato (copia e invia):</p><br>
      <div class="link-box">
        <input id="secretLink" type="text" readonly value="<?php echo htmlspecialchars($link); ?>">
        <button id="copyBtn" type="button">Copia</button>
      </div>
    <?php else: ?>
      <form method="POST">
        <textarea name="secret" placeholder="Inserisci il tuo segreto..." required></textarea>
        <input 
          type="password" 
          name="passphrase" 
          placeholder="Password di visione" 
          required 
          style="
            width:100%;
            padding:1rem;
            font-size:1rem;
            height:3rem;
            background:var(--bg-input);
            color:var(--text-primary);
            border:1px solid var(--border-input);
            border-radius:4px;
            margin-bottom:1.5rem;
            text-align:center;
          ">
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
