<!--
    SayNoMore
    Created by Leproide – https://github.com/Leproide/SayNoMore

    This project is distributed under the terms of the GNU General Public License v2.
    You are free to redistribute and/or modify it under the conditions of the license.

    No warranty is provided
-->


<?php
// view.php – sblocca e decripta con passphrase onetime hashed

session_start();
$storage = __DIR__ . '/data';
$token   = $_GET['token'] ?? '';
$aesKey  = $_GET['key']   ?? '';
$decrypted = null;
$error     = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputPass = trim($_POST['view_pass']);
    $sessPass  = $inputPass; // Temporaneo, useremo subito l'hash
}

// se non ho ancora POST, mostro il form
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo '<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sblocca Segreto</title><link rel="stylesheet" href="style.css"></head><body><div class="container"><h1>Sblocca Segreto</h1><form method="POST"><input type="password" name="view_pass" placeholder="Password di visione" required style="
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
        "><button type="submit" class="generate">Sblocca segreto</button></form></div><footer><div class="footer-content"><p>Offerto con 💀 da Leprechaun — <a href="https://github.com/leproide" target="_blank">GitHub</a></p></div></footer></body></html>';
    exit;
}

// se POST, procedo
if ($token && file_exists("{$storage}/{$token}")) {
    $raw  = file_get_contents("{$storage}/{$token}");
    $data = base64_decode($raw);
    list($iv_ct, $storedHash) = explode('::', $data, 2);

    // confronto hash
    if (hash('sha512', $inputPass) !== $storedHash) {
        $error = '<h1>Password errata</h1>';
    } else {
        // decripto
        if ($aesKey && ctype_xdigit($aesKey) && strlen($aesKey)===64) {
            $cipher = 'aes-256-cbc';
            $ivLen  = openssl_cipher_iv_length($cipher);
            $iv     = substr($iv_ct, 0, $ivLen);
            $ct     = substr($iv_ct, $ivLen);
            $decrypted = openssl_decrypt($ct, $cipher, hex2bin($aesKey), OPENSSL_RAW_DATA, $iv);
        }
    }
    // secure delete
    $fp = fopen("{$storage}/{$token}", 'r+');
    if ($fp) {
        $size=filesize("{$storage}/{$token}");
        rewind($fp);
        $chunk=str_repeat("\0",1024*1024); $w=0;
        while($w<$size){ $to=min(1024*1024,$size-$w); fwrite($fp,substr($chunk,0,$to)); $w+=$to; }
        fflush($fp); fclose($fp);
    }
    unlink("{$storage}/{$token}");
} else {
    $error = 'Link invalido o già usato.';
}

?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SayNoMore - Visualizza</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="container">
    <?php if ($error): ?>
      <h1>Errore</h1>
      <p><?php echo $error; ?></p>
      <div class="actions">
        <form action="index.php" method="get"><button type="submit" class="generate">Home</button></form>
      </div>
    <?php else: ?>
      <h1>SayNoMore</h1><br>
      <h2>Il tuo segreto:</h2><br>
      <textarea readonly style="
        width:100%;
        height:360px;
        padding:1rem;
        font-size:1rem;
        background:var(--bg-input);
        color:var(--text-primary);
        border:1px solid var(--border-input);
        border-radius:4px;
      "><?php echo htmlspecialchars($decrypted, ENT_QUOTES, 'UTF-8'); ?></textarea>
      <div class="actions">
        <form action="index.php" method="get"><button type="submit" class="generate">Home</button></form>
      </div>
    <?php endif; ?>
  </div>
  
  <footer>
    <div class="footer-content">
      <p>Offerto con 💀 da Leprechaun — <a href="https://github.com/leproide" target="_blank">GitHub</a></p>
    </div>
  </footer>
</body>
</html>
