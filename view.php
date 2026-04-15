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

// FIX #1 – Valida token: solo hex 32 char (bin2hex(random_bytes(16)))
// Blocca path traversal e qualsiasi token non legittimo
if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
    http_response_code(400);
    die('Token non valido.');
}

// FIX #2 – Valida aesKey: solo hex 64 char, già qui prima di qualsiasi operazione
if (!ctype_xdigit($aesKey) || strlen($aesKey) !== 64) {
    http_response_code(400);
    die('Chiave non valida.');
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

// FIX #3 – Rate limiting per token: max 5 tentativi falliti
$attemptsFile = "{$storage}/.attempts_{$token}";
$attempts = 0;
if (file_exists($attemptsFile)) {
    $attempts = (int)file_get_contents($attemptsFile);
}
if ($attempts >= 5) {
    // Troppi tentativi: cancella il segreto e blocca
    @unlink("{$storage}/{$token}");
    @unlink($attemptsFile);
    http_response_code(429);
    die('Troppi tentativi falliti. Il segreto è stato distrutto.');
}

$inputPass = trim($_POST['view_pass'] ?? '');

// FIX #3 – Race condition: usa lock esclusivo sul file
$filePath = "{$storage}/{$token}";

if (file_exists($filePath)) {
    $fp = fopen($filePath, 'r+');
    if (!$fp || !flock($fp, LOCK_EX | LOCK_NB)) {
        // Un'altra richiesta sta già processando questo token
        if ($fp) fclose($fp);
        http_response_code(409);
        die('Richiesta in corso, riprova.');
    }

    $raw  = stream_get_contents($fp);
    $data = base64_decode($raw);

    // Separa IV+ciphertext dall'hash della passphrase
    $parts = explode('::', $data, 2);
    if (count($parts) !== 2) {
        flock($fp, LOCK_UN);
        fclose($fp);
        $error = 'Dati corrotti.';
    } else {
        list($iv_ct, $storedHash) = $parts;

        if (hash('sha512', $inputPass) !== $storedHash) {
            // FIX #4 – Password errata: NON cancellare, incrementa tentativi
            flock($fp, LOCK_UN);
            fclose($fp);
            file_put_contents($attemptsFile, $attempts + 1);
            $error = 'Password errata.';
        } else {
            // Password corretta: decripta
            $cipher = 'aes-256-cbc';
            $ivLen  = openssl_cipher_iv_length($cipher);
            $iv     = substr($iv_ct, 0, $ivLen);
            $ct     = substr($iv_ct, $ivLen);
            $decrypted = openssl_decrypt($ct, $cipher, hex2bin($aesKey), OPENSSL_RAW_DATA, $iv);

            // FIX #3 – Secure delete SOLO dopo decrittazione riuscita, dentro il lock
            rewind($fp);
            $size = filesize($filePath);
            if ($size > 0) {
                $chunk = str_repeat("\0", min(1024 * 1024, $size));
                $w = 0;
                while ($w < $size) {
                    $to = min(1024 * 1024, $size - $w);
                    fwrite($fp, substr($chunk, 0, $to));
                    $w += $to;
                }
                fflush($fp);
            }
            flock($fp, LOCK_UN);
            fclose($fp);
            unlink($filePath);
            @unlink($attemptsFile);
        }
    }
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
      <p><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
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
