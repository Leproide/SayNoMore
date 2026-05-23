<?php
/**
 * SayNoMore - index.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes (rispetto alla versione originale):
 *  - Chiave AES nel fragment URL (non in query string): zero knowledge reale
 *  - Password hashate con Argon2id (era SHA-512 unsalted)
 *  - Cifratura AES-256-GCM authenticated (era CBC senza MAC)
 *  - Payload in JSON con: iv, tag, ct, hash, created, attempts
 *  - Scrittura atomica del file (tmp + rename)
 *  - Rimosso session_start() inutile
 *  - Rimosso trim() sulla password (era silenzioso)
 *  - Security headers
 *  - Niente JS inline (CSP-friendly)
 */

// --- Security headers ---
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Permissions-Policy: interest-cohort=()');

// --- Storage setup ---
$storage = __DIR__ . '/data';
if (!file_exists($storage)) {
    mkdir($storage, 0700, true);
}

$link = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['secret']) && !empty($_POST['passphrase'])) {

    // Il secret lo trimmiamo solo da spazi accidentali a inizio/fine,
    // la password NO (potrebbero esserci spazi voluti, es. da password manager).
    $secret     = trim($_POST['secret']);
    $passphrase = $_POST['passphrase'];

    // Token: 128 bit hex, usato come nome file
    $token = bin2hex(random_bytes(16));

    // Chiave AES: 256 bit hex, sara' nel fragment URL (mai inviata al server tramite link)
    $aesKey = bin2hex(random_bytes(32));

    // Hash password: Argon2id (slow hash, salt automatico, work factor incluso)
    $hashPass = password_hash($passphrase, PASSWORD_ARGON2ID);
    if ($hashPass === false) {
        http_response_code(500);
        die('Errore interno durante la generazione.');
    }

    // Cifratura AES-256-GCM (authenticated encryption)
    $cipher = 'aes-256-gcm';
    $ivLen  = openssl_cipher_iv_length($cipher); // 12 byte per GCM
    $iv     = random_bytes($ivLen);
    $tag    = '';
    $ct     = openssl_encrypt(
        $secret,
        $cipher,
        hex2bin($aesKey),
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );

    if ($ct === false) {
        http_response_code(500);
        die('Errore interno durante la cifratura.');
    }

    // Payload JSON (tutto base64 per sicurezza nello storage)
    $payload = json_encode([
        'iv'       => base64_encode($iv),
        'tag'      => base64_encode($tag),
        'ct'       => base64_encode($ct),
        'hash'     => $hashPass,
        'created'  => time(),
        'attempts' => 0,
    ]);

    // Scrittura atomica: scrivo su file temporaneo, poi rename
    $finalPath = "{$storage}/{$token}";
    $tmpPath   = "{$storage}/.tmp_{$token}";

    if (file_put_contents($tmpPath, $payload, LOCK_EX) === false) {
        http_response_code(500);
        die('Errore interno durante il salvataggio.');
    }
    if (!rename($tmpPath, $finalPath)) {
        @unlink($tmpPath);
        http_response_code(500);
        die('Errore interno durante il salvataggio.');
    }
    @chmod($finalPath, 0600);

    // --- Costruzione link ---
    // Schema rilevato lato server; HTTPS effettivo deve essere garantito dal webserver
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $host  = $_SERVER['HTTP_HOST'];
    $path  = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');

    // Chiave AES nel FRAGMENT (#): non viene inviata al server, non finisce nei log,
    // non finisce nei referer, non finisce nei link preview di Slack/WhatsApp/etc.
    $link = "{$proto}://{$host}{$path}/view.php?token={$token}#{$aesKey}";
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
        <input id="secretLink" type="text" readonly value="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>">
        <button id="copyBtn" type="button">Copia</button>
      </div>
    <?php else: ?>
      <form method="POST" autocomplete="off">
        <textarea name="secret" placeholder="Inserisci il tuo segreto..." required></textarea>
        <input
          type="password"
          name="passphrase"
          placeholder="Inserisci una password"
          required
          autocomplete="new-password"
          class="pw-input">
        <button type="submit" class="generate">Genera link</button>
      </form>
    <?php endif; ?>
  </div>

  <script src="script.js"></script>

  <footer>
    <div class="footer-content">
      <p>Offerto con &#x1F480; da Leprechaun &mdash; <a href="https://github.com/leproide" target="_blank" rel="noopener noreferrer">GitHub</a></p>
    </div>
  </footer>
</body>
</html>
