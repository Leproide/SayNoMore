<?php
/**
 * SayNoMore - view.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes:
 *  - Chiave AES letta dal FRAGMENT lato JS, inviata al server SOLO via POST
 *  - Password verificata con password_verify (timing-safe, Argon2id)
 *  - AES-256-GCM con verifica del tag (authenticated decryption)
 *  - Rate limit (max 5 tentativi) memorizzato nel file stesso, dentro al lock,
 *    quindi niente race condition possibile
 *  - Cleanup on-access: segreti piu' vecchi di SECRET_TTL vengono distrutti
 *  - Security headers
 *  - session_start() rimosso (mai usato)
 *  - Messaggi di errore piu' uniformi (meno info leak)
 */

// --- Security headers ---
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Permissions-Policy: interest-cohort=()');

// --- Config ---
const SECRET_TTL     = 7 * 24 * 60 * 60; // 7 giorni
const MAX_ATTEMPTS   = 5;
const STORAGE_SUBDIR = '/data';

$storage = __DIR__ . STORAGE_SUBDIR;
$token   = $_GET['token'] ?? '';

$decrypted = null;
$error     = '';

// --- Validazione token (anche prevenzione path traversal) ---
if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
    http_response_code(400);
    die('Token non valido.');
}

$filePath = "{$storage}/{$token}";

// --- Cleanup opportunistico: se il file esiste ed e' scaduto, distruggi ---
if (file_exists($filePath)) {
    $mtime = @filemtime($filePath);
    if ($mtime !== false && (time() - $mtime) > SECRET_TTL) {
        @unlink($filePath);
    }
}

/**
 * Output del form HTML per inserire la password.
 * Includiamo un campo hidden "key" che verra' popolato lato client dal fragment URL.
 */
function render_form(string $token, string $errMsg = ''): void {
    $tokenEsc = htmlspecialchars($token, ENT_QUOTES, 'UTF-8');
    $errEsc   = htmlspecialchars($errMsg, ENT_QUOTES, 'UTF-8');
    ?>
    <!DOCTYPE html>
    <html lang="it">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Sblocca Segreto</title>
      <link rel="stylesheet" href="style.css">
    </head>
    <body>
      <div class="container">
        <h1>Sblocca Segreto</h1>
        <?php if ($errEsc): ?>
          <p class="error-text"><?= $errEsc ?></p>
        <?php endif; ?>
        <noscript>
          <p class="error-text">Questo servizio richiede JavaScript abilitato per recuperare la chiave dal link.</p>
        </noscript>
        <form id="unlockForm" method="POST" autocomplete="off">
          <input type="hidden" name="token" value="<?= $tokenEsc ?>">
          <input type="hidden" name="key"   id="keyField" value="">
          <input
            type="password"
            name="view_pass"
            placeholder="Password di visione"
            required
            autocomplete="off"
            class="pw-input">
          <button type="submit" class="generate">Sblocca segreto</button>
        </form>
      </div>
      <script src="script.js"></script>
      <footer>
        <div class="footer-content">
          <p>Offerto con &#x1F480; da Leprechaun &mdash; <a href="https://github.com/leproide" target="_blank" rel="noopener noreferrer">GitHub</a></p>
        </div>
      </footer>
    </body>
    </html>
    <?php
}

// --- GET: mostra il form ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    render_form($token);
    exit;
}

// --- POST: tenta lo sblocco ---

// La chiave AES arriva via POST (riempita lato JS dal fragment)
$aesKey    = $_POST['key']       ?? '';
$inputPass = $_POST['view_pass'] ?? '';

// Validazione chiave AES (256 bit hex)
if (!ctype_xdigit($aesKey) || strlen($aesKey) !== 64) {
    http_response_code(400);
    die('Chiave non valida o mancante.');
}

if (!file_exists($filePath)) {
    $error = 'Link non valido o gia\' usato.';
} else {

    // Lock esclusivo: blocca race condition su lettura/scrittura/incremento tentativi
    $fp = fopen($filePath, 'r+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        http_response_code(409);
        die('Richiesta in corso, riprova.');
    }

    $raw = stream_get_contents($fp);
    $obj = json_decode($raw, true);

    if (!is_array($obj) || !isset($obj['iv'], $obj['tag'], $obj['ct'], $obj['hash'])) {
        // Payload corrotto: distruggi e fail
        ftruncate($fp, 0);
        flock($fp, LOCK_UN);
        fclose($fp);
        @unlink($filePath);
        $error = 'Link non valido o gia\' usato.';
    } else {

        // Controllo scadenza dentro al lock
        $created = (int)($obj['created'] ?? 0);
        if ($created > 0 && (time() - $created) > SECRET_TTL) {
            ftruncate($fp, 0);
            flock($fp, LOCK_UN);
            fclose($fp);
            @unlink($filePath);
            $error = 'Link non valido o gia\' usato.';
        } else {

            $attempts = (int)($obj['attempts'] ?? 0);

            // Tentativi gia' esauriti: distruggi e blocca
            if ($attempts >= MAX_ATTEMPTS) {
                ftruncate($fp, 0);
                flock($fp, LOCK_UN);
                fclose($fp);
                @unlink($filePath);
                http_response_code(429);
                die('Troppi tentativi falliti. Il segreto e\' stato distrutto.');
            }

            // Verifica password (timing-safe, slow hash)
            if (!password_verify($inputPass, $obj['hash'])) {
                // Password errata: incrementa attempts e riscrivi il file
                $obj['attempts'] = $attempts + 1;
                $newPayload = json_encode($obj);
                ftruncate($fp, 0);
                rewind($fp);
                fwrite($fp, $newPayload);
                fflush($fp);
                flock($fp, LOCK_UN);
                fclose($fp);

                // Se l'incremento ha raggiunto il limite, distruggi subito
                if ($obj['attempts'] >= MAX_ATTEMPTS) {
                    @unlink($filePath);
                    http_response_code(429);
                    die('Troppi tentativi falliti. Il segreto e\' stato distrutto.');
                }

                $error = 'Password errata.';
            } else {
                // Password corretta: prova a decifrare con AES-GCM (verifica tag inclusa)
                $iv  = base64_decode($obj['iv'],  true);
                $tag = base64_decode($obj['tag'], true);
                $ct  = base64_decode($obj['ct'],  true);

                if ($iv === false || $tag === false || $ct === false) {
                    ftruncate($fp, 0);
                    flock($fp, LOCK_UN);
                    fclose($fp);
                    @unlink($filePath);
                    $error = 'Link non valido o gia\' usato.';
                } else {
                    $cipher = 'aes-256-gcm';
                    $plain  = openssl_decrypt(
                        $ct,
                        $cipher,
                        hex2bin($aesKey),
                        OPENSSL_RAW_DATA,
                        $iv,
                        $tag
                    );

                    if ($plain === false) {
                        // Tag GCM non valido -> chiave sbagliata o dati alterati.
                        // Trattiamo come "link non valido" per non distinguere dai casi precedenti.
                        ftruncate($fp, 0);
                        flock($fp, LOCK_UN);
                        fclose($fp);
                        @unlink($filePath);
                        $error = 'Link non valido o gia\' usato.';
                    } else {
                        // OK: sovrascrivi a zeri (best effort, vedi nota sicurezza nel README)
                        // e cancella il file.
                        $size = strlen($raw);
                        if ($size > 0) {
                            ftruncate($fp, 0);
                            rewind($fp);
                            $chunk = str_repeat("\0", min(1048576, $size));
                            $written = 0;
                            while ($written < $size) {
                                $toWrite = min(1048576, $size - $written);
                                fwrite($fp, substr($chunk, 0, $toWrite));
                                $written += $toWrite;
                            }
                            fflush($fp);
                        }
                        flock($fp, LOCK_UN);
                        fclose($fp);
                        @unlink($filePath);

                        $decrypted = $plain;
                    }
                }
            }
        }
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
</head>
<body>
  <div class="container">
    <?php if ($error !== ''): ?>
      <h1>Errore</h1>
      <p><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
      <?php if ($error === 'Password errata.'): ?>
        <noscript>
          <p class="error-text">Questo servizio richiede JavaScript abilitato.</p>
        </noscript>
        <form id="unlockForm" method="POST" autocomplete="off">
          <input type="hidden" name="token" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="key"   id="keyField" value="">
          <input
            type="password"
            name="view_pass"
            placeholder="Password di visione"
            required
            autocomplete="off"
            class="pw-input">
          <button type="submit" class="generate">Riprova</button>
        </form>
      <?php else: ?>
        <div class="actions">
          <form action="index.php" method="get"><button type="submit" class="generate">Home</button></form>
        </div>
      <?php endif; ?>
    <?php else: ?>
      <h1>SayNoMore</h1><br>
      <h2>Il tuo segreto:</h2><br>
      <textarea readonly class="secret-box"><?= htmlspecialchars($decrypted, ENT_QUOTES, 'UTF-8') ?></textarea>
      <div class="actions">
        <form action="index.php" method="get"><button type="submit" class="generate">Home</button></form>
      </div>
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
