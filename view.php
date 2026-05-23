<?php
/**
 * SayNoMore - view.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v4:
 *  - Cleanup globale ora usa flock LOCK_EX | LOCK_NB su ogni file prima di
 *    leggerlo, salta i file in uso. Previene race con update di attempts.
 *  - Validazione del tipo input ($_GET / $_POST) come stringa
 *  - random_int wrappato in try/catch
 */

// --- Security headers ---
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Permissions-Policy: interest-cohort=()');
header('Cache-Control: no-store, no-cache, must-revalidate');

// --- Config ---
const MAX_ATTEMPTS      = 5;
const STORAGE_SUBDIR    = '/data';
const CLEANUP_PROB_PCT  = 50;
const TMP_ORPHAN_TTL    = 3600;
const LEGACY_TTL_SEC    = 7 * 24 * 60 * 60; // per payload vecchi senza "expires"

/**
 * Hash Argon2id "dummy" pre-calcolato.
 * Serve per uniformare i tempi di risposta tra "token inesistente"
 * (caso veloce) e "password errata" (caso lento per via di password_verify).
 * I parametri (m=65536, t=4, p=1) sono quelli di default di PHP 7.4+ per Argon2id;
 * se in futuro PHP cambiasse i default e i nuovi segreti usassero parametri piu'
 * costosi, questo dummy sarebbe leggermente piu' veloce e fornirebbe un segnale
 * residuo. Per ora e' una mitigazione robusta.
 */
const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$cTlTSUtPTW96N0RxWEVBNQ$u1JqJ9F/mRRhHp0mmX9HsCM5b0qz+gy2YaUu8JbzPpk';

$storage = __DIR__ . STORAGE_SUBDIR;

// --- Validazione tipo del token ($_GET['token'] potrebbe essere array) ---
$tokenInput = $_GET['token'] ?? '';
$token = is_string($tokenInput) ? $tokenInput : '';

$decrypted = null;
$error     = '';

/**
 * Cleanup globale. Per ogni file acquisisce flock LOCK_EX | LOCK_NB:
 * se il lock non e' disponibile (file in uso) lo salta.
 * Questo evita di leggere un file durante una sua riscrittura legittima.
 */
function snm_cleanup_expired(string $storage): void {
    if (!is_dir($storage)) return;
    $dh = @opendir($storage);
    if (!$dh) return;

    $now = time();
    while (($entry = readdir($dh)) !== false) {
        if ($entry === '.' || $entry === '..') continue;
        $path = $storage . '/' . $entry;
        if (!is_file($path)) continue;

        // File .tmp_ orfani
        if (strpos($entry, '.tmp_') === 0) {
            $fp = @fopen($path, 'r+');
            if (!$fp) continue;
            if (!@flock($fp, LOCK_EX | LOCK_NB)) {
                fclose($fp);
                continue;
            }
            $mtime = @filemtime($path);
            if ($mtime !== false && ($now - $mtime) > TMP_ORPHAN_TTL) {
                @unlink($path);
            }
            @flock($fp, LOCK_UN);
            fclose($fp);
            continue;
        }

        // Segreti
        if (!preg_match('/^[a-f0-9]{32}$/', $entry)) continue;

        $fp = @fopen($path, 'r+');
        if (!$fp) continue;
        if (!@flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            continue; // file in uso, lo prendera' la prossima passata
        }

        $raw = stream_get_contents($fp);
        if ($raw === false) {
            @flock($fp, LOCK_UN);
            fclose($fp);
            continue;
        }

        $obj = json_decode($raw, true);
        $shouldDelete = false;

        if (!is_array($obj)) {
            $shouldDelete = true;
        } elseif (isset($obj['expires'])) {
            if ($now > (int)$obj['expires']) $shouldDelete = true;
        } elseif (isset($obj['created'])) {
            if ($now > ((int)$obj['created'] + LEGACY_TTL_SEC)) $shouldDelete = true;
        }

        @flock($fp, LOCK_UN);
        fclose($fp);

        if ($shouldDelete) @unlink($path);
    }
    closedir($dh);
}

/**
 * Ritorna true se il payload e' scaduto. Supporta nuovo e vecchio formato.
 */
function snm_is_expired(array $obj): bool {
    $now = time();
    if (isset($obj['expires'])) {
        return $now > (int)$obj['expires'];
    }
    if (isset($obj['created'])) {
        return $now > ((int)$obj['created'] + LEGACY_TTL_SEC);
    }
    return true; // payload sospetto senza nessun timestamp: trattalo come scaduto
}

// Cleanup probabilistico (50%) - random_int wrappato per robustezza
try {
    $shouldCleanup = (random_int(1, 100) <= CLEANUP_PROB_PCT);
} catch (\Throwable $e) {
    $shouldCleanup = false;
}
if ($shouldCleanup) {
    snm_cleanup_expired($storage);
}

// --- Validazione token (anche prevenzione path traversal) ---
if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
    http_response_code(400);
    die('Token non valido.');
}

$filePath = "{$storage}/{$token}";

/**
 * Rende il form di sblocco con campo nascosto per la chiave (popolato lato JS).
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

// --- POST: tentativo di sblocco ---

// Validazione tipo input (anti TypeError da array forgiati)
$keyInput  = $_POST['key']       ?? '';
$passInput = $_POST['view_pass'] ?? '';

$aesKey    = is_string($keyInput)  ? $keyInput  : '';
$inputPass = is_string($passInput) ? $passInput : '';

// Validazione chiave AES (256 bit hex)
if (!ctype_xdigit($aesKey) || strlen($aesKey) !== 64) {
    // Dummy verify per uniformare timing
    password_verify($inputPass, DUMMY_HASH);
    http_response_code(400);
    die('Chiave non valida o mancante.');
}

if (!file_exists($filePath)) {
    // Token inesistente: dummy verify per consumare lo stesso tempo
    // di un password_verify reale (mitigazione token enumeration via timing)
    password_verify($inputPass, DUMMY_HASH);
    $error = 'Link non valido o gia\' usato.';
} else {

    $fp = fopen($filePath, 'r+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        password_verify($inputPass, DUMMY_HASH); // uniformita' timing
        http_response_code(409);
        die('Richiesta in corso, riprova.');
    }

    $raw = stream_get_contents($fp);
    $obj = json_decode($raw, true);

    if (!is_array($obj) || !isset($obj['iv'], $obj['tag'], $obj['ct'], $obj['hash'])) {
        ftruncate($fp, 0);
        flock($fp, LOCK_UN);
        fclose($fp);
        @unlink($filePath);
        password_verify($inputPass, DUMMY_HASH);
        $error = 'Link non valido o gia\' usato.';
    } elseif (snm_is_expired($obj)) {
        ftruncate($fp, 0);
        flock($fp, LOCK_UN);
        fclose($fp);
        @unlink($filePath);
        password_verify($inputPass, DUMMY_HASH);
        $error = 'Link non valido o gia\' usato.';
    } else {

        $attempts = (int)($obj['attempts'] ?? 0);

        if ($attempts >= MAX_ATTEMPTS) {
            ftruncate($fp, 0);
            flock($fp, LOCK_UN);
            fclose($fp);
            @unlink($filePath);
            password_verify($inputPass, DUMMY_HASH);
            http_response_code(429);
            die('Troppi tentativi falliti. Il segreto e\' stato distrutto.');
        }

        // Verifica password (qui usiamo il vero hash)
        if (!password_verify($inputPass, $obj['hash'])) {
            $obj['attempts'] = $attempts + 1;
            $newPayload = json_encode($obj);
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, $newPayload);
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);

            if ($obj['attempts'] >= MAX_ATTEMPTS) {
                @unlink($filePath);
                http_response_code(429);
                die('Troppi tentativi falliti. Il segreto e\' stato distrutto.');
            }
            $error = 'Password errata.';
        } else {
            // Password corretta: decifra con AES-GCM (verifica tag inclusa)
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
                    ftruncate($fp, 0);
                    flock($fp, LOCK_UN);
                    fclose($fp);
                    @unlink($filePath);
                    $error = 'Link non valido o gia\' usato.';
                } else {
                    // OK: sovrascrivi a zeri (best effort) e cancella
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
      <p class="error-text"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
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
