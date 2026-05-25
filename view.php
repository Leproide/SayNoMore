<?php
/**
 * SayNoMore - view.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v5:
 *  - i18n: stringhe via lang.php, lingua scelta da Accept-Language
 *  - <html lang="..."> sincronizzato con la lingua attiva
 */

require_once __DIR__ . '/lang.php';

// --- Security headers ---
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Permissions-Policy: interest-cohort=()');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Content-Language: ' . snm_lang());

// --- Config ---
const MAX_ATTEMPTS      = 5;
const STORAGE_SUBDIR    = '/data';
const CLEANUP_ENABLED   = true;             // false = disattiva cleanup in-request (usa solo cron)
const CLEANUP_PROB_PCT  = 50;
const TMP_ORPHAN_TTL    = 3600;
const LEGACY_TTL_SEC    = 7 * 24 * 60 * 60;

/**
 * Hash Argon2id "dummy" pre-calcolato per uniformare i tempi di risposta.
 */
const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$cTlTSUtPTW96N0RxWEVBNQ$u1JqJ9F/mRRhHp0mmX9HsCM5b0qz+gy2YaUu8JbzPpk';

$storage = __DIR__ . STORAGE_SUBDIR;

// Validazione tipo del token ($_GET['token'] potrebbe essere array)
$tokenInput = $_GET['token'] ?? '';
$token = is_string($tokenInput) ? $tokenInput : '';

$decrypted = null;
$error     = '';

/**
 * Cleanup globale (lock non-bloccante, race-safe).
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

        if (!preg_match('/^[a-f0-9]{32}$/', $entry)) continue;

        $fp = @fopen($path, 'r+');
        if (!$fp) continue;
        if (!@flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            continue;
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

function snm_is_expired(array $obj): bool {
    $now = time();
    if (isset($obj['expires'])) {
        return $now > (int)$obj['expires'];
    }
    if (isset($obj['created'])) {
        return $now > ((int)$obj['created'] + LEGACY_TTL_SEC);
    }
    return true;
}

// Cleanup probabilistico (controllato da CLEANUP_ENABLED)
if (CLEANUP_ENABLED) {
    try {
        $shouldCleanup = (random_int(1, 100) <= CLEANUP_PROB_PCT);
    } catch (\Throwable $e) {
        $shouldCleanup = false;
    }
    if ($shouldCleanup) {
        snm_cleanup_expired($storage);
    }
}

// Validazione token (anti path traversal)
if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
    render_error_page(t('err.token_invalid'), 400);
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
    <html lang="<?= htmlspecialchars(snm_lang(), ENT_QUOTES, 'UTF-8') ?>">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title><?= htmlspecialchars(t('page.title.unlock'), ENT_QUOTES, 'UTF-8') ?></title>
      <link rel="stylesheet" href="style.css">
    </head>
    <body>
      <div class="container">
        <h1><?= htmlspecialchars(t('view.heading.unlock'), ENT_QUOTES, 'UTF-8') ?></h1>
        <?php if ($errEsc): ?>
          <p class="error-text"><?= $errEsc ?></p>
        <?php endif; ?>
        <noscript>
          <p class="error-text"><?= htmlspecialchars(t('view.noscript'), ENT_QUOTES, 'UTF-8') ?></p>
        </noscript>
        <form id="unlockForm" method="POST" autocomplete="off">
          <input type="hidden" name="token" value="<?= $tokenEsc ?>">
          <input type="hidden" name="key"   id="keyField" value="">
          <input
            type="password"
            name="view_pass"
            placeholder="<?= htmlspecialchars(t('view.placeholder.password'), ENT_QUOTES, 'UTF-8') ?>"
            required
            autocomplete="off"
            class="pw-input">
          <button type="submit" class="generate"><?= htmlspecialchars(t('view.btn.unlock'), ENT_QUOTES, 'UTF-8') ?></button>
        </form>
      </div>
      <script src="script.js"></script>
      <footer>
        <div class="footer-content">
          <p><?= t('footer.tagline') ?> &mdash; <a href="https://github.com/leproide" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars(t('footer.github'), ENT_QUOTES, 'UTF-8') ?></a></p>
        </div>
      </footer>
    </body>
    </html>
    <?php
}

/**
 * Rende una pagina di errore integrata (stessa UI del resto del sito) e
 * termina lo script. Usata per tutti i casi in cui prima si chiamava
 * die(testoNudo): token invalido, link rotto, troppi tentativi, busy, ecc.
 *
 * @param string $errMsg     Messaggio gia' tradotto da mostrare
 * @param int    $httpStatus Codice HTTP da impostare prima di renderizzare
 */
function render_error_page(string $errMsg, int $httpStatus = 400): void {
    http_response_code($httpStatus);
    $errEsc = htmlspecialchars($errMsg, ENT_QUOTES, 'UTF-8');
    ?>
    <!DOCTYPE html>
    <html lang="<?= htmlspecialchars(snm_lang(), ENT_QUOTES, 'UTF-8') ?>">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title><?= htmlspecialchars(t('page.title.error'), ENT_QUOTES, 'UTF-8') ?></title>
      <link rel="stylesheet" href="style.css">
      <link rel="icon" href="favicon.ico">
      <link rel="shortcut icon" href="favicon.ico">
    </head>
    <body>
      <div class="container">
        <h1><?= htmlspecialchars(t('err.heading'), ENT_QUOTES, 'UTF-8') ?></h1>
        <p class="error-text"><?= $errEsc ?></p>
        <div class="actions">
          <form action="index.php" method="get"><button type="submit" class="generate"><?= htmlspecialchars(t('view.btn.home'), ENT_QUOTES, 'UTF-8') ?></button></form>
        </div>
      </div>
      <footer>
        <div class="footer-content">
          <p><?= t('footer.tagline') ?> &mdash; <a href="https://github.com/leproide" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars(t('footer.github'), ENT_QUOTES, 'UTF-8') ?></a></p>
        </div>
      </footer>
    </body>
    </html>
    <?php
    exit;
}

// --- GET: mostra il form ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    render_form($token);
    exit;
}

// --- POST: tentativo di sblocco ---

$keyInput  = $_POST['key']       ?? '';
$passInput = $_POST['view_pass'] ?? '';

$aesKey    = is_string($keyInput)  ? $keyInput  : '';
$inputPass = is_string($passInput) ? $passInput : '';

if (!ctype_xdigit($aesKey) || strlen($aesKey) !== 64) {
    password_verify($inputPass, DUMMY_HASH);
    render_error_page(t('err.key_invalid'), 400);
}

if (!file_exists($filePath)) {
    password_verify($inputPass, DUMMY_HASH);
    $error = t('err.link_invalid');
} else {

    $fp = fopen($filePath, 'r+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        password_verify($inputPass, DUMMY_HASH);
        render_error_page(t('err.busy'), 409);
    }

    $raw = stream_get_contents($fp);
    $obj = json_decode($raw, true);

    if (!is_array($obj) || !isset($obj['iv'], $obj['tag'], $obj['ct'], $obj['hash'])) {
        ftruncate($fp, 0);
        flock($fp, LOCK_UN);
        fclose($fp);
        @unlink($filePath);
        password_verify($inputPass, DUMMY_HASH);
        $error = t('err.link_invalid');
    } elseif (snm_is_expired($obj)) {
        ftruncate($fp, 0);
        flock($fp, LOCK_UN);
        fclose($fp);
        @unlink($filePath);
        password_verify($inputPass, DUMMY_HASH);
        $error = t('err.link_invalid');
    } else {

        $attempts = (int)($obj['attempts'] ?? 0);

        if ($attempts >= MAX_ATTEMPTS) {
            ftruncate($fp, 0);
            flock($fp, LOCK_UN);
            fclose($fp);
            @unlink($filePath);
            password_verify($inputPass, DUMMY_HASH);
            render_error_page(t('err.too_many'), 429);
        }

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
                render_error_page(t('err.too_many'), 429);
            }
            $error = t('err.wrong_pass');
        } else {
            $iv  = base64_decode($obj['iv'],  true);
            $tag = base64_decode($obj['tag'], true);
            $ct  = base64_decode($obj['ct'],  true);

            if ($iv === false || $tag === false || $ct === false) {
                ftruncate($fp, 0);
                flock($fp, LOCK_UN);
                fclose($fp);
                @unlink($filePath);
                $error = t('err.link_invalid');
            } else {
                $cipher = 'aes-256-gcm';
                $plain  = openssl_decrypt(
                    $ct, $cipher, hex2bin($aesKey),
                    OPENSSL_RAW_DATA, $iv, $tag
                );

                if ($plain === false) {
                    ftruncate($fp, 0);
                    flock($fp, LOCK_UN);
                    fclose($fp);
                    @unlink($filePath);
                    $error = t('err.link_invalid');
                } else {
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

// La password errata e' un caso speciale: ricostruisci il form, non confondere con l'errore generico
$isWrongPass = ($error === t('err.wrong_pass'));
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(snm_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= htmlspecialchars(t('page.title.view'), ENT_QUOTES, 'UTF-8') ?></title>
  <link rel="stylesheet" href="style.css">
  <link rel="icon" href="favicon.ico">
  <link rel="shortcut icon" href="favicon.ico">
</head>
<body>
  <div class="container">
    <?php if ($error !== ''): ?>
      <h1><?= htmlspecialchars(t('err.heading'), ENT_QUOTES, 'UTF-8') ?></h1>
      <p class="error-text"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
      <?php if ($isWrongPass): ?>
        <noscript>
          <p class="error-text"><?= htmlspecialchars(t('view.noscript.short'), ENT_QUOTES, 'UTF-8') ?></p>
        </noscript>
        <form id="unlockForm" method="POST" autocomplete="off">
          <input type="hidden" name="token" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="key"   id="keyField" value="">
          <input
            type="password"
            name="view_pass"
            placeholder="<?= htmlspecialchars(t('view.placeholder.password'), ENT_QUOTES, 'UTF-8') ?>"
            required
            autocomplete="off"
            class="pw-input">
          <button type="submit" class="generate"><?= htmlspecialchars(t('view.btn.retry'), ENT_QUOTES, 'UTF-8') ?></button>
        </form>
      <?php else: ?>
        <div class="actions">
          <form action="index.php" method="get"><button type="submit" class="generate"><?= htmlspecialchars(t('view.btn.home'), ENT_QUOTES, 'UTF-8') ?></button></form>
        </div>
      <?php endif; ?>
    <?php else: ?>
      <h1>SayNoMore</h1><br>
      <h2><?= htmlspecialchars(t('view.heading.secret'), ENT_QUOTES, 'UTF-8') ?></h2><br>
      <textarea readonly class="secret-box" id="secretBox"><?= htmlspecialchars($decrypted, ENT_QUOTES, 'UTF-8') ?></textarea>
      <div class="actions">
        <button
          type="button"
          id="copySecretBtn"
          class="generate"
          data-label-default="<?= htmlspecialchars(t('view.btn.copy_secret'),         ENT_QUOTES, 'UTF-8') ?>"
          data-label-success="<?= htmlspecialchars(t('view.btn.copy_secret.success'), ENT_QUOTES, 'UTF-8') ?>"
          data-label-error="<?=   htmlspecialchars(t('view.btn.copy_secret.error'),   ENT_QUOTES, 'UTF-8') ?>"
        ><?= htmlspecialchars(t('view.btn.copy_secret'), ENT_QUOTES, 'UTF-8') ?></button>
        <form action="index.php" method="get"><button type="submit" class="generate"><?= htmlspecialchars(t('view.btn.home'), ENT_QUOTES, 'UTF-8') ?></button></form>
      </div>
    <?php endif; ?>
  </div>

  <script src="script.js"></script>

  <footer>
    <div class="footer-content">
      <p><?= t('footer.tagline') ?> &mdash; <a href="https://github.com/leproide" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars(t('footer.github'), ENT_QUOTES, 'UTF-8') ?></a></p>
    </div>
  </footer>
</body>
</html>
