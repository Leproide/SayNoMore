<?php
/**
 * SayNoMore - view.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v6 (E2E):
 *  - La decifratura avviene NEL BROWSER. Il server non riceve piu' la chiave
 *    AES (fragKey) nel POST: riceve solo token + passphrase.
 *  - Flusso: il server verifica la password (gate: 5 tentativi, one-time,
 *    timing dummy invariati) e SOLO a password corretta restituisce iv + ct
 *    (JSON) distruggendo il file. Il client decifra localmente con fragKey.
 *  - Conseguenza: chi ha la password ma non fragKey riceve il ciphertext (che
 *    viene comunque consumato) ma non puo' leggerlo. Semantica one-time
 *    invariata. Il server non puo' decifrare in alcun caso.
 */

require_once __DIR__ . '/lang.php';
require_once __DIR__ . '/mail.php';

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

/**
 * Risposta JSON e stop. Usata dalla API di unlock (POST).
 */
function snm_json(int $status, array $payload): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload);
    exit;
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

/**
 * Rende il form di sblocco. La chiave NON e' piu' inviata al server: viene
 * letta da script.js dal fragment e usata solo per la decifratura locale.
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
      <link rel="icon" href="favicon.ico">
      <link rel="shortcut icon" href="favicon.ico">
    </head>
    <body>
      <div class="container"
           data-err-wrong="<?= htmlspecialchars(t('err.wrong_pass'),      ENT_QUOTES, 'UTF-8') ?>"
           data-err-toomany="<?= htmlspecialchars(t('err.too_many'),      ENT_QUOTES, 'UTF-8') ?>"
           data-err-link="<?= htmlspecialchars(t('err.link_invalid'),     ENT_QUOTES, 'UTF-8') ?>"
           data-err-busy="<?= htmlspecialchars(t('err.busy'),             ENT_QUOTES, 'UTF-8') ?>"
           data-err-key="<?= htmlspecialchars(t('err.key_invalid'),       ENT_QUOTES, 'UTF-8') ?>"
           data-err-decrypt="<?= htmlspecialchars(t('err.decrypt_failed'),ENT_QUOTES, 'UTF-8') ?>"
           data-err-ctx="<?= htmlspecialchars(t('err.crypto_unavailable'),ENT_QUOTES, 'UTF-8') ?>"
           data-err-generic="<?= htmlspecialchars(t('err.input_invalid'), ENT_QUOTES, 'UTF-8') ?>">
        <h1 id="unlockHeading"><?= htmlspecialchars(t('view.heading.unlock'), ENT_QUOTES, 'UTF-8') ?></h1>

        <?php if ($errEsc): ?>
          <p class="error-text" id="viewError"><?= $errEsc ?></p>
        <?php else: ?>
          <p class="error-text" id="viewError" hidden></p>
        <?php endif; ?>

        <noscript>
          <p class="error-text"><?= htmlspecialchars(t('view.noscript'), ENT_QUOTES, 'UTF-8') ?></p>
        </noscript>

        <!-- Form di sblocco (intercettato da JS: invia solo token + password) -->
        <form id="unlockForm" method="POST" autocomplete="off"
              data-heading-secret="<?= htmlspecialchars(t('view.heading.secret'), ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="token" value="<?= $tokenEsc ?>">
          <input
            type="password"
            name="view_pass"
            id="viewPass"
            placeholder="<?= htmlspecialchars(t('view.placeholder.password'), ENT_QUOTES, 'UTF-8') ?>"
            required
            autocomplete="off"
            class="pw-input">
          <button type="submit" class="generate"><?= htmlspecialchars(t('view.btn.unlock'), ENT_QUOTES, 'UTF-8') ?></button>
        </form>

        <!-- Contenitore del segreto decifrato (popolato da JS dopo decrypt) -->
        <div id="secretResult" hidden>
          <h1>SayNoMore</h1><br>
          <h2><?= htmlspecialchars(t('view.heading.secret'), ENT_QUOTES, 'UTF-8') ?></h2><br>
          <textarea readonly class="secret-box" id="secretBox"></textarea>
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
        </div>
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
 * Pagina di errore integrata (per i casi non-POST: token invalido).
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

// Validazione token (anti path traversal). Per GET mostra pagina, per POST JSON.
if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        snm_json(400, ['ok' => false, 'error' => t('err.token_invalid')]);
    }
    render_error_page(t('err.token_invalid'), 400);
}

$filePath = "{$storage}/{$token}";

// --- GET: mostra il form ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    render_form($token);
    exit;
}

// ============================================================================
//  POST = API di unlock (JSON). Riceve SOLO token + view_pass (mai la chiave).
//  A password corretta restituisce iv + ct e distrugge il file.
// ============================================================================

$passInput = $_POST['view_pass'] ?? '';
$inputPass = is_string($passInput) ? $passInput : '';

// Cap lunghezza password (come in creazione): evita POST abnormi che
// alimentano password_verify/Argon2id. Validazione input, nessun oracolo token.
if (strlen($inputPass) > 1024) {
    snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
}

if (!file_exists($filePath)) {
    password_verify($inputPass, DUMMY_HASH); // timing uniforme
    snm_json(404, ['ok' => false, 'error' => t('err.link_invalid')]);
}

$fp = fopen($filePath, 'r+');
if (!$fp || !flock($fp, LOCK_EX)) {
    if ($fp) fclose($fp);
    password_verify($inputPass, DUMMY_HASH);
    snm_json(409, ['ok' => false, 'error' => t('err.busy')]);
}

$raw = stream_get_contents($fp);
$obj = json_decode($raw, true);

// Integrita' record: ora richiediamo iv, ct, hash (niente piu' 'tag' separato)
if (!is_array($obj) || !isset($obj['iv'], $obj['ct'], $obj['hash']) || !is_string($obj['hash'])) {
    ftruncate($fp, 0);
    flock($fp, LOCK_UN);
    fclose($fp);
    @unlink($filePath);
    password_verify($inputPass, DUMMY_HASH);
    snm_json(404, ['ok' => false, 'error' => t('err.link_invalid')]);
}

// Dati notifiche catturati PRIMA di qualsiasi modifica/cancellazione del file
// (servono anche al ramo "scaduto" qui sotto).
$notifyEmail = isset($obj['notify_email']) && is_string($obj['notify_email']) ? $obj['notify_email'] : '';
$notifyLang  = isset($obj['lang']) && is_string($obj['lang']) ? $obj['lang'] : snm_lang();
$notifyId    = substr($token, 0, 8);

if (snm_is_expired($obj)) {
    ftruncate($fp, 0);
    flock($fp, LOCK_UN);
    fclose($fp);
    @unlink($filePath);
    // Notifica "aperto ma scaduto": qualcuno ha aperto il link di un segreto
    // gia' scaduto. Il contenuto non viene mostrato; il file viene rimosso.
    // Invio deferred per non rallentare la risposta (vedi mail.php).
    if ($notifyEmail !== '') {
        snm_send_notification_deferred($notifyEmail, $notifyId, 'expired_open', $notifyLang);
    }
    password_verify($inputPass, DUMMY_HASH);
    snm_json(404, ['ok' => false, 'error' => t('err.link_invalid')]);
}

$attempts = (int)($obj['attempts'] ?? 0);

if ($attempts >= MAX_ATTEMPTS) {
    ftruncate($fp, 0);
    flock($fp, LOCK_UN);
    fclose($fp);
    @unlink($filePath);
    password_verify($inputPass, DUMMY_HASH);
    snm_json(429, ['ok' => false, 'error' => t('err.too_many')]);
}

if (!password_verify($inputPass, $obj['hash'])) {
    // Password errata: incrementa il contatore e persisti.
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
        if ($notifyEmail !== '') {
            snm_send_notification_deferred($notifyEmail, $notifyId, 'destroyed', $notifyLang);
        }
        snm_json(429, ['ok' => false, 'error' => t('err.too_many')]);
    }
    snm_json(401, ['ok' => false, 'error' => t('err.wrong_pass')]);
}

// --- Password corretta: rilascia iv+ct, distruggi il file (one-time) ---
$iv = $obj['iv'];
$ct = $obj['ct'];

// Best-effort overwrite + unlink (come prima; la decifratura e' lato client)
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

if ($notifyEmail !== '') {
    snm_send_notification_deferred($notifyEmail, $notifyId, 'read', $notifyLang);
}

// Il server restituisce solo iv + ct (base64). Decifratura nel browser.
snm_json(200, ['ok' => true, 'iv' => $iv, 'ct' => $ct]);
