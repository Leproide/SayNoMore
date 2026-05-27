<?php
/**
 * SayNoMore - index.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v5:
 *  - i18n: stringhe via lang.php, lingua scelta da Accept-Language
 *    (italiano per browser italiani, inglese per tutti gli altri)
 *  - <html lang="..."> sincronizzato con la lingua attiva
 *  - script.js riceve traduzioni del bottone copy via data-* attributes
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
const STORAGE_SUBDIR    = '/data';
const DEFAULT_TTL_DAYS  = 7;
const MIN_TTL_DAYS      = 1;
const MAX_TTL_DAYS      = 30;
const MAX_SECRET_BYTES  = 64 * 1024;        // 64 KB
const CLEANUP_ENABLED   = true;             // false = disattiva cleanup in-request (usa solo cron)
const CLEANUP_PROB_PCT  = 50;
const TMP_ORPHAN_TTL    = 3600;
const LEGACY_TTL_SEC    = 7 * 24 * 60 * 60;

$storage = __DIR__ . STORAGE_SUBDIR;

// --- Storage setup con umask stretta ---
$oldUmask = umask(0077);
if (!file_exists($storage)) {
    mkdir($storage, 0700, true);
}

/**
 * Cleanup globale: scansiona data/, elimina segreti scaduti e .tmp_ orfani.
 * flock LOCK_EX | LOCK_NB: i file in uso vengono saltati (race-safe).
 * Backward compatible col formato legacy ("created" + LEGACY_TTL_SEC).
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

$link  = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Validazione tipo input (anti TypeError da array forgiati)
    $secretInput = $_POST['secret']     ?? null;
    $passInput   = $_POST['passphrase'] ?? null;

    if (!is_string($secretInput) || !is_string($passInput)) {
        http_response_code(400);
        $error = t('err.input_invalid');
    } elseif ($secretInput === '' || $passInput === '') {
        $error = '';
    } elseif (strlen($secretInput) > MAX_SECRET_BYTES) {
        http_response_code(413);
        $error = t('err.too_large', ['size' => (int)(MAX_SECRET_BYTES / 1024)]);
    } else {

        // Validazione scadenza
        $days = filter_input(INPUT_POST, 'expiry_days', FILTER_VALIDATE_INT, [
            'options' => [
                'default'   => DEFAULT_TTL_DAYS,
                'min_range' => MIN_TTL_DAYS,
                'max_range' => MAX_TTL_DAYS,
            ],
        ]);
        if ($days === false || $days === null) {
            $days = DEFAULT_TTL_DAYS;
        }

        $secret     = trim($secretInput);
        $passphrase = $passInput;

        // --- Notifiche email opzionali ---
        // Attive solo se mailconfig.php ha 'enabled' => true. Se la
        // checkbox e' flaggata l'email viene validata e salvata nel
        // payload del segreto, per essere riusata da view.php quando il
        // segreto verra' letto o distrutto dopo troppi tentativi.
        $notifyEmail = '';
        if (snm_mail_enabled() && !empty($_POST['notify_enabled'])) {
            $rawEmail = $_POST['notify_email'] ?? '';
            if (is_string($rawEmail)) {
                $rawEmail = trim($rawEmail);
                if (filter_var($rawEmail, FILTER_VALIDATE_EMAIL) && strlen($rawEmail) <= 254) {
                    $notifyEmail = $rawEmail;
                }
            }
            if ($notifyEmail === '') {
                $error = t('err.notify_email_invalid');
            }
        }

        if ($error === '') {
        try {
            $token  = bin2hex(random_bytes(16));
            $aesKey = bin2hex(random_bytes(32));
            $cipher = 'aes-256-gcm';
            $ivLen  = openssl_cipher_iv_length($cipher);
            $iv     = random_bytes($ivLen);
        } catch (\Throwable $e) {
            http_response_code(500);
            umask($oldUmask);
            die(t('err.entropy'));
        }

        $hashPass = password_hash($passphrase, PASSWORD_ARGON2ID);
        if ($hashPass === false) {
            http_response_code(500);
            umask($oldUmask);
            die(t('err.gen_internal'));
        }

        $tag = '';
        $ct  = openssl_encrypt(
            $secret, $cipher, hex2bin($aesKey),
            OPENSSL_RAW_DATA, $iv, $tag, '', 16
        );
        if ($ct === false) {
            http_response_code(500);
            umask($oldUmask);
            die(t('err.encryption'));
        }

        $expires = time() + ($days * 86400);

        $payload = json_encode([
            'iv'       => base64_encode($iv),
            'tag'      => base64_encode($tag),
            'ct'       => base64_encode($ct),
            'hash'     => $hashPass,
            'expires'  => $expires,
            'attempts' => 0,
            // Notifiche opzionali: campi presenti solo se l'utente ha
            // flaggato la checkbox. La lingua serve per recapitare la mail
            // nella stessa lingua scelta in fase di creazione, indipendente
            // dall'Accept-Language del lettore.
            'notify_email' => $notifyEmail,
            'lang'         => snm_lang(),
        ]);

        $finalPath = "{$storage}/{$token}";
        $tmpPath   = "{$storage}/.tmp_{$token}";

        if (file_put_contents($tmpPath, $payload, LOCK_EX) === false) {
            http_response_code(500);
            umask($oldUmask);
            die(t('err.save'));
        }
        @chmod($tmpPath, 0600);
        if (!rename($tmpPath, $finalPath)) {
            @unlink($tmpPath);
            http_response_code(500);
            umask($oldUmask);
            die(t('err.save'));
        }

        // Costruzione link (HTTPS demandato al webserver, salvo .onion che usa HTTP)
        $host     = $_SERVER['HTTP_HOST'] ?? '';
        $hostOnly = preg_replace('/:\d+$/', '', $host);
        $isOnion  = substr($hostOnly, -6) === '.onion';

        if ($isOnion) {
            $proto = 'http';
        } else {
            $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        }

        $path = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');

        // Chiave nel FRAGMENT: mai inviata al server tramite il link
        $link = "{$proto}://{$host}{$path}/view.php?token={$token}#{$aesKey}";
        } // chiusura: if ($error === '')
    }
}

umask($oldUmask);
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(snm_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= htmlspecialchars(t('page.title.index'), ENT_QUOTES, 'UTF-8') ?></title>
  <link rel="stylesheet" href="style.css">
  <link rel="icon" href="favicon.ico">
  <link rel="shortcut icon" href="favicon.ico">
</head>
<body>
  <div class="container">
    <h1>SayNoMore</h1>

    <?php if ($error !== ''): ?>
      <p class="error-text"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
    <?php endif; ?>

    <?php if ($link): ?>
      <p class="info-text"><?= htmlspecialchars(t('index.link.label'), ENT_QUOTES, 'UTF-8') ?></p><br>
      <div class="link-box">
        <input id="secretLink" type="text" readonly value="<?= htmlspecialchars($link, ENT_QUOTES, 'UTF-8') ?>">
        <button
          id="copyBtn"
          type="button"
          data-label-default="<?= htmlspecialchars(t('index.btn.copy'),         ENT_QUOTES, 'UTF-8') ?>"
          data-label-success="<?= htmlspecialchars(t('index.btn.copy.success'), ENT_QUOTES, 'UTF-8') ?>"
          data-label-error="<?=   htmlspecialchars(t('index.btn.copy.error'),   ENT_QUOTES, 'UTF-8') ?>"
        ><?= htmlspecialchars(t('index.btn.copy'), ENT_QUOTES, 'UTF-8') ?></button>
      </div>
      <div class="actions">
        <form action="index.php" method="get"><button type="submit" class="generate"><?= htmlspecialchars(t('index.btn.new'), ENT_QUOTES, 'UTF-8') ?></button></form>
      </div>
    <?php else: ?>
      <form method="POST" autocomplete="off">
        <textarea
          name="secret"
          placeholder="<?= htmlspecialchars(t('index.placeholder.secret'), ENT_QUOTES, 'UTF-8') ?>"
          required
          maxlength="<?= MAX_SECRET_BYTES ?>"></textarea>

        <input
          type="password"
          name="passphrase"
          placeholder="<?= htmlspecialchars(t('index.placeholder.password'), ENT_QUOTES, 'UTF-8') ?>"
          required
          autocomplete="new-password"
          class="pw-input">

        <label for="expiry_days" class="field-label"><?= htmlspecialchars(t('index.label.expiry'), ENT_QUOTES, 'UTF-8') ?></label>
        <select name="expiry_days" id="expiry_days" class="pw-input">
          <option value="1"><?=  htmlspecialchars(t('index.opt.1day'),   ENT_QUOTES, 'UTF-8') ?></option>
          <option value="3"><?=  htmlspecialchars(t('index.opt.3days'),  ENT_QUOTES, 'UTF-8') ?></option>
          <option value="7" selected><?= htmlspecialchars(t('index.opt.7days'),  ENT_QUOTES, 'UTF-8') ?></option>
          <option value="14"><?= htmlspecialchars(t('index.opt.14days'), ENT_QUOTES, 'UTF-8') ?></option>
          <option value="30"><?= htmlspecialchars(t('index.opt.30days'), ENT_QUOTES, 'UTF-8') ?></option>
        </select>

        <?php if (snm_mail_enabled()): /* Mostra blocco notifiche solo se SMTP e' configurato e attivo in mailconfig.php */ ?>
        <label for="notify_email" class="field-label"><?= htmlspecialchars(t('index.label.notify_email'), ENT_QUOTES, 'UTF-8') ?></label>
        <input
          type="email"
          name="notify_email"
          id="notify_email"
          placeholder="<?= htmlspecialchars(t('index.placeholder.notify_email'), ENT_QUOTES, 'UTF-8') ?>"
          autocomplete="off"
          maxlength="254"
          class="pw-input">

        <label class="checkbox-row" for="notify_enabled">
          <input type="checkbox" name="notify_enabled" id="notify_enabled" value="1">
          <span><?= htmlspecialchars(t('index.label.notify_cb'), ENT_QUOTES, 'UTF-8') ?></span>
        </label>
        <?php endif; ?>

        <button type="submit" class="generate"><?= htmlspecialchars(t('index.btn.generate'), ENT_QUOTES, 'UTF-8') ?></button>
      </form>
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
