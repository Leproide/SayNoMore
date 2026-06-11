<?php
/**
 * SayNoMore - index.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v6 (E2E):
 *  - Cifratura spostata NEL BROWSER (Web Crypto, AES-256-GCM). Il server non
 *    vede piu' il plaintext ne' la chiave AES (K_frag) in nessuna fase.
 *  - La creazione e' ora una API JSON: il client invia solo iv + ct
 *    (ciphertext+tag) + passphrase + TTL. Il server salva il ciphertext del
 *    client e l'hash Argon2id della passphrase; NON cifra nulla.
 *  - Il link (con K_frag nel fragment) viene costruito dal browser: il server
 *    non conosce K_frag.
 *  - Requisiti: JavaScript + secure context (HTTPS o .onion). Su HTTP clearnet
 *    l'E2E e' disabilitato lato client con messaggio esplicito.
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
const MAX_SECRET_BYTES  = 64 * 1024;        // 64 KB (plaintext lato client)
// Il ciphertext base64 e' piu' grande del plaintext: +16 byte tag GCM, poi
// l'overhead base64 (~33%). Limite generoso ma finito per evitare abusi.
const MAX_CT_B64_BYTES  = 96 * 1024;        // ~96 KB di base64
const GCM_IV_LEN        = 12;               // IV a 12 byte (raccomandato per GCM)
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

/**
 * Risposta JSON e stop. Usata da tutta la API di creazione.
 */
function snm_json(int $status, array $payload): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload);
    exit;
}

// ============================================================================
//  POST = API di creazione (JSON). Il client ha gia' cifrato: riceviamo solo
//  iv + ct + passphrase + TTL. Nessuna cifratura lato server.
// ============================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Validazione tipo input (anti TypeError da array forgiati)
    $ivInput   = $_POST['iv']         ?? null;
    $ctInput   = $_POST['ct']         ?? null;
    $passInput = $_POST['passphrase'] ?? null;

    if (!is_string($ivInput) || !is_string($ctInput) || !is_string($passInput)) {
        snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
    }
    if ($ctInput === '' || $ivInput === '') {
        snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
    }
    if ($passInput === '') {
        snm_json(400, ['ok' => false, 'error' => t('err.password_required')]);
    }
    // Limite di lunghezza passphrase (anti amplificazione costo Argon2id)
    if (strlen($passInput) > 1024) {
        snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
    }
    if (strlen($ctInput) > MAX_CT_B64_BYTES) {
        snm_json(413, ['ok' => false, 'error' => t('err.too_large', ['size' => (int)(MAX_SECRET_BYTES / 1024)])]);
    }

    // Decodifica/validazione binaria di iv e ct (strict base64)
    $ivBin = base64_decode($ivInput, true);
    $ctBin = base64_decode($ctInput, true);
    if ($ivBin === false || $ctBin === false) {
        snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
    }
    if (strlen($ivBin) !== GCM_IV_LEN) {
        snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
    }
    // ct deve contenere almeno il tag GCM (16 byte). Plaintext vuoto non ammesso.
    if (strlen($ctBin) <= 16) {
        snm_json(400, ['ok' => false, 'error' => t('err.input_invalid')]);
    }
    // Plaintext effettivo = ct - tag. Enforce limite lato server (oltre al client).
    if ((strlen($ctBin) - 16) > MAX_SECRET_BYTES) {
        snm_json(413, ['ok' => false, 'error' => t('err.too_large', ['size' => (int)(MAX_SECRET_BYTES / 1024)])]);
    }

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

    // --- Notifiche email opzionali (metadata, NON cifrate) ---
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
            snm_json(400, ['ok' => false, 'error' => t('err.notify_email_invalid')]);
        }
    }

    // --- Token + hash password (l'unico lavoro crypto lato server resta
    //     l'hashing della passphrase, che serve come gate di accesso) ---
    try {
        $token = bin2hex(random_bytes(16));
    } catch (\Throwable $e) {
        umask($oldUmask);
        snm_json(500, ['ok' => false, 'error' => t('err.entropy')]);
    }

    $hashPass = password_hash($passInput, PASSWORD_ARGON2ID);
    if ($hashPass === false) {
        umask($oldUmask);
        snm_json(500, ['ok' => false, 'error' => t('err.gen_internal')]);
    }

    $expires = time() + ($days * 86400);

    // Storage: ct gia' contiene il tag GCM (formato Web Crypto). Nessun campo
    // 'tag' separato, nessuna chiave: il server non puo' decifrare.
    $payload = json_encode([
        'iv'           => base64_encode($ivBin),
        'ct'           => base64_encode($ctBin),
        'hash'         => $hashPass,
        'expires'      => $expires,
        'attempts'     => 0,
        'notify_email' => $notifyEmail,
        'lang'         => snm_lang(),
    ]);

    $finalPath = "{$storage}/{$token}";
    $tmpPath   = "{$storage}/.tmp_{$token}";

    if (file_put_contents($tmpPath, $payload, LOCK_EX) === false) {
        umask($oldUmask);
        snm_json(500, ['ok' => false, 'error' => t('err.save')]);
    }
    @chmod($tmpPath, 0600);
    if (!rename($tmpPath, $finalPath)) {
        @unlink($tmpPath);
        umask($oldUmask);
        snm_json(500, ['ok' => false, 'error' => t('err.save')]);
    }

    umask($oldUmask);
    // Ritorniamo solo il token: il browser costruisce view.php?token=...#K_frag
    snm_json(200, ['ok' => true, 'token' => $token]);
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

    <?php if (snm_mail_debug()): /* Avviso: il logging di debug email e' attivo (mailconfig.php) */ ?>
      <p class="error-text error-strong"><?= htmlspecialchars(t('index.maildebug_warning'), ENT_QUOTES, 'UTF-8') ?></p>
    <?php endif; ?>

    <!-- Avvisi runtime (popolati da script.js): JS assente o secure context mancante -->
    <noscript>
      <p class="error-text error-strong"><?= htmlspecialchars(t('index.js_required'), ENT_QUOTES, 'UTF-8') ?></p>
    </noscript>
    <p id="ctxWarn" class="error-text error-strong" hidden
       data-insecure-msg="<?= htmlspecialchars(t('err.crypto_unavailable'), ENT_QUOTES, 'UTF-8') ?>"></p>

    <!-- Messaggio di errore generico della API (popolato da JS) -->
    <p id="formError" class="error-text" hidden></p>

    <!-- Risultato: link generato. Nascosto finche' JS non lo popola. -->
    <div id="resultBox" hidden>
      <p class="info-text"><?= htmlspecialchars(t('index.link.label'), ENT_QUOTES, 'UTF-8') ?></p><br>
      <div class="link-box">
        <input id="secretLink" type="text" readonly value="">
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
    </div>

    <!-- Form di creazione. Il submit e' intercettato da JS: cifra nel browser
         e invia iv+ct via fetch. maxlength sul plaintext = MAX_SECRET_BYTES. -->
    <form method="POST" autocomplete="off" id="snmForm">
      <textarea
        id="secretField"
        placeholder="<?= htmlspecialchars(t('index.placeholder.secret'), ENT_QUOTES, 'UTF-8') ?>"
        required
        maxlength="<?= MAX_SECRET_BYTES ?>"
        data-required-msg="<?= htmlspecialchars(t('index.required_field'), ENT_QUOTES, 'UTF-8') ?>"></textarea>

      <input
        type="password"
        id="passField"
        placeholder="<?= htmlspecialchars(t('index.placeholder.password'), ENT_QUOTES, 'UTF-8') ?>"
        required
        autocomplete="new-password"
        maxlength="1024"
        class="pw-input"
        data-required-msg="<?= htmlspecialchars(t('err.password_required'), ENT_QUOTES, 'UTF-8') ?>">

      <label for="expiry_days" class="field-label"><?= htmlspecialchars(t('index.label.expiry'), ENT_QUOTES, 'UTF-8') ?></label>
      <select name="expiry_days" id="expiry_days" class="pw-input">
        <option value="1"><?=  htmlspecialchars(t('index.opt.1day'),   ENT_QUOTES, 'UTF-8') ?></option>
        <option value="3"><?=  htmlspecialchars(t('index.opt.3days'),  ENT_QUOTES, 'UTF-8') ?></option>
        <option value="7" selected><?= htmlspecialchars(t('index.opt.7days'),  ENT_QUOTES, 'UTF-8') ?></option>
        <option value="14"><?= htmlspecialchars(t('index.opt.14days'), ENT_QUOTES, 'UTF-8') ?></option>
        <option value="30"><?= htmlspecialchars(t('index.opt.30days'), ENT_QUOTES, 'UTF-8') ?></option>
      </select>

      <?php if (snm_mail_enabled()):
        $notifyChecked  = !empty($_POST['notify_enabled']);
        $notifyEmailVal = (isset($_POST['notify_email']) && is_string($_POST['notify_email'])) ? $_POST['notify_email'] : '';
      ?>
      <label class="checkbox-row" for="notify_enabled">
        <input type="checkbox" name="notify_enabled" id="notify_enabled" value="1"<?= $notifyChecked ? ' checked' : '' ?>>
        <span><?= htmlspecialchars(t('index.label.notify_cb'), ENT_QUOTES, 'UTF-8') ?></span>
      </label>

      <div id="notifyEmailWrap"<?= $notifyChecked ? '' : ' hidden' ?>>
        <label for="notify_email" class="field-label"><?= htmlspecialchars(t('index.label.notify_email'), ENT_QUOTES, 'UTF-8') ?></label>
        <input
          type="email"
          name="notify_email"
          id="notify_email"
          placeholder="<?= htmlspecialchars(t('index.placeholder.notify_email'), ENT_QUOTES, 'UTF-8') ?>"
          value="<?= htmlspecialchars($notifyEmailVal, ENT_QUOTES, 'UTF-8') ?>"
          autocomplete="off"
          maxlength="254"
          data-required-msg="<?= htmlspecialchars(t('index.required_field'), ENT_QUOTES, 'UTF-8') ?>"
          data-invalid-msg="<?= htmlspecialchars(t('err.notify_email_invalid'), ENT_QUOTES, 'UTF-8') ?>"
          class="pw-input">
      </div>
      <?php endif; ?>

      <button type="submit" class="generate"><?= htmlspecialchars(t('index.btn.generate'), ENT_QUOTES, 'UTF-8') ?></button>
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
