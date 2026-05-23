<?php
/**
 * SayNoMore - index.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v3:
 *  - TTL configurabile dall'utente (1-30 giorni, default 7), validato server-side
 *  - Limite dimensione secret (default 64 KB)
 *  - Cleanup globale probabilistico (50% delle richieste): scansiona data/
 *    e cancella tutti i segreti scaduti, oltre ai file .tmp_ orfani > 1h
 *  - Payload: il campo "created" e' stato sostituito da "expires" (timestamp assoluto)
 *  - umask 0077 prima della scrittura, niente finestra di permessi laschi
 */

// --- Security headers ---
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Permissions-Policy: interest-cohort=()');
header('Cache-Control: no-store, no-cache, must-revalidate');

// --- Config ---
const STORAGE_SUBDIR    = '/data';
const DEFAULT_TTL_DAYS  = 7;
const MIN_TTL_DAYS      = 1;
const MAX_TTL_DAYS      = 30;
const MAX_SECRET_BYTES  = 64 * 1024;        // 64 KB
const CLEANUP_PROB_PCT  = 50;               // 50% di probabilita' di scan completo
const TMP_ORPHAN_TTL    = 3600;             // file .tmp_ piu' vecchi di 1h vengono rimossi

$storage = __DIR__ . STORAGE_SUBDIR;

// --- Storage setup con umask stretta per evitare finestre di permessi laschi ---
$oldUmask = umask(0077);
if (!file_exists($storage)) {
    mkdir($storage, 0700, true);
}

/**
 * Cleanup globale: scansiona la cartella data/, elimina i segreti scaduti
 * e i file temporanei orfani. Probabilistico, non bloccante.
 * Backward compatible col vecchio formato che usava "created" + SECRET_TTL.
 */
function snm_cleanup_expired(string $storage): void {
    if (!is_dir($storage)) return;
    $dh = @opendir($storage);
    if (!$dh) return;

    $now = time();
    // Fallback per vecchi payload privi del campo "expires" (compat con versione precedente)
    $legacyTtl = 7 * 24 * 60 * 60;

    while (($entry = readdir($dh)) !== false) {
        if ($entry === '.' || $entry === '..') continue;
        $path = $storage . '/' . $entry;
        if (!is_file($path)) continue;

        // File temporanei orfani (scritture fallite)
        if (strpos($entry, '.tmp_') === 0) {
            $mtime = @filemtime($path);
            if ($mtime !== false && ($now - $mtime) > TMP_ORPHAN_TTL) {
                @unlink($path);
            }
            continue;
        }

        // Segreti: nome valido = 32 hex chars
        if (!preg_match('/^[a-f0-9]{32}$/', $entry)) continue;

        $raw = @file_get_contents($path);
        if ($raw === false) continue;

        $obj = json_decode($raw, true);
        if (!is_array($obj)) {
            // Payload corrotto: rimuovi
            @unlink($path);
            continue;
        }

        // Nuovo formato: campo "expires" (timestamp assoluto)
        if (isset($obj['expires'])) {
            if ($now > (int)$obj['expires']) {
                @unlink($path);
            }
            continue;
        }

        // Vecchio formato: "created" + TTL fisso a 7 giorni
        if (isset($obj['created'])) {
            if ($now > ((int)$obj['created'] + $legacyTtl)) {
                @unlink($path);
            }
        }
    }
    closedir($dh);
}

// Cleanup probabilistico (al 50%)
if (random_int(1, 100) <= CLEANUP_PROB_PCT) {
    snm_cleanup_expired($storage);
}

$link  = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['secret']) && !empty($_POST['passphrase'])) {

    $secretRaw = (string)$_POST['secret'];

    // Limite dimensione (anti-DoS): controllo PRIMA di qualsiasi processing
    if (strlen($secretRaw) > MAX_SECRET_BYTES) {
        http_response_code(413);
        $error = 'Segreto troppo grande. Massimo ' . (MAX_SECRET_BYTES / 1024) . ' KB.';
    } else {

        // Validazione lato server della scadenza scelta dall'utente
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

        // Trim solo del secret (la password no, potrebbero esserci spazi voluti)
        $secret     = trim($secretRaw);
        $passphrase = $_POST['passphrase'];

        // Token: 128 bit hex, nome file
        $token = bin2hex(random_bytes(16));

        // Chiave AES: 256 bit hex, andra' nel fragment URL
        $aesKey = bin2hex(random_bytes(32));

        // Hash password con Argon2id (slow hash, salt automatico)
        $hashPass = password_hash($passphrase, PASSWORD_ARGON2ID);
        if ($hashPass === false) {
            http_response_code(500);
            umask($oldUmask);
            die('Errore interno durante la generazione.');
        }

        // Cifratura AES-256-GCM (authenticated encryption)
        $cipher = 'aes-256-gcm';
        $ivLen  = openssl_cipher_iv_length($cipher);
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
            umask($oldUmask);
            die('Errore interno durante la cifratura.');
        }

        $expires = time() + ($days * 86400);

        $payload = json_encode([
            'iv'       => base64_encode($iv),
            'tag'      => base64_encode($tag),
            'ct'       => base64_encode($ct),
            'hash'     => $hashPass,
            'expires'  => $expires,
            'attempts' => 0,
        ]);

        // Scrittura atomica con umask stretta gia' applicata
        $finalPath = "{$storage}/{$token}";
        $tmpPath   = "{$storage}/.tmp_{$token}";

        if (file_put_contents($tmpPath, $payload, LOCK_EX) === false) {
            http_response_code(500);
            umask($oldUmask);
            die('Errore interno durante il salvataggio.');
        }
        @chmod($tmpPath, 0600);
        if (!rename($tmpPath, $finalPath)) {
            @unlink($tmpPath);
            http_response_code(500);
            umask($oldUmask);
            die('Errore interno durante il salvataggio.');
        }

        // Costruzione link (HTTPS effettivo demandato al webserver)
        $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        $host  = $_SERVER['HTTP_HOST'];
        $path  = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');

        // Chiave nel FRAGMENT: mai inviata al server tramite il link
        $link = "{$proto}://{$host}{$path}/view.php?token={$token}#{$aesKey}";
    }
}

umask($oldUmask);
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

    <?php if ($error !== ''): ?>
      <p class="error-text"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>

    <?php if ($link): ?>
      <p class="info-text">Link generato (copia e invia):</p><br>
      <div class="link-box">
        <input id="secretLink" type="text" readonly value="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>">
        <button id="copyBtn" type="button">Copia</button>
      </div>
    <?php else: ?>
      <form method="POST" autocomplete="off">
        <textarea name="secret" placeholder="Inserisci il tuo segreto..." required maxlength="<?php echo MAX_SECRET_BYTES; ?>"></textarea>

        <input
          type="password"
          name="passphrase"
          placeholder="Inserisci una password"
          required
          autocomplete="new-password"
          class="pw-input">

        <label for="expiry_days" class="field-label">Scadenza del link:</label>
        <select name="expiry_days" id="expiry_days" class="pw-input">
          <option value="1">1 giorno</option>
          <option value="3">3 giorni</option>
          <option value="7" selected>7 giorni (default)</option>
          <option value="14">14 giorni</option>
          <option value="30">30 giorni (massimo)</option>
        </select>

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
