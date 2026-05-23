<?php
/**
 * SayNoMore - index.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v4:
 *  - Cleanup globale ora usa flock LOCK_EX | LOCK_NB su ogni file prima di
 *    leggerlo: se il file e' in uso da un'altra richiesta (update attempts,
 *    decifratura in corso) viene saltato, niente race condition possibile
 *  - Validazione del tipo input ($_POST) come stringa, evita TypeError 500
 *    e log sporchi causati da array forgiati
 *  - Generazione random_int / random_bytes wrappata in try/catch
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
const LEGACY_TTL_SEC    = 7 * 24 * 60 * 60; // fallback per payload vecchi senza "expires"

$storage = __DIR__ . STORAGE_SUBDIR;

// --- Storage setup con umask stretta per evitare finestre di permessi laschi ---
$oldUmask = umask(0077);
if (!file_exists($storage)) {
    mkdir($storage, 0700, true);
}

/**
 * Cleanup globale: scansiona la cartella data/, elimina i segreti scaduti
 * e i file temporanei orfani. Probabilistico, non bloccante.
 *
 * NB: per ogni file acquisisce flock LOCK_EX | LOCK_NB. Se il lock non e'
 * disponibile (file in uso da un'altra richiesta) il file viene saltato.
 * Questo previene la race condition con update di attempts/decifratura in
 * corso, che potrebbero trovare il file appena truncato durante un rewrite.
 *
 * Backward compatible col vecchio formato che usava "created" + LEGACY_TTL_SEC.
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

        // File temporanei orfani (scritture fallite)
        if (strpos($entry, '.tmp_') === 0) {
            $fp = @fopen($path, 'r+');
            if (!$fp) continue;
            if (!@flock($fp, LOCK_EX | LOCK_NB)) {
                fclose($fp);
                continue; // qualcuno lo sta scrivendo
            }
            $mtime = @filemtime($path);
            if ($mtime !== false && ($now - $mtime) > TMP_ORPHAN_TTL) {
                @unlink($path);
            }
            @flock($fp, LOCK_UN);
            fclose($fp);
            continue;
        }

        // Segreti: nome valido = 32 hex chars
        if (!preg_match('/^[a-f0-9]{32}$/', $entry)) continue;

        $fp = @fopen($path, 'r+');
        if (!$fp) continue;
        if (!@flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            continue; // file in uso, lo gestira' la prossima passata
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
            // Payload corrotto: rimuovi (abbiamo gia' il lock, e' stabile)
            $shouldDelete = true;
        } elseif (isset($obj['expires'])) {
            // Nuovo formato
            if ($now > (int)$obj['expires']) $shouldDelete = true;
        } elseif (isset($obj['created'])) {
            // Vecchio formato (compat con segreti pre-v3)
            if ($now > ((int)$obj['created'] + LEGACY_TTL_SEC)) $shouldDelete = true;
        }

        @flock($fp, LOCK_UN);
        fclose($fp);

        if ($shouldDelete) @unlink($path);
    }
    closedir($dh);
}

// Cleanup probabilistico (50%) - random_int wrappato per robustezza
try {
    $shouldCleanup = (random_int(1, 100) <= CLEANUP_PROB_PCT);
} catch (\Throwable $e) {
    // Se la sorgente di entropia fallisce, saltiamo il cleanup (innocuo)
    $shouldCleanup = false;
}
if ($shouldCleanup) {
    snm_cleanup_expired($storage);
}

$link  = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // --- Validazione tipo input (anti TypeError da array forgiati) ---
    $secretInput = $_POST['secret']     ?? null;
    $passInput   = $_POST['passphrase'] ?? null;

    if (!is_string($secretInput) || !is_string($passInput)) {
        http_response_code(400);
        $error = 'Input non valido.';
    } elseif ($secretInput === '' || $passInput === '') {
        // Solo se entrambi presenti e non vuoti procediamo
        $error = '';
    } elseif (strlen($secretInput) > MAX_SECRET_BYTES) {
        // Limite dimensione (anti-DoS): controllo PRIMA di qualsiasi processing
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

        // Trim solo del secret, non della password (potrebbero esserci spazi voluti)
        $secret     = trim($secretInput);
        $passphrase = $passInput;

        // Generazione sicura di token, chiave AES e IV.
        // Se la sorgente di entropia fallisce, fail-fast: non possiamo proseguire
        // senza randomness sicura.
        try {
            $token  = bin2hex(random_bytes(16));        // 128 bit token
            $aesKey = bin2hex(random_bytes(32));        // 256 bit AES key
            $cipher = 'aes-256-gcm';
            $ivLen  = openssl_cipher_iv_length($cipher);
            $iv     = random_bytes($ivLen);             // 96 bit GCM IV
        } catch (\Throwable $e) {
            http_response_code(500);
            umask($oldUmask);
            die('Sorgente di entropia non disponibile.');
        }

        // Hash password con Argon2id (slow hash, salt automatico)
        $hashPass = password_hash($passphrase, PASSWORD_ARGON2ID);
        if ($hashPass === false) {
            http_response_code(500);
            umask($oldUmask);
            die('Errore interno durante la generazione.');
        }

        // Cifratura AES-256-GCM (authenticated encryption)
        $tag = '';
        $ct  = openssl_encrypt(
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
        // $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';

        // Fix per TOR
	$isOnion = str_ends_with($_SERVER['HTTP_HOST'] ?? '', '.onion');
	if ($isOnion) {
		$proto = 'http';
	} else {
		$proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
	}

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
