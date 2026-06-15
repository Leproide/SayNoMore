<?php
/**
 * SayNoMore - cleanup.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Script CLI per la pulizia garantita dei segreti scaduti e dei file
 * temporanei orfani. Da eseguire via cron come opzione alternativa o
 * complementare al cleanup probabilistico in-request.
 *
 * Uso:
 *   php /path/to/SayNoMore/cleanup.php
 *
 * Esempio crontab (ogni ora, alle :15):
 *   15 * * * * /usr/bin/php /var/www/saynomore/cleanup.php >/dev/null 2>&1
 *
 * Nota: e' SICURO eseguirlo in parallelo a richieste web,
 * grazie a flock LOCK_EX | LOCK_NB su ogni file (i file in uso vengono saltati).
 *
 * Patch notes v5:
 *  - set_time_limit(0) esplicito (CLI di default lo e', ma essere espliciti
 *    evita sorprese su build PHP custom)
 *  - Errori di accesso ai file ora vengono loggati su STDERR con il path,
 *    invece di essere conteggiati silenziosamente
 *  - Messaggi di output sempre in inglese (CLI per amministratori,
 *    indipendente dalla lingua del browser)
 */

// Blocca l'esecuzione se chiamato da web (CGI/FPM/qualsiasi non-CLI)
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die("This script must be run from CLI only.\n");
}

// CLI di solito ha gia' time limit 0, ma essere espliciti evita sorprese
@set_time_limit(0);

// --- Config (identica a index.php / view.php) ---
const STORAGE_SUBDIR = '/data';
const TMP_ORPHAN_TTL = 3600;
const LEGACY_TTL_SEC = 7 * 24 * 60 * 60;

// Client SMTP per le notifiche opzionali (no-op se mailconfig.php assente o
// 'enabled' => false). Usato solo per i segreti scaduti che non sono mai stati
// aperti e che contengono un campo notify_email valido.
require_once __DIR__ . '/mail.php';

$storage = __DIR__ . STORAGE_SUBDIR;

if (!is_dir($storage)) {
    fwrite(STDERR, "Storage folder not found: {$storage}\n");
    exit(1);
}

if (!is_readable($storage) || !is_writable($storage)) {
    fwrite(STDERR, "Storage folder not readable/writable: {$storage}\n");
    fwrite(STDERR, "Check that the user running this script has the right permissions.\n");
    exit(1);
}

$now   = time();
$stats = [
    'scanned'        => 0,
    'expired'        => 0,
    'notified'       => 0,
    'corrupted'      => 0,
    'tmp_orphan'     => 0,
    'locked_skipped' => 0,
    'errors'         => 0,
];

$dh = @opendir($storage);
if (!$dh) {
    fwrite(STDERR, "Unable to open {$storage}\n");
    exit(1);
}

while (($entry = readdir($dh)) !== false) {
    if ($entry === '.' || $entry === '..') continue;
    $path = $storage . '/' . $entry;
    if (!is_file($path)) continue;

    $stats['scanned']++;

    // File temporanei orfani
    if (strpos($entry, '.tmp_') === 0) {
        $fp = @fopen($path, 'r+');
        if (!$fp) {
            fwrite(STDERR, "Cannot open: {$path}\n");
            $stats['errors']++;
            continue;
        }
        if (!@flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            $stats['locked_skipped']++;
            continue;
        }
        $mtime = @filemtime($path);
        if ($mtime !== false && ($now - $mtime) > TMP_ORPHAN_TTL) {
            @unlink($path);
            $stats['tmp_orphan']++;
        }
        @flock($fp, LOCK_UN);
        fclose($fp);
        continue;
    }

    // Solo file con nome valido (32 hex char)
    if (!preg_match('/^[a-f0-9]{32}$/', $entry)) continue;

    $fp = @fopen($path, 'r+');
    if (!$fp) {
        fwrite(STDERR, "Cannot open: {$path}\n");
        $stats['errors']++;
        continue;
    }
    if (!@flock($fp, LOCK_EX | LOCK_NB)) {
        fclose($fp);
        $stats['locked_skipped']++;
        continue;
    }

    $raw = stream_get_contents($fp);
    if ($raw === false) {
        @flock($fp, LOCK_UN);
        fclose($fp);
        fwrite(STDERR, "Cannot read: {$path}\n");
        $stats['errors']++;
        continue;
    }

    $obj          = json_decode($raw, true);
    $shouldDelete = false;
    $reason       = '';

    // Estratti per l'eventuale notifica (usati solo per i segreti scaduti).
    $notifyEmail  = (is_array($obj) && isset($obj['notify_email']) && is_string($obj['notify_email']))
        ? $obj['notify_email'] : '';
    $notifyLang   = (is_array($obj) && isset($obj['lang']) && is_string($obj['lang']))
        ? $obj['lang'] : 'en';

    if (!is_array($obj)) {
        $shouldDelete = true;
        $reason       = 'corrupted';
    } elseif (isset($obj['expires'])) {
        if ($now > (int)$obj['expires']) {
            $shouldDelete = true;
            $reason       = 'expired';
        }
    } elseif (isset($obj['created'])) {
        // Legacy (pre-v3)
        if ($now > ((int)$obj['created'] + LEGACY_TTL_SEC)) {
            $shouldDelete = true;
            $reason       = 'expired';
        }
    }

    @flock($fp, LOCK_UN);
    fclose($fp);

    if ($shouldDelete) {
        @unlink($path);
        if ($reason === 'expired')   $stats['expired']++;
        if ($reason === 'corrupted') $stats['corrupted']++;

        // Notifica "scaduto e rimosso": il segreto e' scaduto SENZA essere mai
        // aperto e viene ora eliminato dal cleanup. Solo se: scaduto (non
        // corrotto), email valida, notifiche abilitate in mailconfig.php.
        // In CLI l'invio e' sincrono (niente deferred: non c'e' un client web
        // da rilasciare). I fallimenti SMTP sono gestiti/loggati in mail.php e
        // non interrompono il cleanup. tokenId = primi 8 char del nome file
        // (il token e' il nome del file), coerente con view.php.
        if ($reason === 'expired'
            && $notifyEmail !== ''
            && filter_var($notifyEmail, FILTER_VALIDATE_EMAIL)
            && snm_mail_enabled()) {
            $tokenId = substr($entry, 0, 8);
            if (snm_send_notification($notifyEmail, $tokenId, 'expired_clean', $notifyLang)) {
                $stats['notified']++;
            }
        }
    }
}
closedir($dh);

// Output su STDOUT (redirezionabile a /dev/null in crontab se non serve)
echo "[" . date('Y-m-d H:i:s') . "] SayNoMore cleanup:\n";
echo "  scanned:        {$stats['scanned']}\n";
echo "  expired:        {$stats['expired']}\n";
echo "  notified:       {$stats['notified']}\n";
echo "  corrupted:      {$stats['corrupted']}\n";
echo "  tmp orphans:    {$stats['tmp_orphan']}\n";
echo "  locked skipped: {$stats['locked_skipped']}\n";
echo "  errors:         {$stats['errors']}\n";

exit(0);
