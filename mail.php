<?php
/**
 * SayNoMore - mail.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Client SMTP nativo (niente PHPMailer, niente Composer) per l'invio delle
 * notifiche email opzionali generate da view.php quando un segreto viene
 * letto o distrutto per troppi tentativi errati.
 *
 * Supporta:
 *  - SSL implicito (porta 465, secure='ssl')
 *  - STARTTLS      (porta 587, secure='tls')
 *  - Plaintext     (porta 25,  secure='')
 *  - Autenticazione AUTH LOGIN (utente/password base64)
 *  - Messaggi multipart/alternative (plain + HTML)
 *
 * Filosofia: i fallimenti di invio NON devono mai impattare il flusso
 * principale. Tutti gli errori vengono catturati e loggati via error_log,
 * mai mostrati all'utente.
 */

require_once __DIR__ . '/lang.php';

/**
 * Carica e memorizza in cache la configurazione SMTP da mailconfig.php.
 * Restituisce ['enabled' => false] se il file e' assente o malformato.
 */
function snm_mail_config(): array {
    static $cfg = null;
    if ($cfg !== null) return $cfg;

    $path = __DIR__ . '/mailconfig.php';
    if (!is_file($path)) {
        return $cfg = ['enabled' => false];
    }
    $loaded = @include $path;
    if (!is_array($loaded)) {
        return $cfg = ['enabled' => false];
    }
    return $cfg = $loaded;
}

/**
 * Helper: la funzionalita' notifiche e' attiva?
 */
function snm_mail_enabled(): bool {
    $cfg = snm_mail_config();
    return !empty($cfg['enabled']);
}

/**
 * Helper: il logging di debug e' attivo?
 */
function snm_mail_debug(): bool {
    $cfg = snm_mail_config();
    return !empty($cfg['debug']);
}

/**
 * Scrive una riga nel file di debug "maildebug.txt" (stessa cartella di
 * mail.php) SOLO se 'debug' => true in mailconfig.php. No-op altrimenti.
 * Le credenziali SMTP non vengono mai passate qui (i chiamanti loggano
 * placeholder al posto di username/password).
 *
 * @param string $msg Riga da loggare (verra' prefissata da timestamp)
 */
function snm_mail_debug_log(string $msg): void {
    if (!snm_mail_debug()) return;
    $line = '[' . date('Y-m-d H:i:s T') . '] ' . $msg . "\n";
    @file_put_contents(__DIR__ . '/maildebug.txt', $line, FILE_APPEND | LOCK_EX);
}

/**
 * Costruisce e invia una notifica per un evento sul segreto.
 *
 * @param string $to       Indirizzo destinatario (gia' validato dal chiamante)
 * @param string $tokenId  Identificatore breve da mostrare (es. primi 8 char del token)
 * @param string $event    'read' | 'destroyed' | 'expired_open' | 'expired_clean'
 * @param string $lang     'it' o 'en' (lingua scelta alla creazione del segreto)
 * @return bool true se l'invio è stato accettato dal server SMTP
 */
function snm_send_notification(string $to, string $tokenId, string $event, string $lang = 'en'): bool {
    if (!snm_mail_enabled()) return false;
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
        snm_mail_debug_log('send aborted: invalid recipient address');
        return false;
    }

    // Sanifica id (solo hex), max 32 char come il token completo
    $tokenId = substr(preg_replace('/[^a-f0-9]/i', '', $tokenId), 0, 32);
    if ($tokenId === '') {
        snm_mail_debug_log('send aborted: empty token id');
        return false;
    }

    snm_mail_debug_log("=== notification start: to={$to} event={$event} lang={$lang} id={$tokenId} ===");

    $when = date('Y-m-d H:i:s T');
    $lang = ($lang === 'it') ? 'it' : 'en';

    // Eventi supportati (qualsiasi valore sconosciuto ricade su 'destroyed'
    // per retrocompatibilita'):
    //   'read'          -> segreto aperto correttamente
    //   'destroyed'     -> distrutto dopo troppi tentativi errati
    //   'expired_open'  -> qualcuno ha aperto il link ma il segreto era gia'
    //                      scaduto: contenuto NON mostrato (rilevato da view.php)
    //   'expired_clean' -> scaduto senza essere mai aperto e rimosso dal
    //                      cleanup CLI (cleanup.php)
    $isRead         = ($event === 'read');
    $isExpiredOpen  = ($event === 'expired_open');
    $isExpiredClean = ($event === 'expired_clean');

    // --- Soggetto + corpo testuale + frammenti per il corpo HTML ---
    // Il footer e' spezzato in prefisso/suffisso attorno al brand "SayNoMore"
    // cosi' da poterlo rendere come link al sito (vedi $brandHtml piu' sotto).
    if ($lang === 'it') {
        if ($isRead) {
            $subject  = "[SayNoMore] Segreto {$tokenId} letto";
            $bodyText = "Il segreto {$tokenId} è stato aperto in data {$when}.\r\n";
            $heading  = 'Segreto letto';
            $intro    = "Il segreto <strong>{$tokenId}</strong> è stato aperto correttamente.";
        } elseif ($isExpiredOpen) {
            $subject  = "[SayNoMore] Segreto {$tokenId} aperto dopo la scadenza";
            $bodyText = "Il link del segreto {$tokenId} è stato aperto in data {$when}, "
                      . "ma il segreto era già scaduto: il contenuto non è stato mostrato.\r\n";
            $heading  = 'Aperto dopo la scadenza';
            $intro    = "Il link del segreto <strong>{$tokenId}</strong> è stato aperto, "
                      . "ma il segreto era già scaduto e il contenuto non è stato mostrato.";
        } elseif ($isExpiredClean) {
            $subject  = "[SayNoMore] Segreto {$tokenId} scaduto e rimosso";
            $bodyText = "Il segreto {$tokenId} è scaduto senza essere mai stato aperto "
                      . "ed è stato rimosso in data {$when}.\r\n";
            $heading  = 'Scaduto e rimosso';
            $intro    = "Il segreto <strong>{$tokenId}</strong> è scaduto senza essere mai stato aperto "
                      . "ed è stato rimosso.";
        } else { // destroyed
            $subject  = "[SayNoMore] Segreto {$tokenId} distrutto";
            $bodyText = "Il segreto {$tokenId} è stato distrutto in data {$when} dopo troppi tentativi errati.\r\n";
            $heading  = 'Segreto distrutto';
            $intro    = "Il segreto <strong>{$tokenId}</strong> è stato distrutto dopo troppi tentativi errati.";
        }
        $labelId   = 'ID segreto';
        $labelWhen = 'Data e ora';
        $footerPre = 'Notifica automatica generata da ';
        $footerEnd = '.';
    } else {
        if ($isRead) {
            $subject  = "[SayNoMore] Secret {$tokenId} read";
            $bodyText = "Secret {$tokenId} was opened on {$when}.\r\n";
            $heading  = 'Secret read';
            $intro    = "Secret <strong>{$tokenId}</strong> has been successfully opened.";
        } elseif ($isExpiredOpen) {
            $subject  = "[SayNoMore] Secret {$tokenId} opened after expiry";
            $bodyText = "The link for secret {$tokenId} was opened on {$when}, "
                      . "but the secret had already expired: its content was not shown.\r\n";
            $heading  = 'Opened after expiry';
            $intro    = "The link for secret <strong>{$tokenId}</strong> was opened, "
                      . "but the secret had already expired and its content was not shown.";
        } elseif ($isExpiredClean) {
            $subject  = "[SayNoMore] Secret {$tokenId} expired and removed";
            $bodyText = "Secret {$tokenId} expired without ever being opened "
                      . "and was removed on {$when}.\r\n";
            $heading  = 'Expired and removed';
            $intro    = "Secret <strong>{$tokenId}</strong> expired without ever being opened "
                      . "and was removed.";
        } else { // destroyed
            $subject  = "[SayNoMore] Secret {$tokenId} destroyed";
            $bodyText = "Secret {$tokenId} was destroyed on {$when} after too many failed attempts.\r\n";
            $heading  = 'Secret destroyed';
            $intro    = "Secret <strong>{$tokenId}</strong> has been destroyed after too many failed attempts.";
        }
        $labelId   = 'Secret ID';
        $labelWhen = 'Date and time';
        $footerPre = 'Automatic notification generated by ';
        $footerEnd = '.';
    }

    // URL del sito dal config: solo http/https sono accettati, per evitare
    // schemi pericolosi (javascript:, data:) iniettati nella mail.
    $cfg     = snm_mail_config();
    $siteUrl = (string)($cfg['site_url'] ?? '');
    $urlOk   = ($siteUrl !== '' && filter_var($siteUrl, FILTER_VALIDATE_URL) && preg_match('#^https?://#i', $siteUrl));

    // Footer plaintext: brand + eventuale URL tra parentesi.
    $bodyText .= "\r\n" . $footerPre . 'SayNoMore' . $footerEnd;
    if ($urlOk) {
        $bodyText .= ' (' . $siteUrl . ')';
    }
    $bodyText .= "\r\n";

    // Accento coerente con la palette CSS del sito:
    //   blu   = read           (#4A76D9)
    //   ambra = expired_open   (#d99a4a) qualcuno ha aperto, troppo tardi
    //   slate = expired_clean  (#7a7f9c) scaduto e rimosso in silenzio
    //   rosso = destroyed      (#ff6b6b) error-color
    if ($isRead) {
        $accent = '#4A76D9';
    } elseif ($isExpiredOpen) {
        $accent = '#d99a4a';
    } elseif ($isExpiredClean) {
        $accent = '#7a7f9c';
    } else {
        $accent = '#ff6b6b';
    }

    // Corpo HTML: layout table-based (compatibile con tutti i client email),
    // colori in linea (gli MUA spesso strippano <style>), nessuna risorsa
    // esterna, tutte le stringhe gia' escaped o costanti.
    $idEsc      = htmlspecialchars($tokenId,   ENT_QUOTES, 'UTF-8');
    $whenEsc    = htmlspecialchars($when,      ENT_QUOTES, 'UTF-8');
    $headingEsc = htmlspecialchars($heading,   ENT_QUOTES, 'UTF-8');
    $labelIdEsc = htmlspecialchars($labelId,   ENT_QUOTES, 'UTF-8');
    $labelWhEsc = htmlspecialchars($labelWhen, ENT_QUOTES, 'UTF-8');

    // Footer HTML: il brand "SayNoMore" diventa un link al sito se configurato.
    $brandHtml = $urlOk
        ? '<a href="' . htmlspecialchars($siteUrl, ENT_QUOTES, 'UTF-8') . '" style="color:#A5A8C5;text-decoration:underline;" target="_blank" rel="noopener noreferrer">SayNoMore</a>'
        : 'SayNoMore';
    $footerHtml = htmlspecialchars($footerPre, ENT_QUOTES, 'UTF-8')
        . $brandHtml
        . htmlspecialchars($footerEnd, ENT_QUOTES, 'UTF-8');

    $bodyHtml =
        '<!DOCTYPE html><html><body style="margin:0;padding:0;background:#1a1d2e;font-family:Arial,Helvetica,sans-serif;color:#E5E9F0;">'
      . '<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#1a1d2e;padding:32px 0;">'
      .   '<tr><td align="center">'
      .     '<table width="520" cellpadding="0" cellspacing="0" border="0" style="background:#2A2F4A;border-radius:12px;border:1px solid #3B3F5C;">'
      .       '<tr><td style="padding:24px 28px;border-bottom:1px solid #3B3F5C;">'
      .         '<div style="font-size:22px;font-weight:bold;color:#E5E9F0;letter-spacing:0.5px;">SayNoMore</div>'
      .       '</td></tr>'
      .       '<tr><td style="padding:28px;">'
      .         '<div style="text-align:center;">'
      .           '<div style="display:inline-block;padding:6px 12px;border-radius:6px;background:' . $accent . ';color:#ffffff;font-size:11px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;">'
      .             $headingEsc
      .           '</div>'
      .         '</div>'
      .         '<p style="margin:20px 0 0 0;font-size:15px;line-height:1.6;color:#E5E9F0;">' . $intro . '</p>'
      .         '<table cellpadding="0" cellspacing="0" border="0" style="margin-top:24px;width:100%;border-collapse:collapse;">'
      .           '<tr>'
      .             '<td style="padding:12px 0;font-size:13px;color:#A5A8C5;width:38%;border-top:1px solid #3B3F5C;">' . $labelIdEsc . '</td>'
      .             '<td style="padding:12px 0;font-size:13px;color:#E5E9F0;font-family:Consolas,Menlo,monospace;border-top:1px solid #3B3F5C;">' . $idEsc . '</td>'
      .           '</tr>'
      .           '<tr>'
      .             '<td style="padding:12px 0;font-size:13px;color:#A5A8C5;border-top:1px solid #3B3F5C;">' . $labelWhEsc . '</td>'
      .             '<td style="padding:12px 0;font-size:13px;color:#E5E9F0;border-top:1px solid #3B3F5C;">' . $whenEsc . '</td>'
      .           '</tr>'
      .         '</table>'
      .       '</td></tr>'
      .       '<tr><td style="padding:18px 28px;border-top:1px solid #3B3F5C;font-size:11px;color:#6e7396;text-align:center;">'
      .         $footerHtml
      .       '</td></tr>'
      .     '</table>'
      .   '</td></tr>'
      . '</table>'
      . '</body></html>';

    // Invio con ritentativi. snm_smtp_send() lancia un'eccezione su qualsiasi
    // errore e ritorna true SOLO dopo aver ricevuto il "250" finale dopo il
    // blocco DATA, cioe' la conferma SMTP di accettazione del messaggio.
    // Quindi:
    //  - se ritorna true => il server ha accettato la mail: usciamo subito,
    //    nessun rischio di invii multipli.
    //  - se lancia eccezione => il messaggio NON e' stato accettato: possiamo
    //    ritentare senza generare duplicati.
    $maxAttempts = (int)($cfg['max_retries'] ?? 3);
    if ($maxAttempts < 1) $maxAttempts = 1;

    snm_mail_debug_log('generated: subject="' . $subject . '" textBytes=' . strlen($bodyText)
        . ' htmlBytes=' . strlen($bodyHtml) . ' siteLink=' . ($urlOk ? $siteUrl : '(none)')
        . ' maxRetries=' . $maxAttempts);

    for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
        snm_mail_debug_log("attempt {$attempt}/{$maxAttempts}: starting SMTP send");
        try {
            if (snm_smtp_send($cfg, $to, $subject, $bodyText, $bodyHtml)) {
                snm_mail_debug_log("attempt {$attempt}/{$maxAttempts}: SUCCESS (server accepted message)");
                return true; // accettato dal server: stop.
            }
        } catch (\Throwable $e) {
            // Fallimento silenzioso lato utente: solo log lato server.
            error_log('[SayNoMore] mail send attempt ' . $attempt . '/' . $maxAttempts . ' failed: ' . $e->getMessage());
            snm_mail_debug_log("attempt {$attempt}/{$maxAttempts}: FAILED - " . $e->getMessage());
        }
        // Piccolo backoff tra i tentativi (non dopo l'ultimo). L'invio avviene
        // in shutdown dopo il rilascio del client, quindi lo sleep non rallenta
        // la risposta vista dall'utente.
        if ($attempt < $maxAttempts) {
            sleep(2);
        }
    }
    snm_mail_debug_log('all attempts exhausted: message NOT sent');
    return false;
}

/**
 * Variante "deferred" di snm_send_notification: posticipa l'invio dopo
 * che la response e' stata consegnata al client. Questo evita che l'utente
 * resti in attesa per tutto il timeout SMTP (fino a 10s di default) prima
 * di vedere il segreto o la pagina di errore "Troppi tentativi".
 *
 * Strategia:
 *  - register_shutdown_function() esegue la callback dopo la fine dello script
 *  - dentro la callback, se siamo su PHP-FPM chiamiamo fastcgi_finish_request()
 *    che chiude la connessione TCP al client e libera il browser
 *  - su mod_php (Apache embedded) fallback best-effort: flush + ignore_user_abort
 *
 * Risultato: l'utente vede la pagina immediatamente, la mail parte in
 * background. Anche un timing-attack che misurasse "ha notifiche attive?"
 * dal tempo di risposta non riceve informazione utile.
 *
 * @param string $to       Indirizzo destinatario
 * @param string $tokenId  Identificatore breve del segreto
 * @param string $event    'read' | 'destroyed' | 'expired_open' | 'expired_clean'
 * @param string $lang     'it' | 'en'
 */
function snm_send_notification_deferred(string $to, string $tokenId, string $event, string $lang = 'en'): void {
    if (!snm_mail_enabled()) return;
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return;

    register_shutdown_function(static function () use ($to, $tokenId, $event, $lang) {
        // Rilascia il client prima di parlare con l'SMTP
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        } else {
            // mod_php / SAPI senza fastcgi_finish_request: best effort
            @ignore_user_abort(true);
            if (session_status() === PHP_SESSION_ACTIVE) {
                @session_write_close();
            }
            while (ob_get_level() > 0) {
                @ob_end_flush();
            }
            @flush();
        }
        snm_send_notification($to, $tokenId, $event, $lang);
    });
}

/**
 * Invio SMTP via socket. Implementazione sincrona, single-shot.
 * Lancia RuntimeException su qualsiasi errore (catturata dal chiamante).
 */
function snm_smtp_send(array $cfg, string $to, string $subject, string $bodyText, string $bodyHtml): bool {
    $host    = (string)($cfg['host']      ?? '');
    $port    = (int)   ($cfg['port']      ?? 587);
    $secure  = strtolower((string)($cfg['secure']    ?? ''));
    $user    = (string)($cfg['username']  ?? '');
    $pass    = (string)($cfg['password']  ?? '');
    $from    = (string)($cfg['from']      ?? $user);
    $fromN   = (string)($cfg['from_name'] ?? 'SayNoMore');
    $timeout = (int)   ($cfg['timeout']   ?? 10);

    if ($host === '' || $port <= 0 || $from === '') {
        throw new \RuntimeException('SMTP config incomplete');
    }

    // --- Defense in depth contro SMTP command injection ---
    // $to e' gia' validato con FILTER_VALIDATE_EMAIL (che rifiuta CRLF) sia
    // in index.php sia in snm_send_notification(). $from arriva dalla config
    // statica, sotto controllo admin. Aggiungiamo comunque uno strip esplicito
    // dei CRLF prima di scriverli nei comandi MAIL FROM / RCPT TO per evitare
    // SMTP smuggling se in futuro qualcuno aggira una delle validazioni.
    $to   = str_replace(["\r", "\n", "\0"], '', $to);
    $from = str_replace(["\r", "\n", "\0"], '', $from);

    // SSL implicito = wrapper ssl:// gia' al connect.
    // STARTTLS    = connessione plaintext, upgrade dopo EHLO.
    $remote = ($secure === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;

    snm_mail_debug_log("connecting to {$remote} (secure='{$secure}', timeout={$timeout}s)");

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client($remote, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
    if (!$sock) {
        snm_mail_debug_log("connect FAILED: {$errstr} ({$errno})");
        throw new \RuntimeException("SMTP connect failed: {$errstr} ({$errno})");
    }
    stream_set_timeout($sock, $timeout);

    // Lettore di risposte SMTP multi-line: l'ultima riga ha lo space dopo il
    // codice numerico (es. "250 OK"), le precedenti hanno il dash ("250-EHLO").
    $read = static function () use ($sock) {
        $data = '';
        while (!feof($sock)) {
            $line = fgets($sock, 1024);
            if ($line === false) break;
            $data .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        snm_mail_debug_log('<< ' . trim($data));
        return $data;
    };
    // $logAs: testo alternativo da loggare al posto del comando reale (usato
    // per non scrivere username/password base64 nel file di debug).
    $write = static function (string $cmd, ?string $logAs = null) use ($sock) {
        snm_mail_debug_log('>> ' . ($logAs !== null ? $logAs : $cmd));
        fwrite($sock, $cmd . "\r\n");
    };
    $expect = static function (string $resp, string $code) {
        if (substr($resp, 0, 3) !== $code) {
            throw new \RuntimeException('SMTP unexpected response: ' . trim($resp));
        }
    };

    $resp = $read();
    $expect($resp, '220');

    $hostname = gethostname() ?: 'localhost';
    $write('EHLO ' . $hostname);
    $expect($read(), '250');

    if ($secure === 'tls') {
        $write('STARTTLS');
        $expect($read(), '220');
        // Crypto upgrade. Accettiamo TLS 1.2 e successivi (la costante
        // STREAM_CRYPTO_METHOD_TLS_CLIENT include automaticamente le versioni
        // moderne supportate dall'openssl in uso).
        if (!stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            fclose($sock);
            throw new \RuntimeException('STARTTLS upgrade failed');
        }
        // EHLO va ripetuto dopo STARTTLS (RFC 3207).
        $write('EHLO ' . $hostname);
        $expect($read(), '250');
    }

    if ($user !== '' && $pass !== '') {
        $write('AUTH LOGIN');
        $expect($read(), '334');
        $write(base64_encode($user), '<username base64>');
        $expect($read(), '334');
        $write(base64_encode($pass), '<password base64 redacted>');
        $expect($read(), '235');
    }

    $write('MAIL FROM:<' . $from . '>');
    $expect($read(), '250');
    $write('RCPT TO:<' . $to . '>');
    // 250 = OK, 251 = forward (entrambi accettabili)
    $resp = $read();
    if (substr($resp, 0, 3) !== '250' && substr($resp, 0, 3) !== '251') {
        throw new \RuntimeException('SMTP RCPT rejected: ' . trim($resp));
    }
    $write('DATA');
    $expect($read(), '354');

    // Boundary random per multipart/alternative
    $boundary = 'snm_' . bin2hex(random_bytes(12));
    $date     = date('r');
    $hostSan  = preg_replace('/[^a-z0-9.\-]/i', '', $hostname) ?: 'localhost';
    $msgId    = '<' . bin2hex(random_bytes(8)) . '@' . $hostSan . '>';

    // Header From con nome encoded in RFC 2047 (UTF-8 base64) per safety.
    $fromEnc = '=?UTF-8?B?' . base64_encode($fromN) . '?=';
    $subjEnc = '=?UTF-8?B?' . base64_encode($subject) . '?=';

    $headers   = [];
    $headers[] = 'Date: ' . $date;
    $headers[] = 'Message-ID: ' . $msgId;
    $headers[] = 'From: ' . $fromEnc . ' <' . $from . '>';
    $headers[] = 'To: <' . $to . '>';
    $headers[] = 'Subject: ' . $subjEnc;
    $headers[] = 'MIME-Version: 1.0';
    $headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';
    $headers[] = 'X-Mailer: SayNoMore';

    // Corpo multipart/alternative con quoted-printable.
    // Necessario per evitare che righe HTML troppo lunghe (l'HTML qui e' una
    // singola riga ~1.5KB) vengano soft-wrappate dagli MTA: il wrap puo'
    // cadere dentro una parola e Outlook su Windows la rende con uno spazio
    // visibile (es. "co rrettamente"). quoted_printable_encode() inserisce
    // soft break "=\r\n" a 76 char, che il client email decodifica
    // rimuovendoli, garantendo che nessuna parola venga spezzata.
    $body  = '';
    $body .= '--' . $boundary . "\r\n";
    $body .= 'Content-Type: text/plain; charset=UTF-8' . "\r\n";
    $body .= 'Content-Transfer-Encoding: quoted-printable' . "\r\n\r\n";
    $body .= quoted_printable_encode($bodyText) . "\r\n";
    $body .= '--' . $boundary . "\r\n";
    $body .= 'Content-Type: text/html; charset=UTF-8' . "\r\n";
    $body .= 'Content-Transfer-Encoding: quoted-printable' . "\r\n\r\n";
    $body .= quoted_printable_encode($bodyHtml) . "\r\n";
    $body .= '--' . $boundary . '--' . "\r\n";

    $data = implode("\r\n", $headers) . "\r\n\r\n" . $body;
    // Dot-stuffing: ogni riga che inizia con "." va raddoppiata (RFC 5321 §4.5.2)
    // perche' la singola "." su una riga marca la fine del DATA block.
    $data = preg_replace('/^\./m', '..', $data);

    // Dump del messaggio grezzo per ispezione di formato/spazi (solo in debug).
    snm_mail_debug_log('sending message DATA (' . strlen($data) . " bytes):\n"
        . "----- BEGIN RAW MESSAGE -----\n" . $data . "\n----- END RAW MESSAGE -----");

    fwrite($sock, $data . "\r\n.\r\n");
    $expect($read(), '250');

    $write('QUIT');
    @fread($sock, 1024);
    fclose($sock);
    snm_mail_debug_log('message accepted by server, connection closed');
    return true;
}
