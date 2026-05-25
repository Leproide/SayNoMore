<?php
/**
 * SayNoMore - lang.php
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Sistema di traduzione minimale basato su Accept-Language.
 * - Se il browser preferisce italiano (it, it-IT, ecc) -> italiano
 * - Altrimenti -> inglese (lingua di default)
 *
 * Uso:
 *   require_once __DIR__ . '/lang.php';
 *   echo t('btn.generate');
 *   echo t('error.too_large', ['size' => 64]);
 *
 * Per aggiungere nuove stringhe basta aggiungerle in entrambi gli array.
 */

/**
 * Determina la lingua attiva basandosi su Accept-Language.
 * Cached: la calcola una volta sola per richiesta.
 */
function snm_lang(): string {
    static $cached = null;
    if ($cached !== null) return $cached;

    $accept = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if (!is_string($accept) || $accept === '') {
        return $cached = 'en';
    }

    // Parsing leggero: per ogni voce "lang;q=0.x" estraggo lang e qualita'.
    // Non uso intl/Locale per non aggiungere dipendenze. Robusto abbastanza
    // per il caso d'uso (it vs en).
    $entries = explode(',', $accept);
    $best = ['lang' => 'en', 'q' => -1.0];

    foreach ($entries as $entry) {
        $parts = explode(';', trim($entry));
        $lang = strtolower(trim($parts[0] ?? ''));
        if ($lang === '') continue;

        // Solo il codice principale (es. "it-IT" -> "it")
        $primary = explode('-', $lang)[0];

        $q = 1.0;
        for ($i = 1; $i < count($parts); $i++) {
            $kv = explode('=', trim($parts[$i]), 2);
            if (count($kv) === 2 && strtolower(trim($kv[0])) === 'q') {
                $q = (float)trim($kv[1]);
            }
        }

        if ($q > $best['q']) {
            $best = ['lang' => $primary, 'q' => $q];
        }
    }

    // Per ora supportiamo solo italiano e inglese (default).
    return $cached = ($best['lang'] === 'it') ? 'it' : 'en';
}

/**
 * Restituisce la stringa tradotta per la chiave fornita.
 * Supporta interpolazione semplice di placeholder {nome}.
 *
 * @param string $key  Chiave (es. 'btn.generate')
 * @param array  $vars Variabili per l'interpolazione (es. ['size' => 64])
 */
function t(string $key, array $vars = []): string {
    static $strings = null;

    if ($strings === null) {
        $strings = snm_translations();
    }

    $lang = snm_lang();
    $msg  = $strings[$lang][$key] ?? $strings['en'][$key] ?? $key;

    if (!empty($vars)) {
        foreach ($vars as $k => $v) {
            $msg = str_replace('{' . $k . '}', (string)$v, $msg);
        }
    }
    return $msg;
}

/**
 * Tabella delle traduzioni.
 * Centralizzata qui per renderle facili da aggiornare.
 */
function snm_translations(): array {
    return [
        'it' => [
            // Titoli pagina
            'page.title.index'    => 'SayNoMore',
            'page.title.view'     => 'SayNoMore - Visualizza',
            'page.title.unlock'   => 'Sblocca Segreto',
            'page.title.error'    => 'SayNoMore - Errore',

            // Form index
            'index.placeholder.secret'    => 'Inserisci il tuo segreto...',
            'index.placeholder.password'  => 'Inserisci una password',
            'index.label.expiry'          => 'Scadenza del link:',
            'index.opt.1day'              => '1 giorno',
            'index.opt.3days'             => '3 giorni',
            'index.opt.7days'             => '7 giorni (default)',
            'index.opt.14days'            => '14 giorni',
            'index.opt.30days'            => '30 giorni (massimo)',
            'index.btn.generate'          => 'Genera link',
            'index.link.label'            => 'Link generato (copia e invia):',
            'index.btn.copy'              => 'Copia',
            'index.btn.copy.success'      => 'Copiato!',
            'index.btn.copy.error'        => 'Errore',
            'index.btn.new'               => 'Crea un altro segreto',

            // Form view
            'view.heading.unlock'         => 'Sblocca Segreto',
            'view.heading.secret'         => 'Il tuo segreto:',
            'view.placeholder.password'   => 'Password di visione',
            'view.btn.unlock'             => 'Sblocca segreto',
            'view.btn.retry'              => 'Riprova',
            'view.btn.home'               => 'Home',
            'view.btn.copy_secret'        => 'Copia negli appunti',
            'view.btn.copy_secret.success'=> 'Copiato!',
            'view.btn.copy_secret.error'  => 'Errore',
            'view.noscript'               => 'Questo servizio richiede JavaScript abilitato per recuperare la chiave dal link.',
            'view.noscript.short'         => 'Questo servizio richiede JavaScript abilitato.',

            // Errori
            'err.heading'                 => 'Errore',
            'err.input_invalid'           => 'Input non valido.',
            'err.too_large'               => 'Segreto troppo grande. Massimo {size} KB.',
            'err.gen_internal'            => 'Errore interno durante la generazione.',
            'err.entropy'                 => 'Sorgente di entropia non disponibile.',
            'err.encryption'              => 'Errore interno durante la cifratura.',
            'err.save'                    => 'Errore interno durante il salvataggio.',
            'err.token_invalid'           => 'Token non valido.',
            'err.key_invalid'             => 'Chiave non valida o mancante.',
            'err.link_invalid'            => 'Link non valido o gia\' usato.',
            'err.busy'                    => 'Richiesta in corso, riprova.',
            'err.too_many'                => 'Troppi tentativi falliti. Il segreto e\' stato distrutto.',
            'err.wrong_pass'              => 'Password errata.',

            // Footer
            'footer.tagline'              => 'Made with &#x1F480; by Leprechaun',
            'footer.github'               => 'GitHub',
        ],
        'en' => [
            // Page titles
            'page.title.index'    => 'SayNoMore',
            'page.title.view'     => 'SayNoMore - View',
            'page.title.unlock'   => 'Unlock Secret',
            'page.title.error'    => 'SayNoMore - Error',

            // Index form
            'index.placeholder.secret'    => 'Enter your secret...',
            'index.placeholder.password'  => 'Enter a password',
            'index.label.expiry'          => 'Link expiry:',
            'index.opt.1day'              => '1 day',
            'index.opt.3days'             => '3 days',
            'index.opt.7days'             => '7 days (default)',
            'index.opt.14days'            => '14 days',
            'index.opt.30days'            => '30 days (maximum)',
            'index.btn.generate'          => 'Generate link',
            'index.link.label'            => 'Link generated (copy and send):',
            'index.btn.copy'              => 'Copy',
            'index.btn.copy.success'      => 'Copied!',
            'index.btn.copy.error'        => 'Error',
            'index.btn.new'               => 'Create another secret',

            // View form
            'view.heading.unlock'         => 'Unlock Secret',
            'view.heading.secret'         => 'Your secret:',
            'view.placeholder.password'   => 'View password',
            'view.btn.unlock'             => 'Unlock secret',
            'view.btn.retry'              => 'Retry',
            'view.btn.home'               => 'Home',
            'view.btn.copy_secret'        => 'Copy to clipboard',
            'view.btn.copy_secret.success'=> 'Copied!',
            'view.btn.copy_secret.error'  => 'Error',
            'view.noscript'               => 'This service requires JavaScript enabled to retrieve the key from the link.',
            'view.noscript.short'         => 'This service requires JavaScript enabled.',

            // Errors
            'err.heading'                 => 'Error',
            'err.input_invalid'           => 'Invalid input.',
            'err.too_large'               => 'Secret too large. Maximum {size} KB.',
            'err.gen_internal'            => 'Internal error during generation.',
            'err.entropy'                 => 'Entropy source not available.',
            'err.encryption'              => 'Internal error during encryption.',
            'err.save'                    => 'Internal error during saving.',
            'err.token_invalid'           => 'Invalid token.',
            'err.key_invalid'             => 'Invalid or missing key.',
            'err.link_invalid'            => 'Invalid or already-used link.',
            'err.busy'                    => 'Request in progress, please retry.',
            'err.too_many'                => 'Too many failed attempts. The secret has been destroyed.',
            'err.wrong_pass'              => 'Wrong password.',

            // Footer
            'footer.tagline'              => 'Made with &#x1F480; by Leprechaun',
            'footer.github'               => 'GitHub',
        ],
    ];
}
