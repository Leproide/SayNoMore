/**
 * SayNoMore - script.js
 *
 * Responsabilita':
 *  - index.php: focus textarea + copia link (con fragment incluso)
 *  - view.php : legge la chiave AES dal fragment URL (#) e la trasferisce
 *               nel campo hidden del form, in modo che venga inviata SOLO
 *               via POST. Il fragment non viene mai trasmesso al server.
 */

(function () {
    'use strict';

    // -------- index.php : focus + copia --------
    const ta = document.querySelector('textarea[name="secret"]');
    if (ta) ta.focus();

    const copyBtn = document.getElementById('copyBtn');
    const linkInput = document.getElementById('secretLink');

    if (copyBtn && linkInput) {
        copyBtn.addEventListener('click', async function (e) {
            e.preventDefault();
            try {
                // Il value contiene gia' il fragment con la chiave, va copiato cosi' com'e'
                await navigator.clipboard.writeText(linkInput.value);
                copyBtn.textContent = 'Copiato!';
            } catch (err) {
                // Fallback per browser senza Clipboard API
                try {
                    linkInput.removeAttribute('readonly');
                    linkInput.select();
                    document.execCommand('copy');
                    linkInput.setAttribute('readonly', 'readonly');
                    copyBtn.textContent = 'Copiato!';
                } catch (e2) {
                    copyBtn.textContent = 'Errore';
                }
            }
            setTimeout(function () { copyBtn.textContent = 'Copia'; }, 2000);
        });
    }

    // -------- view.php : recupera chiave dal fragment --------
    const keyField = document.getElementById('keyField');
    const unlockForm = document.getElementById('unlockForm');

    if (keyField && unlockForm) {
        // window.location.hash include il '#', lo togliamo
        const rawHash = window.location.hash || '';
        const key = rawHash.startsWith('#') ? rawHash.substring(1) : rawHash;

        // Validazione minima lato client (256 bit hex = 64 char)
        if (/^[a-fA-F0-9]{64}$/.test(key)) {
            keyField.value = key;
            // NB: NON cancelliamo il fragment dall'URL finche' il segreto
            // non e' stato sbloccato con successo. Se la password e' sbagliata
            // l'utente puo' riprovare senza perdere la chiave.
        }

        // Focus sulla password
        const pwInput = unlockForm.querySelector('input[name="view_pass"]');
        if (pwInput) pwInput.focus();
    }

    // -------- view.php (success) : pulizia URL dopo decrittazione riuscita --------
    // Se siamo nella pagina del segreto sbloccato, rimuoviamo il fragment dall'URL
    // per evitare che resti nella history del browser.
    const secretBox = document.querySelector('textarea.secret-box');
    if (secretBox && window.location.hash) {
        try {
            history.replaceState(null, '', window.location.pathname + window.location.search);
        } catch (e) {
            // Browser molto vecchi: ignora
        }
    }
})();
