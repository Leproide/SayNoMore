/**
 * SayNoMore - script.js
 *
 * Responsabilita':
 *  - index.php: focus textarea + copia link
 *  - view.php : legge la chiave AES dal fragment URL e la trasferisce nel
 *               campo hidden del form (la chiave non transita mai via GET)
 *  - view.php (success): copia il segreto negli appunti
 *
 * Patch notes v5.x:
 *  - Funzione snmCopyText() standalone con triplo fallback per garantire
 *    la copia anche su browser/contesti dove navigator.clipboard fallisce
 *    silenziosamente (es. HTTP non-secure, permission policy)
 *  - Le label dei bottoni vengono lette da data-* attributes lato HTML
 */

(function () {
    'use strict';

    /**
     * Copia testo negli appunti con triplo fallback:
     *   1) navigator.clipboard.writeText (moderno, richiede HTTPS o localhost)
     *   2) execCommand('copy') su una textarea OFF-SCREEN appena creata
     *      (sempre permesso, non dipende dal readonly del DOM esistente)
     *   3) ritorna false in caso di fallimento totale
     *
     * @param {string} text - testo da copiare
     * @returns {Promise<boolean>} true se copiato, false altrimenti
     */
    async function snmCopyText(text) {
        // Tentativo 1: API moderna
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(text);
                return true;
            } catch (e) {
                // cade nel fallback sotto
            }
        }

        // Tentativo 2: textarea off-screen + execCommand('copy')
        // Creiamo un elemento nuovo invece di usare quello del segreto:
        // - non dobbiamo togliere readonly al textarea originale
        // - select() funziona sempre su una textarea pulita
        // - styling off-screen per non far saltare il layout o lo scroll
        try {
            const tmp = document.createElement('textarea');
            tmp.value = text;
            tmp.setAttribute('readonly', '');
            tmp.style.position = 'fixed';
            tmp.style.top = '0';
            tmp.style.left = '0';
            tmp.style.width = '1px';
            tmp.style.height = '1px';
            tmp.style.padding = '0';
            tmp.style.border = 'none';
            tmp.style.outline = 'none';
            tmp.style.boxShadow = 'none';
            tmp.style.background = 'transparent';
            tmp.style.opacity = '0';
            document.body.appendChild(tmp);
            tmp.focus();
            tmp.select();
            tmp.setSelectionRange(0, text.length); // necessario su iOS
            const ok = document.execCommand('copy');
            document.body.removeChild(tmp);
            return !!ok;
        } catch (e) {
            return false;
        }
    }

    /**
     * Attacca a un bottone il comportamento "copia X negli appunti", con
     * cambio etichetta successo/errore e ripristino dopo timeout.
     *
     * @param {HTMLElement} btn - il bottone
     * @param {function():string} getText - callback che fornisce il testo da copiare
     * @param {number} resetMs - dopo quanti ms ripristinare l'etichetta default
     */
    function attachCopyButton(btn, getText, resetMs) {
        if (!btn) return;
        const labelDefault = btn.dataset.labelDefault || 'Copy';
        const labelSuccess = btn.dataset.labelSuccess || 'Copied!';
        const labelError   = btn.dataset.labelError   || 'Error';

        btn.addEventListener('click', async function (e) {
            e.preventDefault();
            const ok = await snmCopyText(getText());
            btn.textContent = ok ? labelSuccess : labelError;
            setTimeout(function () {
                btn.textContent = labelDefault;
            }, resetMs);
        });
    }

    // -------- index.php : focus textarea --------
    const taSecret = document.querySelector('textarea[name="secret"]');
    if (taSecret) taSecret.focus();

    // -------- index.php : bottone Copia link --------
    const copyBtn = document.getElementById('copyBtn');
    const linkInput = document.getElementById('secretLink');
    if (copyBtn && linkInput) {
        attachCopyButton(copyBtn, function () { return linkInput.value; }, 2000);
    }

    // -------- index.php : campo email notifiche visibile solo se checkbox ON --------
    // La checkbox sta sopra il campo email; il campo compare solo quando la
    // checkbox e' spuntata. sync() viene chiamata anche all'avvio per allineare
    // lo stato a un eventuale re-render server-side (es. dopo errore di
    // validazione) in cui la checkbox risulta gia' flaggata.
    // Quando la checkbox e' ON il campo diventa "required" (cosi' compare il
    // popup nativo localizzato se vuoto/non valido); quando e' OFF il campo
    // viene disabilitato, cosi' un eventuale valore non valido rimasto non
    // blocca invisibilmente il submit (un campo hidden resterebbe comunque
    // soggetto a validazione del formato email).
    const notifyCb    = document.getElementById('notify_enabled');
    const notifyWrap  = document.getElementById('notifyEmailWrap');
    const notifyEmail = document.getElementById('notify_email');
    if (notifyCb && notifyWrap) {
        const sync = function () {
            const on = notifyCb.checked;
            notifyWrap.hidden = !on;
            if (notifyEmail) {
                notifyEmail.disabled = !on;
                notifyEmail.required = on;
                if (!on) notifyEmail.setCustomValidity('');
            }
        };
        notifyCb.addEventListener('change', sync);
        sync();
    }

    // -------- index.php : messaggi di validazione localizzati --------
    // Il messaggio nativo del browser (es. "compila questo campo") segue la
    // lingua del BROWSER, non quella della pagina. Per i campi con
    // data-required-msg / data-invalid-msg (textarea segreto, password, email)
    // sostituiamo quel messaggio con la stringa tradotta da lang.php, coerente
    // con la lingua della pagina:
    //   - valueMissing (campo vuoto)   -> data-required-msg
    //   - typeMismatch (es. email mal formattata) -> data-invalid-msg
    // Il messaggio va impostato solo nell'evento invalid e azzerato appena
    // l'utente digita, altrimenti il campo resterebbe sempre invalido.
    const reqFields = document.querySelectorAll('#snmForm [data-required-msg], #snmForm [data-invalid-msg]');
    reqFields.forEach(function (field) {
        field.addEventListener('invalid', function () {
            if (field.validity.valueMissing && field.dataset.requiredMsg) {
                field.setCustomValidity(field.dataset.requiredMsg);
            } else if (field.validity.typeMismatch && field.dataset.invalidMsg) {
                field.setCustomValidity(field.dataset.invalidMsg);
            } else {
                field.setCustomValidity('');
            }
        });
        field.addEventListener('input', function () {
            field.setCustomValidity('');
        });
    });

    // -------- view.php : recupera chiave dal fragment --------
    const keyField = document.getElementById('keyField');
    const unlockForm = document.getElementById('unlockForm');

    if (keyField && unlockForm) {
        const rawHash = window.location.hash || '';
        const key = rawHash.startsWith('#') ? rawHash.substring(1) : rawHash;

        if (/^[a-fA-F0-9]{64}$/.test(key)) {
            keyField.value = key;
        }

        const pwInput = unlockForm.querySelector('input[name="view_pass"]');
        if (pwInput) pwInput.focus();
    }

    // -------- view.php (success) : bottone Copia segreto --------
    const copySecretBtn = document.getElementById('copySecretBtn');
    const secretBoxEl   = document.getElementById('secretBox');
    if (copySecretBtn && secretBoxEl) {
        attachCopyButton(copySecretBtn, function () { return secretBoxEl.value; }, 2000);
    }

    // -------- view.php (success) : pulizia URL dopo decrittazione --------
    const secretBox = document.querySelector('textarea.secret-box');
    if (secretBox && window.location.hash) {
        try {
            history.replaceState(null, '', window.location.pathname + window.location.search);
        } catch (e) {
            // Browser molto vecchi: ignora
        }
    }
})();
