/**
 * SayNoMore - script.js
 *
 * Responsabilita':
 *  - index.php: focus textarea + copia link (con fragment incluso)
 *  - view.php : legge la chiave AES dal fragment URL (#) e la trasferisce
 *               nel campo hidden del form, in modo che venga inviata SOLO
 *               via POST. Il fragment non viene mai trasmesso al server.
 *
 * Patch notes v5:
 *  - Le label del bottone "Copia" vengono lette da data-* attributes
 *    impostati dal PHP. Cosi' il JS resta language-agnostic e la
 *    traduzione e' gestita interamente lato server.
 */

(function () {
    'use strict';

    // -------- index.php : focus + copia --------
    const ta = document.querySelector('textarea[name="secret"]');
    if (ta) ta.focus();

    const copyBtn = document.getElementById('copyBtn');
    const linkInput = document.getElementById('secretLink');

    if (copyBtn && linkInput) {
        const labelDefault = copyBtn.dataset.labelDefault || 'Copy';
        const labelSuccess = copyBtn.dataset.labelSuccess || 'Copied!';
        const labelError   = copyBtn.dataset.labelError   || 'Error';

        copyBtn.addEventListener('click', async function (e) {
            e.preventDefault();
            try {
                await navigator.clipboard.writeText(linkInput.value);
                copyBtn.textContent = labelSuccess;
            } catch (err) {
                try {
                    linkInput.removeAttribute('readonly');
                    linkInput.select();
                    document.execCommand('copy');
                    linkInput.setAttribute('readonly', 'readonly');
                    copyBtn.textContent = labelSuccess;
                } catch (e2) {
                    copyBtn.textContent = labelError;
                }
            }
            setTimeout(function () { copyBtn.textContent = labelDefault; }, 2000);
        });
    }

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
