/**
 * SayNoMore - script.js
 * Created by Leproide - https://github.com/Leproide/SayNoMore
 *
 * Distributed under GNU GPL v2.
 * No warranty provided.
 *
 * Patch notes v6 (E2E):
 *  - index.php: la cifratura AES-256-GCM avviene QUI (Web Crypto). Il browser
 *    genera fragKey + IV, cifra il plaintext e invia al server solo iv + ct.
 *    Il link (con fragKey nel fragment) viene costruito lato client.
 *  - view.php : invia solo token + password; a password corretta il server
 *    restituisce iv + ct e il browser decifra localmente con fragKey.
 *  - fragKey non lascia MAI il browser in chiaro verso il server.
 *  - Richiede secure context (HTTPS o .onion): senza crypto.subtle l'E2E e'
 *    disabilitato con messaggio esplicito.
 */

(function () {
    'use strict';

    // ---------------------------------------------------------------- utils

    /** crypto.subtle disponibile solo in secure context (HTTPS / .onion). */
    function cryptoReady() {
        return !!(window.crypto && window.crypto.subtle && window.isSecureContext);
    }

    function bytesToHex(bytes) {
        let out = '';
        for (let i = 0; i < bytes.length; i++) {
            out += bytes[i].toString(16).padStart(2, '0');
        }
        return out;
    }

    function hexToBytes(hex) {
        const len = hex.length / 2;
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            out[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return out;
    }

    function bytesToB64(bytes) {
        let bin = '';
        const chunk = 0x8000; // evita stack overflow su input grandi
        for (let i = 0; i < bytes.length; i += chunk) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }
        return btoa(bin);
    }

    function b64ToBytes(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    // --- base64url (per la CHIAVE nel fragment: 32 byte -> 43 char, vs 64 hex) ---
    // base64url = base64 con '+'->'-', '/'->'_', senza padding '='.
    function bytesToB64url(bytes) {
        return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function b64urlToBytes(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';        // ripristina il padding per atob
        return b64ToBytes(s);
    }
    // Decodifica la chiave dal fragment accettando ENTRAMBI i formati:
    // base64url (43 char, formato attuale) e hex (64 char, link legacy pre-cambio).
    function keyToBytes(keyStr) {
        if (/^[a-fA-F0-9]{64}$/.test(keyStr)) return hexToBytes(keyStr);   // legacy
        return b64urlToBytes(keyStr);                                       // base64url
    }

    const enc = new TextEncoder();
    const dec = new TextDecoder();

    /** Importa fragKey (32 byte) come chiave AES-GCM. */
    async function importKey(keyBytes, usages) {
        return window.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, usages);
    }

    /**
     * Cifra plaintext con una chiave random fresca.
     * La chiave per il fragment e' codificata in base64url (43 char).
     * @returns {Promise<{keyStr:string, ivB64:string, ctB64:string}>}
     */
    async function encryptSecret(plaintext) {
        const keyBytes = window.crypto.getRandomValues(new Uint8Array(32)); // AES-256
        const iv       = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
        const key      = await importKey(keyBytes, ['encrypt']);
        const ctBuf    = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, tagLength: 128 },
            key,
            enc.encode(plaintext)
        );
        return {
            keyStr: bytesToB64url(keyBytes),       // -> fragment (base64url, 43 char)
            ivB64:  bytesToB64(iv),                // -> server
            ctB64:  bytesToB64(new Uint8Array(ctBuf)) // ct+tag -> server
        };
    }

    /** Decifra ct (ct+tag) con la chiave del fragment. Lancia su fallimento (tag errato). */
    async function decryptSecret(keyStr, ivB64, ctB64) {
        const key = await importKey(keyToBytes(keyStr), ['decrypt']);
        const ptBuf = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64ToBytes(ivB64), tagLength: 128 },
            key,
            b64ToBytes(ctB64)
        );
        return dec.decode(ptBuf);
    }

    // ------------------------------------------------------ copy-to-clipboard

    async function snmCopyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            try { await navigator.clipboard.writeText(text); return true; } catch (e) {}
        }
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
            tmp.setSelectionRange(0, text.length); // iOS
            const ok = document.execCommand('copy');
            document.body.removeChild(tmp);
            return !!ok;
        } catch (e) {
            return false;
        }
    }

    function attachCopyButton(btn, getText, resetMs) {
        if (!btn) return;
        const labelDefault = btn.dataset.labelDefault || 'Copy';
        const labelSuccess = btn.dataset.labelSuccess || 'Copied!';
        const labelError   = btn.dataset.labelError   || 'Error';
        btn.addEventListener('click', async function (e) {
            e.preventDefault();
            const ok = await snmCopyText(getText());
            btn.textContent = ok ? labelSuccess : labelError;
            setTimeout(function () { btn.textContent = labelDefault; }, resetMs);
        });
    }

    // ============================================================== index.php

    const snmForm = document.getElementById('snmForm');
    if (snmForm) {
        const secretField = document.getElementById('secretField');
        const passField   = document.getElementById('passField');
        const formError   = document.getElementById('formError');
        const ctxWarn     = document.getElementById('ctxWarn');
        const resultBox   = document.getElementById('resultBox');
        const secretLink  = document.getElementById('secretLink');
        const expiry      = document.getElementById('expiry_days');
        const notifyCb    = document.getElementById('notify_enabled');
        const notifyEmail = document.getElementById('notify_email');

        if (secretField) secretField.focus();

        // Secure context obbligatorio per cifrare nel browser.
        if (!cryptoReady() && ctxWarn) {
            ctxWarn.textContent = ctxWarn.dataset.insecureMsg || 'Secure context required.';
            ctxWarn.hidden = false;
            const submitBtn = snmForm.querySelector('button[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;
        }

        // Toggle campo email notifiche (visibile solo se checkbox ON)
        const notifyWrap = document.getElementById('notifyEmailWrap');
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

        // Messaggi di validazione nativi localizzati
        const reqFields = snmForm.querySelectorAll('[data-required-msg], [data-invalid-msg]');
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
            field.addEventListener('input', function () { field.setCustomValidity(''); });
        });

        snmForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            if (formError) formError.hidden = true;

            if (!cryptoReady()) {
                if (ctxWarn) {
                    ctxWarn.textContent = ctxWarn.dataset.insecureMsg || 'Secure context required.';
                    ctxWarn.hidden = false;
                }
                return;
            }
            if (!snmForm.reportValidity()) return;

            const submitBtn = snmForm.querySelector('button[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;

            try {
                // 1) Cifra nel browser
                const out = await encryptSecret(secretField.value);

                // 2) Invia solo iv + ct + password + TTL (+ notifiche opzionali)
                const body = new URLSearchParams();
                body.set('iv', out.ivB64);
                body.set('ct', out.ctB64);
                body.set('passphrase', passField.value);
                body.set('expiry_days', expiry ? expiry.value : '7');
                if (notifyCb && notifyCb.checked) {
                    body.set('notify_enabled', '1');
                    if (notifyEmail) body.set('notify_email', notifyEmail.value);
                }

                const resp = await fetch('index.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString()
                });
                const data = await resp.json().catch(function () { return null; });

                if (!data || !data.ok) {
                    if (formError) {
                        formError.textContent = (data && data.error) ? data.error : 'Error';
                        formError.hidden = false;
                    }
                    if (submitBtn) submitBtn.disabled = false;
                    return;
                }

                // 3) Costruisci il link lato client: fragKey resta nel fragment.
                // origin+pathname ignora query/fragment correnti -> link sempre
                // ben formato; lo schema http/https e' ereditato da origin
                // (quindi onion=http e clearnet=https sono gestiti in automatico).
                const base = window.location.origin + window.location.pathname.replace(/index\.php$/, '');
                const link = base + 'view.php?token=' + encodeURIComponent(data.token) + '#' + out.keyStr;

                if (secretLink) secretLink.value = link;
                if (resultBox)  resultBox.hidden = false;
                snmForm.hidden = true;

                if (secretLink) { secretLink.focus(); secretLink.select(); }
            } catch (err) {
                if (formError) {
                    formError.textContent = 'Error';
                    formError.hidden = false;
                }
                if (submitBtn) submitBtn.disabled = false;
            }
        });

        // Bottone copia link
        const copyBtn = document.getElementById('copyBtn');
        if (copyBtn && secretLink) {
            attachCopyButton(copyBtn, function () { return secretLink.value; }, 2000);
        }
    }

    // =============================================================== view.php

    const unlockForm = document.getElementById('unlockForm');
    if (unlockForm) {
        const container   = document.querySelector('.container');
        const viewError   = document.getElementById('viewError');
        const viewPass    = document.getElementById('viewPass');
        const secretResult= document.getElementById('secretResult');
        const secretBox   = document.getElementById('secretBox');
        const D = container ? container.dataset : {};

        // Leggi la chiave dal fragment (mai inviata al server)
        const rawHash = window.location.hash || '';
        let keyStr = rawHash.startsWith('#') ? rawHash.substring(1) : rawHash;
        // Accetta base64url (43 char, formato attuale) o hex (64 char, link legacy)
        if (!/^[A-Za-z0-9_-]{43}$/.test(keyStr) && !/^[a-fA-F0-9]{64}$/.test(keyStr)) keyStr = '';

        if (viewPass) viewPass.focus();

        function showError(msg) {
            if (viewError) { viewError.textContent = msg; viewError.hidden = false; }
        }

        // NB: il fragment con fragKey NON viene rimosso all'avvio: deve restare
        // nell'URL finche' lo sblocco non riesce, cosi' un reload dopo password
        // errata conserva la chiave e l'utente puo' ritentare (entro i 5 tentativi).
        // La rimozione avviene solo dopo decifratura riuscita (vedi sotto).

        unlockForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            if (viewError) viewError.hidden = true;

            if (!cryptoReady()) { showError(D.errCtx || 'Secure context required.'); return; }
            if (!keyStr)        { showError(D.errKey || 'Invalid or missing key.'); return; }
            if (!unlockForm.reportValidity()) return;

            const submitBtn = unlockForm.querySelector('button[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;

            try {
                const body = new URLSearchParams();
                body.set('token', unlockForm.querySelector('input[name="token"]').value);
                body.set('view_pass', viewPass.value);

                const resp = await fetch(window.location.pathname + window.location.search, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString()
                });
                const data = await resp.json().catch(function () { return null; });

                if (!data || !data.ok) {
                    // Password errata: ripresenta il form. Altri errori: stop.
                    showError((data && data.error) ? data.error : (D.errGeneric || 'Error'));
                    if (data && data.error === (D.errWrong || '\u0000')) {
                        if (submitBtn) submitBtn.disabled = false;
                        if (viewPass) { viewPass.value = ''; viewPass.focus(); }
                    } else {
                        // link non valido / troppi tentativi / busy: form inutile
                        unlockForm.hidden = true;
                    }
                    return;
                }

                // Decifra localmente
                let plaintext;
                try {
                    plaintext = await decryptSecret(keyStr, data.iv, data.ct);
                } catch (err) {
                    // ct gia' consumato lato server: link corrotto/incompleto
                    showError(D.errDecrypt || 'Decryption failed.');
                    unlockForm.hidden = true;
                    return;
                }

                if (secretBox)    secretBox.value = plaintext;
                unlockForm.hidden = true;
                if (viewError)    viewError.hidden = true;
                const heading = document.getElementById('unlockHeading');
                if (heading)      heading.hidden = true;
                if (secretResult) secretResult.hidden = false;

                // Sblocco riuscito: ora rimuovi fragKey dall'URL (history) cosi'
                // non resta nella barra indirizzi / cronologia dopo la lettura.
                if (window.location.hash) {
                    try {
                        history.replaceState(null, '', window.location.pathname + window.location.search);
                    } catch (e2) {}
                }

                const copySecretBtn = document.getElementById('copySecretBtn');
                if (copySecretBtn && secretBox) {
                    attachCopyButton(copySecretBtn, function () { return secretBox.value; }, 2000);
                }
            } catch (err) {
                showError(D.errGeneric || 'Error');
                if (submitBtn) submitBtn.disabled = false;
            }
        });

        // Avviso preventivo se il contesto non e' sicuro o la chiave manca
        if (!cryptoReady()) showError(D.errCtx || 'Secure context required.');
        else if (!keyStr)   showError(D.errKey || 'Invalid or missing key.');
    }
})();
