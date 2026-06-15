# SayNoMore

![c4b311a6-165e-437a-b2af-3d02f8bf007f](https://github.com/user-attachments/assets/7d2c6928-2344-41e8-ab6a-c9ae7ce6c8a3)

SayNoMore is a simple One Time Secret service for sharing passwords or sensitive information that can only be viewed once.

> ### ⚠ BREAKING UPDATE (end-to-end encryption)
> 
> Since **v6**, encryption and decryption happen **entirely in the browser** (Web Crypto, AES-256-GCM). The server never sees the plaintext nor the AES key, in any phase. **Read before upgrading:**
> 
> - **Secrets created with previous versions become unreadable** (the on-disk format and the key scheme changed). Since secrets are ephemeral (max 30 days), do a clean cutover: empty the `data/` folder on deploy, or wait for old secrets to expire.
> - **Creating and reading now require JavaScript and a secure context.** On clearnet you need **HTTPS**; on a `.onion` hidden service it works. On plain-HTTP clearnet, encryption is disabled with an explicit on-screen message — never a silent downgrade.
> - **OpenSSL is no longer required on the server** for secret encryption (it moved to the browser); it is only used by the optional email notifications over SSL/STARTTLS.
> - `cleanup.php`, `ExpireCheck.sh` and the email notifications are **unchanged and fully compatible** with the new format.

## 🔐 Features

- ✉️ Secrets readable only once, protected by a password (Argon2id hashing with automatic salt)
- 🔒 **End-to-end AES-256-GCM**: encryption and decryption happen in the browser (Web Crypto). The server only stores and relays ciphertext and can never decrypt it. The GCM authentication tag detects any ciphertext tampering.
- 🧠 **Zero-knowledge on the content**: the AES key is generated in the browser, lives only in the URL fragment (`#`), and is never sent to the server — not in the link, not in any request. A correct password alone cannot decrypt without it.
- 🔑 **Password as a server-side access gate**: the view-password is verified server-side (Argon2id) to enforce the one-time read and the 5-attempt limit; it does not decrypt the content, so a stolen password alone is useless.
- ⏳ User-configurable expiration: from 1 to 30 days (default 7)
- 🧹 Automatic cleanup with non-blocking locking: expired secrets are removed in the background without interfering with active unlock attempts
- 🧼 Destruction after read (with best-effort overwrite, see notes below)
- 🛡 Anti-abuse mitigations: 64 KB secret size limit, max 5 password attempts, uniform timing against token enumeration, input type validation against malformed requests
- 🌍 Multilingual: Italian for Italian browsers, English everywhere else (based on `Accept-Language`)
- 📬 Optional email notifications (off by default): when enabled in `mailconfig.php`, the creator can tick a checkbox to receive an email when the secret is opened or destroyed after too many failed attempts
- 🧅 Tor support: links generated on `.onion` hidden services automatically use `http://` instead of `https://`
- 💻 No database required, just the file system

## 🚀 How it works

**Creating a secret**

1. Enter a message, choose a password, and select how many days the link should remain valid.
2. **In your browser**, JavaScript generates a random AES-256 key (`fragKey`) and IV and encrypts the message (AES-256-GCM). Plaintext and `fragKey` never leave the browser.
3. The browser sends to the server only the IV, the ciphertext (with auth tag), the password, and the TTL.
4. The server hashes the password (Argon2id) and stores `{iv, ct, hash, expires, attempts}` — it does not encrypt anything and holds no key.
5. The browser builds the link `view.php?token=...#fragKey` (the server never knows `fragKey`).

**Reading a secret**

1. The recipient opens the link; JavaScript reads `fragKey` from the URL fragment.
2. The recipient enters the password; the browser sends only the `token` and the `password` (never `fragKey`).
3. The server verifies the password. On success it returns the stored IV + ciphertext **and destroys the file** (one-time). On wrong password it increments the counter; after 5 failures the secret is destroyed.
4. The browser decrypts the ciphertext locally with `fragKey` and shows the secret; the fragment is then removed from the address bar. If `fragKey` is missing/corrupted, decryption fails client-side (the secret is already consumed).

> The password is **mandatory**: trying to generate a link without one shows a localized popup ("La password è obbligatoria." / "Password is required.") attached to the field. Validation messages are shown in the **page language** (not the browser language) by overriding the native message via `setCustomValidity`. The secret and (when notifications are on) the email field use the same mechanism. The empty-password rule is also enforced **server-side**, so no secret is ever created without a password.

## 🔗 Demo

https://saynomore.muninn.ovh

## 🛠️ Requirements

- PHP 7.4+ (8.x recommended)
- Argon2id available (PHP built with libargon2, default on modern distros)
- `random_bytes` / `random_int` (CSPRNG)
- OpenSSL is **not** required for secret encryption anymore (it now runs in the browser); it is only used by the optional email notifications over SSL/STARTTLS
- Web server with write permissions, the script will create a `data` folder
- Protect the `data` directory from unauthorized read access (recommended, see the Security section).
- **HTTPS configured at the web server level** (required on clearnet — Web Crypto needs a secure context; see security section)
- JavaScript enabled on the client (required both to encrypt on creation and to read the key on viewing)
- Modern browser with Web Crypto (`crypto.subtle`) in a **secure context**: HTTPS, `localhost`, or a `.onion` address. On plain-HTTP clearnet the app refuses to encrypt/decrypt and shows a message.
- Local filesystem (ext4, xfs, btrfs, ntfs). On NFS/SMB file locking is not guaranteed.

## ✅ Verify PHP dependencies

Before deploying, make sure the PHP runtime serving SayNoMore has the
**required** crypto primitives. Missing Argon2id would break password hashing
and verification.

> **v6 note:** secret encryption is now done in the browser, so server-side you
> only need **Argon2id** and **random_bytes**. `OpenSSL` is **optional** — it is
> used only by the email notifications over SSL/STARTTLS (and AES-256-GCM is no
> longer used server-side at all, since it runs in the browser).

### One-line CLI check

Run this from the same environment that serves the app:

```bash
php -r "echo 'Argon2id (required):      ', (defined('PASSWORD_ARGON2ID') ? 'OK' : 'MISSING'), PHP_EOL, 'random_bytes (required):  ', (function_exists('random_bytes') ? 'OK' : 'MISSING'), PHP_EOL, 'OpenSSL (email TLS only): ', (extension_loaded('openssl') ? 'OK' : 'absent (fine if you do not use email)'), PHP_EOL;"
```

Expected output:

```
Argon2id (required):      OK
random_bytes (required):  OK
OpenSSL (email TLS only): OK
```

If **Argon2id** or **random_bytes** says `MISSING`, **do not deploy**: rebuild
PHP with the missing support, or switch to a modern distro package (`php:8.x`),
where they are present by default. `OpenSSL` showing `absent` is fine unless you
enable the email notifications.

### Browser-side check (recommended)

The CLI `php` binary may differ from the one serving HTTP requests.
To test the **exact** PHP that will run SayNoMore, the repo ships a
ready-made probe file. Rename it to activate it:

```bash
mv argon-check.php.lock argon-check.php
```

Open `https://your-domain/argon-check.php` in a browser, read the output,
then **delete the file immediately**:

```bash
rm argon-check.php
```

Leaving it online would expose your PHP version and capabilities, useful
information for an attacker.

## ⚙️ Configuration

The main parameters are constants at the top of `index.php`, `view.php`, and `cleanup.php`:

| Constant           | File                 | Default       | Description                                                                                                              |
| ------------------ | -------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `DEFAULT_TTL_DAYS` | index.php            | 7             | Default validity in days for new secrets                                                                                 |
| `MIN_TTL_DAYS`     | index.php            | 1             | Minimum TTL selectable by the user                                                                                       |
| `MAX_TTL_DAYS`     | index.php            | 30            | Maximum TTL selectable by the user                                                                                       |
| `MAX_SECRET_BYTES` | index.php            | 65536 (64 KB) | Plaintext size limit (enforced client-side, re-checked server-side as `ciphertext − 16` GCM tag)                         |
| `MAX_CT_B64_BYTES` | index.php            | 98304 (96 KB) | Hard cap on the base64 ciphertext accepted by the server (bounds memory before decoding)                                 |
| `GCM_IV_LEN`       | index.php            | 12            | Expected GCM IV length in bytes (validated server-side)                                                                  |
| `MAX_ATTEMPTS`     | view.php             | 5             | Maximum number of password attempts before destruction                                                                   |
| `CLEANUP_ENABLED`  | index.php / view.php | true          | Master switch for in-request cleanup. Set to `false` to disable it entirely (useful when you run `cleanup.php` via cron) |
| `CLEANUP_PROB_PCT` | index.php / view.php | 50            | Probability (%) of running a global cleanup on each request (ignored when `CLEANUP_ENABLED` is `false`)                  |
| `TMP_ORPHAN_TTL`   | all                  | 3600          | Orphan temporary files (failed writes) older than X seconds are removed                                                  |
| `LEGACY_TTL_SEC`   | all                  | 7 days        | Fallback TTL for secrets created with previous versions (`created` field)                                                |

## 🌍 Internationalization

The interface language is automatically selected based on the browser's `Accept-Language` header:

- Italian browsers (`it`, `it-IT`, ...) → Italian interface
- All other languages → English interface (default fallback)

All UI strings live in `lang.php`, which contains a translation table for both languages. To add a new language: add a new entry to the array returned by `snm_translations()` and update the language detection in `snm_lang()`.

CLI output (`cleanup.php`) is always in English, since the script is intended for system administrators.

## 📬 Email notifications (optional)

SayNoMore can optionally email the secret creator when the secret is read, destroyed after too many failed password attempts, opened after it has already expired, or expired and removed by the cleanup job. The feature is **off by default** and is configured entirely in `mailconfig.php`.

### Enable

Edit `mailconfig.php` and set `enabled` to `true`, then fill in your SMTP credentials:

```php
return [
    'enabled'   => true,
    'host'      => 'smtp.example.com',
    'port'      => 587,
    'secure'    => 'tls',                // 'ssl' | 'tls' | ''
    'username'  => 'noreply@example.com',
    'password'  => 'your-smtp-password',
    'from'      => 'noreply@example.com',
    'from_name' => 'SayNoMore',
    'site_url'  => 'https://your-site.example',  // optional: turns "SayNoMore" in the email footer into a link
    'max_retries' => 3,                  // SMTP send attempts before giving up
    'debug'     => false,                // true = log to maildebug.txt + red warning on home (keep off in production)
    'timeout'   => 10,
];
```

Common SMTP profiles:

| Mode                      | Port | `secure` |
| ------------------------- | ---- | -------- |
| SSL implicit              | 465  | `'ssl'`  |
| STARTTLS (recommended)    | 587  | `'tls'`  |
| Plaintext (internal only) | 25   | `''`     |

### How it works

- When `enabled` is `true`, a **checkbox** ("Email me when the secret is read or destroyed") appears in the secret creation form; the **email field** is shown only after the checkbox is ticked
- While the checkbox is ticked the email field becomes required: leaving it empty or typing an invalid address shows a localized popup (in the page language); the address is also re-validated server-side
- If the user ticks the checkbox, the address is validated and stored inside the secret payload along with the language chosen at creation time
- Four notifications can be triggered (all sent to the address provided at creation time):
  - **Secret read**: sent right after the recipient successfully decrypts the secret
  - **Secret destroyed**: sent right after the secret is deleted following the maximum number of failed password attempts
  - **Opened after expiry**: sent when someone opens the link of a secret that has **already expired** — the content is **not** shown and the file is removed (triggered from `view.php` on the unlock request)
  - **Expired and removed**: sent when the **cron cleanup** (`cleanup.php`) deletes a secret that expired **without ever being opened**
- The notification is localized in the same language as the creator's UI (Italian or English)
- The email contains a short ID (first 8 characters of the token) plus date and time
- When `enabled` is `false` the checkbox is **not shown** and the application behaves exactly as before

### Implementation notes

- The SMTP client is implemented natively (no PHPMailer, no Composer dependency); see `mail.php`
- Supports `AUTH LOGIN`, multipart/alternative bodies (plaintext + HTML), STARTTLS and SSL
- **Send retries**: the notification is attempted up to `max_retries` times (default 3). Delivery is confirmed by the SMTP `250` reply after the `DATA` block, so the send stops on the first accepted attempt and a delivered message is **never sent more than once**. Retries only occur when a previous attempt failed before that confirmation, with a short back-off between attempts
- **Email footer link**: the footer reads "Automatic notification generated by SayNoMore"; if `site_url` is set to a valid `http(s)` URL, the word "SayNoMore" becomes a clickable link to that address (otherwise it stays plain text)
- The mail is sent in background after the response is delivered to the client (`register_shutdown_function` + `fastcgi_finish_request` when available), so retries and SMTP timeouts never delay the page shown to the user
- Failures are silent for the end user: SMTP errors only get logged via `error_log()` so that a misconfigured SMTP server never breaks the secret read flow
- The notification email is stored in clear text inside the secret file; protect the `data/` directory just like for the secret payload itself (see the Security section)

### Debug logging

To diagnose why a notification is or isn't being delivered, set `'debug' => true` in `mailconfig.php`. When enabled:

- Every step of the pipeline is appended to **`maildebug.txt`** (created in the same folder as `mail.php`): message generation (subject, body sizes, footer link), the full SMTP conversation (`>>` commands sent / `<<` server replies), the **raw RFC message** (headers + body, so you can inspect format and spacing), and the outcome of each retry attempt
- A **red warning banner** is shown on the home page (Italian or English, via `lang.php`) so it is obvious the log is active
- SMTP credentials are **never** written to the log: the `AUTH LOGIN` username/password lines are replaced with `<username base64>` / `<password base64 redacted>`

> ⚠ `maildebug.txt` can contain recipient addresses and message content. It lives inside the document root, so **protect it like the `data/` directory** (deny web access) and keep `debug` **off in production** — turn it on only while troubleshooting.

## 🧹 Expired secret cleanup

Two complementary mechanisms are available; you can use one or both together.

### 1. Probabilistic in-request cleanup (enabled by default)

On every request to `index.php` or `view.php` there's a 50% chance that the server scans `data/` and removes expired secrets and orphan temporary files older than 1 hour.

Pros: zero configuration, works out of the box.
Cons: if traffic is very low, expired files may stay on disk longer than expected before enough traffic triggers cleanup.

> ⚠ **Notifications:** the probabilistic in-request cleanup removes expired secrets **silently — it does not send the "Expired and removed" email**. Only the cron job below sends that notification. If you rely on expiry notifications, run the cron (and consider disabling the in-request cleanup as shown at the end of this section); otherwise a secret purged in-request — or even one already removed in-request before an unlock request reaches it — won't generate an email.

### 2. Cron-based cleanup (optional, recommended for low-traffic services)

The `cleanup.php` script is a standalone CLI job that guarantees cleanup. It is safe to run in parallel with web requests thanks to non-blocking locking (in-use files are skipped). When email notifications are enabled, it also sends the **"Expired and removed"** email for each expired-and-never-opened secret that carries a notification address (the send is synchronous, as there is no web client to release).

**Manual test:**

```bash
php /var/www/saynomore/cleanup.php
```

Example output:

```
[2025-01-20 03:15:02] SayNoMore cleanup:
  scanned:        42
  expired:        7
  notified:       2
  corrupted:      0
  tmp orphans:    1
  locked skipped: 0
  errors:         0
```

> The `notified` line counts the **"Expired and removed"** emails sent during this run: one per expired-and-never-opened secret that carried a notification address (only when email notifications are enabled in `mailconfig.php`).

**Crontab (every hour at :15):**

```cron
15 * * * * /usr/bin/php /var/www/saynomore/cleanup.php >/dev/null 2>&1
```

**Crontab (once a day at 3:15, fine for personal use):**

```cron
15 3 * * * /usr/bin/php /var/www/saynomore/cleanup.php >/dev/null 2>&1
```

**If you want to keep a cleanup log:**

```cron
15 3 * * * /usr/bin/php /var/www/saynomore/cleanup.php >> /var/log/saynomore-cleanup.log 2>&1
```

The script refuses to run if invoked over the web (it checks `PHP_SAPI`), so even if the file were accidentally reachable from a browser it couldn't be abused.

If you enable the cron, you can disable the in-request probabilistic cleanup by setting `CLEANUP_ENABLED` to `false` in both `index.php` and `view.php`. This avoids the small per-request I/O overhead of the random check and leaves cleanup entirely to the cron job.

```php
const CLEANUP_ENABLED = false;
```

## 🔒 Important security notes

**Key in the URL fragment (end-to-end).** The AES key is generated in the browser and used only in the browser. It sits after the `#`, so it never reaches the server — not in Apache/nginx logs, referer headers, link-preview systems (Slack/WhatsApp/Telegram), or proxy/CDN/WAF logs, and **not in the unlock POST either** (the browser sends only `token` + `password`; the server returns the ciphertext, which the browser decrypts locally). A compromised or malicious server — at rest or in the request path — therefore sees `iv`, `ct`, the Argon2id hash, and the password, but never the key, and cannot decrypt. The fragment is kept until the secret is successfully unlocked (so a reload after a wrong password still lets you retry within the attempt budget), then removed from the address bar/history via `history.replaceState`.

> **Why is the IV sent to the server?** The IV (nonce) is **not secret** in AES-GCM — the only security requirement is that the (key, IV) pair is unique, not that the IV is hidden (see NIST SP 800-38D, §8). The IV is needed to decrypt, so it is stored next to the ciphertext and returned to the recipient's browser. Only the **key** must stay secret, and it never leaves the fragment. Sending the IV in clear is standard practice (TLS does the same) and does not weaken anything. In SayNoMore the point is moot anyway: every secret uses a fresh random key, so (key, IV) uniqueness is guaranteed by the key alone.

**Fragment key encoding (base64url).** The key in the fragment is a 256-bit AES key encoded in **base64url** (`A–Z a–z 0–9 - _`, no padding) → **43 characters**, instead of the previous hex encoding (64 characters). This is purely an encoding change: same 256-bit key, shorter link. The IV is unaffected (it is non-secret and stays server-side). **Does this break anything?** No: the reader accepts **both** formats — new links are base64url, and any link generated before this change (64-hex fragment) is still decoded correctly. If you don't care about in-flight legacy links, you can drop the hex branch in `keyToBytes()`/the fragment validation regex in `script.js`. This change touches only `script.js`; the server and the `token` (still hex) are unchanged.

**Secure context required.** Web Crypto's `crypto.subtle` only works in a secure context. On clearnet this means HTTPS; `.onion` services qualify. On plain-HTTP clearnet the app disables encryption/decryption and shows a clear message instead of silently weakening security.

**Protect the `data/` folder.** The script creates `data/` inside the document root. It is **strongly recommended** to block its web access (`.htaccess` with `Deny from all` on Apache, or a `location` deny rule on nginx), or to move it outside the document root by editing `$storage` in `index.php`, `view.php`, and `cleanup.php`.

### Apache

Create a `.htaccess` file inside `data/`:

```apache
Require all denied
```

If you are using an older Apache version:

```apache
Deny from all
```

To protect the SMTP config and debug log, add this to the site config or an `.htaccess` in the document root:

```apache
<FilesMatch "^(mailconfig\.php|maildebug\.txt)$">
    Require all denied
</FilesMatch>
```

### Nginx

Add a rule to block direct access to `data/`:

```nginx
location ^~ /data/ {
    deny all;
    return 403;
}
```

Also deny web access to the SMTP config and the debug log (they live in the document root). The `mailconfig.php` rule below is required to keep your SMTP credentials private if PHP execution ever breaks:

```nginx
location = /mailconfig.php {
        return 404;
}

location = /maildebug.txt {
        return 404;
}
```

**Force HTTPS.** The script does not force HTTPS because that is assumed to be handled by the web server. Without HTTPS, passwords and keys travel in clear text. Exception: `.onion` hidden services over Tor, where the link is generated with `http://` because anonymity and encryption are already provided by the Tor protocol.

**"Secure delete" overwrite is best-effort.** On journaled filesystems (ext4, NTFS, APFS, XFS), on SSDs with wear leveling, and on setups with backups/snapshots, overwriting with zeros does not guarantee data unrecoverability. For serious at-rest protection, use an encrypted filesystem.

**Timing attack against token enumeration.** Every unlock POST performs a password verification (real or a pre-computed dummy hash) so existing and non-existing tokens consume comparable time. Missing, corrupted, and expired tokens all return the same response (HTTP 404, identical message), avoiding a status/message oracle. Token enumeration is infeasible regardless (128-bit random tokens).

**Input type validation.** All HTTP inputs (both GET and POST) are validated as strings before processing, to avoid TypeError 500 errors and noisy logs caused by bots forging requests with array-typed parameters (`?token[]=...`).

**Cleanup vs. unlock race condition.** Global cleanup (both in-request and via cron) uses `flock LOCK_EX | LOCK_NB` on every file before reading it. If a file is in use (because another request is updating the attempts counter or decrypting the secret), it is silently skipped and will be handled on a later pass. This prevents cleanup running during a legitimate unlock attempt from destroying the secret prematurely.

# Secret Expiration Check

The `ExpireCheck.sh` script allows you to verify the status of your secrets and quickly identify potential issues.

It provides the following checks:

- Expired secrets
- Secrets expiring within the next 24 hours
- Secrets still valid for more than 24 hours
- Misconfigured or broken secrets without an expiration date

This script is useful for monitoring secret lifecycle management and preventing unexpected authentication or service failures caused by expired credentials.

![image](https://github.com/user-attachments/assets/716c7f59-8b79-49e3-8461-aac097d4042d)

# Screenshots

Write your secret, choose a password, set expiration, and generate the link  
![image](https://github.com/user-attachments/assets/ec9b9d69-1d1a-41cd-a053-4cb80a957e05)

Copy the link using the Copy button, or manually if you prefer, and send it to the recipient  
![image](https://github.com/user-attachments/assets/45c0349c-c363-4a43-9ebb-aaccd258b4dc)

Once opened and the password is entered, the recipient will see it like this  
![image](https://github.com/user-attachments/assets/aecc3ef9-1e70-42eb-8f07-bbb1b990caff)

![image](https://github.com/user-attachments/assets/87ba51f1-c9fb-40f6-bd3d-3953dc6dd197)

## ⚠ Warning

Everything I publish exists because it was useful to me first. I'm not a software developer, and there may be even critical bugs even though all the code has been reviewed by multiple LLMs (Claude Fable 5 + Opus 4.8 , GPT, DeepSeek) looking for vulnerabilities and should be clean.

Use what I publish at your own risk, no warranty whatsoever.

## Fonts

This project uses **Chakra Petch**.
Font by cadsondemak, licensed under the **SIL Open Font License 1.1 (OFL-1.1)**.
<https://github.com/cadsondemak/Chakra-Petch>

## License

This project is distributed under the **GNU General Public License v2.0 (GPL-2.0)**. See the `LICENSE` file for the full text. The bundled font is licensed separately under **OFL-1.1** (see `Font_License.md`).

## Author

Created by **Leproide**: <https://github.com/Leproide>
Project: <https://github.com/Leproide/SayNoMore>