# SayNoMore

![c4b311a6-165e-437a-b2af-3d02f8bf007f](https://github.com/user-attachments/assets/7d2c6928-2344-41e8-ab6a-c9ae7ce6c8a3)

SayNoMore is a simple One Time Secret service for sharing passwords or sensitive information that can only be viewed once.

## 🔐 Features

- ✉️ Secrets readable only once, protected by a password (Argon2id hashing with automatic salt)
- 🔒 AES-256-GCM encryption with authentication tag (detects ciphertext tampering)
- 🧠 Real zero-knowledge: the decryption key travels in the URL fragment (`#`) and is never sent to the server through the link
- ⏳ User-configurable expiration: from 1 to 30 days (default 7)
- 🧹 Automatic cleanup with non-blocking locking: expired secrets are removed in the background without interfering with active unlock attempts
- 🧼 Destruction after read (with best-effort overwrite, see notes below)
- 🛡 Anti-abuse mitigations: 64 KB secret size limit, max 5 password attempts, uniform timing against token enumeration, input type validation against malformed requests
- 🌍 Multilingual: Italian for Italian browsers, English everywhere else (based on `Accept-Language`)
- 🧅 Tor support: links generated on `.onion` hidden services automatically use `http://` instead of `https://`
- 💻 No database required, just the file system

## 🚀 How it works

1. Enter a message, choose a password, and select how many days the link should remain valid
2. Get a link in the form `view.php?token=...#key`
3. Send the link to the recipient
4. The recipient opens the link, enters the password, and reads the secret
5. The secret self-destructs after opening, after 5 failed attempts, or at the chosen expiration

## 🔗 Demo

https://saynomore.muninn.ovh

## 🛠️ Requirements

- PHP 7.4+ (8.x recommended)
- OpenSSL extension enabled
- Argon2id available (PHP built with libargon2, default on modern distros)
- Web server with write permissions, the script will create a `data` folder
- Protect the `data` directory from unauthorized read access (recommended, see the Security section).
- HTTPS configured at the web server level (recommended, see security section)
- JavaScript enabled on the client (required to read the key from the fragment)
- Local filesystem (ext4, xfs, btrfs, ntfs). On NFS/SMB file locking is not guaranteed.

## ⚙️ Configuration

The main parameters are constants at the top of `index.php`, `view.php`, and `cleanup.php`:

| Constant | File | Default | Description |
|---|---|---|---|
| `DEFAULT_TTL_DAYS` | index.php | 7 | Default validity in days for new secrets |
| `MIN_TTL_DAYS` | index.php | 1 | Minimum TTL selectable by the user |
| `MAX_TTL_DAYS` | index.php | 30 | Maximum TTL selectable by the user |
| `MAX_SECRET_BYTES` | index.php | 65536 (64 KB) | Secret size limit |
| `MAX_ATTEMPTS` | view.php | 5 | Maximum number of password attempts before destruction |
| `CLEANUP_ENABLED` | index.php / view.php | true | Master switch for in-request cleanup. Set to `false` to disable it entirely (useful when you run `cleanup.php` via cron) |
| `CLEANUP_PROB_PCT` | index.php / view.php | 50 | Probability (%) of running a global cleanup on each request (ignored when `CLEANUP_ENABLED` is `false`) |
| `TMP_ORPHAN_TTL` | all | 3600 | Orphan temporary files (failed writes) older than X seconds are removed |
| `LEGACY_TTL_SEC` | all | 7 days | Fallback TTL for secrets created with previous versions (`created` field) |

## 🌍 Internationalization

The interface language is automatically selected based on the browser's `Accept-Language` header:

- Italian browsers (`it`, `it-IT`, ...) → Italian interface
- All other languages → English interface (default fallback)

All UI strings live in `lang.php`, which contains a translation table for both languages. To add a new language: add a new entry to the array returned by `snm_translations()` and update the language detection in `snm_lang()`.

CLI output (`cleanup.php`) is always in English, since the script is intended for system administrators.

## 🧹 Expired secret cleanup

Two complementary mechanisms are available; you can use one or both together.

### 1. Probabilistic in-request cleanup (enabled by default)

On every request to `index.php` or `view.php` there's a 50% chance that the server scans `data/` and removes expired secrets and orphan temporary files older than 1 hour.

Pros: zero configuration, works out of the box.
Cons: if traffic is very low, expired files may stay on disk longer than expected before enough traffic triggers cleanup.

### 2. Cron-based cleanup (optional, recommended for low-traffic services)

The `cleanup.php` script is a standalone CLI job that guarantees cleanup. It is safe to run in parallel with web requests thanks to non-blocking locking (in-use files are skipped).

**Manual test:**
```bash
php /var/www/saynomore/cleanup.php
```

Example output:
```
[2025-01-20 03:15:02] SayNoMore cleanup:
  scanned:        42
  expired:        7
  corrupted:      0
  tmp orphans:    1
  locked skipped: 0
  errors:         0
```

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

**Key in the URL fragment.** The AES key sits after the `#`, so it doesn't end up in Apache/nginx logs, in referer headers, in the link-preview systems of Slack/WhatsApp/Telegram, or in proxy/CDN/WAF logs. It only remains in the recipient's browser history until unlock, after which it is automatically removed via `history.replaceState`.

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

### Nginx

Add a rule to block direct access to `data/`:

```nginx
location ^~ /data/ {
    deny all;
    return 403;
}
```

**Force HTTPS.** The script does not force HTTPS because that is assumed to be handled by the web server. Without HTTPS, passwords and keys travel in clear text. Exception: `.onion` hidden services over Tor, where the link is generated with `http://` because anonymity and encryption are already provided by the Tor protocol.

**"Secure delete" overwrite is best-effort.** On journaled filesystems (ext4, NTFS, APFS, XFS), on SSDs with wear leveling, and on setups with backups/snapshots, overwriting with zeros does not guarantee data unrecoverability. For serious at-rest protection, use an encrypted filesystem.

**Timing attack against token enumeration.** To prevent an attacker from distinguishing "existing token" from "non-existing token" by measuring response times, every POST request performs a password verification (real or dummy) so the same time is consumed in both cases.

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
![image](https://github.com/user-attachments/assets/20cdc384-1b4f-4b33-96f7-290fbb776199)

Copy the link using the Copy button, or manually if you prefer, and send it to the recipient  
![image](https://github.com/user-attachments/assets/221b8a15-4d68-412e-88dd-ab3fed90695a)

Once opened and the password is entered, the recipient will see it like this  
![image](https://github.com/user-attachments/assets/aecc3ef9-1e70-42eb-8f07-bbb1b990caff)

![image](https://github.com/user-attachments/assets/1f4cb15f-f161-4368-ae13-d8a5ecf6ca52)

## ⚠ Warning

Everything I publish exists because it was useful to me first. I'm not a software developer, and there may be even critical bugs even though all the code has been reviewed by multiple LLMs (Claude, GPT, DeepSeek) looking for vulnerabilities and should be clean.

Use what I publish at your own risk, no warranty whatsoever.

## Fonts

This project uses **Chakra Petch**.
Font by cadsondemak, licensed under the **SIL Open Font License 1.1 (OFL-1.1)**.
https://github.com/cadsondemak/Chakra-Petch
