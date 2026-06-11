# SayNoMore

#saynomore

SayNoMore is a simple One Time Secret service for sharing passwords or sensitive information that can only be viewed once.

> ### ⚠ BREAKING UPDATE — v6 (end-to-end encryption)
>
> Starting from **v6**, encryption and decryption happen **entirely in the browser** (Web Crypto, AES-256-GCM). The server never sees the plaintext nor the AES key, in any phase.
>
> **This is a breaking change. Read before upgrading:**
> - **Secrets created with previous versions become unreadable.** The on-disk storage format and the key scheme changed. Since secrets are ephemeral (max 30 days), do a clean cutover: empty the `data/` folder on deploy, or wait for old secrets to expire.
> - **Creating and reading now require JavaScript and a secure context.** On clearnet you need **HTTPS**; on a `.onion` hidden service it works (onion is a trusted context). On plain-HTTP clearnet, encryption is disabled with an explicit on-screen message — never a silent downgrade.
> - **OpenSSL is no longer required on the server** for secret encryption (it moved to the browser). It is still used only by the optional email notifications when SSL/STARTTLS is selected.
> - `cleanup.php`, `ExpireCheck.sh` and the email notifications are **unchanged and fully compatible** with the new format (they rely on the `expires`/`created` fields and on the secret filename, none of which changed).

## 🔐 Features

- ✉️ Secrets readable only once, protected by a password (Argon2id hashing with automatic salt)
- 🔒 **End-to-end AES-256-GCM**: encryption/decryption run in the recipient's and sender's browser via the Web Crypto API. The server only ever stores and relays ciphertext.
- 🧠 **True zero-knowledge on the content**: the AES key (`K_frag`) is generated in the browser, lives only in the URL fragment (`#`), and is **never** sent to the server — not in the link, not in any POST. The server cannot decrypt, even if fully compromised.
- 🔑 **Password as a server-side access gate**: the view-password is verified server-side (Argon2id) to enforce the one-time read and the 5-attempt limit. It does **not** decrypt the content (that requires `K_frag`), so a stolen password alone is useless.
- ⏳ User-configurable expiration: from 1 to 30 days (default 7)
- 🧹 Automatic cleanup with non-blocking locking: expired secrets are removed in the background without interfering with active unlock attempts
- 🧼 Destruction after read (with best-effort overwrite, see notes below)
- 🛡 Anti-abuse mitigations: 64 KB secret size limit (enforced client- and server-side), max 5 password attempts, uniform timing against token enumeration, strict input/type validation against malformed requests
- 🌍 Multilingual: Italian for Italian browsers, English everywhere else (based on `Accept-Language`)
- 🧅 Tor support: on `.onion` hidden services the generated link inherits `http://` automatically from the page address
- 💻 No database required, just the file system

## 🚀 How it works (v6, end-to-end)

**Creating a secret**

1. You enter a message, a password, and how many days the link stays valid.
2. **In your browser**, JavaScript generates a random AES-256 key (`K_frag`) and a random IV, then encrypts the message (AES-256-GCM). Plaintext and `K_frag` never leave the browser.
3. The browser sends to the server only: the IV, the ciphertext (with authentication tag), the password, and the TTL.
4. The server hashes the password (Argon2id) and stores `{iv, ct, hash, expires, attempts}` — it does not encrypt anything and has no key.
5. The browser builds the link `view.php?token=...#K_frag` (the server never knows `K_frag`).

**Reading a secret**

1. The recipient opens the link. JavaScript reads `K_frag` from the URL fragment. The fragment is kept until the secret is successfully unlocked (so a reload after a wrong password still lets you retry within the attempt budget), then removed from the address bar/history.
2. The recipient enters the password. The browser sends to the server only the `token` and the `password` (never `K_frag`).
3. The server verifies the password. On success it returns the stored IV + ciphertext **and destroys the file** (one-time). On wrong password it increments the counter; after 5 failures the secret is destroyed.
4. The browser decrypts the ciphertext locally with `K_frag` and shows the secret. If `K_frag` is missing/corrupted, decryption fails client-side (the secret is already consumed).

## 🔗 Demo

<https://saynomore.muninn.ovh>

## 🛠️ Requirements

**Server**
- PHP 7.4+ (8.x recommended)
- Argon2id available (PHP built with libargon2, default on modern distros)
- `random_bytes` / `random_int` (CSPRNG)
- Web server with write permissions; the script will create a `data` folder
- Protect the `data` directory from unauthorized read access (recommended, see the Security section)
- **HTTPS configured at the web server level** (required for clearnet, see Security section)
- Local filesystem (ext4, xfs, btrfs, ntfs). On NFS/SMB file locking is not guaranteed.
- OpenSSL is **not** required for secret encryption anymore (it now runs in the browser); it is only used by the optional email notifications over SSL/STARTTLS.

**Client (browser)**
- JavaScript enabled (required to encrypt on creation and to read the key on viewing)
- Web Crypto API (`crypto.subtle`) — available in any modern browser
- **Secure context**: HTTPS, `localhost`, or a `.onion` address. On plain-HTTP clearnet the app refuses to encrypt/decrypt and shows a message.

## ⚙️ Configuration

The main parameters are constants at the top of `index.php`, `view.php`, and `cleanup.php`:

| Constant            | File                 | Default        | Description                                                                                                              |
| ------------------- | -------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `DEFAULT_TTL_DAYS`  | index.php            | 7              | Default validity in days for new secrets                                                                                 |
| `MIN_TTL_DAYS`      | index.php            | 1              | Minimum TTL selectable by the user                                                                                       |
| `MAX_TTL_DAYS`      | index.php            | 30             | Maximum TTL selectable by the user                                                                                       |
| `MAX_SECRET_BYTES`  | index.php            | 65536 (64 KB)  | Plaintext size limit (enforced client-side and re-checked server-side as `ciphertext − 16` byte GCM tag)                |
| `MAX_CT_B64_BYTES`  | index.php            | 98304 (96 KB)  | Hard cap on the base64 ciphertext accepted by the server (bounds memory before decoding)                                |
| `GCM_IV_LEN`        | index.php            | 12             | Expected GCM IV length in bytes (validated server-side)                                                                  |
| `MAX_ATTEMPTS`      | view.php             | 5              | Maximum number of password attempts before destruction                                                                   |
| `CLEANUP_ENABLED`   | index.php / view.php | true           | Master switch for in-request cleanup. Set to `false` to disable it entirely (useful when you run `cleanup.php` via cron) |
| `CLEANUP_PROB_PCT`  | index.php / view.php | 50             | Probability (%) of running a global cleanup on each request (ignored when `CLEANUP_ENABLED` is `false`)                  |
| `TMP_ORPHAN_TTL`    | all                  | 3600           | Orphan temporary files (failed writes) older than X seconds are removed                                                  |
| `LEGACY_TTL_SEC`    | all                  | 7 days         | Fallback TTL for secrets created with previous versions (`created` field)                                                |

### Storage format (on disk, in `data/`)

Each secret is a JSON file named with a 32-hex token:

```json
{
  "iv": "<base64 12-byte IV>",
  "ct": "<base64 ciphertext+GCM-tag, produced by the browser>",
  "hash": "<Argon2id hash of the view-password>",
  "expires": 1700000000,
  "attempts": 0,
  "notify_email": "",
  "lang": "en"
}
```

Note: there is no separate `tag` field anymore — the 16-byte GCM tag is appended to `ct` (Web Crypto convention). `notify_email` and `lang` are metadata and are **not** encrypted (see Security notes).

## 🌍 Internationalization

The interface language is automatically selected based on the browser's `Accept-Language` header:

- Italian browsers (`it`, `it-IT`, ...) → Italian interface
- All other languages → English interface (default fallback)

All UI strings live in `lang.php`, which contains a translation table for both languages. To add a new language: add a new entry to the array returned by `snm_translations()` and update the language detection in `snm_lang()`. CLI output (`cleanup.php`) is always in English, since the script is intended for system administrators.

## 🧹 Expired secret cleanup

Two complementary mechanisms are available; you can use one or both together. Both are unchanged in v6 and fully compatible with the new format.

### 1. Probabilistic in-request cleanup (enabled by default)

On every request to `index.php` or `view.php` there's a 50% chance that the server scans `data/` and removes expired secrets and orphan temporary files older than 1 hour.

Pros: zero configuration, works out of the box.
Cons: if traffic is very low, expired files may stay on disk longer than expected before enough traffic triggers cleanup.

### 2. Cron-based cleanup (optional, recommended for low-traffic services)

The `cleanup.php` script is a standalone CLI job that guarantees cleanup. It is safe to run in parallel with web requests thanks to non-blocking locking (in-use files are skipped). It keys solely on the `expires`/`created` fields, so it works identically with v6 storage.

**Manual test:**

```
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

```
15 * * * * /usr/bin/php /var/www/saynomore/cleanup.php >/dev/null 2>&1
```

**Crontab (once a day at 3:15, fine for personal use):**

```
15 3 * * * /usr/bin/php /var/www/saynomore/cleanup.php >/dev/null 2>&1
```

The script refuses to run if invoked over the web (it checks `PHP_SAPI`), so even if the file were accidentally reachable from a browser it couldn't be abused.

If you enable the cron, you can disable the in-request probabilistic cleanup by setting `CLEANUP_ENABLED` to `false` in both `index.php` and `view.php`:

```
const CLEANUP_ENABLED = false;
```

## 🔒 Important security notes

**End-to-end encryption (v6).** The AES key `K_frag` is generated in the browser and used only in the browser. It is placed after the `#` in the link and is therefore never sent to the server — not in the original link (fragments are not transmitted in HTTP requests), and **not in the unlock POST either** (the browser sends only `token` + `password`; the server returns the ciphertext, which the browser decrypts locally). Consequence: a compromised or malicious server — at rest or actively in the request path — sees `iv`, `ct`, the Argon2id hash, and the password, but **never `K_frag`**, and therefore cannot decrypt the secret.

**Password is an access gate, not a content key.** The view-password is verified server-side to enforce the one-time read and the 5-attempt limit. Because the ciphertext is released only after a correct password, an attacker who has the link but not the password cannot brute-force the blob offline. A correct password alone still cannot decrypt anything without `K_frag`. Residual, stated honestly: the password does transit to the server (it is the gate); use a password you do not reuse elsewhere.

**Secure context required.** Web Crypto's `crypto.subtle` only works in a secure context. On clearnet this means HTTPS; `.onion` services qualify as trusted contexts. On plain-HTTP clearnet the app disables encryption/decryption and shows a clear message instead of silently weakening security.

**Protect the `data/` folder.** The script creates `data/` inside the document root. It is **strongly recommended** to block its web access (`.htaccess` with `Require all denied` on Apache, or a `location` deny rule on nginx), or to move it outside the document root by editing `$storage` in `index.php`, `view.php`, and `cleanup.php`. Note that even if `data/` is read by an attacker, the secrets remain confidential (no `K_frag` is stored), but the `notify_email` metadata is stored in clear and would be exposed — do not rely on `data/` exposure being harmless.

### Apache

Create a `.htaccess` file inside `data/`:

```
Require all denied
```

Older Apache:

```
Deny from all
```

### Nginx

```
location ^~ /data/ {
    deny all;
    return 403;
}
```

It is also recommended to deny web access to `mailconfig.php` (SMTP credentials), `maildebug.txt` (if debug is ever enabled), and any `*.php.lock` diagnostic files, or to move credentials/logs outside the document root.

**Force HTTPS.** The script does not force HTTPS itself; that is assumed to be handled by the web server. On clearnet, without HTTPS the browser cannot encrypt (no secure context) and passwords would travel in clear. Exception: `.onion` hidden services over Tor, where anonymity and encryption are already provided by the Tor protocol and the link inherits `http://`.

**"Secure delete" overwrite is best-effort.** On journaled filesystems (ext4, NTFS, APFS, XFS), on SSDs with wear leveling, and on setups with backups/snapshots, overwriting with zeros does not guarantee data unrecoverability. For serious at-rest protection, use an encrypted filesystem. (This is moot for the plaintext, which never touches the server, but still applies to the ciphertext file.)

**Timing attack against token enumeration.** Every unlock POST performs a password verification (real or a pre-computed dummy hash) so that existing and non-existing tokens consume comparable time. Missing, corrupted, and expired tokens all return the same response (HTTP 404, identical message), avoiding a status/message oracle. Token enumeration is infeasible regardless (128-bit random tokens).

**Input type validation.** All HTTP inputs (GET and POST) are validated as strings before processing; `iv`/`ct` are strictly base64-decoded and length-checked; the token is matched against `^[a-f0-9]{32}$` (anti path-traversal). This avoids TypeError 500s and noisy logs from bots forging array-typed parameters (`?token[]=...`).

**Cleanup vs. unlock race condition.** Global cleanup (in-request and cron) uses `flock LOCK_EX | LOCK_NB` on every file before reading it. Files in use are silently skipped and handled on a later pass, so cleanup never destroys a secret during a legitimate unlock.

# Secret Expiration Check

The `ExpireCheck.sh` script verifies the status of your secrets and quickly identifies potential issues. It is unchanged in v6 and reads the `expires` field directly.

It reports:

- Expired secrets
- Secrets expiring within the next 24 hours
- Secrets still valid for more than 24 hours
- Misconfigured or broken secrets without an expiration date

```
bash ExpireCheck.sh /var/www/saynomore/data
```

# Threat model (quick reference)

| Adversary                                   | Outcome                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Server compromised at rest (`data/` read)   | Sees `iv`, `ct`, Argon2id hash, `notify_email`. **Cannot decrypt** (no `K_frag`).        |
| Malicious/MITM server in the request path   | Sees the password (gate). **Never receives `K_frag`** → cannot decrypt.                  |
| Has the link, not the password              | Blocked by the server-side 5-attempt gate; ciphertext never released.                    |
| Has the password, not the link (`K_frag`)   | Server releases the ciphertext (and consumes it), but it cannot be decrypted.            |
| Network observer (HTTPS)                     | Sees only TLS-encrypted traffic.                                                         |

Not covered by design: a malicious server could serve tampered JavaScript to exfiltrate the plaintext/key in the victim's browser. This is inherent to any browser-delivered E2E web app; mitigate with HTTPS, integrity controls, and trusting the operator/host.

## ⚠ Warning

Everything I publish exists because it was useful to me first. I'm not a software developer, and there may be even critical bugs even though all the code has been reviewed by multiple LLMs (Claude, GPT, DeepSeek) looking for vulnerabilities and should be clean.

Use what I publish at your own risk, no warranty whatsoever.

## Fonts

This project uses **Chakra Petch**.
Font by cadsondemak, licensed under the **SIL Open Font License 1.1 (OFL-1.1)**. <https://github.com/cadsondemak/Chakra-Petch>

## License

This project is distributed under the **GNU General Public License v2.0 (GPL-2.0)**. See the `LICENSE` file for the full text. The bundled font is licensed separately under **OFL-1.1** (see `Font_License.md`).

## Author

Created by **Leproide** — <https://github.com/Leproide>
Project: <https://github.com/Leproide/SayNoMore>
