<?php
/**
 * SayNoMore - mailconfig.php
 *
 * SMTP configuration for optional email notifications.
 *
 * Set 'enabled' => true to enable this feature: when enabled, the secret
 * creation form will display a "Notify me by email" checkbox; the email
 * field appears only once the checkbox is ticked. If the checkbox is checked
 * and the email is valid, two types of notifications may be sent:
 *   - Secret opened and read successfully
 *   - Secret destroyed after too many failed attempts
 *
 * Leaving 'enabled' => false (default) will hide the checkbox and no
 * emails will be sent: the rest of the application will continue working
 * exactly as before with no behavior changes.
 *
 * Common SMTP ports:
 *   - 465 with 'secure' => 'ssl' (implicit SSL)
 *   - 587 with 'secure' => 'tls' (STARTTLS, recommended)
 *   - 25  with 'secure' => ''    (plaintext, internal networks only)
 */

return [
    // Master switch for the feature. False = hidden checkbox, no emails sent.
    'enabled'   => false,

    // Sender SMTP server
    'host'      => 'smtp.example.com',
    'port'      => 587,
    'secure'    => 'tls',                // 'ssl' | 'tls' | ''

    // Authentication credentials
    'username'  => 'noreply@example.com',
    'password'  => 'change-me',

    // Visible sender shown to the recipient
    'from'      => 'noreply@example.com',
    'from_name' => 'SayNoMore',

    // Public site URL. If set (http/https), the word "SayNoMore" in the
    // notification email footer becomes a clickable link to this address.
    // Leave empty to render the footer brand as plain text.
    'site_url'  => '',

    // How many times to attempt the SMTP send before giving up. The send
    // stops as soon as the server confirms acceptance (SMTP 250 after DATA),
    // so a delivered message is never sent more than once. Retries only
    // happen when a previous attempt failed before that confirmation.
    'max_retries' => 3,

    // Debug logging. When true, every step of the notification pipeline
    // (generation, full SMTP conversation, raw message, errors) is appended
    // to "maildebug.txt" in this same folder, and a red warning is shown on
    // the home page. SMTP credentials are NEVER written to the log.
    // WARNING: the log can contain recipient addresses and message content.
    // Keep it OFF in production and protect the "data/"-style access to this
    // file (the file lives in the document root). Use only to diagnose.
    'debug'     => false,

    // Connection/read timeout in seconds
    'timeout'   => 10,
];
