<?php
/**
 * SayNoMore - mailconfig.php
 *
 * SMTP configuration for optional email notifications.
 *
 * Set 'enabled' => true to enable this feature: when enabled, the secret
 * creation form will display a "Notify me by email" checkbox and an email
 * field. If the checkbox is checked and the email is valid, two types of
 * notifications may be sent:
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

    // Connection/read timeout in seconds
    'timeout'   => 10,
];
