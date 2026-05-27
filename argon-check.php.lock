<?php
header('Content-Type: text/plain; charset=utf-8');
echo 'PHP ', PHP_VERSION, ' (', PHP_SAPI, ")\n";
echo 'Argon2id:     ', (defined('PASSWORD_ARGON2ID') ? 'OK' : 'MISSING'), "\n";
echo 'OpenSSL:      ', (extension_loaded('openssl') ? 'OK' : 'MISSING'), "\n";
echo 'AES-256-GCM:  ', (in_array('aes-256-gcm', openssl_get_cipher_methods(), true) ? 'OK' : 'MISSING'), "\n";
echo 'random_bytes: ', (function_exists('random_bytes') ? 'OK' : 'MISSING'), "\n";
