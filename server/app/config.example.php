<?php
declare(strict_types=1);

/**
 * Copy this file to app/config.php on the server and fill in real values.
 * app/config.php must never be committed (see server/.gitignore).
 *
 * Prefer the unix socket: the MySQL account is created as 'sibaihua'@'localhost',
 * which matches socket connections (and TCP only if 127.0.0.1 resolves to localhost).
 */
return [
    'db' => [
        'socket' => '/tmp/mysql.sock',
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'sibaihua',
        'user' => 'sibaihua',
        'password' => 'CHANGE_ME',
    ],

    // OpenID Connect provider settings.
    // `issuer` must exactly match the host members use — pick one canonical host
    // (apex) and 301 the other, or tokens will carry a mismatched issuer.
    'oidc' => [
        'issuer' => 'https://sibaihua.com',
        'key_path' => '/www/server/sibaihua-app/oidc-key.pem',
        // 32 random bytes, base64. Encrypts client secrets at rest so the console
        // can show them again. Generate with:
        //   openssl rand -base64 32
        'secret_key' => 'CHANGE_ME_32_BYTES_BASE64',
    ],
];
