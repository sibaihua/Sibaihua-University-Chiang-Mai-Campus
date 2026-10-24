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

    // Sign in to the admin console through an external OAuth 2.0 / OIDC provider.
    // Leave `enabled => false` to fall back to the local password only.
    // The external identity must match a local admin account (oauth_sub, then
    // e-mail, then username); unknown identities are always rejected.
    'external_oauth' => [
        'enabled' => false,
        'name' => 'pan.sibh.cn',
        'icon' => '',
        'button_label' => '',           // defaults to "使用 {name} 登录"
        'client_id' => '',
        'client_secret' => '',          // leave empty only if the provider allows public clients
        'redirect_uri' => 'https://sibaihua.com/admin.html',
        'scopes' => 'openid profile email',
        'pkce' => true,
        'authorization_endpoint' => '',
        'token_endpoint' => '',
        'userinfo_endpoint' => '',
    ],
];
