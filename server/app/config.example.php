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
];
