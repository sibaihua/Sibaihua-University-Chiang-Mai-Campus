<?php
declare(strict_types=1);

/**
 * Front controller for /api/*  (nginx rewrites /api/... here).
 *
 * Application code lives OUTSIDE the web root on purpose, so that a regenerated
 * vhost config can never expose it.
 */

define('SIB_APP_DIR', '/www/server/sibaihua-app');

require SIB_APP_DIR . '/bootstrap.php';
require SIB_APP_DIR . '/handlers.php';
require SIB_APP_DIR . '/oidc.php';

function db_error(PDOException $e): void
{
    $msg = $e->getMessage();
    if (stripos($msg, 'Unknown database') !== false) {
        fail(500, '数据库不存在：请先创建数据库并导入 schema.sql');
    }
    if (stripos($msg, "doesn't exist") !== false || stripos($msg, 'Base table or view not found') !== false) {
        fail(500, '数据表尚未初始化：请先导入 schema.sql');
    }
    if (stripos($msg, 'Access denied') !== false) {
        fail(500, '数据库凭据无效：请检查 config.php');
    }
    fail(500, '数据库错误：' . $msg);
}

$rawPath = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$path = '/' . trim(is_string($rawPath) ? $rawPath : '/', '/');
if ($path === '/') {
    $path = '/api';
}
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

try {
    route($path, $method);
} catch (PDOException $e) {
    db_error($e);
} catch (Throwable $e) {
    fail(500, '服务器错误：' . $e->getMessage());
}
