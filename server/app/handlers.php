<?php
declare(strict_types=1);

/* ─────────────────────────── setup (first run) ─────────────────────────── */

function handle_setup_status(): void
{
    $count = (int) db()->query('SELECT COUNT(*) AS n FROM users')->fetch()['n'];
    ok(['needsSetup' => $count === 0]);
}

function handle_setup_create(): void
{
    $count = (int) db()->query('SELECT COUNT(*) AS n FROM users')->fetch()['n'];
    if ($count > 0) {
        fail(403, '管理员账号已存在，无法再次初始化');
    }

    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }
    $username = trim((string) ($body['username'] ?? ''));
    $password = (string) ($body['password'] ?? '');
    $email = trim((string) ($body['email'] ?? ''));

    if (!preg_match(USERNAME_PATTERN, $username)) {
        fail(400, '用户名需为 3-32 位的字母、数字、点、下划线或短横线');
    }
    if (str_len($password) < 8 || str_len($password) > 128) {
        fail(400, '密码长度需为 8-128 位');
    }
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        fail(400, '邮箱格式不正确');
    }

    $stmt = db()->prepare('INSERT INTO users (username, password_hash, role, status, email) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT), 'admin', 'active', $email]);
    $userId = (int) db()->lastInsertId();

    set_session_cookie(create_session($userId));
    ok(['user' => ['id' => $userId, 'username' => $username, 'role' => 'admin']], '管理员账号已创建');
}

/* ─────────────────────────── auth ─────────────────────────── */

function handle_login(): void
{
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }
    $username = trim((string) ($body['username'] ?? ''));
    $password = (string) ($body['password'] ?? '');
    if ($username === '' || $password === '') {
        fail(400, '请输入用户名和密码');
    }

    $stmt = db()->prepare('SELECT id, username, role, status, email, password_hash FROM users WHERE username = ? LIMIT 1');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // Identical response for unknown user and wrong password, so accounts cannot be enumerated.
    if (!$user) {
        fail(401, '用户名或密码错误');
    }
    if ($user['status'] !== 'active') {
        fail(403, '该账号已被停用');
    }
    if (!password_verify($password, $user['password_hash'])) {
        fail(401, '用户名或密码错误');
    }

    set_session_cookie(create_session((int) $user['id']));
    ok([
        'user' => [
            'id' => (int) $user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'email' => (string) $user['email'],
        ],
    ], '登录成功');
}

function handle_logout(): void
{
    $token = current_session_token();
    if ($token !== null) {
        db()->prepare('DELETE FROM sessions WHERE token = ?')->execute([$token]);
    }
    clear_session_cookie();
    ok(null, '已退出登录');
}

function handle_me(): void
{
    $user = require_login();
    ok(['user' => $user]);
}

function handle_change_password(): void
{
    $user = require_login();
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }
    $current = (string) ($body['currentPassword'] ?? '');
    $new = (string) ($body['newPassword'] ?? '');
    if (str_len($new) < 8 || str_len($new) > 128) {
        fail(400, '新密码长度需为 8-128 位');
    }

    $stmt = db()->prepare('SELECT password_hash FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$user['id']]);
    $row = $stmt->fetch();
    if (!$row || !password_verify($current, $row['password_hash'])) {
        fail(400, '当前密码不正确');
    }

    db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        ->execute([password_hash($new, PASSWORD_DEFAULT), $user['id']]);

    // Revoke every other session; this device stays signed in.
    $token = current_session_token() ?? '';
    db()->prepare('DELETE FROM sessions WHERE user_id = ? AND token <> ?')->execute([$user['id'], $token]);

    ok(null, '密码已更新');
}

function handle_update_profile(): void
{
    $user = require_login();
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }
    $email = trim((string) ($body['email'] ?? ''));
    if ($email !== '' && (!filter_var($email, FILTER_VALIDATE_EMAIL) || str_len($email) > 190)) {
        fail(400, '邮箱格式不正确');
    }
    db()->prepare('UPDATE users SET email = ? WHERE id = ?')->execute([$email, (int) $user['id']]);
    ok([
        'user' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'email' => $email,
        ],
    ], '资料已更新');
}

/* ─────────────────────────── posts ─────────────────────────── */

function find_post(string $key): ?array
{
    $raw = trim($key);
    if ($raw === '') {
        return null;
    }
    if (preg_match('/^\d+$/', $raw)) {
        $stmt = db()->prepare('SELECT * FROM posts WHERE id = ? LIMIT 1');
        $stmt->execute([(int) $raw]);
    } else {
        $stmt = db()->prepare('SELECT * FROM posts WHERE slug = ? LIMIT 1');
        $stmt->execute([$raw]);
    }
    $row = $stmt->fetch();
    return $row ?: null;
}

function handle_posts_index(): void
{
    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 10;
    $limit = max(1, min(50, $limit === 0 ? 10 : $limit));
    $offset = isset($_GET['offset']) ? max(0, (int) $_GET['offset']) : 0;
    $includeDrafts = (isset($_GET['includeDrafts']) && $_GET['includeDrafts'] === '1');

    if ($includeDrafts) {
        require_admin();
        $where = '';
        $order = 'ORDER BY COALESCE(published_at, updated_at) DESC, id DESC';
    } else {
        $where = "WHERE status = 'published'";
        $order = 'ORDER BY COALESCE(published_at, created_at) DESC, id DESC';
    }

    $total = (int) db()->query("SELECT COUNT(*) AS n FROM posts $where")->fetch()['n'];
    $stmt = db()->prepare("SELECT * FROM posts $where $order LIMIT ? OFFSET ?");
    $stmt->bindValue(1, $limit, PDO::PARAM_INT);
    $stmt->bindValue(2, $offset, PDO::PARAM_INT);
    $stmt->execute();

    $posts = [];
    foreach ($stmt->fetchAll() as $row) {
        $posts[] = post_summary($row);
    }
    ok(['posts' => $posts, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);
}

function handle_posts_create(): void
{
    $user = require_admin();
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }

    $title = trim((string) ($body['title'] ?? ''));
    if ($title === '' || str_len($title) > 200) {
        fail(400, '标题长度需为 1-200 字');
    }
    $excerpt = function_exists('mb_substr')
        ? mb_substr(trim((string) ($body['excerpt'] ?? '')), 0, 400, 'UTF-8')
        : substr(trim((string) ($body['excerpt'] ?? '')), 0, 400);
    $content = (string) ($body['content'] ?? '');
    if (strlen($content) > 60000) {
        fail(400, '正文过长（上限 60000 字符）');
    }
    $status = in_array(($body['status'] ?? ''), POST_STATUSES, true) ? $body['status'] : 'draft';
    $slug = unique_slug(trim((string) ($body['slug'] ?? '')) !== '' ? (string) $body['slug'] : $title);
    $publishedAt = $status === 'published' ? gmdate('Y-m-d H:i:s') : null;

    $stmt = db()->prepare(
        'INSERT INTO posts (slug, title, excerpt, content, status, author_id, published_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([$slug, $title, $excerpt, $content, $status, $user['id'], $publishedAt]);
    $id = (int) db()->lastInsertId();

    $row = find_post((string) $id);
    ok(['post' => post_detail($row)], '文章已创建');
}

function handle_post_get(string $key): void
{
    $row = find_post($key);
    if (!$row) {
        fail(404, '文章不存在');
    }
    if ($row['status'] !== 'published') {
        $user = current_user();
        if ($user === null || $user['role'] !== 'admin') {
            fail(404, '文章不存在');
        }
    }
    ok(['post' => post_detail($row)]);
}

function handle_post_update(string $key): void
{
    require_admin();
    $row = find_post($key);
    if (!$row) {
        fail(404, '文章不存在');
    }
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }

    $title = array_key_exists('title', $body) ? trim((string) $body['title']) : $row['title'];
    if ($title === '' || str_len($title) > 200) {
        fail(400, '标题长度需为 1-200 字');
    }
    $rawExcerpt = array_key_exists('excerpt', $body) ? trim((string) $body['excerpt']) : (string) $row['excerpt'];
    $excerpt = function_exists('mb_substr') ? mb_substr($rawExcerpt, 0, 400, 'UTF-8') : substr($rawExcerpt, 0, 400);
    $content = array_key_exists('content', $body) ? (string) $body['content'] : (string) $row['content'];
    if (strlen($content) > 60000) {
        fail(400, '正文过长（上限 60000 字符）');
    }
    $status = in_array(($body['status'] ?? ''), POST_STATUSES, true) ? $body['status'] : $row['status'];

    $desiredSlug = array_key_exists('slug', $body) ? (trim((string) $body['slug']) !== '' ? (string) $body['slug'] : $title) : $row['slug'];
    $slug = unique_slug($desiredSlug, (int) $row['id']);

    $publishedAt = $row['published_at'];
    if ($status === 'published' && ($publishedAt === null || $publishedAt === '')) {
        $publishedAt = gmdate('Y-m-d H:i:s');
    }

    db()->prepare(
        'UPDATE posts SET slug = ?, title = ?, excerpt = ?, content = ?, status = ?, published_at = ? WHERE id = ?'
    )->execute([$slug, $title, $excerpt, $content, $status, $publishedAt, (int) $row['id']]);

    $updated = find_post((string) $row['id']);
    ok(['post' => post_detail($updated)], '文章已保存');
}

function handle_post_delete(string $key): void
{
    require_admin();
    $row = find_post($key);
    if (!$row) {
        fail(404, '文章不存在');
    }
    db()->prepare('DELETE FROM posts WHERE id = ?')->execute([(int) $row['id']]);
    ok(['id' => (int) $row['id']], '文章已删除');
}

/* ─────────────────────────── router ─────────────────────────── */

function route(string $path, string $method): void
{
    if ($path === '/api/setup') {
        if ($method === 'GET') {
            handle_setup_status();
        }
        if ($method === 'POST') {
            handle_setup_create();
        }
        fail(405, '方法不允许');
    }

    $routes = [
        '/api/auth/login' => ['POST' => 'handle_login'],
        '/api/auth/logout' => ['POST' => 'handle_logout'],
        '/api/auth/me' => ['GET' => 'handle_me'],

        // Sign-in through an external OAuth 2.0 / OIDC provider (司白画云盘)
        '/api/auth/oauth/config' => ['GET' => 'handle_auth_oauth_config'],
        '/api/auth/oauth/start' => ['GET' => 'handle_auth_oauth_start'],
        '/api/auth/oauth/callback' => ['POST' => 'handle_auth_oauth_callback'],
        '/api/auth/oauth/binding' => ['GET' => 'handle_auth_oauth_binding'],
        '/api/auth/oauth/unbind' => ['POST' => 'handle_auth_oauth_unbind'],
        '/api/auth/change-password' => ['POST' => 'handle_change_password'],
        '/api/auth/profile' => ['POST' => 'handle_update_profile'],
        '/api/posts' => ['GET' => 'handle_posts_index', 'POST' => 'handle_posts_create'],

        // OpenID Connect discovery + JWKS (served from /.well-known/*)
        '/.well-known/openid-configuration' => ['GET' => 'handle_oidc_discovery'],
        '/.well-known/oauth-authorization-server' => ['GET' => 'handle_oidc_oauth_metadata'],
        '/.well-known/jwks.json' => ['GET' => 'handle_oidc_jwks'],

        // OAuth 2.0 / OIDC protocol endpoints
        '/oauth/authorize' => ['GET' => 'handle_oauth_authorize_get', 'POST' => 'handle_oauth_authorize_post'],
        '/api/oauth/token' => ['POST' => 'handle_oauth_token'],
        '/api/oauth/userinfo' => ['GET' => 'handle_oauth_userinfo', 'POST' => 'handle_oauth_userinfo'],
        '/api/oauth/revoke' => ['POST' => 'handle_oauth_revoke'],
        '/api/oauth/introspect' => ['POST' => 'handle_oauth_introspect'],

        // Admin: OAuth client management
        '/api/admin/oauth-clients' => ['GET' => 'handle_admin_clients_index', 'POST' => 'handle_admin_clients_create'],
    ];

    if (isset($routes[$path])) {
        $handlers = $routes[$path];
        if (!isset($handlers[$method])) {
            fail(405, '方法不允许');
        }
        $handlers[$method]();
        return;
    }

    if (preg_match('#^/api/admin/oauth-clients/([^/]+)/(rotate-secret|reveal-secret)$#', $path, $m)) {
        $key = rawurldecode($m[1]);
        if ($method === 'POST' && $m[2] === 'rotate-secret') {
            handle_admin_clients_rotate($key);
        }
        if ($method === 'POST' && $m[2] === 'reveal-secret') {
            handle_admin_clients_reveal($key);
        }
        fail(405, '方法不允许');
    }

    if (preg_match('#^/api/admin/oauth-clients/([^/]+)$#', $path, $m)) {
        $key = rawurldecode($m[1]);
        if ($method === 'PUT') {
            handle_admin_clients_update($key);
        }
        if ($method === 'DELETE') {
            handle_admin_clients_delete($key);
        }
        fail(405, '方法不允许');
    }

    if (preg_match('#^/api/posts/([^/]+)$#', $path, $m)) {
        $key = rawurldecode($m[1]);
        if ($method === 'GET') {
            handle_post_get($key);
        }
        if ($method === 'PUT') {
            handle_post_update($key);
        }
        if ($method === 'DELETE') {
            handle_post_delete($key);
        }
        fail(405, '方法不允许');
    }

    fail(404, '接口不存在：' . $method . ' ' . $path);
}
