<?php
declare(strict_types=1);

/**
 * Sibaihua University — official website backend (PHP 8 + MySQL).
 * Zero dependencies: PDO only, no Composer packages.
 *
 * JSON envelope matches the static front-end: { code, message, data }.
 */

/* ─────────────────────────── config / db ─────────────────────────── */

function config(): array
{
    static $config = null;
    if ($config === null) {
        $file = __DIR__ . '/config.php';
        if (!is_file($file)) {
            throw new RuntimeException('缺少配置文件 app/config.php');
        }
        $config = require $file;
    }
    return $config;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $c = config()['db'];
    $socket = (string) ($c['socket'] ?? '');
    if ($socket !== '' && is_file($socket)) {
        $dsn = sprintf('mysql:unix_socket=%s;dbname=%s;charset=utf8mb4', $socket, $c['name']);
    } else {
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $c['host'], $c['port'], $c['name']);
    }
    $pdo = new PDO($dsn, $c['user'], $c['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    // Every timestamp is stored and read in UTC so browsers can parse it as ISO-8601.
    $pdo->exec("SET time_zone = '+00:00'");
    return $pdo;
}

/* ─────────────────────────── http helpers ─────────────────────────── */

function json_response(int $status, array $payload, array $headers = []): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value, false);
    }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function ok($data = null, string $message = 'ok'): void
{
    json_response(200, ['code' => 200, 'message' => $message, 'data' => $data]);
}

function fail(int $status, string $message): void
{
    json_response($status, ['code' => $status, 'message' => $message, 'data' => null]);
}

function read_json(): ?array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return null;
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

/* ─────────────────────────── cookies / sessions ─────────────────────────── */

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
        return true;
    }
    return false;
}

/**
 * Over HTTPS the session cookie uses the __Host- prefix. Browsers refuse any
 * same-named cookie that carries a Domain attribute, so a compromised subdomain
 * cannot plant or overwrite this session.
 */
function session_cookie_names(): array
{
    return ['__Host-sib_session', 'sib_session'];
}

function set_session_cookie(string $token, int $maxAge = SESSION_TTL): void
{
    $secure = is_https();
    $name = $secure ? '__Host-sib_session' : 'sib_session';
    setcookie($name, $token, [
        'expires' => time() + $maxAge,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function clear_session_cookie(): void
{
    $secure = is_https();
    foreach (session_cookie_names() as $name) {
        setcookie($name, '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}

function read_session_token(): ?string
{
    foreach (session_cookie_names() as $name) {
        if (!empty($_COOKIE[$name])) {
            return (string) $_COOKIE[$name];
        }
    }
    return null;
}

const SESSION_TTL = 604800; // 7 days

function create_session(int $userId): string
{
    $token = bin2hex(random_bytes(32));
    db()->prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
        ->execute([$token, $userId, time() + SESSION_TTL]);
    return $token;
}

function current_user(): ?array
{
    static $resolved = false;
    static $user = null;
    if ($resolved) {
        return $user;
    }
    $resolved = true;

    $token = read_session_token();
    if ($token === null) {
        return null;
    }
    $stmt = db()->prepare(
        'SELECT u.id, u.username, u.role, u.status, s.expires_at
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token = ? LIMIT 1'
    );
    $stmt->execute([$token]);
    $row = $stmt->fetch();
    if (!$row) {
        return null;
    }
    if ((int) $row['expires_at'] <= time()) {
        db()->prepare('DELETE FROM sessions WHERE token = ?')->execute([$token]);
        return null;
    }
    if ($row['status'] !== 'active') {
        return null;
    }
    $user = ['id' => (int) $row['id'], 'username' => $row['username'], 'role' => $row['role']];
    return $user;
}

function require_login(): array
{
    $user = current_user();
    if ($user === null) {
        fail(401, '未登录');
    }
    return $user;
}

function require_admin(): array
{
    $user = require_login();
    if ($user['role'] !== 'admin') {
        fail(403, '需要管理员权限');
    }
    return $user;
}

/* ─────────────────────────── dates / slugs ─────────────────────────── */

function iso_date(?string $mysqlDate): ?string
{
    if ($mysqlDate === null || $mysqlDate === '') {
        return null;
    }
    return str_replace(' ', 'T', $mysqlDate) . 'Z';
}

function str_len(string $value): int
{
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function slugify(string $input): string
{
    $s = strtolower(trim($input));
    $s = preg_replace('/[^a-z0-9\x{4e00}-\x{9fa5}]+/u', '-', $s) ?? '';
    $s = trim($s, '-');
    $s = function_exists('mb_substr') ? mb_substr($s, 0, 80, 'UTF-8') : substr($s, 0, 80);
    return $s !== '' ? $s : 'post';
}

function unique_slug(string $desired, ?int $excludeId = null): string
{
    $base = slugify($desired);
    $candidate = $base;
    $n = 1;
    $stmt = db()->prepare('SELECT id FROM posts WHERE slug = ? LIMIT 1');
    for (;;) {
        $stmt->execute([$candidate]);
        $row = $stmt->fetch();
        if (!$row) {
            return $candidate;
        }
        if ($excludeId !== null && (int) $row['id'] === $excludeId) {
            return $candidate;
        }
        $n++;
        $candidate = $base . '-' . $n;
    }
}

/* ─────────────────────────── markdown (safe) ─────────────────────────── */

function md_escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function md_inline(string $escaped): string
{
    $out = preg_replace_callback('/\[([^\]]+)\]\(([^)\s]+)\)/', static function (array $m): string {
        $label = $m[1];
        $href = $m[2];
        $safe = '#';
        $external = false;
        if (preg_match('~^https?://~i', $href)) {
            $safe = $href;
            $external = true;
        } elseif (preg_match('~^mailto:~i', $href)) {
            $safe = $href;
        } elseif ($href !== '' && ($href[0] === '/' || strpos($href, 'news.html') === 0 || strpos($href, 'index.html') === 0)) {
            $safe = $href;
        }
        $attrs = $external ? ' target="_blank" rel="noopener noreferrer"' : '';
        return '<a href="' . $safe . '"' . $attrs . '>' . $label . '</a>';
    }, $escaped) ?? $escaped;

    $out = preg_replace('/\*\*([^*\n]+)\*\*/', '<strong>$1</strong>', $out) ?? $out;
    $out = preg_replace('/(^|[^*\w])\*([^*\n]+)\*/', '$1<em>$2</em>', $out) ?? $out;
    $out = preg_replace('/`([^`\n]+)`/', '<code>$1</code>', $out) ?? $out;
    return $out;
}

function render_markdown(string $source): string
{
    $source = str_replace(["\r\n", "\r"], "\n", $source);
    $lines = explode("\n", $source);
    $html = [];
    $para = [];
    $list = null;

    $flushPara = static function () use (&$para, &$html): void {
        if ($para !== []) {
            $html[] = '<p>' . implode('<br>', $para) . '</p>';
            $para = [];
        }
    };
    $flushList = static function () use (&$list, &$html): void {
        if ($list !== null) {
            $items = '';
            foreach ($list['items'] as $item) {
                $items .= '<li>' . $item . '</li>';
            }
            $html[] = '<' . $list['type'] . '>' . $items . '</' . $list['type'] . '>';
            $list = null;
        }
    };

    foreach ($lines as $rawLine) {
        $line = rtrim($rawLine);

        if (trim($line) === '') {
            $flushPara();
            $flushList();
            continue;
        }
        if (preg_match('/^-{3,}$/', trim($line))) {
            $flushPara();
            $flushList();
            $html[] = '<hr>';
            continue;
        }
        if (preg_match('/^(#{1,4})\s+(.*)$/', $line, $m)) {
            $flushPara();
            $flushList();
            $level = min(strlen($m[1]) + 1, 4);
            $html[] = "<h{$level}>" . md_inline(md_escape($m[2])) . "</h{$level}>";
            continue;
        }
        if (preg_match('/^>\s?(.*)$/', $line, $m)) {
            $flushPara();
            $flushList();
            $html[] = '<blockquote>' . md_inline(md_escape($m[1])) . '</blockquote>';
            continue;
        }
        if (preg_match('/^\s*[-*+]\s+(.*)$/', $line, $m)) {
            $flushPara();
            if ($list === null || $list['type'] !== 'ul') {
                $flushList();
                $list = ['type' => 'ul', 'items' => []];
            }
            $list['items'][] = md_inline(md_escape($m[1]));
            continue;
        }
        if (preg_match('/^\s*\d+[.)]\s+(.*)$/', $line, $m)) {
            $flushPara();
            if ($list === null || $list['type'] !== 'ol') {
                $flushList();
                $list = ['type' => 'ol', 'items' => []];
            }
            $list['items'][] = md_inline(md_escape($m[1]));
            continue;
        }
        $flushList();
        $para[] = md_inline(md_escape($line));
    }

    $flushPara();
    $flushList();
    return implode("\n", $html);
}

/* ─────────────────────────── posts shaping ─────────────────────────── */

function post_summary(array $row): array
{
    return [
        'id' => (int) $row['id'],
        'slug' => $row['slug'],
        'title' => $row['title'],
        'excerpt' => (string) $row['excerpt'],
        'status' => $row['status'],
        'published_at' => iso_date($row['published_at']),
        'created_at' => iso_date($row['created_at']),
        'updated_at' => iso_date($row['updated_at']),
    ];
}

function post_detail(array $row): array
{
    $detail = post_summary($row);
    $detail['content'] = (string) $row['content'];
    $detail['content_html'] = render_markdown((string) $row['content']);
    return $detail;
}

const POST_STATUSES = ['draft', 'published'];
const USERNAME_PATTERN = '/^[A-Za-z0-9._-]{3,32}$/';
