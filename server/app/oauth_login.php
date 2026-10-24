<?php
declare(strict_types=1);

/**
 * Sign in to this site with an external OAuth 2.0 / OpenID Connect provider.
 *
 * The site is already an OIDC *provider* (see oidc.php). This file makes it an
 * OIDC *relying party* as well: the admin console signs people in through
 * 司白画云盘 instead of (or in addition to) a local password.
 *
 * Flow
 *   1. GET  /api/auth/oauth/start      -> { authorize_url }   (state + PKCE packed into `state`)
 *   2. browser visits authorize_url, provider redirects to /admin.html?code&state
 *   3. POST /api/auth/oauth/callback   -> exchanges the code, reads userinfo,
 *                                         binds to a local admin, sets the session
 *
 * Who may sign in: the external identity must match a *local* account
 * (by oauth_sub, then email, then username) and that account must be an admin.
 * No unknown identity is ever promoted — see eo_resolve_user().
 */

const EO_STATE_TTL = 600; // seconds a pending login may sit idle

/** Read the external provider block from config.php. */
function eo_config(): array
{
    $block = config()['external_oauth'] ?? null;
    return is_array($block) ? $block : [];
}

/** True only when a provider is fully configured (never leaks the secret). */
function eo_enabled(): bool
{
    $c = eo_config();
    return (bool) ($c['enabled'] ?? false)
        && (string) ($c['client_id'] ?? '') !== ''
        && (string) ($c['authorization_endpoint'] ?? '') !== ''
        && (string) ($c['token_endpoint'] ?? '') !== ''
        && (string) ($c['userinfo_endpoint'] ?? '') !== '';
}

/** Public description of the provider, safe to hand to the browser. */
function eo_public_config(): array
{
    $c = eo_config();
    return [
        'enabled' => eo_enabled(),
        'name' => (string) ($c['name'] ?? '外部账号'),
        'icon' => (string) ($c['icon'] ?? ''),
        'button_label' => (string) ($c['button_label'] ?? ''),
    ];
}

/* ─────────────────────────── state packing ─────────────────────────── */

/**
 * `state` carries the CSRF nonce, the PKCE verifier and the expiry. It is
 * AES-256-GCM encrypted with the same key as the OIDC client secrets, so a
 * third party cannot forge or tamper with it, and nothing is stored server-side.
 */
function eo_pack_state(array $payload): string
{
    $payload['exp'] = time() + EO_STATE_TTL;
    return oidc_encrypt_secret((string) json_encode($payload, JSON_UNESCAPED_UNICODE));
}

function eo_unpack_state(string $state): ?array
{
    if ($state === '' || strlen($state) > 2000) {
        return null;
    }
    $raw = oidc_decrypt_secret($state);
    if ($raw === '') {
        return null;
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || empty($data['nonce']) || empty($data['verifier'])) {
        return null;
    }
    if (empty($data['exp']) || (int) $data['exp'] < time()) {
        return null;
    }
    return $data;
}

/* ─────────────────────────── http to the provider ─────────────────────────── */

/**
 * POST/GET to the provider. Uses curl when available, falls back to PHP
 * streams. Returns [status, decodedBody-or-rawText].
 */
function eo_http(string $method, string $url, array $params = [], array $headers = []): array
{
    $method = strtoupper($method);
    $body = $params ? http_build_query($params, '', '&', PHP_QUERY_RFC3986) : '';

    if ($method === 'GET' && $body !== '') {
        $url .= (str_contains($url, '?') ? '&' : '?') . $body;
        $body = '';
    }

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => array_merge(['Accept: application/json'], $headers),
        ];
        if ($method === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $body;
        } elseif ($method !== 'GET') {
            $opts[CURLOPT_CUSTOMREQUEST] = $method;
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $text = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($text === false) {
            return [0, ['error' => 'network_error', 'error_description' => $err]];
        }
    } else {
        $context = stream_context_create(['http' => [
            'method' => $method,
            'timeout' => 15,
            'ignore_errors' => true,
            'header' => implode("\r\n", array_merge(['Accept: application/json'], $headers)),
            'content' => $body,
        ]]);
        $text = @file_get_contents($url, false, $context);
        $status = 0;
        if (isset($http_response_header[0]) && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }
        if ($text === false) {
            return [0, ['error' => 'network_error', 'error_description' => '无法连接外部登录服务']];
        }
    }

    $json = json_decode($text, true);
    return [$status, is_array($json) ? $json : ['raw' => $text]];
}

function eo_error_message(array $response, string $fallback): string
{
    $description = (string) ($response['error_description'] ?? '');
    $error = (string) ($response['error'] ?? '');
    if ($description !== '') {
        return $description;
    }
    if ($error !== '') {
        return $fallback . '（' . $error . '）';
    }
    if (isset($response['raw'])) {
        return $fallback . '（非 JSON 响应）';
    }
    return $fallback;
}

/* ─────────────────────────── endpoints ─────────────────────────── */

/** GET /api/auth/oauth/start — returns the provider's authorize URL. */
function handle_auth_oauth_start(): void
{
    if (!eo_enabled()) {
        fail(503, '外部登录未启用');
    }
    $c = eo_config();

    $returnTo = (string) ($_GET['redirect'] ?? '');
    // Only same-site relative paths are accepted, never an absolute URL.
    if ($returnTo === '' || !str_starts_with($returnTo, '/') || str_starts_with($returnTo, '//')) {
        $returnTo = '/admin.html';
    }

    $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
    $state = eo_pack_state([
        'nonce' => bin2hex(random_bytes(16)),
        'verifier' => $verifier,
        'return_to' => $returnTo,
    ]);

    $query = [
        'response_type' => 'code',
        'client_id' => (string) $c['client_id'],
        'redirect_uri' => (string) ($c['redirect_uri'] ?? 'https://sibaihua.com/admin.html'),
        'scope' => (string) ($c['scopes'] ?? 'openid profile email'),
        'state' => $state,
    ];
    if (($c['pkce'] ?? true) !== false) {
        $query['code_challenge'] = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $query['code_challenge_method'] = 'S256';
    }

    $separator = str_contains((string) $c['authorization_endpoint'], '?') ? '&' : '?';
    ok([
        'authorize_url' => $c['authorization_endpoint'] . $separator . http_build_query($query, '', '&', PHP_QUERY_RFC3986),
        'state' => $state,
    ]);
}

/**
 * Resolve the external identity to a local account.
 * Order: oauth_sub -> email -> username. Unknown identities are rejected.
 */
function eo_resolve_user(array $info): array
{
    $sub = trim((string) ($info['sub'] ?? ''));
    $email = trim((string) ($info['email'] ?? ''));
    $username = trim((string) ($info['preferred_username'] ?? ($info['username'] ?? ($info['name'] ?? ''))));

    $row = null;
    if ($sub !== '') {
        $stmt = db()->prepare('SELECT * FROM users WHERE oauth_sub = ? LIMIT 1');
        $stmt->execute([$sub]);
        $row = $stmt->fetch() ?: null;
    }
    if ($row === null && $email !== '') {
        $stmt = db()->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $row = $stmt->fetch() ?: null;
    }
    if ($row === null && $username !== '') {
        $stmt = db()->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $row = $stmt->fetch() ?: null;
    }
    if ($row === null) {
        fail(403, '该外部账号尚未绑定本站账号：请先用账号密码登录，并在「账户」里填写与该账号一致的邮箱。');
    }
    if (($row['status'] ?? 'active') !== 'active') {
        fail(403, '该账号已被停用。');
    }
    if (($row['role'] ?? '') !== 'admin') {
        fail(403, '该账号没有后台权限。');
    }
    return ['row' => $row, 'sub' => $sub, 'email' => $email, 'username' => $username];
}

/** POST /api/auth/oauth/callback — finish the login, set the session cookie. */
function handle_auth_oauth_callback(): void
{
    if (!eo_enabled()) {
        fail(503, '外部登录未启用');
    }
    $c = eo_config();
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }
    $error = (string) ($body['error'] ?? '');
    if ($error !== '') {
        fail(400, '外部登录被拒绝：' . $error);
    }

    $code = (string) ($body['code'] ?? '');
    $state = (string) ($body['state'] ?? '');
    if ($code === '' || $state === '') {
        fail(400, '缺少 code 或 state');
    }
    $packed = eo_unpack_state($state);
    if ($packed === null) {
        fail(400, '登录请求已过期或被篡改，请重新登录。');
    }

    $redirectUri = (string) ($c['redirect_uri'] ?? 'https://sibaihua.com/admin.html');
    $params = [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $redirectUri,
        'client_id' => (string) $c['client_id'],
    ];
    $secret = (string) ($c['client_secret'] ?? '');
    if ($secret !== '') {
        $params['client_secret'] = $secret;
    }
    if (!empty($packed['verifier']) && ($c['pkce'] ?? true) !== false) {
        $params['code_verifier'] = (string) $packed['verifier'];
    }

    [$status, $token] = eo_http('POST', (string) $c['token_endpoint'], $params);
    if ($status < 200 || $status >= 300 || empty($token['access_token'])) {
        fail(400, eo_error_message($token, '换取令牌失败'));
    }

    [$ustatus, $info] = eo_http('GET', (string) $c['userinfo_endpoint'], [], ['Authorization: Bearer ' . $token['access_token']]);
    if ($ustatus < 200 || $ustatus >= 300 || empty($info['sub'])) {
        fail(400, eo_error_message($info, '读取外部账号信息失败'));
    }

    $resolved = eo_resolve_user($info);
    $row = $resolved['row'];
    $userId = (int) $row['id'];

    // Remember the stable subject so later logins keep working even if the
    // e-mail or nickname at the provider changes.
    if ($resolved['sub'] !== '' && (string) ($row['oauth_sub'] ?? '') === '') {
        db()->prepare('UPDATE users SET oauth_sub = ? WHERE id = ?')->execute([$resolved['sub'], $userId]);
    }

    $sessionToken = create_session($userId);
    set_session_cookie($sessionToken);

    ok([
        'user' => [
            'id' => $userId,
            'username' => (string) $row['username'],
            'role' => (string) $row['role'],
            'email' => (string) ($row['email'] ?? ''),
            'external' => [
                'provider' => (string) ($c['name'] ?? ''),
                'sub' => $resolved['sub'],
                'name' => (string) ($info['name'] ?? ''),
                'picture' => (string) ($info['picture'] ?? ''),
            ],
        ],
        'return_to' => (string) ($packed['return_to'] ?? '/admin.html'),
    ], '登录成功');
}

/** GET /api/auth/oauth/config — tells the login screen whether to offer OAuth. */
function handle_auth_oauth_config(): void
{
    ok(eo_public_config());
}
