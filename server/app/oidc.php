<?php
declare(strict_types=1);

/**
 * OAuth 2.0 + OpenID Connect provider.
 *
 * This site is the identity provider: third-party applications register a client
 * (admin console → Applications) and then send members to /oauth/authorize.
 *
 * Supported: authorization code + PKCE (S256), refresh token, RS256 ID tokens,
 * discovery document, JWKS, userinfo, and RFC 7009 revocation.
 */

const OIDC_SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];
const OIDC_CODE_TTL = 300;        // authorization code: 5 minutes
const OIDC_ACCESS_TTL = 3600;     // access token: 1 hour
const OIDC_REFRESH_TTL = 2592000; // refresh token: 30 days

/* ─────────────────────────── helpers ─────────────────────────── */

function b64url(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function oidc_issuer(): string
{
    $c = config();
    if (!empty($c['oidc']['issuer'])) {
        return rtrim((string) $c['oidc']['issuer'], '/');
    }
    $scheme = is_https() ? 'https' : 'http';
    return $scheme . '://' . (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
}

function oidc_key_path(): string
{
    $c = config();
    if (!empty($c['oidc']['key_path'])) {
        return (string) $c['oidc']['key_path'];
    }
    return __DIR__ . '/oidc-key.pem';
}

/** Loads the RS256 signing key. Throws a readable error when it is missing. */
function oidc_key()
{
    static $key = null;
    if ($key !== null) {
        return $key;
    }
    $path = oidc_key_path();
    if (!is_file($path)) {
        throw new RuntimeException('缺少 OIDC 签名私钥：' . $path . '（用 openssl 生成，见 README）');
    }
    $pem = (string) file_get_contents($path);
    $key = openssl_pkey_get_private($pem);
    if ($key === false) {
        throw new RuntimeException('OIDC 私钥无法解析：' . $path);
    }
    return $key;
}

/** Public half of the signing key, as a JWK set entry. */
function oidc_public_jwk(): array
{
    static $jwk = null;
    if ($jwk !== null) {
        return $jwk;
    }
    $details = openssl_pkey_get_details(oidc_key());
    if (!isset($details['rsa'])) {
        throw new RuntimeException('OIDC 私钥不是 RSA 密钥');
    }
    $n = b64url($details['rsa']['n']);
    $e = b64url($details['rsa']['e']);
    $jwk = [
        'kty' => 'RSA',
        'use' => 'sig',
        'alg' => 'RS256',
        'kid' => b64url(hash('sha256', 'RSA|' . $n . '|' . $e, true)),
        'n' => $n,
        'e' => $e,
    ];
    return $jwk;
}

function oidc_sign_jwt(array $claims): string
{
    $jwk = oidc_public_jwk();
    $header = ['typ' => 'JWT', 'alg' => 'RS256', 'kid' => $jwk['kid']];
    $signingInput = b64url(json_encode($header, JSON_UNESCAPED_SLASHES))
        . '.' . b64url(json_encode($claims, JSON_UNESCAPED_SLASHES));
    $signature = '';
    if (!openssl_sign($signingInput, $signature, oidc_key(), OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('ID token 签名失败');
    }
    return $signingInput . '.' . b64url($signature);
}

/** Reads request parameters from a JSON body or a classic form post. */
function oidc_params(): array
{
    $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    if (strpos($contentType, 'application/json') !== false) {
        $json = read_json();
        return is_array($json) ? $json : [];
    }
    return $_POST ?: [];
}

function oidc_error(int $status, string $error, string $description): void
{
    json_response($status, ['error' => $error, 'error_description' => $description]);
}

function oidc_find_client(string $clientId): ?array
{
    $stmt = db()->prepare('SELECT * FROM oauth_clients WHERE client_id = ? AND status = ? LIMIT 1');
    $stmt->execute([$clientId, 'active']);
    $row = $stmt->fetch();
    return $row ?: null;
}

function oidc_client_redirect_uris(array $client): array
{
    $uris = preg_split('/\r\n|\r|\n/', (string) $client['redirect_uris']) ?: [];
    return array_values(array_filter(array_map('trim', $uris), static fn ($u) => $u !== ''));
}

/**
 * Resolves the calling client for token / revocation requests.
 * Supports client_secret_basic and client_secret_post; public clients send only client_id.
 */
function oidc_authenticate_client(array $params): ?array
{
    $clientId = '';
    $clientSecret = '';

    $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (stripos($header, 'basic ') === 0) {
        $decoded = base64_decode(substr($header, 6), true);
        if ($decoded !== false && strpos($decoded, ':') !== false) {
            [$clientId, $clientSecret] = explode(':', $decoded, 2);
            $clientId = rawurldecode($clientId);
            $clientSecret = rawurldecode($clientSecret);
        }
    }
    if ($clientId === '') {
        $clientId = (string) ($params['client_id'] ?? '');
        $clientSecret = (string) ($params['client_secret'] ?? '');
    }
    if ($clientId === '') {
        return null;
    }

    $client = oidc_find_client($clientId);
    if (!$client) {
        return null;
    }
    if ((int) $client['is_confidential'] === 1) {
        if ($clientSecret === '' || !password_verify($clientSecret, (string) $client['client_secret_hash'])) {
            return null;
        }
    }
    return $client;
}

function oidc_scope_string($raw): string
{
    $parts = preg_split('/\s+/', trim((string) $raw)) ?: [];
    $parts = array_values(array_unique(array_filter($parts, static fn ($s) => $s !== '')));
    return implode(' ', $parts);
}

function oidc_scope_allowed(array $client, string $scope): bool
{
    $allowed = preg_split('/\s+/', trim((string) $client['scopes'])) ?: [];
    foreach (preg_split('/\s+/', $scope) ?: [] as $s) {
        if ($s === '') {
            continue;
        }
        if (!in_array($s, $allowed, true) || !in_array($s, OIDC_SUPPORTED_SCOPES, true)) {
            return false;
        }
    }
    return true;
}

/* ─────────────────────────── discovery / JWKS ─────────────────────────── */

function handle_oidc_discovery(): void
{
    $issuer = oidc_issuer();
    json_response(200, [
        'issuer' => $issuer,
        'authorization_endpoint' => $issuer . '/oauth/authorize',
        'token_endpoint' => $issuer . '/api/oauth/token',
        'userinfo_endpoint' => $issuer . '/api/oauth/userinfo',
        'jwks_uri' => $issuer . '/.well-known/jwks.json',
        'revocation_endpoint' => $issuer . '/api/oauth/revoke',
        'response_types_supported' => ['code'],
        'grant_types_supported' => ['authorization_code', 'refresh_token'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'scopes_supported' => OIDC_SUPPORTED_SCOPES,
        'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        'code_challenge_methods_supported' => ['S256'],
        'claims_supported' => [
            'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
            'name', 'preferred_username', 'email', 'email_verified',
        ],
    ]);
}

function handle_oidc_jwks(): void
{
    $jwk = oidc_public_jwk();
    json_response(200, ['keys' => [$jwk]], ['Cache-Control' => 'public, max-age=3600']);
}

/* ─────────────────────────── authorize (consent page) ─────────────────────────── */

function oidc_page(string $title, string $bodyHtml): void
{
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{$safeTitle} — Sibaihua University</title>
<link rel="icon" href="https://cdn.sibh.cn/img/2026/08/6a82000f8ce84.png">
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;
       background:#f8fafc;color:#1e293b;
       font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
       -webkit-font-smoothing:antialiased;line-height:1.65}
  .card{width:100%;max-width:26rem;background:#fff;border:1px solid #e2e8f0;border-radius:1rem;
        padding:1.9rem;box-shadow:0 10px 30px -16px rgba(15,23,42,.28)}
  .crest{width:2.6rem;height:2.6rem;border-radius:9999px;border:1px solid #e2e8f0;padding:3px;
         object-fit:contain;margin-bottom:1rem}
  h1{margin:0;font-size:1.1rem;font-weight:650;color:#1e3a5f;letter-spacing:-.015em}
  .lede{margin:.4rem 0 0;font-size:.78rem;color:#64748b}
  .app{margin:1.25rem 0 0;padding:.8rem .9rem;background:#f8fafc;border:1px solid #e2e8f0;border-radius:.6rem}
  .app-name{font-size:.9rem;font-weight:650;color:#1e3a5f;word-break:break-word}
  .app-host{font-size:.7rem;color:#94a3b8;margin-top:.15rem;word-break:break-all}
  .scopes{margin:.9rem 0 0;padding:0;list-style:none;font-size:.78rem;color:#475569}
  .scopes li{padding:.3rem 0 .3rem 1.2rem;position:relative}
  .scopes li::before{content:"✓";position:absolute;left:0;color:#067647;font-weight:700}
  .me{margin:.9rem 0 0;font-size:.75rem;color:#64748b}
  .me strong{color:#1e3a5f}
  .row{display:flex;gap:.5rem;margin-top:1.35rem}
  button{font:inherit;cursor:pointer;border:0;border-radius:9999px;padding:.7rem 1rem;font-size:.85rem;font-weight:600;flex:1}
  .allow{background:#1e3a5f;color:#fff}
  .allow:hover{background:#142740}
  .deny{background:#fff;color:#475569;border:1px solid #e2e8f0}
  .deny:hover{background:#f1f5f9}
  label{display:block;margin:.9rem 0 .35rem;font-size:.75rem;font-weight:550;color:#475569}
  input{width:100%;padding:.62rem .75rem;font:inherit;font-size:.85rem;background:#f8fafc;
        border:1px solid #e2e8f0;border-radius:.6rem;outline:none}
  input:focus{background:#fff;border-color:#1e3a5f;box-shadow:0 0 0 3px rgba(30,58,95,.12)}
  .err{margin-top:.9rem;padding:.55rem .7rem;font-size:.75rem;border-radius:.5rem;
       color:#b42318;background:#fef3f2;border:1px solid #fecdca}
  .foot{margin:1.1rem 0 0;font-size:.68rem;color:#94a3b8;text-align:center}
  button[disabled]{opacity:.6;cursor:not-allowed}
</style>
</head>
<body>
<div class="card">
<img class="crest" src="https://cdn.sibh.cn/img/2026/08/6a82000f8ce84.png" alt="Sibaihua University">
{$bodyHtml}
</div>
</body>
</html>
HTML;
    exit;
}

function oidc_page_error(string $message): void
{
    oidc_page('Authorization error',
        '<h1>无法继续授权</h1><p class="lede">Authorization could not continue.</p>'
        . '<div class="err">' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</div>'
        . '<p class="foot">返回 <a href="/">sibaihua.com</a></p>');
}

function oidc_scope_labels(string $scope): string
{
    $map = [
        'openid' => 'Confirm your identity (a stable member identifier)',
        'profile' => 'Read your display name and username',
        'email' => 'Read your email address',
        'offline_access' => 'Stay signed in to this application (refresh token)',
    ];
    $items = '';
    foreach (preg_split('/\s+/', $scope) ?: [] as $s) {
        if (isset($map[$s])) {
            $items .= '<li>' . htmlspecialchars($map[$s], ENT_QUOTES, 'UTF-8') . '</li>';
        }
    }
    return $items;
}

function handle_oauth_authorize_get(): void
{
    $p = $_GET;
    $clientId = trim((string) ($p['client_id'] ?? ''));
    $redirectUri = trim((string) ($p['redirect_uri'] ?? ''));
    $responseType = trim((string) ($p['response_type'] ?? ''));
    $scope = oidc_scope_string($p['scope'] ?? 'openid');
    $state = (string) ($p['state'] ?? '');
    $nonce = (string) ($p['nonce'] ?? '');
    $codeChallenge = (string) ($p['code_challenge'] ?? '');
    $codeChallengeMethod = (string) ($p['code_challenge_method'] ?? '');

    $client = $clientId !== '' ? oidc_find_client($clientId) : null;
    if (!$client) {
        oidc_page_error('未知或已停用的应用（client_id 无效）。');
        return;
    }
    if ($redirectUri === '' || !in_array($redirectUri, oidc_client_redirect_uris($client), true)) {
        oidc_page_error('redirect_uri 与应用登记的回调地址不匹配。');
        return;
    }
    if ($responseType !== 'code') {
        oidc_redirect_error($redirectUri, 'unsupported_response_type', '仅支持 response_type=code', $state);
        return;
    }
    if (!oidc_scope_allowed($client, $scope)) {
        oidc_redirect_error($redirectUri, 'invalid_scope', '请求的 scope 不被该应用允许', $state);
        return;
    }
    if ($codeChallenge !== '' && strtoupper($codeChallengeMethod) !== 'S256') {
        oidc_redirect_error($redirectUri, 'invalid_request', '仅支持 code_challenge_method=S256', $state);
        return;
    }
    if ($codeChallenge === '' && (int) $client['is_confidential'] !== 1) {
        oidc_redirect_error($redirectUri, 'invalid_request', '公共客户端必须使用 PKCE', $state);
        return;
    }

    $user = current_user();
    $clientName = htmlspecialchars((string) $client['name'], ENT_QUOTES, 'UTF-8');
    $host = htmlspecialchars((string) parse_url($redirectUri, PHP_URL_HOST), ENT_QUOTES, 'UTF-8');

    if ($user === null) {
        // Not signed in yet: show a sign-in form that keeps the whole OAuth request intact.
        $selfUrl = '/oauth/authorize?' . http_build_query([
            'response_type' => $responseType,
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $scope,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => $codeChallengeMethod,
        ]);
        oidc_page('Sign in',
            '<h1>登录以继续</h1>'
            . '<p class="lede"><strong>' . $clientName . '</strong> 请求使用你的 Sibaihua 账号登录。</p>'
            . '<form id="f">'
            . '<label for="u">用户名</label><input id="u" autocomplete="username" required>'
            . '<label for="pw">密码</label><input id="pw" type="password" autocomplete="current-password" required>'
            . '<div id="e" class="err" style="display:none"></div>'
            . '<button class="allow" style="width:100%;margin-top:1.2rem" id="s" type="submit">登录并继续</button>'
            . '</form>'
            . '<p class="foot">登录后会被带回本页完成授权。</p>'
            . '<script>'
            . 'var f=document.getElementById("f"),e=document.getElementById("e"),s=document.getElementById("s");'
            . 'f.addEventListener("submit",function(ev){ev.preventDefault();e.style.display="none";s.disabled=true;'
            . 'fetch("/api/auth/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},'
            . 'body:JSON.stringify({username:document.getElementById("u").value.trim(),password:document.getElementById("pw").value})})'
            . '.then(function(r){return r.json().then(function(j){return {ok:r.ok&&j.code===200,msg:j.message}})})'
            . '.then(function(res){if(res.ok){location.replace(' . json_encode($selfUrl) . ')}'
            . 'else{e.textContent=res.msg||"登录失败";e.style.display="block";s.disabled=false}})'
            . '.catch(function(){e.textContent="网络错误，请重试";e.style.display="block";s.disabled=false})});'
            . '</script>');
        return;
    }

    $fields = '';
    foreach ([
        'response_type' => $responseType,
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'scope' => $scope,
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => $codeChallengeMethod,
    ] as $name => $value) {
        $fields .= '<input type="hidden" name="' . $name . '" value="' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '">';
    }

    $userName = htmlspecialchars((string) $user['username'], ENT_QUOTES, 'UTF-8');

    oidc_page('Authorize',
        '<h1>授权登录</h1>'
        . '<p class="lede">An application is asking to use your Sibaihua University account.</p>'
        . '<div class="app"><div class="app-name">' . $clientName . '</div>'
        . '<div class="app-host">' . $host . '</div></div>'
        . '<ul class="scopes">' . oidc_scope_labels($scope) . '</ul>'
        . '<p class="me">当前账号：<strong>' . $userName . '</strong></p>'
        . '<form method="post" action="/oauth/authorize">' . $fields
        . '<div class="row">'
        . '<button class="deny" type="submit" name="decision" value="deny">拒绝</button>'
        . '<button class="allow" type="submit" name="decision" value="allow">允许</button>'
        . '</div></form>'
        . '<p class="foot">允许后你会被带回 ' . $host . '，本页不会分享你的密码。</p>');
}

function oidc_redirect_error(string $redirectUri, string $error, string $description, string $state): void
{
    $query = ['error' => $error, 'error_description' => $description];
    if ($state !== '') {
        $query['state'] = $state;
    }
    $sep = strpos($redirectUri, '?') === false ? '?' : '&';
    header('Location: ' . $redirectUri . $sep . http_build_query($query), true, 302);
    exit;
}

function handle_oauth_authorize_post(): void
{
    $p = $_POST ?: [];
    $clientId = trim((string) ($p['client_id'] ?? ''));
    $redirectUri = trim((string) ($p['redirect_uri'] ?? ''));
    $scope = oidc_scope_string($p['scope'] ?? 'openid');
    $state = (string) ($p['state'] ?? '');
    $nonce = (string) ($p['nonce'] ?? '');
    $codeChallenge = (string) ($p['code_challenge'] ?? '');
    $codeChallengeMethod = (string) ($p['code_challenge_method'] ?? '');
    $decision = (string) ($p['decision'] ?? '');

    $client = $clientId !== '' ? oidc_find_client($clientId) : null;
    if (!$client) {
        oidc_page_error('未知或已停用的应用（client_id 无效）。');
        return;
    }
    if ($redirectUri === '' || !in_array($redirectUri, oidc_client_redirect_uris($client), true)) {
        oidc_page_error('redirect_uri 与应用登记的回调地址不匹配。');
        return;
    }

    // SameSite=Lax keeps this cookie off cross-site POSTs, so a third party cannot
    // auto-approve on the member's behalf.
    $user = current_user();
    if ($user === null) {
        oidc_redirect_error($redirectUri, 'login_required', '请先登录', $state);
        return;
    }
    if ($decision !== 'allow') {
        oidc_redirect_error($redirectUri, 'access_denied', '用户拒绝了授权', $state);
        return;
    }
    if (!oidc_scope_allowed($client, $scope)) {
        oidc_redirect_error($redirectUri, 'invalid_scope', '请求的 scope 不被该应用允许', $state);
        return;
    }

    $code = bin2hex(random_bytes(32));
    db()->prepare(
        'INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )->execute([
        $code, $clientId, $user['id'], $redirectUri, $scope, $nonce,
        $codeChallenge, strtoupper($codeChallengeMethod), time() + OIDC_CODE_TTL,
    ]);

    $query = ['code' => $code];
    if ($state !== '') {
        $query['state'] = $state;
    }
    $sep = strpos($redirectUri, '?') === false ? '?' : '&';
    header('Location: ' . $redirectUri . $sep . http_build_query($query), true, 302);
    exit;
}

/* ─────────────────────────── token ─────────────────────────── */

function oidc_user_row(int $userId): ?array
{
    $stmt = db()->prepare('SELECT id, username, role, status, email FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function oidc_id_token(array $user, string $clientId, string $scope, string $nonce): string
{
    $now = time();
    $claims = [
        'iss' => oidc_issuer(),
        'sub' => (string) $user['id'],
        'aud' => $clientId,
        'iat' => $now,
        'exp' => $now + OIDC_ACCESS_TTL,
        'auth_time' => $now,
    ];
    if ($nonce !== '') {
        $claims['nonce'] = $nonce;
    }
    $scopes = preg_split('/\s+/', $scope) ?: [];
    if (in_array('profile', $scopes, true)) {
        $claims['name'] = (string) $user['username'];
        $claims['preferred_username'] = (string) $user['username'];
    }
    if (in_array('email', $scopes, true) && (string) $user['email'] !== '') {
        $claims['email'] = (string) $user['email'];
        $claims['email_verified'] = true;
    }
    return oidc_sign_jwt($claims);
}

function oidc_issue_tokens(array $client, int $userId, string $scope, string $nonce): array
{
    $user = oidc_user_row($userId);
    if (!$user) {
        oidc_error(400, 'invalid_grant', '用户不存在');
    }
    $scopes = preg_split('/\s+/', $scope) ?: [];
    $withRefresh = in_array('offline_access', $scopes, true);

    $accessToken = bin2hex(random_bytes(32));
    $refreshToken = $withRefresh ? bin2hex(random_bytes(32)) : null;
    $now = time();

    db()->prepare(
        'INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at, refresh_expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)'
    )->execute([
        $accessToken,
        $refreshToken,
        (string) $client['client_id'],
        $userId,
        $scope,
        $now + OIDC_ACCESS_TTL,
        $withRefresh ? $now + OIDC_REFRESH_TTL : null,
    ]);

    $response = [
        'access_token' => $accessToken,
        'token_type' => 'Bearer',
        'expires_in' => OIDC_ACCESS_TTL,
        'scope' => $scope,
    ];
    if ($refreshToken !== null) {
        $response['refresh_token'] = $refreshToken;
    }
    if (in_array('openid', $scopes, true)) {
        $response['id_token'] = oidc_id_token($user, (string) $client['client_id'], $scope, $nonce);
    }
    return $response;
}

function handle_oauth_token(): void
{
    $params = oidc_params();
    $client = oidc_authenticate_client($params);
    if ($client === null) {
        oidc_error(401, 'invalid_client', '客户端认证失败');
    }

    $grantType = (string) ($params['grant_type'] ?? '');

    if ($grantType === 'authorization_code') {
        $code = (string) ($params['code'] ?? '');
        $redirectUri = (string) ($params['redirect_uri'] ?? '');
        $codeVerifier = (string) ($params['code_verifier'] ?? '');
        if ($code === '') {
            oidc_error(400, 'invalid_request', '缺少 code');
        }

        $stmt = db()->prepare('SELECT * FROM oauth_codes WHERE code = ? LIMIT 1');
        $stmt->execute([$code]);
        $row = $stmt->fetch();
        if (!$row || (int) $row['used'] === 1 || (int) $row['expires_at'] <= time()) {
            oidc_error(400, 'invalid_grant', '授权码无效或已过期');
        }
        if ((string) $row['client_id'] !== (string) $client['client_id']) {
            oidc_error(400, 'invalid_grant', '授权码不属于该客户端');
        }
        if ($redirectUri !== '' && $redirectUri !== (string) $row['redirect_uri']) {
            oidc_error(400, 'invalid_grant', 'redirect_uri 与授权时不一致');
        }

        $challenge = (string) $row['code_challenge'];
        if ($challenge !== '') {
            if ($codeVerifier === '') {
                oidc_error(400, 'invalid_grant', '缺少 code_verifier');
            }
            $computed = b64url(hash('sha256', $codeVerifier, true));
            if (!hash_equals($challenge, $computed)) {
                oidc_error(400, 'invalid_grant', 'code_verifier 校验失败');
            }
        } elseif ((int) $client['is_confidential'] !== 1) {
            oidc_error(400, 'invalid_grant', '公共客户端必须使用 PKCE');
        }

        db()->prepare('UPDATE oauth_codes SET used = 1 WHERE code = ?')->execute([$code]);

        json_response(200, oidc_issue_tokens(
            $client,
            (int) $row['user_id'],
            (string) $row['scope'],
            (string) $row['nonce']
        ));
    }

    if ($grantType === 'refresh_token') {
        $refresh = (string) ($params['refresh_token'] ?? '');
        if ($refresh === '') {
            oidc_error(400, 'invalid_request', '缺少 refresh_token');
        }
        $stmt = db()->prepare('SELECT * FROM oauth_tokens WHERE refresh_token = ? LIMIT 1');
        $stmt->execute([$refresh]);
        $row = $stmt->fetch();
        if (!$row || (int) $row['revoked'] === 1) {
            oidc_error(400, 'invalid_grant', 'refresh_token 无效');
        }
        if ($row['refresh_expires_at'] !== null && (int) $row['refresh_expires_at'] <= time()) {
            oidc_error(400, 'invalid_grant', 'refresh_token 已过期');
        }
        if ((string) $row['client_id'] !== (string) $client['client_id']) {
            oidc_error(400, 'invalid_grant', 'refresh_token 不属于该客户端');
        }

        // Rotate: the old pair is revoked as soon as a new one is issued.
        db()->prepare('UPDATE oauth_tokens SET revoked = 1 WHERE access_token = ?')->execute([(string) $row['access_token']]);

        $scope = oidc_scope_string($params['scope'] ?? $row['scope']);
        if (!oidc_scope_allowed($client, $scope)) {
            oidc_error(400, 'invalid_scope', '请求的 scope 不被允许');
        }
        json_response(200, oidc_issue_tokens($client, (int) $row['user_id'], $scope, ''));
    }

    oidc_error(400, 'unsupported_grant_type', '不支持的 grant_type');
}

/* ─────────────────────────── userinfo / revoke ─────────────────────────── */

function oidc_bearer_token(): string
{
    $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (stripos($header, 'bearer ') === 0) {
        return trim(substr($header, 7));
    }
    return '';
}

function handle_oauth_userinfo(): void
{
    $token = oidc_bearer_token();
    if ($token === '') {
        header('WWW-Authenticate: Bearer error="invalid_token"', true, 401);
        oidc_error(401, 'invalid_token', '缺少 access token');
    }
    $stmt = db()->prepare('SELECT * FROM oauth_tokens WHERE access_token = ? LIMIT 1');
    $stmt->execute([$token]);
    $row = $stmt->fetch();
    if (!$row || (int) $row['revoked'] === 1 || (int) $row['expires_at'] <= time()) {
        header('WWW-Authenticate: Bearer error="invalid_token"', true, 401);
        oidc_error(401, 'invalid_token', 'access token 无效或已过期');
    }
    $user = oidc_user_row((int) $row['user_id']);
    if (!$user || $user['status'] !== 'active') {
        oidc_error(401, 'invalid_token', '账号不可用');
    }

    $scopes = preg_split('/\s+/', (string) $row['scope']) ?: [];
    $claims = ['sub' => (string) $user['id']];
    if (in_array('profile', $scopes, true)) {
        $claims['name'] = (string) $user['username'];
        $claims['preferred_username'] = (string) $user['username'];
    }
    if (in_array('email', $scopes, true) && (string) $user['email'] !== '') {
        $claims['email'] = (string) $user['email'];
        $claims['email_verified'] = true;
    }
    json_response(200, $claims);
}

function handle_oauth_revoke(): void
{
    $params = oidc_params();
    $client = oidc_authenticate_client($params);
    if ($client === null) {
        oidc_error(401, 'invalid_client', '客户端认证失败');
    }
    $token = (string) ($params['token'] ?? '');
    if ($token !== '') {
        db()->prepare('UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ? AND (access_token = ? OR refresh_token = ?)')
            ->execute([(string) $client['client_id'], $token, $token]);
    }
    // RFC 7009: always answer 200.
    json_response(200, ['ok' => true]);
}

/* ─────────────────────────── admin: client management ─────────────────────────── */

function handle_admin_clients_index(): void
{
    require_admin();
    $rows = db()->query('SELECT id, client_id, name, redirect_uris, scopes, is_confidential, status, created_at FROM oauth_clients ORDER BY id DESC')->fetchAll();
    $clients = [];
    foreach ($rows as $r) {
        $clients[] = [
            'id' => (int) $r['id'],
            'client_id' => $r['client_id'],
            'name' => $r['name'],
            'redirect_uris' => oidc_client_redirect_uris($r),
            'scopes' => $r['scopes'],
            'is_confidential' => (int) $r['is_confidential'] === 1,
            'status' => $r['status'],
            'created_at' => iso_date($r['created_at']),
        ];
    }
    ok(['clients' => $clients]);
}

function handle_admin_clients_create(): void
{
    require_admin();
    $body = read_json();
    if ($body === null) {
        fail(400, '请求格式错误');
    }
    $name = trim((string) ($body['name'] ?? ''));
    if ($name === '' || str_len($name) > 120) {
        fail(400, '应用名称需为 1-120 字');
    }

    $rawUris = $body['redirect_uris'] ?? '';
    if (is_array($rawUris)) {
        $rawUris = implode("\n", $rawUris);
    }
    $uris = [];
    foreach (preg_split('/[\r\n,]+/', (string) $rawUris) ?: [] as $u) {
        $u = trim($u);
        if ($u === '') {
            continue;
        }
        if (!preg_match('~^https?://[^\s]+$~i', $u)) {
            fail(400, '回调地址必须以 http:// 或 https:// 开头：' . $u);
        }
        $uris[] = $u;
    }
    if ($uris === []) {
        fail(400, '至少填写一个回调地址（redirect URI）');
    }

    $requested = $body['scopes'] ?? ['openid', 'profile', 'email'];
    if (is_string($requested)) {
        $requested = preg_split('/\s+/', $requested) ?: [];
    }
    $scopes = [];
    foreach ($requested as $s) {
        if (in_array($s, OIDC_SUPPORTED_SCOPES, true)) {
            $scopes[] = $s;
        }
    }
    if (!in_array('openid', $scopes, true)) {
        $scopes[] = 'openid';
    }

    $confidential = !isset($body['is_confidential']) || (bool) $body['is_confidential'];

    $clientId = 'sib_' . bin2hex(random_bytes(8));
    $plainSecret = $confidential ? 'sib_cs_' . bin2hex(random_bytes(24)) : '';
    $secretHash = $confidential ? password_hash($plainSecret, PASSWORD_DEFAULT) : '';

    db()->prepare(
        'INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, is_confidential)
         VALUES (?, ?, ?, ?, ?, ?)'
    )->execute([$clientId, $secretHash, $name, implode("\n", $uris), implode(' ', $scopes), $confidential ? 1 : 0]);

    ok([
        'client' => [
            'id' => (int) db()->lastInsertId(),
            'client_id' => $clientId,
            // The plaintext secret is returned exactly once and never stored.
            'client_secret' => $plainSecret !== '' ? $plainSecret : null,
            'name' => $name,
            'redirect_uris' => $uris,
            'scopes' => implode(' ', $scopes),
            'is_confidential' => $confidential,
        ],
    ], '应用已创建');
}

function handle_admin_clients_delete(string $id): void
{
    require_admin();
    $stmt = db()->prepare('SELECT id, client_id FROM oauth_clients WHERE id = ? LIMIT 1');
    $stmt->execute([(int) $id]);
    $row = $stmt->fetch();
    if (!$row) {
        fail(404, '应用不存在');
    }
    $clientId = (string) $row['client_id'];
    db()->prepare('DELETE FROM oauth_clients WHERE id = ?')->execute([(int) $row['id']]);
    db()->prepare('DELETE FROM oauth_tokens WHERE client_id = ?')->execute([$clientId]);
    db()->prepare('DELETE FROM oauth_codes WHERE client_id = ?')->execute([$clientId]);
    ok(['id' => (int) $row['id']], '应用及其令牌已删除');
}
