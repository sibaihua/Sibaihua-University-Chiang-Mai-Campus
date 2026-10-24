#!/bin/bash
# 幂等地（重新）补上本站点所需的 Nginx 规则。
# 面板改动站点设置会重写 vhost，随时可以再跑一次本脚本恢复。
#
#   用法：sudo bash patch-nginx.sh [vhost 路径]
#
set -u
CONF="${1:-/www/server/panel/vhost/nginx/sibaihua.com.conf}"
NGINX=/www/server/nginx/sbin/nginx
SOCK=/run/php/php8.3-fpm.sock

[ -f "$CONF" ] || { echo "找不到 vhost: $CONF"; exit 1; }

echo "=== 备份 ==="
sudo cp -a "$CONF" "$CONF.bak.fix.$(date +%s)" && echo "已备份"

echo "=== 补规则 ==="
sudo python3 - "$CONF" <<'PY'
import re, sys

p = sys.argv[1]
s = open(p, encoding='utf-8').read()

wellknown_block = """
    # ── OIDC / OAuth 发现文档 ──
    location ~ ^/\\.well-known/(openid-configuration|oauth-authorization-server|jwks\\.json)$ {
        rewrite ^ /api.php last;
    }
"""

authorize_block = """
    # ── OAuth 授权端点 ──
    location = /oauth/authorize {
        rewrite ^ /api.php last;
    }
"""

api_block = """
    # ── API 前置控制器：/api/* -> /api.php ──
    # 规则必须带斜杠，否则 /api.php 会被再次匹配造成 rewrite 死循环
    location = /api {
        rewrite ^ /api.php last;
    }
    location ~ ^/api/ {
        rewrite ^/api/(.*)$ /api.php last;
    }
"""

# 清理早期写下的精确匹配版本，统一改成上面的正则形式
for old in (
    r'\n[ \t]*location = /\.well-known/openid-configuration\s*\{[^}]*\}\n',
    r'\n[ \t]*location = /\.well-known/jwks\.json\s*\{[^}]*\}\n',
    # 早期版本给外部 OAuth 登录用的 /callback 落地页，现已改为直接回调 /admin.html
    r'\n[ \t]*#[^\n]*外部 OAuth 登录回调[^\n]*\n[ \t]*location = /callback\s*\{[^}]*\}\n',
    r'\n[ \t]*location = /callback\s*\{[^}]*\}\n',
):
    s = re.sub(old, '\n', s)

needed = ''
if 'oauth-authorization-server' not in s:
    needed += wellknown_block
if 'location = /oauth/authorize' not in s:
    needed += authorize_block
if 'rewrite ^/api/' not in s:
    needed += api_block

if not needed:
    print('规则已齐全，跳过')
else:
    s, n = re.subn(r'(^[ \t]*root[ \t]+[^\n]*\n)', lambda m: m.group(1) + needed, s, count=1, flags=re.M)
    print('已插入缺失规则' if n else 'WARN: 未找到 root 锚点，请手工插入')

open(p, 'w', encoding='utf-8').write(s)
PY

echo "=== 检查 PHP socket 指向 ==="
if grep -q 'php8.3-fpm.sock' "$CONF"; then
  echo "OK: 使用 $SOCK"
elif grep -q 'enable-php-' "$CONF"; then
  echo "WARN: 配置里是 Baota 的 enable-php-XX.conf，请确认面板「PHP版本」已设为自定义 unix:$SOCK"
else
  echo "WARN: 未发现 PHP fastcgi 配置"
fi

echo "=== 校验并重载 ==="
sudo "$NGINX" -t 2>&1 | tail -2
sudo "$NGINX" -s reload && echo "已重载"
sleep 1

echo "=== 验证 ==="
probe() {
  printf '%-42s ' "$1"
  curl -ks --resolve sibaihua.com:443:127.0.0.1 -o /dev/null -w "%{http_code}\n" "https://sibaihua.com$1"
}
probe /
probe /api/setup
probe /api/posts
probe /.well-known/openid-configuration
probe /.well-known/oauth-authorization-server
probe /.well-known/jwks.json
probe /admin.html
