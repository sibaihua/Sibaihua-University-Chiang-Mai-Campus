#!/bin/bash
# 幂等地（重新）补上本站点 API 所需的两条 Nginx 规则。
# 面板改动站点设置会重写 vhost，随时可以再跑一次本脚本恢复。
#
#   用法：bash patch-nginx.sh [vhost 路径]
#
set -u
CONF="${1:-/www/server/panel/vhost/nginx/sibaihua.com.conf}"
NGINX=/www/server/nginx/sbin/nginx
SOCK=/run/php/php8.3-fpm.sock

[ -f "$CONF" ] || { echo "找不到 vhost: $CONF"; exit 1; }

echo "=== 备份 ==="
sudo cp -a "$CONF" "$CONF.bak.fix.$(date +%s)" && echo "已备份"

echo "=== 补 /api/ 规则 ==="
sudo python3 - "$CONF" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()

block = """
    # ── API 前置控制器：/api/* -> /api.php ──
    # 规则必须带斜杠，否则 /api.php 会被再次匹配造成 rewrite 死循环
    location = /api {
        rewrite ^ /api.php last;
    }
    location ~ ^/api/ {
        rewrite ^/api/(.*)$ /api.php last;
    }
"""

if 'rewrite ^/api/' in s:
    print('API 规则已存在，跳过')
else:
    # 插在 root 指令之后，这是 Baota vhost 里最稳定的锚点
    s, n = re.subn(r'(^[ \t]*root[ \t]+[^\n]*\n)', lambda m: m.group(1) + block, s, count=1, flags=re.M)
    print('已插入 API 规则' if n else 'WARN: 未找到 root 锚点，请手工插入')

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
printf 'GET /            '; curl -ks --resolve sibaihua.com:443:127.0.0.1 -o /dev/null -w "%{http_code}\n" https://sibaihua.com/
printf 'GET /api/setup   '; curl -ks --resolve sibaihua.com:443:127.0.0.1 -o /dev/null -w "%{http_code}\n" https://sibaihua.com/api/setup
printf 'GET /api/posts   '; curl -ks --resolve sibaihua.com:443:127.0.0.1 -o /dev/null -w "%{http_code}\n" https://sibaihua.com/api/posts
echo -n 'body: '; curl -ks --resolve sibaihua.com:443:127.0.0.1 https://sibaihua.com/api/setup; echo
