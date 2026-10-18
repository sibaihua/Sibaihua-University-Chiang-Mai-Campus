# Sibaihua University — Chiang Mai Campus

> Official website of **Sibaihua University, Chiang Mai Campus**.
> Motto: *One World, One Dream.*

This repository holds the whole site: three static pages, a zero-dependency PHP
backend, and the MySQL schema. It is served by **Nginx + PHP 8.2 + MySQL 5.7** on
an **Oracle Cloud** instance, with the apex domain `sibaihua.com`.

---

## Overview

| | |
|---|---|
| **Site title** | Sibaihua University, Chiang Mai Campus |
| **Canonical host** | `https://sibaihua.com` (apex; `www` must 301 to it) |
| **Server** | Oracle Cloud, Ubuntu 24.04, Baota panel |
| **Stack** | Nginx 1.30 · PHP 8.2 (php-fpm) · MySQL 5.7 |
| **Front-end** | HTML5 · Tailwind CSS (compiled, inlined in `index.html`) · Vue 3 (CDN) · FontAwesome (CDN) |
| **Backend** | `api.php` front controller + `app/*.php` (PDO only, no Composer) |
| **Repository** | https://github.com/sibaihua/Sibaihua-University-Chiang-Mai-Campus |

---

## Repository layout

```
.
├── index.html          # Single-page homepage (Tailwind CSS inlined, Vue 3)
├── news.html           # Public newsroom: article list + article detail
├── admin.html          # Editorial console: sign in, write/publish/delete articles
├── server/             # backend source (deployed outside the web root)
│   ├── api.php         # front controller for /api/*
│   ├── schema.sql      # MySQL schema (users, sessions, posts)
│   ├── .gitignore      # keeps app/config.php out of git
│   └── app/
│       ├── bootstrap.php      # config, PDO, sessions, cookies, markdown, helpers
│       ├── handlers.php       # setup / auth / posts handlers + router
│       └── config.example.php # copy to config.php on the server
└── README.md
```

### Server layout

```
/www/wwwroot/sibaihua.com/     # public web root
├── index.html
├── news.html
├── admin.html
└── api.php                    # requires /www/server/sibaihua-app/*

/www/server/sibaihua-app/      # application code, NOT web-accessible
├── bootstrap.php
├── handlers.php
├── config.php                 # credentials, chmod 640 www:www
└── schema.sql
```

Application code lives outside the web root on purpose: if the Baota panel ever
regenerates the vhost config, nothing sensitive can become publicly readable.

---

## API

Same-origin JSON. Envelope: `{ "code": 200, "message": "…", "data": … }`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/setup` | — | whether the site still needs its first administrator |
| `POST` | `/api/setup` | — | create the first administrator (only while `users` is empty) |
| `POST` | `/api/auth/login` | — | sign in, sets an HttpOnly session cookie |
| `POST` | `/api/auth/logout` | session | revoke the current session |
| `GET` | `/api/auth/me` | session | current user |
| `POST` | `/api/auth/change-password` | session | change password, revokes other sessions |
| `GET` | `/api/posts` | — | published articles (`limit`, `offset`) |
| `GET` | `/api/posts?includeDrafts=1` | admin | drafts included |
| `POST` | `/api/posts` | admin | create an article |
| `GET` | `/api/posts/{idOrSlug}` | — / admin for drafts | article detail (`content` + rendered `content_html`) |
| `PUT` | `/api/posts/{id}` | admin | update an article |
| `DELETE` | `/api/posts/{id}` | admin | delete an article |

Article bodies are Markdown. Rendering happens **server-side** and the text is escaped
before any inline pattern is applied, so author-supplied content can never inject HTML
or scripts.

---

## First run

1. Visit `https://sibaihua.com/admin.html`.
2. With an empty `users` table the console shows **Create administrator**.
3. Choose a username and password (≥ 8 characters); that account gets the `admin` role.
4. The form disappears permanently — `/api/setup` refuses once any account exists.

Publish the first article from the console; it appears immediately in the homepage
**News & Announcements** section and on `news.html`.

---

## Deployment

### 1. Database

```sql
-- once, as a MySQL administrator
CREATE DATABASE sibaihua CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sibaihua'@'localhost' IDENTIFIED BY '<strong-password>';
GRANT ALL PRIVILEGES ON sibaihua.* TO 'sibaihua'@'localhost';
FLUSH PRIVILEGES;
```

```bash
mysql -u sibaihua -p sibaihua < /www/server/sibaihua-app/schema.sql
```

### 2. Files

Copy `index.html`, `news.html`, `admin.html` and `api.php` into
`/www/wwwroot/sibaihua.com/`; copy `server/app/*` and `server/schema.sql` into
`/www/server/sibaihua-app/`. Then create `config.php` from `config.example.php`:

```bash
chown -R www:www /www/wwwroot/sibaihua.com /www/server/sibaihua-app
chmod 640 /www/server/sibaihua-app/config.php
```

### 3. Nginx

In the site vhost (`/www/server/panel/vhost/nginx/sibaihua.com.conf`):

```nginx
    # /api/* -> front controller
    # The pattern must contain the slash, otherwise /api.php matches again and
    # the rewrite loops.
    location = /api {
        rewrite ^ /api.php last;
    }
    location ~ ^/api/ {
        rewrite ^/api/(.*)$ /api.php last;
    }

    # switch the site from static-only to PHP
    include enable-php-82.conf;
```

Reload: `/www/server/nginx/sbin/nginx -t && /www/server/nginx/sbin/nginx -s reload`.

### 3b. Baota panel — set the PHP version to "自定义"

PHP 8.3 comes from `apt` (`php8.3-fpm`), so Baota does not list it. To make the panel
display the site as using PHP instead of "纯静态":

> Panel → 网站 → 设置 → PHP版本 → **自定义** → `unix:/run/php/php8.3-fpm.sock` → 切换

Saving that setting makes Baota **regenerate the vhost**, which drops the two `/api/`
rewrite rules. Re-apply them with the bundled idempotent script:

```bash
sudo bash /www/server/sibaihua-app/patch-nginx.sh
```

The same script is the fix for any future panel change that regenerates the vhost. It
backs up the config, inserts the rules only if missing, tests and reloads nginx, and
prints a 200/404 check for `/` and `/api/*`.


### 4. DNS

- `A  sibaihua.com  →  <server IPv4>` (optionally orange-clouded through Cloudflare for CDN/WAF)
- `www.sibaihua.com` must **301** to `https://sibaihua.com` — never serve the app on both
  hosts. Two hosts mean two cookie scopes, so a session started on `www` looks signed out
  on the apex, and a future OIDC issuer would split in two.

---

## Security notes

- **Session cookie.** `HttpOnly`, `Secure`, `SameSite=Lax`, and — over HTTPS — named
  `__Host-sib_session`. The `__Host-` prefix makes browsers reject any same-named cookie
  carrying a `Domain` attribute, so a compromised subdomain cannot plant or overwrite it.
  The session is deliberately **not** shared with subdomains.
- **Passwords.** `password_hash()` / `password_verify()` (bcrypt). Login returns the same
  message for unknown users and wrong passwords, so accounts cannot be enumerated.
- **Firewall.** The host currently has **UFW disabled**. Re-enable it before this site
  handles real credentials:
  ```bash
  sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
  sudo ufw allow 2778/tcp   # Baota panel
  sudo ufw enable && sudo systemctl enable ufw
  ```
- **Backups.** A single box is a single point of failure. Schedule `mysqldump` to
  off-box storage (Baota → Cron).
