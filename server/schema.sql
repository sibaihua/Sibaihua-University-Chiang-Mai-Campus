-- Sibaihua University — official website backend schema (MySQL 5.7+ / InnoDB / utf8mb4)
-- Import once:  mysql -u sibaihua -p sibaihua < schema.sql
-- No administrator is seeded: the first account is created on first visit to /admin.html
-- (the /api/setup endpoint stops working as soon as one account exists).

CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(32)  NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(16)  NOT NULL DEFAULT 'admin',
  status        VARCHAR(16)  NOT NULL DEFAULT 'active',
  email         VARCHAR(190) NOT NULL DEFAULT '',
  -- Stable subject (`sub`) from the external OAuth provider, recorded on the
  -- first OAuth sign-in so later logins survive e-mail / nickname changes.
  oauth_sub     VARCHAR(190) NOT NULL DEFAULT '',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_username (username),
  KEY idx_users_oauth_sub (oauth_sub),
  KEY idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
  token      CHAR(64)     NOT NULL,
  user_id    INT UNSIGNED NOT NULL,
  expires_at BIGINT       NOT NULL,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (token),
  KEY idx_sessions_user (user_id),
  KEY idx_sessions_exp (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS posts (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  slug         VARCHAR(100) NOT NULL,
  title        VARCHAR(200) NOT NULL,
  excerpt      VARCHAR(400) NOT NULL DEFAULT '',
  content      MEDIUMTEXT   NOT NULL,
  status       VARCHAR(16)  NOT NULL DEFAULT 'draft',
  author_id    INT UNSIGNED NULL,
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  published_at DATETIME     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_slug (slug),
  KEY idx_posts_status (status, published_at),
  CONSTRAINT fk_posts_author FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────────────────────
-- OAuth 2.0 / OpenID Connect provider
-- This site acts as the identity provider: third-party applications register
-- here and send members to /oauth/authorize.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS oauth_clients (
  id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  client_id          VARCHAR(64)  NOT NULL,
  client_secret_hash VARCHAR(255) NOT NULL DEFAULT '',
  client_secret_enc  TEXT         DEFAULT NULL,
  name               VARCHAR(120) NOT NULL,
  redirect_uris      TEXT         NOT NULL,
  scopes             VARCHAR(255) NOT NULL DEFAULT 'openid profile email',
  is_confidential    TINYINT(1)   NOT NULL DEFAULT 1,
  status             VARCHAR(16)  NOT NULL DEFAULT 'active',
  created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS oauth_codes (
  code                  CHAR(64)     NOT NULL,
  client_id             VARCHAR(64)  NOT NULL,
  user_id               INT UNSIGNED NOT NULL,
  redirect_uri          VARCHAR(400) NOT NULL,
  scope                 VARCHAR(255) NOT NULL,
  nonce                 VARCHAR(200) NOT NULL DEFAULT '',
  code_challenge        VARCHAR(128) NOT NULL DEFAULT '',
  code_challenge_method VARCHAR(10)  NOT NULL DEFAULT '',
  expires_at            BIGINT       NOT NULL,
  used                  TINYINT(1)   NOT NULL DEFAULT 0,
  created_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (code),
  KEY idx_codes_client (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS oauth_tokens (
  access_token       CHAR(64)     NOT NULL,
  refresh_token      CHAR(64)     DEFAULT NULL,
  client_id          VARCHAR(64)  NOT NULL,
  user_id            INT UNSIGNED NOT NULL,
  scope              VARCHAR(255) NOT NULL,
  expires_at         BIGINT       NOT NULL,
  refresh_expires_at BIGINT       DEFAULT NULL,
  revoked            TINYINT(1)   NOT NULL DEFAULT 0,
  created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (access_token),
  UNIQUE KEY uniq_refresh_token (refresh_token),
  KEY idx_tokens_user (user_id),
  KEY idx_tokens_client (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
