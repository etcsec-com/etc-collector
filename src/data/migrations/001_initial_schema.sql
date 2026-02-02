-- Initial Schema Migration
-- Creates tokens table for JWT token management with constraints and views

-- Tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 0,
    used_count INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    revoked_by TEXT,
    revoked_reason TEXT,
    metadata TEXT,
    CONSTRAINT check_usage CHECK (used_count <= max_uses OR max_uses = 0),
    CONSTRAINT check_dates CHECK (datetime(expires_at) > datetime(created_at))
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_tokens_jti ON tokens(jti);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_revoked_at ON tokens(revoked_at);
CREATE INDEX IF NOT EXISTS idx_tokens_created_at ON tokens(created_at);

-- Partial index for active tokens (optimization)
CREATE INDEX IF NOT EXISTS idx_tokens_expired
ON tokens(expires_at)
WHERE revoked_at IS NULL;

-- View for active tokens
CREATE VIEW IF NOT EXISTS v_active_tokens AS
SELECT
  id,
  jti,
  created_at,
  expires_at,
  max_uses,
  used_count,
  CASE
    WHEN max_uses = 0 THEN -1
    ELSE (max_uses - used_count)
  END AS remaining_uses
FROM tokens
WHERE revoked_at IS NULL
  AND datetime(expires_at) > datetime('now');
