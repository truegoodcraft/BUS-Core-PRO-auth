-- Transaction-free SoT rebuild of auth_magic_links (remote-safe).
DROP TABLE IF EXISTS auth_magic_links_new;

CREATE TABLE auth_magic_links_new (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  ip_address TEXT
);

-- Remote has token_hash + attempt_count; map token_hash -> code_hash, drop attempt_count.
INSERT INTO auth_magic_links_new (email, code_hash, expires_at, created_at, ip_address)
SELECT
  email,
  token_hash,
  expires_at,
  created_at,
  ip_address
FROM auth_magic_links;

DROP TABLE auth_magic_links;
ALTER TABLE auth_magic_links_new RENAME TO auth_magic_links;

CREATE INDEX IF NOT EXISTS idx_magic_expires ON auth_magic_links(expires_at);
