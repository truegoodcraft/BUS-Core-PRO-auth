-- Rebuild auth_magic_links to match SoT exactly, preserving rows and renaming token_hash -> code_hash.
BEGIN IMMEDIATE;

CREATE TABLE auth_magic_links_new (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  ip_address TEXT
);

INSERT INTO auth_magic_links_new (email, code_hash, expires_at, created_at, ip_address)
SELECT
  email,
  -- token_hash → code_hash (fallback if already code_hash)
  COALESCE(code_hash, token_hash),
  expires_at,
  created_at,
  ip_address
FROM auth_magic_links;

DROP TABLE auth_magic_links;
ALTER TABLE auth_magic_links_new RENAME TO auth_magic_links;

CREATE INDEX IF NOT EXISTS idx_magic_expires ON auth_magic_links(expires_at);

COMMIT;
