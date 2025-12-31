CREATE TABLE auth_magic_links (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  ip_address TEXT
);

CREATE INDEX idx_magic_expires ON auth_magic_links(expires_at);
