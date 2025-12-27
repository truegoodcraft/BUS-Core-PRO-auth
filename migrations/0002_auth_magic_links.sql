-- Magic Link Challenges
CREATE TABLE auth_magic_links (
    email TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL, -- Unix timestamp
    created_at INTEGER NOT NULL, -- Unix timestamp
    ip_address TEXT,
    attempt_count INTEGER DEFAULT 0
);

-- Index for finding expired tokens
CREATE INDEX idx_auth_magic_links_expires_at ON auth_magic_links(expires_at);
