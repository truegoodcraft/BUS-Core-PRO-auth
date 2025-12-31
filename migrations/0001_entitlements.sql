CREATE TABLE entitlements (
  email TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('active','canceled','past_due','incomplete','incomplete_expired','trialing','unpaid','paused')),
  price_id TEXT,
  current_period_end INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_token_mint INTEGER,
  last_ip TEXT
);

CREATE INDEX idx_entitlements_status ON entitlements(status);
CREATE INDEX idx_entitlements_last_token_mint ON entitlements(last_token_mint);
