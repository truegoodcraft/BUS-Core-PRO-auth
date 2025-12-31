-- Rebuild entitlements to match SoT exactly, preserving rows.
BEGIN IMMEDIATE;

CREATE TABLE entitlements_new (
  email TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('active','canceled','past_due','incomplete','incomplete_expired','trialing','unpaid','paused')),
  price_id TEXT,
  current_period_end INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_token_mint INTEGER,
  last_ip TEXT
);

-- Copy across known fields; fill missing timestamps
INSERT INTO entitlements_new (email, status, price_id, current_period_end, created_at, updated_at, last_token_mint, last_ip)
SELECT
  email,
  status,
  price_id,
  current_period_end,
  COALESCE(created_at, strftime('%s','now')),
  COALESCE(updated_at, strftime('%s','now')),
  last_token_mint,
  last_ip
FROM entitlements;

DROP TABLE entitlements;
ALTER TABLE entitlements_new RENAME TO entitlements;

CREATE INDEX IF NOT EXISTS idx_entitlements_status ON entitlements(status);
CREATE INDEX IF NOT EXISTS idx_entitlements_last_token_mint ON entitlements(last_token_mint);

COMMIT;
