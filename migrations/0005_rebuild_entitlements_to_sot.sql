-- Transaction-free SoT rebuild of entitlements (remote-safe).
DROP TABLE IF EXISTS entitlements_new;

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

-- Remote currently has: email, stripe_customer_id, stripe_subscription_id, status, price_id, current_period_end, updated_at, last_ip
INSERT INTO entitlements_new (email, status, price_id, current_period_end, created_at, updated_at, last_token_mint, last_ip)
SELECT
  email,
  status,
  price_id,
  current_period_end,
  strftime('%s','now')                         AS created_at,
  COALESCE(updated_at, strftime('%s','now'))   AS updated_at,
  NULL                                         AS last_token_mint,
  last_ip
FROM entitlements;

DROP TABLE entitlements;
ALTER TABLE entitlements_new RENAME TO entitlements;

CREATE INDEX IF NOT EXISTS idx_entitlements_status ON entitlements(status);
CREATE INDEX IF NOT EXISTS idx_entitlements_last_token_mint ON entitlements(last_token_mint);
