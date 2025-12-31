CREATE TABLE IF NOT EXISTS entitlements (
  email TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('active','canceled','past_due','incomplete','incomplete_expired','trialing','unpaid','paused')),
  price_id TEXT,
  current_period_end INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_token_mint INTEGER,
  last_ip TEXT
);
