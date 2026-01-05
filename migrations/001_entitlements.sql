-- Entitlement state per email; keyed by email, unique by subscription_id
CREATE TABLE IF NOT EXISTS entitlements (
  email TEXT PRIMARY KEY,
  subscription_id TEXT UNIQUE,
  status TEXT,                   -- trialing | active | canceled | past_due | unpaid | incomplete | incomplete_expired
  entitled INTEGER NOT NULL,     -- 1=true, 0=false
  trial_end INTEGER,             -- epoch seconds
  current_period_end INTEGER,    -- epoch seconds
  updated_at INTEGER NOT NULL    -- epoch seconds
);
