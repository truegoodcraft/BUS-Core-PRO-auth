import type { Context } from "hono";

type Scope = "magic:start:ip" | "magic:start:email" | "magic:verify:ip";

export async function assertRateLimit(
  c: Context,
  scope: Scope,
  key: string,
  limit: number,
  windowSec: number
) {
  const kv = c.env.RATE_LIMITS as KVNamespace;
  const bucket = `${scope}:${key}`;
  const now = Math.floor(Date.now() / 1000);

  const raw = await kv.get(bucket);
  let count = 0;
  // Cloudflare KV requires expiration_ttl >= 60; also guard windowSec
  const minTtl = 60;
  const window = Math.max(windowSec, minTtl);
  let reset = now + window;

  if (raw) {
    const [storedCount, storedReset] = raw.split(":").map(Number);
    count = storedCount || 0;
    reset = storedReset || reset;
    // Window elapsed → reset counter/window
    if (now >= reset) {
      count = 0;
      reset = now + window;
    }
  }

  count += 1;

  // write (store as "count:reset") with TTL clamped to >= 60s
  const ttl = Math.max(minTtl, reset - now);
  await kv.put(bucket, `${count}:${reset}`, { expirationTtl: ttl });

  if (count > limit) {
    return c.json({ ok: false, error: "rate_limited", reset }, 429);
  }

  return null;
}
