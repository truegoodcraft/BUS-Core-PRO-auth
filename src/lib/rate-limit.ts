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
  let reset = now + windowSec;

  if (raw) {
    const [storedCount, storedReset] = raw.split(":").map(Number);
    count = storedCount || 0;
    reset = storedReset || reset;
    if (now > reset) {
      count = 0;
      reset = now + windowSec;
    }
  }

  count += 1;

  await kv.put(bucket, `${count}:${reset}`, { expirationTtl: Math.max(1, reset - now) });

  if (count > limit) {
    return c.json({ ok: false, error: "rate_limited", reset }, 429);
  }

  return null;
}
