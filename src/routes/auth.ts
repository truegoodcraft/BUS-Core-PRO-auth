import { Hono } from "hono";
import { hashString, generateNumericCode, signIdentityToken } from "../services/crypto";
import { sendMagicCode } from "../services/email";
import { checkRateLimit } from "../services/ratelimit";
import type { Env } from "../index";

export const app = new Hono<{ Bindings: Env }>();

app.post("/magic/start", async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({}));
  const email = typeof body.email === "string" ? body.email : "";
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";

  const allowed = await checkRateLimit(
    c.env.RATE_LIMITS,
    `ratelimit:ip:${ip}`,
    5,
    900
  );
  if (!allowed) {
    return c.json({ error: "Too many requests" }, 429);
  }

  const code = generateNumericCode(6);
  const tokenHash = await hashString(code);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 900;

  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO auth_magic_links (
      email,
      token_hash,
      expires_at,
      created_at,
      ip_address
    ) VALUES (?, ?, ?, ?, ?)`
  )
    .bind(email, tokenHash, expiresAt, now, ip)
    .run();

  await sendMagicCode(c.env.RESEND_API_KEY, c.env.EMAIL_FROM, email, code);

  return c.json({ ok: true });
});

app.post("/magic/verify", async (c) => {
  const body = await c.req.json<{ email?: string; code?: string }>().catch(() => ({}));
  const email = typeof body.email === "string" ? body.email : "";
  const code = typeof body.code === "string" ? body.code : "";
  const now = Math.floor(Date.now() / 1000);

  const record = await c.env.DB.prepare(
    "SELECT token_hash, expires_at FROM auth_magic_links WHERE email = ?"
  )
    .bind(email)
    .first<{ token_hash: string; expires_at: number }>();

  if (!record || record.expires_at < now) {
    return c.json({ error: "Invalid or expired" }, 401);
  }

  const tokenHash = await hashString(code);
  if (tokenHash !== record.token_hash) {
    return c.json({ error: "Invalid or expired" }, 401);
  }

  await c.env.DB.prepare("DELETE FROM auth_magic_links WHERE email = ?")
    .bind(email)
    .run();

  const token = await signIdentityToken({ email }, c.env.IDENTITY_PRIVATE_KEY);
  const expiresAt = now + 7 * 24 * 60 * 60;

  return c.json({ token, expires_at: expiresAt });
});
