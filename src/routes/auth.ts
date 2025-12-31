import { Hono } from "hono";
import { hashString, generateNumericCode, signIdentityToken } from "../services/crypto";
import { sendMagicCode } from "../services/email";
import { checkRateLimit } from "../services/ratelimit";
import type { Env } from "../index";

export const app = new Hono<{ Bindings: Env }>();

app.post("/magic/start", async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({}));
  const rawEmail = typeof body.email === "string" ? body.email : "";
  const email = rawEmail.trim().toLowerCase();
  const forwardedFor = (c.req.header("x-forwarded-for") ?? "").split(",")[0]?.trim();
  const cfIp = c.req.header("CF-Connecting-IP");
  const ip = cfIp || forwardedFor || (c.req.raw.cf?.colo ?? "unknown");
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const ipAllowed = await checkRateLimit(
    c.env.RATE_LIMITS,
    `rl:magic:start:ip:${ip}`,
    5,
    900
  );
  const emailAllowed = isValidEmail
    ? await checkRateLimit(
        c.env.RATE_LIMITS,
        `rl:magic:start:email:${email}`,
        3,
        900
      )
    : true;
  if (!ipAllowed || !emailAllowed || !isValidEmail) {
    return c.json({ ok: true });
  }

  const code = generateNumericCode(6);
  const tokenHash = await hashString(`${code}:${email}`);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 900;

  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO auth_magic_links (
      email,
      code_hash,
      expires_at,
      created_at,
      ip_address
    ) VALUES (?, ?, ?, ?, ?)`
  )
    .bind(email, tokenHash, expiresAt, now, ip)
    .run();

  await sendMagicCode(c.env.RESEND_API_KEY, c.env.EMAIL_FROM, email, code);

  if (c.env.ENVIRONMENT === "dev" || c.env.WORKER_ENV === "development") {
    console.log({ event: "magic_start_dev", email, code });
  }

  return c.json({ ok: true });
});

app.post("/magic/verify", async (c) => {
  const body = await c.req.json<{ email?: string; code?: string }>().catch(() => ({}));
  const email = typeof body.email === "string" ? body.email : "";
  const code = typeof body.code === "string" ? body.code : "";
  const now = Math.floor(Date.now() / 1000);

  const record = await c.env.DB.prepare(
    "SELECT code_hash, expires_at FROM auth_magic_links WHERE email = ?"
  )
    .bind(email)
    .first<{ code_hash: string; expires_at: number }>();

  if (!record || record.expires_at < now) {
    return c.json({ error: "Invalid or expired" }, 401);
  }

  const tokenHash = await hashString(code);
  if (tokenHash !== record.code_hash) {
    return c.json({ error: "Invalid or expired" }, 401);
  }

  await c.env.DB.prepare("DELETE FROM auth_magic_links WHERE email = ?")
    .bind(email)
    .run();

  const token = await signIdentityToken({ email }, c.env.IDENTITY_PRIVATE_KEY);
  const expiresAt = now + 7 * 24 * 60 * 60;

  return c.json({ token, expires_at: expiresAt });
});
