import { Hono } from "hono";
import { hashString, generateNumericCode } from "../services/crypto";
import { sendMagicCode } from "../services/email";
import { checkRateLimit } from "../services/ratelimit";
import type { Env } from "../index";

export const app = new Hono<{ Bindings: Env }>();

const constantTimeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
};

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

  try {
    const code = generateNumericCode(6);
    const tokenHash = await hashString(`${code}:${email}`);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 900;

    if (c.env.ENVIRONMENT !== "prod") {
      console.log(JSON.stringify({ event: "magic_start_dev", email, code, expires_in_sec: 900 }));
    }

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

    c.executionCtx.waitUntil((async () => {
      if (c.env.ENVIRONMENT !== "prod") {
        console.log(JSON.stringify({ event: "magic_email_skip", to: email }));
        return;
      }
      await sendMagicCode(c.env.RESEND_API_KEY, c.env.EMAIL_FROM, email, code);
    })());

    if (c.env.ENVIRONMENT !== "prod" && c.req.header("x-admin-key") === c.env.ADMIN_API_KEY) {
      c.header("x-bus-dev-code", code);
    }
    return c.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown";
    console.warn(JSON.stringify({ event: "magic_start_error", msg: message }));
    return c.json({ ok: true });
  }
});

app.post("/magic/verify", async (c) => {
  const body = await c.req.json<{ email?: string; code?: string }>().catch(() => ({}));
  const rawEmail = typeof body.email === "string" ? body.email : "";
  const email = rawEmail.trim().toLowerCase();
  const code = typeof body.code === "string" ? body.code : "";
  const forwardedFor = (c.req.header("x-forwarded-for") ?? "").split(",")[0]?.trim();
  const cfIp = c.req.header("CF-Connecting-IP");
  const ip = cfIp || forwardedFor || (c.req.raw.cf?.colo ?? "unknown");
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  if (c.env.ENVIRONMENT !== "prod") {
    console.log(JSON.stringify({ event: "magic_verify_dev", email }));
  }

  if (!isValidEmail || !code) {
    return c.json({ ok: false, error: "invalid_input" }, 400);
  }

  const ipAllowed = await checkRateLimit(
    c.env.RATE_LIMITS,
    `rl:magic:verify:ip:${ip}`,
    5,
    900
  );
  const emailAllowed = await checkRateLimit(
    c.env.RATE_LIMITS,
    `rl:magic:verify:email:${email}`,
    5,
    900
  );
  if (!ipAllowed || !emailAllowed) {
    return c.json({ ok: false, error: "rate_limited" });
  }

  try {
    const record = await c.env.DB.prepare(
      "SELECT code_hash, expires_at FROM auth_magic_links WHERE email = ?"
    )
      .bind(email)
      .first<{ code_hash: string; expires_at: number }>();

    const now = Math.floor(Date.now() / 1000);
    if (!record) {
      return c.json({ ok: false, error: "invalid_or_expired" });
    }
    if (record.expires_at <= now) {
      await c.env.DB.prepare("DELETE FROM auth_magic_links WHERE email = ?")
        .bind(email)
        .run();
      return c.json({ ok: false, error: "invalid_or_expired" });
    }

    const expectedHash = await hashString(`${code}:${email}`);
    if (!constantTimeEqual(expectedHash, record.code_hash)) {
      return c.json({ ok: false, error: "invalid_or_expired" });
    }

    await c.env.DB.prepare("DELETE FROM auth_magic_links WHERE email = ?")
      .bind(email)
      .run();

    return c.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown";
    console.warn(JSON.stringify({ event: "magic_verify_error", msg: message }));
    return c.json({ ok: false, error: "invalid_or_expired" });
  }
});
