import { Hono } from "hono";
import {
  constantTimeEqual,
  generateNumericCode,
  hashMagicCode,
  normalizeEmail,
  short8,
  signIdentityToken,
} from "../services/crypto";
import { sendMagicEmail } from "../email/resend";
import { getExpFromJwt } from "../lib/jwt";
import { assertRateLimit } from "../lib/rate-limit";
import type { Env } from "../index";

export const app = new Hono<{ Bindings: Env }>();

app.post("/magic/start", async (c) => {
  console.log("[magic:start] handler entry");

  const ct = c.req.header("content-type") || "";
  const rawReq = await c.req.raw.clone().text();
  console.log("[magic:start] content-type", ct);

  let email = "";
  if (ct.includes("application/json")) {
    try {
      const j = JSON.parse(rawReq);
      email = normalizeEmail(j?.email ?? "");
    } catch {
      // fall through
    }
  }
  if (!email && ct.includes("application/x-www-form-urlencoded")) {
    const p = new URLSearchParams(rawReq);
    email = normalizeEmail(p.get("email") ?? "");
  }
  if (!email) {
    const match = rawReq.match(/email\s*:\s*"?([^\s"'}]+)"?/i);
    if (match && match[1]) {
      email = normalizeEmail(match[1]);
    }
  }

  if (!email) {
    console.log("[magic:start] early-exit: missing email");
    return c.json({ ok: true });
  }
  console.log("[magic:start] parsed email", { to: email });
  const normalizedEmail = normalizeEmail(email);
  const ip = c.req.header("CF-Connecting-IP") ?? "0.0.0.0";
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  if (!isValidEmail) {
    return c.json({ ok: true });
  }

  const tooManyIp = await assertRateLimit(c, "magic:start:ip", ip, 5, 15 * 60);
  if (tooManyIp) return tooManyIp;

  const tooManyEmail = await assertRateLimit(c, "magic:start:email", email, 3, 15 * 60);
  if (tooManyEmail) return tooManyEmail;

  console.log("[magic:start] passed rate limit");

  try {
    const code = generateNumericCode(6);
    const tokenHash = await hashMagicCode(code, normalizedEmail, c.env.PEPPER);
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

    console.log("[magic:start] persisted", {
      email: normalizedEmail,
      code_hash_8: short8(tokenHash),
      expires_at: expiresAt,
    });
    console.log("[magic:start] code persisted");
    console.log("[magic:start] about to send", { to: normalizedEmail });
    try {
      const subject = "Your BUS Core Login Code";
      const text = `Your code is ${code}. It expires in 15 minutes.`;
      await sendMagicEmail(c.env, normalizedEmail, subject, text);
      console.log("[magic:start] send completed", { to: normalizedEmail });
    } catch (err) {
      console.error("[magic:start] send failed", {
        to: normalizedEmail,
        err: String(err),
      });
    }

    return c.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown";
    console.warn(JSON.stringify({ event: "magic_start_error", msg: message }));
    return c.json({ ok: true });
  }
});

app.post("/magic/verify", async (c) => {
  console.log("[magic:verify] handler entry");
  const body = await c.req.json<{ email?: string; code?: string }>().catch(() => ({}));
  const email = (body.email ?? "").trim().toLowerCase();
  const code = (body.code ?? "").trim();
  const ip = c.req.header("CF-Connecting-IP") ?? "0.0.0.0";

  if (!email || !code) {
    console.log("[magic:verify] invalid_input", { hasEmail: !!email, hasCode: !!code });
    return c.json({ ok: false, error: "invalid_input" }, 400);
  }

  const tooManyVerify = await assertRateLimit(c, "magic:verify:ip", ip, 10, 15 * 60);
  if (tooManyVerify) return tooManyVerify;

  try {
    const record = await c.env.DB.prepare(
      "SELECT code_hash, expires_at FROM auth_magic_links WHERE email = ? ORDER BY created_at DESC LIMIT 1"
    )
      .bind(email)
      .first<{ code_hash: string; expires_at: number }>();

    if (!record) {
      console.log("[magic:verify] no_code", { email });
      return c.json({ ok: false, error: "invalid_or_expired" }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > record.expires_at) {
      console.log("[magic:verify] expired", { email, now, exp: record.expires_at });
      return c.json({ ok: false, error: "invalid_or_expired" }, 401);
    }

    const expectedHash = await hashMagicCode(code, email, c.env.PEPPER);
    const match = constantTimeEqual(expectedHash, record.code_hash);
    console.log("[magic:verify] compare", {
      stored_8: short8(record.code_hash),
      expected_8: short8(expectedHash),
    });
    if (!match) {
      console.log("[magic:verify] mismatch", { email });
      return c.json({ ok: false, error: "invalid_or_expired" }, 401);
    }
    const identityToken = await signIdentityToken({ email }, c.env.IDENTITY_PRIVATE_KEY);
    let exp = 0;
    try {
      exp = getExpFromJwt(identityToken);
    } catch {
      exp = 0;
    }

    try {
      await c.env.DB.prepare("DELETE FROM auth_magic_links WHERE email = ?")
        .bind(email)
        .run();
    } catch (err) {
      console.log("[magic:verify] cleanup failed (non-fatal)", { email });
    }

    console.log("[magic:verify] success", {
      sub: email,
      exp,
      token_len: identityToken.length,
    });
    return c.json({
      ok: true,
      identity_token: identityToken,
      token: identityToken,
      exp,
    });
  } catch (error) {
    console.error("[magic:verify] internal error", error);
    return c.json({ ok: false, error: "invalid_or_expired" }, 401);
  }
});
