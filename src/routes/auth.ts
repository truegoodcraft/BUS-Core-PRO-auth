import { Hono } from "hono";
import { hashString, generateNumericCode, signIdentityToken } from "../services/crypto";
import { sendMagicEmail } from "../email/resend";
import { getExpFromJwt } from "../lib/jwt";
import { assertRateLimit } from "../lib/rate-limit";
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
  console.log("[magic:start] handler entry");

  const ct = c.req.header("content-type") || "";
  const rawReq = await c.req.raw.clone().text();
  console.log("[magic:start] content-type", ct);

  let email = "";
  if (ct.includes("application/json")) {
    try {
      const j = JSON.parse(rawReq);
      email = (j?.email ?? "").trim().toLowerCase();
    } catch {
      // fall through
    }
  }
  if (!email && ct.includes("application/x-www-form-urlencoded")) {
    const p = new URLSearchParams(rawReq);
    email = (p.get("email") ?? "").trim().toLowerCase();
  }
  if (!email) {
    const match = rawReq.match(/email\s*:\s*"?([^\s"'}]+)"?/i);
    if (match && match[1]) {
      email = match[1].trim().toLowerCase();
    }
  }

  if (!email) {
    console.log("[magic:start] early-exit: missing email");
    return c.json({ ok: true });
  }
  console.log("[magic:start] parsed email", { to: email });
  const normalizedEmail = email;
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
  const body = await c.req.json<{ email?: string; code?: string }>().catch(() => ({}));
  const rawEmail = typeof body.email === "string" ? body.email : "";
  const email = rawEmail.trim().toLowerCase();
  const code = typeof body.code === "string" ? body.code : "";
  const ip = c.req.header("CF-Connecting-IP") ?? "0.0.0.0";
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  if (!isValidEmail || !code) {
    return c.json({ ok: false, error: "invalid_input" }, 400);
  }

  const tooManyVerify = await assertRateLimit(c, "magic:verify:ip", ip, 10, 15 * 60);
  if (tooManyVerify) return tooManyVerify;

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

    const token = await signIdentityToken({ email }, c.env.IDENTITY_PRIVATE_KEY);
    const exp = getExpFromJwt(token);
    console.log("[magic:verify] ok", { sub: email, exp });

    return c.json({
      ok: true,
      identity_token: token,
      token,
      exp,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown";
    console.warn(JSON.stringify({ event: "magic_verify_error", msg: message }));
    return c.json({ ok: false, error: "invalid_or_expired" });
  }
});
