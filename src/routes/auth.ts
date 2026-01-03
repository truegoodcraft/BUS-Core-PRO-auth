import { Hono } from "hono";
import {
  constantTimeEqual,
  generateNumericCode,
  hashMagicCode,
  short8,
  signIdentityToken,
} from "../services/crypto";
import { sendMagicEmail } from "../email/resend";
import { getExpFromJwt } from "../lib/jwt";
import { assertRateLimit } from "../lib/rate-limit";
import type { Env } from "../index";

export const app = new Hono<{ Bindings: Env }>();

app.post("/magic/start", async (c) => {
  console.log("[magic:start] entry");
  const body = await c.req.json<{ email?: string }>().catch(() => ({}));
  const email = (body.email ?? "").trim().toLowerCase();
  if (!email) return c.json({ ok: true });

  const ip = c.req.header("CF-Connecting-IP") ?? "0.0.0.0";
  const limitedByIp = await assertRateLimit(c, "magic:start:ip", ip, 5, 15 * 60);
  if (limitedByIp) return limitedByIp;

  const limitedByEmail = await assertRateLimit(c, "magic:start:email", email, 3, 15 * 60);
  if (limitedByEmail) return limitedByEmail;

  const code = generateNumericCode(6);
  const codeHash = await hashMagicCode(code, email, c.env.PEPPER);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 15 * 60;

  await c.env.DB.prepare(
    "INSERT OR REPLACE INTO auth_magic_links (email, code_hash, expires_at, created_at, ip_address) VALUES (?1, ?2, ?3, ?4, ?5)"
  )
    .bind(email, codeHash, exp, now, ip)
    .run();

  console.log("[magic:start] persisted", {
    emailMasked: email.replace(/(.{2}).+(@.*)/, "$1***$2"),
  });

  try {
    await sendMagicEmail(
      c.env,
      email,
      "Your BUS Core Login Code",
      `Your code is ${code}. It expires in 15 minutes.`
    );
  } catch {
    // ignore email send errors to keep response privacy-preserving
  }

  return c.json({ ok: true });
});

app.post("/magic/verify", async (c) => {
  console.log("[magic:verify] entry");
  const body = await c.req.json<{ email?: string; code?: string }>().catch(() => ({}));
  const email = (body.email ?? "").trim().toLowerCase();
  const code = (body.code ?? "").trim();
  if (!email || !code) return c.json({ ok: false, error: "invalid_input" }, 400);

  const ip = c.req.header("CF-Connecting-IP") ?? "0.0.0.0";
  const limited = await assertRateLimit(c, "magic:verify:ip", ip, 10, 15 * 60);
  if (limited) return limited;

  const rec = await c.env.DB.prepare(
    "SELECT code_hash, expires_at FROM auth_magic_links WHERE email = ? ORDER BY created_at DESC LIMIT 1"
  )
    .bind(email)
    .first<{ code_hash: string; expires_at: number }>();

  if (!rec) return c.json({ ok: false, error: "invalid_or_expired" }, 401);

  const now = Math.floor(Date.now() / 1000);
  if (now > rec.expires_at) return c.json({ ok: false, error: "invalid_or_expired" }, 401);

  const expected = await hashMagicCode(code, email, c.env.PEPPER);
  if (!constantTimeEqual(expected, rec.code_hash)) {
    console.log("[magic:verify] mismatch", {
      emailMasked: email.replace(/(.{2}).+(@.*)/, "$1***$2"),
      stored8: short8(rec.code_hash),
      calc8: short8(expected),
    });
    return c.json({ ok: false, error: "invalid_or_expired" }, 401);
  }

  let identityToken = "";
  try {
    identityToken = await signIdentityToken({ email }, c.env.IDENTITY_PRIVATE_KEY);
  } catch {
    return c.json({ ok: false, error: "server_misconfigured" }, 500);
  }

  const exp = getExpFromJwt(identityToken);

  c.env.DB.prepare("DELETE FROM auth_magic_links WHERE email = ?")
    .bind(email)
    .run()
    .catch(() => {});

  console.log("[magic:verify] success", {
    emailMasked: email.replace(/(.{2}).+(@.*)/, "$1***$2"),
  });
  return c.json({ ok: true, identity_token: identityToken, token: identityToken, exp });
});
