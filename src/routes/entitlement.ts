import type { Context } from "hono";
import type { Env } from "../index";
import { checkRateLimit } from "../services/ratelimit";

const SEVEN_DAYS_SECONDS = 7 * 24 * 60 * 60;
const ENTITLEMENT_MAX_TTL_SECONDS = 86400;
const MIN_TTL_IF_ACTIVE_ABOUT_TO_EXPIRE = 600;
const INACTIVE_TTL_SECONDS = 300;

const utf8Encode = (value: string): Uint8Array => {
  return new TextEncoder().encode(value);
};

const base64urlEncode = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const base64urlEncodeString = (value: string): string => {
  return base64urlEncode(utf8Encode(value));
};

const base64urlDecodeToBytes = (value: string): Uint8Array => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const base64 = `${normalized}${padding}`;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const base64urlDecodeToString = (value: string): string => {
  const bytes = base64urlDecodeToBytes(value);
  return new TextDecoder().decode(bytes);
};

const pemToDer = (pem: string): ArrayBuffer => {
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(stripped);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

const verifyIdentityJwt = async (token: string, publicKeyPem: string): Promise<string | null> => {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerEncoded, payloadEncoded, signatureEncoded] = parts;
  let payload: { aud?: string; purpose?: string; v?: number; sub?: string; iat?: number };
  try {
    payload = JSON.parse(base64urlDecodeToString(payloadEncoded)) as {
      aud?: string;
      purpose?: string;
      v?: number;
      sub?: string;
      iat?: number;
    };
  } catch {
    return null;
  }

  if (payload.aud !== "bus-auth" || payload.purpose !== "identity" || payload.v !== 1) {
    return null;
  }
  if (typeof payload.sub !== "string" || typeof payload.iat !== "number") {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (now - payload.iat > SEVEN_DAYS_SECONDS) {
    return null;
  }

  const signatureBytes = base64urlDecodeToBytes(signatureEncoded);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemToDer(publicKeyPem),
    { name: "Ed25519" },
    true,
    ["verify"]
  );
  const signingInput = `${headerEncoded}.${payloadEncoded}`;
  const valid = await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signatureBytes,
    utf8Encode(signingInput)
  );
  if (!valid) return null;
  return payload.sub.toLowerCase();
};

const calculateEntitlementExp = (
  eligible: boolean,
  currentPeriodEnd: number | null,
  now: number
): number => {
  if (!eligible) return now + INACTIVE_TTL_SECONDS;

  if (currentPeriodEnd && currentPeriodEnd > now) {
    const untilPeriodEnd = currentPeriodEnd - now;
    const clamped = Math.min(untilPeriodEnd, ENTITLEMENT_MAX_TTL_SECONDS);
    return now + Math.max(clamped, MIN_TTL_IF_ACTIVE_ABOUT_TO_EXPIRE);
  }

  return now + ENTITLEMENT_MAX_TTL_SECONDS;
};

const signEntitlementJwt = async (payload: Record<string, unknown>, privateKeyPem: string): Promise<string> => {
  const header = { alg: "EdDSA", typ: "JWT" };
  const headerEncoded = base64urlEncodeString(JSON.stringify(header));
  const payloadEncoded = base64urlEncodeString(JSON.stringify(payload));
  const signingInput = `${headerEncoded}.${payloadEncoded}`;
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    utf8Encode(signingInput)
  );
  const signatureEncoded = base64urlEncode(new Uint8Array(signature));
  return `${signingInput}.${signatureEncoded}`;
};

const isValidEmail = (email: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

export const entitlementTokenHandler = async (c: Context<{ Bindings: Env }>) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({}));
  const adminOverride = c.env.ENVIRONMENT !== "prod" && c.req.header("x-admin-key") === c.env.ADMIN_API_KEY;
  let email = "";

  const adminKeyHeader = c.req.header("x-admin-key") ?? "";
  if (adminOverride) {
    email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!email || !isValidEmail(email)) {
      console.log(JSON.stringify({ event: "entitlement_mint_auth_error", reason: "invalid_identity" }));
      return c.json({ ok: false, error: "invalid_identity" });
    }
  } else {
    const authHeader = c.req.header("Authorization") ?? "";
    if (!authHeader.startsWith("Bearer ")) {
      if (c.env.ENVIRONMENT !== "prod" && adminKeyHeader) {
        console.log(JSON.stringify({ event: "entitlement_mint_auth_error", reason: "bad_admin_key" }));
      } else {
        console.log(JSON.stringify({ event: "entitlement_mint_auth_error", reason: "missing_bearer" }));
      }
      return c.json({ ok: false, error: "invalid_identity" });
    }
    const token = authHeader.slice(7).trim();
    const subject = await verifyIdentityJwt(token, c.env.IDENTITY_PUBLIC_KEY);
    if (!subject) {
      console.log(JSON.stringify({ event: "entitlement_mint_auth_error", reason: "invalid_identity" }));
      return c.json({ ok: false, error: "invalid_identity" });
    }
    email = subject;
  }

  const forwardedFor = (c.req.header("x-forwarded-for") ?? "").split(",")[0]?.trim();
  const cfIp = c.req.header("CF-Connecting-IP");
  const ip = cfIp || forwardedFor || (c.req.raw.cf?.colo ?? "unknown");
  const ipAllowed = await checkRateLimit(c.env.RATE_LIMITS, `entmint:ip:${ip}`, 10, 60);
  const emailAllowed = await checkRateLimit(c.env.RATE_LIMITS, `entmint:email:${email}`, 5, 60);
  if (!ipAllowed || !emailAllowed) {
    return c.json({ ok: false, error: "not_entitled" });
  }

  try {
    const row = await c.env.DB.prepare(
      "SELECT status, price_id, current_period_end FROM entitlements WHERE email = ?"
    )
      .bind(email)
      .first<{ status: string | null; price_id: string | null; current_period_end: number | null }>();

    const status = row?.status ?? "none";
    const priceId = row?.price_id ?? null;
    const currentPeriodEnd = row?.current_period_end ?? null;
    const now = Math.floor(Date.now() / 1000);
    const isActiveStatus = status === "active" || status === "trialing";
    const isWithinPeriod = currentPeriodEnd ? currentPeriodEnd > now : true;
    const eligible = isActiveStatus && isWithinPeriod;
    if (!eligible) {
      if (c.env.ENVIRONMENT !== "prod") {
        console.log(JSON.stringify({ event: "entitlement_denied", email, status }));
      }
      return c.json({ ok: false, error: "not_entitled" });
    }
    const exp = calculateEntitlementExp(eligible, currentPeriodEnd, now);

    const payload = {
      v: 1,
      sub: email,
      aud: "bus-auth",
      purpose: "entitlement",
      iat: now,
      exp,
      eligible,
      status,
      price_id: priceId,
      current_period_end: currentPeriodEnd,
    };

    const token = await signEntitlementJwt(payload, c.env.ENTITLEMENT_PRIVATE_KEY);

    if (row) {
      await c.env.DB.prepare("UPDATE entitlements SET last_token_mint = ? WHERE email = ?")
        .bind(now, email)
        .run();
    }

    if (c.env.ENVIRONMENT !== "prod") {
      console.log(JSON.stringify({ event: "entitlement_mint_dev", email, exp }));
      c.header("x-bus-dev-entitlement", token);
    }

    return c.json({ ok: true, token, expires_at: exp, ttl_seconds: exp - now });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown";
    console.log(JSON.stringify({ event: "entitlement_mint_error", msg: message }));
    return c.json({ ok: false, error: "internal" });
  }
};
