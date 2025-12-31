import { Hono } from "hono";
import Stripe from "stripe";
import { app as authRouter } from "./routes/auth";
import { verifyIdentityToken } from "./services/crypto";

export type Env = {
  ADMIN_API_KEY: string;
  ADMIN_IP_ALLOWLIST: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  ELIGIBLE_PRICE_IDS: string;
  STRIPE_PRICE_DEFAULT?: string;
  CHECKOUT_SUCCESS_URL: string;
  CHECKOUT_CANCEL_URL: string;
  ENTITLEMENT_PRIVATE_KEY: string;
  ENTITLEMENT_PUBLIC_KEY: string;
  ENTITLEMENT_GRACE_SECONDS?: string;
  ENTITLEMENT_MAX_TTL_SECONDS?: string;
  IDENTITY_PRIVATE_KEY: string;
  IDENTITY_PUBLIC_KEY: string;
  RESEND_API_KEY: string;
  STATS_KEY: string;
  MAGIC_LINK_TTL: string;
  EMAIL_FROM: string;
  RATE_LIMITS: KVNamespace;
  DB: D1Database;
};

const app = new Hono<{ Bindings: Env }>();
app.route("/auth", authRouter);

const VALID_STATUSES = new Set(["active", "trialing"]);
let cachedEntitlementPrivateKey: CryptoKey | null = null;

const parseEligiblePriceIds = (env: Env): string[] => {
  return (env.ELIGIBLE_PRICE_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
};

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

const importEntitlementPrivateKey = async (env: Env): Promise<CryptoKey> => {
  if (cachedEntitlementPrivateKey) return cachedEntitlementPrivateKey;
  const der = pemToDer(env.ENTITLEMENT_PRIVATE_KEY);
  cachedEntitlementPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  return cachedEntitlementPrivateKey;
};

const getStripe = (env: Env) => {
  return new Stripe(env.STRIPE_SECRET_KEY, {
    apiVersion: "2024-06-20",
    httpClient: Stripe.createFetchHttpClient(),
  });
};

const upsertEntitlement = async (env: Env, data: {
  email: string;
  stripeCustomerId: string | null;
  stripeSubscriptionId: string | null;
  status: string | null;
  priceId: string | null;
  currentPeriodEnd: number | null;
}) => {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO entitlements (
      email, stripe_customer_id, stripe_subscription_id, status, price_id, current_period_end, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET
      stripe_customer_id = excluded.stripe_customer_id,
      stripe_subscription_id = excluded.stripe_subscription_id,
      status = excluded.status,
      price_id = excluded.price_id,
      current_period_end = excluded.current_period_end,
      updated_at = excluded.updated_at`
  )
    .bind(
      data.email,
      data.stripeCustomerId,
      data.stripeSubscriptionId,
      data.status,
      data.priceId,
      data.currentPeriodEnd,
      now,
      now
    )
    .run();
};

// Middleware
app.use("*", async (c, next) => {
  const start = Date.now();
  let reqId = (c.req.header("x-request-id") ?? "").trim() || crypto.randomUUID();
  c.header("x-request-id", reqId);
  try {
    await next();
  } finally {
    const ms = Date.now() - start;
    const ip = c.req.header("CF-Connecting-IP") || "unknown";
    console.log(JSON.stringify({
      at: new Date().toISOString(),
      req_id: reqId,
      method: c.req.method,
      path: new URL(c.req.url).pathname,
      status: c.res.status,
      ms,
      ip,
    }));
  }
});

app.use("/admin/*", async (c, next) => {
  const ip = (c.req.header("CF-Connecting-IP") ?? "").trim();
  const allowlist = (c.env.ADMIN_IP_ALLOWLIST || "").split(",").map(s => s.trim());
  if (!ip || !allowlist.includes(ip)) return c.json({ ok: false, error: "forbidden" }, 403);
  const authHeader = c.req.header("Authorization") ?? "";
  if (!c.env.ADMIN_API_KEY || authHeader !== `Bearer ${c.env.ADMIN_API_KEY}`) return c.json({ ok: false, error: "unauthorized" }, 401);
  await next();
});

// Routes
app.get("/health", (c) => c.json({ ok: true, service: "bus-auth", version: "0.1.0" }));

app.post("/checkout/session", async (c) => {
  const authHeader = c.req.header("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return c.json({ ok: false, error: "missing_bearer" }, 401);
  const token = authHeader.slice(7).trim();
  const email = await verifyIdentityToken(token, c.env.IDENTITY_PUBLIC_KEY);
  if (!email) return c.json({ ok: false, error: "invalid_token" }, 401);

  if (!c.env.STRIPE_SECRET_KEY || !c.env.CHECKOUT_SUCCESS_URL || !c.env.CHECKOUT_CANCEL_URL) 
    return c.json({ ok: false, error: "env_misconfigured" }, 500);

  let body: any = {};
  try { body = await c.req.json(); } catch (e) {}
  const priceId = body.price_id || c.env.STRIPE_PRICE_DEFAULT;
  const eligiblePrices = parseEligiblePriceIds(c.env);
  
  if (!priceId || !eligiblePrices.includes(priceId)) return c.json({ ok: false, error: "invalid_price_id" }, 400);

  try {
    const stripe = getStripe(c.env);
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: c.env.CHECKOUT_SUCCESS_URL,
      cancel_url: c.env.CHECKOUT_CANCEL_URL,
      metadata: { email }
    });
    return c.json({ ok: true, url: session.url });
  } catch (err: any) {
    return c.json({ ok: false, error: "stripe_error", details: err.message }, 400);
  }
});

app.post("/stripe/webhook", async (c) => {
  const signature = c.req.header("Stripe-Signature");
  if (!signature) return c.json({ ok: false, error: "bad_signature" }, 400);
  const payload = await c.req.text();
  const stripe = getStripe(c.env);
  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(payload, signature, c.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return c.json({ ok: false, error: "bad_signature" }, 400);
  }

  const handleSubscription = async (subscription: Stripe.Subscription) => {
    const customerId = typeof subscription.customer === "string" ? subscription.customer : null;
    let email = (subscription as any).customer_email || null;
    if (!email && customerId) {
      const customer = await stripe.customers.retrieve(customerId);
      if (!customer.deleted && (customer as Stripe.Customer).email) email = (customer as Stripe.Customer).email;
    }
    if (!email) return;

    await upsertEntitlement(c.env, {
      email,
      stripeCustomerId: customerId,
      stripeSubscriptionId: subscription.id,
      status: subscription.status,
      priceId: subscription.items.data[0]?.price.id,
      currentPeriodEnd: subscription.current_period_end,
    });
  };

  if (["customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"].includes(event.type)) {
    await handleSubscription(event.data.object as Stripe.Subscription);
  }
  return c.json({ ok: true });
});

// --- UPDATED ENTITLEMENT WITH HEARTBEAT ---
app.post("/entitlement", async (c) => {
  const authHeader = c.req.header("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return c.json({ ok: false, error: "unauthorized" }, 401);
  const token = authHeader.slice(7).trim();
  const email = await verifyIdentityToken(token, c.env.IDENTITY_PUBLIC_KEY);
  if (!email) return c.json({ ok: false, error: "unauthorized" }, 401);

  // Heartbeat Update
  const ip = c.req.header("CF-Connecting-IP") || "unknown";
  const now = Math.floor(Date.now() / 1000);
  await c.env.DB.prepare("UPDATE entitlements SET updated_at = ?, last_ip = ? WHERE email = ?;")
    .bind(now, ip, email).run();

  const row = await c.env.DB.prepare("SELECT status, price_id, current_period_end FROM entitlements WHERE email = ?;")
    .bind(email).first<{ status: string | null; price_id: string | null; current_period_end: number | null; }>();

  const priceAllowlist = new Set(parseEligiblePriceIds(c.env));
  const isEligible = !!row && VALID_STATUSES.has(row.status || "") && priceAllowlist.has(row.price_id || "");
  
  return c.json({ ok: true, email, eligible: isEligible, status: row?.status ?? null, price_id: row?.price_id ?? null, current_period_end: row?.current_period_end ?? null });
});

app.post("/entitlement/token", async (c) => {
  const authHeader = c.req.header("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return c.json({ ok: false, error: "unauthorized" }, 401);
  const token = authHeader.slice(7).trim();
  const email = await verifyIdentityToken(token, c.env.IDENTITY_PUBLIC_KEY);
  if (!email) return c.json({ ok: false, error: "unauthorized" }, 401);

  const row = await c.env.DB.prepare("SELECT status, price_id, current_period_end FROM entitlements WHERE email = ?;")
    .bind(email).first<{ status: string | null; price_id: string | null; current_period_end: number | null; }>();

  const priceAllowlist = new Set(parseEligiblePriceIds(c.env));
  const eligible = !!row && VALID_STATUSES.has(row.status || "") && priceAllowlist.has(row.price_id || "");
  
  const now = Math.floor(Date.now() / 1000);
  const grace = Number.parseInt(c.env.ENTITLEMENT_GRACE_SECONDS ?? "604800");
  const maxTtl = Number.parseInt(c.env.ENTITLEMENT_MAX_TTL_SECONDS ?? "2592000");
  let exp = now + 600;
  if (eligible && row?.current_period_end) exp = Math.min(now + maxTtl, row.current_period_end + grace);

  const payload = { v: 1, sub: email, iat: now, exp, eligible, price_id: row?.price_id ?? null, status: row?.status ?? null, current_period_end: row?.current_period_end ?? null };
  const privateKey = await importEntitlementPrivateKey(c.env);
  const payloadB64 = base64urlEncodeString(JSON.stringify(payload));
  const signingInput = `v1.${payloadB64}`;
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8Encode(signingInput));
  const entitlementToken = `v1.${payloadB64}.${base64urlEncode(new Uint8Array(signature))}`;

  return c.json({ ok: true, email, eligible, token: entitlementToken });
});

app.get("/.well-known/identity-public-key", (c) => {
  return c.json({ ok: true, public_key_pem: c.env.IDENTITY_PUBLIC_KEY });
});

app.get("/.well-known/entitlement-public-key", (c) => {
  return c.json({ ok: true, public_key_pem: c.env.ENTITLEMENT_PUBLIC_KEY });
});

export default app;
