import { Hono } from "hono";
import Stripe from "stripe";
import { app as authRouter } from "./routes/auth";
import { identityAuth } from "./middleware/identityAuth";
import { sendMagicEmail } from "./email/resend";
import { entitlementTokenHandler } from "./routes/entitlement";
import { verifyIdentityToken } from "./services/crypto";
import { getEligiblePriceIds, upsertFromCheckoutSession, upsertFromSubscription } from "./entitlements";

export type Env = {
  ADMIN_API_KEY: string;
  ADMIN_IP_ALLOWLIST: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  ELIGIBLE_PRICE_IDS: string;
  STRIPE_PRICE_DEFAULT?: string;
  CHECKOUT_SUCCESS_URL: string;
  CHECKOUT_CANCEL_URL: string;
  TRIAL_DAYS?: string;
  ENTITLEMENT_PRIVATE_KEY: string;
  ENTITLEMENT_PUBLIC_KEY: string;
  ENTITLEMENT_GRACE_SECONDS?: string;
  ENTITLEMENT_MAX_TTL_SECONDS?: string;
  IDENTITY_PRIVATE_KEY: string;
  IDENTITY_PUBLIC_KEY: string;
  ENVIRONMENT?: string;
  WORKER_ENV?: string;
  RESEND_API_KEY: string;
  STATS_KEY: string;
  MAGIC_LINK_TTL: string;
  EMAIL_FROM: string;
  RATE_LIMITS: KVNamespace;
  DB: D1Database;
};

const app = new Hono<{ Bindings: Env }>();
app.route("/auth", authRouter);

const parseEligiblePriceIds = (env: Env): string[] => {
  return (env.ELIGIBLE_PRICE_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
};

const getStripe = (env: Env) => {
  return new Stripe(env.STRIPE_SECRET_KEY, {
    apiVersion: "2024-06-20",
    httpClient: Stripe.createFetchHttpClient(),
  });
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
app.get("/health", (c) => {
  const env = c.env as Env;
  const emailConfigured = Boolean(env?.RESEND_API_KEY && env?.EMAIL_FROM);
  return c.json({
    ok: true,
    service: "bus-auth",
    version: "0.1.0",
    email_configured: emailConfigured,
  });
});

app.post("/admin/test/email", async (c) => {
  const to = c.req.query("to") || "you@your-verified-domain.com";
  await sendMagicEmail(c.env, to, "BUS Core test email", "This is a test email from bus-auth.");
  return c.json({ ok: true, to });
});

app.post("/billing/create-checkout-session", async (c) => {
  const body = await c.req.json<{ email?: string; price_id?: string }>().catch(() => ({}));
  const rawEmail = typeof body.email === "string" ? body.email : "";
  const email = rawEmail.trim().toLowerCase();
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isValidEmail) {
    return c.json({ ok: false, error: "invalid_input" }, 400);
  }

  const eligiblePrices = parseEligiblePriceIds(c.env);
  let priceId = typeof body.price_id === "string" ? body.price_id : "";
  if (priceId && !eligiblePrices.includes(priceId)) {
    return c.json({ ok: false, error: "price_not_allowed" }, 400);
  }
  if (!priceId) {
    priceId = c.env.STRIPE_PRICE_DEFAULT ?? "";
  }
  if (!priceId || !eligiblePrices.includes(priceId)) {
    return c.json({ ok: false, error: "price_not_allowed" }, 400);
  }

  if (c.env.ENVIRONMENT !== "prod") {
    console.log(JSON.stringify({ event: "checkout_create_dev", email, priceId }));
  }

  try {
    const stripe = getStripe(c.env);
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: c.env.CHECKOUT_SUCCESS_URL,
      cancel_url: c.env.CHECKOUT_CANCEL_URL,
    });
    return c.json({ ok: true, url: session.url });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown";
    console.warn(JSON.stringify({ event: "checkout_create_error", msg: message }));
    return c.json({ ok: false, error: "stripe_error" });
  }
});

app.post("/checkout/session", identityAuth, async (c) => {
  const env = c.env as {
    STRIPE_SECRET_KEY: string;
    STRIPE_PRICE_DEFAULT: string;
    CHECKOUT_SUCCESS_URL: string;
    CHECKOUT_CANCEL_URL: string;
    TRIAL_DAYS?: string;
  };

  const email = c.get("tokenSubject") as string | undefined;
  if (!email) {
    return c.json({ ok: false, error: "invalid_identity" }, 401);
  }

  if (!env.STRIPE_SECRET_KEY || !/^sk_(live|test)/.test(env.STRIPE_SECRET_KEY)) {
    return c.json({ ok: false, error: "config_missing_secret" }, 500);
  }
  if (!env.STRIPE_PRICE_DEFAULT || !/^price_/.test(env.STRIPE_PRICE_DEFAULT)) {
    return c.json({ ok: false, error: "config_missing_price" }, 500);
  }
  if (!env.CHECKOUT_SUCCESS_URL || !env.CHECKOUT_CANCEL_URL) {
    return c.json({ ok: false, error: "config_missing_urls" }, 500);
  }
  const trialDays = Number(env.TRIAL_DAYS ?? 14);
  if (!(trialDays > 0 && Number.isFinite(trialDays))) {
    return c.json({ ok: false, error: "config_invalid_trial" }, 500);
  }

  try {
    const stripe = new Stripe(env.STRIPE_SECRET_KEY, {
      apiVersion: "2023-10-16",
      httpClient: Stripe.createFetchHttpClient(),
    });
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      success_url: env.CHECKOUT_SUCCESS_URL,
      cancel_url: env.CHECKOUT_CANCEL_URL,
      line_items: [{ price: env.STRIPE_PRICE_DEFAULT, quantity: 1 }],
      customer_email: email,
      allow_promotion_codes: true,
      subscription_data: { trial_period_days: trialDays },
    });
    if (!session.url) {
      return c.json({ ok: false, error: "stripe_error" }, 500);
    }
    return c.json({ ok: true, url: session.url });
  } catch (err: any) {
    const detail = { type: err?.type, code: err?.code, message: err?.message };
    console.error("checkout_session_error", detail);
    const debug = c.req.header("x-debug") === "1";
    return c.json(
      debug
        ? { ok: false, error: "stripe_error", detail, using_price: env.STRIPE_PRICE_DEFAULT }
        : { ok: false, error: "stripe_error" },
      500
    );
  }
});

app.get("/_health/checkout", (c) => {
  const env = c.env as Env;
  return c.json({
    ok: true,
    hasSecret: !!env.STRIPE_SECRET_KEY,
    secretMode: env.STRIPE_SECRET_KEY?.startsWith("sk_live")
      ? "live"
      : env.STRIPE_SECRET_KEY?.startsWith("sk_test")
        ? "test"
        : "unknown",
    hasPrice: !!env.STRIPE_PRICE_DEFAULT,
    priceId: env.STRIPE_PRICE_DEFAULT || null,
    hasUrls: !!env.CHECKOUT_SUCCESS_URL && !!env.CHECKOUT_CANCEL_URL,
    trialMode: `explicit:${Number(env.TRIAL_DAYS ?? 14)}`,
  });
});

app.post("/billing/webhook", async (c) => {
  const env = c.env as {
    STRIPE_SECRET_KEY: string;
    STRIPE_WEBHOOK_SECRET: string;
    ELIGIBLE_PRICE_IDS?: string;
    DB: D1Database;
  } & Record<string, any>;

  const payload = await c.req.text();
  const sig = c.req.header("stripe-signature") || "";
  if (!env.STRIPE_WEBHOOK_SECRET) {
    return c.json({ ok: false, error: "missing_webhook_secret" }, 500);
  }

  const stripe = new Stripe(env.STRIPE_SECRET_KEY, {
    apiVersion: "2023-10-16",
    httpClient: Stripe.createFetchHttpClient(),
  });

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      payload,
      sig,
      env.STRIPE_WEBHOOK_SECRET,
      undefined,
      Stripe.createSubtleCryptoProvider()
    );
  } catch (err: any) {
    console.error("webhook_signature_error", { message: err?.message });
    return c.json({ ok: false, error: "invalid_signature" }, 400);
  }

  const db = env.DB;
  const elig = getEligiblePriceIds(env);

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const subId =
          typeof session.subscription === "string" ? session.subscription : session.subscription?.id ?? null;
        const email = session.customer_details?.email || session.customer_email || null;
        if (email) {
          await upsertFromCheckoutSession(db, email, subId);
        }
        break;
      }
      case "customer.subscription.created":
      case "customer.subscription.updated": {
        const sub = event.data.object as Stripe.Subscription;
        const priceId = sub.items?.data?.[0]?.price?.id;
        if (elig.size && priceId && !elig.has(priceId)) break;

        let email: string | null | undefined = (sub as any).customer_email;
        if (!email && typeof sub.customer === "string") {
          try {
            const cust = await stripe.customers.retrieve(sub.customer as string);
            if (!cust.deleted) email = (cust as Stripe.Customer).email ?? null;
          } catch {
            // ignore lookup errors
          }
        }
        await upsertFromSubscription(db, sub, email ?? null);
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object as Stripe.Subscription;
        sub.status = "canceled";
        await upsertFromSubscription(db, sub, null);
        break;
      }
      default:
        break;
    }
  } catch (err: any) {
    console.error("webhook_handle_error", { type: event.type, message: err?.message });
    return c.json({ ok: false, error: "webhook_error" }, 500);
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

  const now = Math.floor(Date.now() / 1000);
  await c.env.DB.prepare("UPDATE entitlements SET updated_at = ? WHERE email = ?;")
    .bind(now, email).run();

  const row = await c.env.DB.prepare(
    "SELECT status, entitled, trial_end, current_period_end FROM entitlements WHERE email = ?;"
  )
    .bind(email)
    .first<{ status: string | null; entitled: number | null; trial_end: number | null; current_period_end: number | null }>();

  const isEligible = !!row && row.entitled === 1;
  return c.json({
    ok: true,
    email,
    eligible: isEligible,
    status: row?.status ?? null,
    price_id: null,
    trial_end: row?.trial_end ?? null,
    current_period_end: row?.current_period_end ?? null,
  });
});

app.post("/entitlement/token", entitlementTokenHandler);

app.get("/.well-known/identity-public-key", (c) => {
  return c.json({ ok: true, public_key_pem: c.env.IDENTITY_PUBLIC_KEY });
});

app.get("/.well-known/entitlement-public-key", (c) => {
  return c.json({ ok: true, public_key_pem: c.env.ENTITLEMENT_PUBLIC_KEY });
});

export default app;
