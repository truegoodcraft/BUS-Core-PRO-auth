import { Hono } from "hono";
import Stripe from "stripe";

type Env = {
  ADMIN_API_KEY: string;
  ADMIN_IP_ALLOWLIST: string; // comma-separated IPv4 list, e.g. "142.90.207.149"
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  ELIGIBLE_PRICE_IDS: string;
  CHECKOUT_SUCCESS_URL: string;
  CHECKOUT_CANCEL_URL: string;
  DB: D1Database;
};

const app = new Hono<{ Bindings: Env }>();

const VALID_STATUSES = new Set(["active", "trialing"]);

const parseEligiblePriceIds = (env: Env): string[] => {
  return (env.ELIGIBLE_PRICE_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
};

const isValidEmail = (email: string): boolean => {
  if (!email || email.length > 254) {
    return false;
  }
  return email.includes("@");
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
      email,
      stripe_customer_id,
      stripe_subscription_id,
      status,
      price_id,
      current_period_end,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
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
      now
    )
    .run();
};

// ─────────────────────────────────────────────────────────────
// Request ID + Structured Logging Middleware
// ─────────────────────────────────────────────────────────────
app.use("*", async (c, next) => {
  const start = Date.now();

  let reqId = (c.req.header("x-request-id") ?? "").trim();
  if (!reqId) {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      reqId = crypto.randomUUID();
    } else {
      reqId = `${Date.now()}-${Math.random()}`;
    }
  }

  c.header("x-request-id", reqId);

  try {
    await next();
  } finally {
    const ms = Date.now() - start;
    const ip = c.req.header("CF-Connecting-IP") || "unknown";
    const ua = c.req.header("User-Agent") || "unknown";

    const logData = {
      at: new Date().toISOString(),
      req_id: reqId,
      method: c.req.method,
      path: new URL(c.req.url).pathname,
      status: c.res.status,
      ms,
      ip,
      ua,
    };

    // SECURITY: never log Authorization headers or secrets
    console.log(JSON.stringify(logData));
  }
});

// ─────────────────────────────────────────────────────────────
// Admin Protection Middleware
// ─────────────────────────────────────────────────────────────
app.use("/admin/*", async (c, next) => {
  // A) IP allowlist check
  const ip = (c.req.header("CF-Connecting-IP") ?? "").trim();
  const allowlistStr = c.env.ADMIN_IP_ALLOWLIST || "";
  const allowlist = allowlistStr
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");

  if (!ip || !allowlist.includes(ip)) {
    return c.json({ ok: false, error: "forbidden" }, 403);
  }

  // B) API key check
  const authHeader = c.req.header("Authorization") ?? "";
  const expectedKey = c.env.ADMIN_API_KEY;

  if (!expectedKey || authHeader !== `Bearer ${expectedKey}`) {
    return c.json({ ok: false, error: "unauthorized" }, 401);
  }

  await next();
});

// ─────────────────────────────────────────────────────────────
// Routes
// ─────────────────────────────────────────────────────────────

// Public health check
app.get("/health", (c) => {
  return c.json({
    ok: true,
    service: "bus-auth",
    version: "0.2.0",
  });
});

// Admin health (read-only)
app.get("/admin/health/detailed", (c) => {
  const ip = c.req.header("CF-Connecting-IP") || "unknown";
  const hasAdminKey = !!(c.env.ADMIN_API_KEY && c.env.ADMIN_API_KEY.length > 0);

  return c.json({
    ok: true,
    admin: true,
    ip,
    has_admin_key: hasAdminKey,
    allowlist: c.env.ADMIN_IP_ALLOWLIST,
    version: "0.2.0",
  });
});

// Admin-only DB bootstrap
app.post("/admin/db/bootstrap", async (c) => {
  await c.env.DB.exec(`CREATE TABLE IF NOT EXISTS entitlements (
    email TEXT PRIMARY KEY,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    status TEXT,
    price_id TEXT,
    current_period_end INTEGER,
    updated_at INTEGER
  );`);
  await c.env.DB.exec(
    "CREATE INDEX IF NOT EXISTS idx_entitlements_customer ON entitlements(stripe_customer_id);"
  );
  await c.env.DB.exec(
    "CREATE INDEX IF NOT EXISTS idx_entitlements_subscription ON entitlements(stripe_subscription_id);"
  );
  return c.json({ ok: true });
});

// Create a Stripe Checkout Session (public)
app.post("/checkout/session", async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({}));
  const email = (body.email ?? "").trim();
  if (!isValidEmail(email)) {
    return c.json({ ok: false, error: "bad_request" }, 400);
  }

  const priceIds = parseEligiblePriceIds(c.env);
  const firstPriceId = priceIds[0];
  if (!firstPriceId) {
    return c.json({ ok: false, error: "stripe_error" }, 500);
  }

  const stripe = getStripe(c.env);

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: [{ price: firstPriceId, quantity: 1 }],
      success_url: c.env.CHECKOUT_SUCCESS_URL,
      cancel_url: c.env.CHECKOUT_CANCEL_URL,
      allow_promotion_codes: false,
    });

    return c.json({ ok: true, url: session.url });
  } catch {
    return c.json({ ok: false, error: "stripe_error" }, 500);
  }
});

// Stripe webhook (public)
app.post("/stripe/webhook", async (c) => {
  const signature = c.req.header("Stripe-Signature");
  if (!signature) {
    return c.json({ ok: false, error: "bad_signature" }, 400);
  }

  const payload = await c.req.text();
  const stripe = getStripe(c.env);
  let event: Stripe.Event;

  try {
    event = await stripe.webhooks.constructEventAsync(
      payload,
      signature,
      c.env.STRIPE_WEBHOOK_SECRET
    );
  } catch {
    return c.json({ ok: false, error: "bad_signature" }, 400);
  }

  const handleSubscription = async (subscription: Stripe.Subscription) => {
    const customerId =
      typeof subscription.customer === "string" ? subscription.customer : null;
    const subscriptionId = subscription.id;
    const status = subscription.status ?? null;
    const currentPeriodEnd = subscription.current_period_end ?? null;
    const priceId = subscription.items?.data?.[0]?.price?.id ?? null;
    const customerEmail =
      (subscription as Stripe.Subscription & { customer_email?: string })
        .customer_email ?? null;
    const priceAllowlist = new Set(parseEligiblePriceIds(c.env));
    const eligible =
      !!status &&
      VALID_STATUSES.has(status) &&
      !!priceId &&
      priceAllowlist.has(priceId);

    let email = customerEmail ?? null;
    if (!email && customerId) {
      const customer = await stripe.customers.retrieve(customerId);
      if (!customer.deleted && customer.email) {
        email = customer.email;
      }
    }

    if (!email) {
      console.log(
        JSON.stringify({
          tag: "stripe_webhook_missing_email",
          event_id: event.id,
          customer_id: customerId,
          subscription_id: subscriptionId,
          eligible,
        })
      );
      return;
    }

    await upsertEntitlement(c.env, {
      email,
      stripeCustomerId: customerId,
      stripeSubscriptionId: subscriptionId,
      status,
      priceId,
      currentPeriodEnd,
    });
  };

  try {
    if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const subscription = event.data.object as Stripe.Subscription;
      await handleSubscription(subscription);
    } else if (event.type === "checkout.session.completed") {
      const session = event.data.object as Stripe.Checkout.Session;
      if (typeof session.subscription === "string") {
        const subscription = await stripe.subscriptions.retrieve(
          session.subscription
        );
        await handleSubscription(subscription);
      }
    }
  } catch {
    return c.json({ ok: false, error: "stripe_error" }, 500);
  }

  return c.json({ ok: true });
});

// Entitlement lookup (public)
app.post("/entitlement", async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({}));
  const email = (body.email ?? "").trim();
  if (!isValidEmail(email)) {
    return c.json({ ok: false, error: "bad_request" }, 400);
  }

  const row = await c.env.DB.prepare(
    "SELECT email, status, price_id, current_period_end FROM entitlements WHERE email = ?;"
  )
    .bind(email)
    .first<{
      email: string;
      status: string | null;
      price_id: string | null;
      current_period_end: number | null;
    }>();

  const priceAllowlist = new Set(parseEligiblePriceIds(c.env));
  const isEligible =
    !!row &&
    !!row.status &&
    VALID_STATUSES.has(row.status) &&
    !!row.price_id &&
    priceAllowlist.has(row.price_id);

  return c.json({
    ok: true,
    email,
    eligible: isEligible,
    status: row?.status ?? null,
    price_id: row?.price_id ?? null,
    current_period_end: row?.current_period_end ?? null,
  });
});

export default app;
