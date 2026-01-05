import Stripe from "stripe";

export type EntitlementRow = {
  email: string;
  subscription_id: string | null;
  status: string | null;
  entitled: number;
  trial_end: number | null;
  current_period_end: number | null;
  updated_at: number;
};

export function entitledFromStatus(status: string | null): number {
  return status === "trialing" || status === "active" ? 1 : 0;
}

export function getEligiblePriceIds(env: any): Set<string> {
  const raw = (env.ELIGIBLE_PRICE_IDS as string | undefined) ?? "";
  return new Set(raw.split(/[,\s]+/).filter(Boolean));
}

export async function upsertFromCheckoutSession(
  db: D1Database,
  email: string,
  subscriptionId: string | null
) {
  const now = Math.floor(Date.now() / 1000);
  await db.prepare(
    `
    INSERT INTO entitlements (email, subscription_id, status, entitled, trial_end, current_period_end, updated_at)
    VALUES (?, ?, ?, ?, NULL, NULL, ?)
    ON CONFLICT(email)
    DO UPDATE SET
      subscription_id=excluded.subscription_id,
      status=excluded.status,
      entitled=excluded.entitled,
      updated_at=excluded.updated_at
  `
  )
    .bind(email, subscriptionId, "trialing", 1, now)
    .run();
}

export async function upsertFromSubscription(
  db: D1Database,
  sub: Stripe.Subscription,
  email?: string | null
) {
  const status = sub.status;
  const entitled = entitledFromStatus(status);
  const trial_end = sub.trial_end ?? null;
  const current_period_end = sub.current_period_end ?? null;
  const now = Math.floor(Date.now() / 1000);

  const res = await db.prepare(
    `
    UPDATE entitlements
       SET status=?, entitled=?, trial_end=?, current_period_end=?, updated_at=?
     WHERE subscription_id=?
  `
  )
    .bind(status, entitled, trial_end, current_period_end, now, sub.id)
    .run();

  if (res.meta.changes === 0 && email) {
    await db.prepare(
      `
      INSERT INTO entitlements (email, subscription_id, status, entitled, trial_end, current_period_end, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(email)
      DO UPDATE SET
        subscription_id=excluded.subscription_id,
        status=excluded.status,
        entitled=excluded.entitled,
        trial_end=excluded.trial_end,
        current_period_end=excluded.current_period_end,
        updated_at=excluded.updated_at
    `
    )
      .bind(email, sub.id, status, entitled, trial_end, current_period_end, now)
      .run();
  }
}

export async function getEntitlement(db: D1Database, email: string): Promise<EntitlementRow | null> {
  return (
    (await db
      .prepare(
        `
    SELECT email, subscription_id, status, entitled, trial_end, current_period_end, updated_at
      FROM entitlements WHERE email=? LIMIT 1
  `
      )
      .bind(email)
      .first<EntitlementRow>()) ?? null
  );
}
