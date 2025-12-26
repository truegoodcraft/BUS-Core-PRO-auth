# BUS Auth Cloudflare Worker (bus-auth)

This repo contains the Cloudflare Worker for **bus-auth** (custom domain `auth.buscore.ca`).

## Deploy

`wrangler deploy` uploads the Worker to Cloudflare and publishes it to your account and routes.

## Required secrets (Cloudflare)

Set these as **secrets** (case-sensitive):

- `ADMIN_API_KEY`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

Example:

```bash
npx wrangler secret put ADMIN_API_KEY
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_WEBHOOK_SECRET
```

## Required vars

Set these as plaintext vars (in `wrangler.toml` or `wrangler vars`):

- `ADMIN_IP_ALLOWLIST`
- `ELIGIBLE_PRICE_IDS`
- `CHECKOUT_SUCCESS_URL`
- `CHECKOUT_CANCEL_URL`

## Local dev

```bash
npx wrangler dev --local --port 8788
```

## Bootstrap the D1 database

Create the `entitlements` table and indexes by calling the admin-only endpoint:

```
POST /admin/db/bootstrap
```

This must be called from an allowlisted IP with `Authorization: Bearer <ADMIN_API_KEY>`.

## Stripe webhook

Set the Stripe webhook endpoint to:

```
https://auth.buscore.ca/stripe/webhook
```

The webhook handler requires the **raw request body** for signature verification; do not parse JSON before verification.

## Firewall rule snippet (free plan)

Use a rule that matches `/admin/*` paths. Example expression:

```
(http.request.uri.path contains "/admin/")
```
