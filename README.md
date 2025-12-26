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

## Entitlement Tokens (Ed25519)

Entitlement tokens let clients cache proof of eligibility for offline verification with a **7-day grace period** after subscription ends. Stripe + D1 remain the source of truth; tokens are derived outputs only.

### Required Cloudflare config

- Secret: `ENTITLEMENT_PRIVATE_KEY` (Ed25519 PKCS8 PEM, contains `BEGIN PRIVATE KEY`)
- Var: `ENTITLEMENT_PUBLIC_KEY` (Ed25519 SPKI PEM, contains `BEGIN PUBLIC KEY`)
- Optional vars:
  - `ENTITLEMENT_GRACE_SECONDS`
  - `ENTITLEMENT_MAX_TTL_SECONDS`

### Endpoints

- `POST /entitlement/token` with JSON `{ "email": "user@example.com" }`
- `GET /.well-known/entitlement-public-key` to fetch the public key for clients

### Security notes

- The private key never lives in git or on the client.
- Clients verify the token signature and `exp` locally.
