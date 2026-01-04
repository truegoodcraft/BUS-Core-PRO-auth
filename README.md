# 🔐 BUS Core Auth (`bus-auth`) 🔐

🚀 **Status:** Production Ready 🛡️ **Service Role:** Identity + Entitlement Authority 

---

### ✨ 1. Overview ✨

`bus-auth` is the central gateway for **BUS Core Pro**. It operates on the philosophy of **"Gate Key, Not Hall Monitor"**. The service is responsible for:

* 🆔 **Identity:** Issuing tokens that prove email ownership.


* 🎟️ **Entitlements:** Verifying subscription status via Stripe and issuing signed entitlement tokens.


* ⏳ **Persistence:** Clients are encouraged to trust token expiry (`exp`) for offline grace periods.



---

### 🛠️ 2. Technology Stack 🛠️

* ⚡ **Runtime:** Cloudflare Workers 


* 🔥 **Framework:** Hono (TypeScript) 


* 🗄️ **Database:** Cloudflare D1 


* ⚡ **Cache:** Cloudflare KV 


* 💳 **Billing:** Stripe (Checkout + Webhooks) 


* ✍️ **Signing:** Ed25519 Asymmetric Signing 



---

### 📡 3. API Reference 📡

#### 🌐 Public Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| 🏥 `GET` | `/health` | Service health check 

 |
| 🪄 `POST` | `/auth/magic/start` | Trigger a 6-digit magic code email 

 |
| ✅ `POST` | `/auth/magic/verify` | Exchange code for an Identity Token 

 |
| 🔍 `POST` | `/entitlement` | Public eligibility check 

 |
| 🔑 `GET` | `/.well-known/identity-public-key` | Verification key for Identity Tokens 

 |
| 🔑 `GET` | `/.well-known/entitlement-public-key` | Verification key for Entitlement Tokens 

 |

#### 🔒 Authenticated Endpoints

*Requires a valid Bearer Identity Token* 

| Method | Path | Purpose |
| --- | --- | --- |
| 💎 `POST` | `/entitlement/token` | Mint a signed Entitlement Token 

 |
| 🛒 `POST` | `/checkout/session` | Create a Stripe Checkout session 

 |

---

### 🛡️ 4. Security & Authentication 🛡️

* 🔢 **Magic Codes:** 6-digit numeric codes with a 15-minute expiry.


* ⏱️ **Token TTL:** Identity tokens are valid for 7 days.


* 🗓️ **Entitlement Grace:** Tokens include a built-in 7-day grace period beyond the `current_period_end` to handle intermittent connectivity.


* 🖊️ **Verification:** All tokens are signed using Ed25519.



---

### 🚀 5. Development & Deployment 🚀

#### ⚙️ Required Environment Variables (`wrangler.toml`)

Ensure the following variables are defined in your environment:

* 📧 `EMAIL_FROM`: The sender address for magic links.
* 🔗 `CHECKOUT_SUCCESS_URL` / `CHECKOUT_CANCEL_URL`: Stripe redirect paths.
* 🔑 `IDENTITY_PUBLIC_KEY` / `ENTITLEMENT_PUBLIC_KEY`: The public half of your Ed25519 pairs.

#### 🤐 Secrets Management

The following secrets must be set via `wrangler secret put`:

* 🗝️ `IDENTITY_PRIVATE_KEY` / `ENTITLEMENT_PRIVATE_KEY`
* 💳 `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET`
* ✉️ `RESEND_API_KEY`
* 👔 `ADMIN_API_KEY`

