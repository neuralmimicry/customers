# Customers

Customers is NeuralMimicry's dedicated identity service.
It owns user registration, login, logout, browser sessions, SSO/OIDC exchange, profile management, and voice-token lifecycle.

## Why this repo exists

The original Refiner codebase had four operational concerns mixed together:

- Refiner workflows and job orchestration
- user registration and authentication
- token and billing logic
- speech-to-text

That split is now explicit:

- Refiner stays in `/home/pbisaacs/Developer/neuralmimicry/rag_demo`
- Customers lives in `/home/pbisaacs/Developer/neuralmimicry/customers`
- Billing lives in `/home/pbisaacs/Developer/neuralmimicry/billing`
- nmstt lives in `/home/pbisaacs/Developer/neuralmimicry/nmstt`
- nmchain in `/home/pbisaacs/Developer/neuralmimicry/nmchain` remains the audit ledger of record

The public API host remains `https://api.neuralmimicry.ai`.
Refiner proxies auth routes there so the frontend commercial site at `https://neuralmimicry.ai` does not need a second backend host.

## Topology

Request path for public users:

1. Browser loads `https://neuralmimicry.ai`
2. Frontend calls `https://api.neuralmimicry.ai`
3. Traffic enters the internal network through `vega.neuralmimicry.ai`
4. Traffic is routed onward to `spirit.neuralmimicry.ai` and the tenant Kubernetes services
5. Refiner proxies auth/session/profile/voice-token routes to Customers when the split-service env is configured

Service interactions:

- Refiner reads session state from Customers through `/api/session`
- Refiner resolves voice tokens through `/api/internal/voice/resolve`
- Billing verifies passwords through `/api/internal/credentials/verify`
- Customers emits identity and login events to nmchain when `CUSTOMERS_CHAIN_*` is configured

## Responsibilities

Customers owns:

- first-user bootstrap and local account creation
- password verification and login throttling
- browser session cookies
- SSO token issue/exchange
- OIDC login and callback handling
- user profile reads and updates
- voice-token issue, list, revoke, and internal resolution

Customers does not own:

- job execution
- token balances or payment settlement
- speech recognition

## API surface

HTML routes:

- `GET /login`
- `GET /setup`
- `GET /logout`
- `GET /oidc/login`
- `GET /oidc/callback`
- `GET /sso`

Public JSON routes:

- `GET /api/health`
- `GET /api/version`
- `POST /api/setup`
- `POST /api/login`
- `POST /api/logout`
- `GET /api/session`
- `GET|POST /api/profile`
- `POST /api/sso/issue`
- `POST /api/oidc/exchange`
- `GET /api/authz/nginx`
- `GET|POST /api/voice/tokens`
- `DELETE /api/voice/tokens/<token_id>`

Internal JSON routes protected by app tokens:

- `POST /api/internal/voice/resolve`
- `POST /api/internal/credentials/verify`

## Storage model

Customers supports two backends:

- Postgres-backed central store for production
- file-backed store for fallback and local development

The production default in the Continuum deployment is the shared tenant Postgres service:

- host: `postgres.postgres.svc.cluster.local`
- port: `5432`
- database: `continuum` by default unless overridden through the shared auth host vars

That keeps user/session/voice-token records in the cluster relational store rather than per-pod local files.

Relevant tables created in Postgres include:

- `nm_users`
- `nm_auth_tokens`
- `nm_token_accounts`
- `nm_token_ledger_entries`

The token-ledger tables remain present because the original shared store schema was extracted intact, but billing responsibility now lives in the Billing service. Customers should be treated as the source of truth for identity, not balances.

For pod-local fallback state and any file-backed development mode, the Continuum role also provisions an NFS-backed PVC on the `continuum-shared` storage class with `ReadWriteMany`.
That avoids tying stateful failover behavior to a single node-local filesystem.

## Auditing with nmchain

When `CUSTOMERS_CHAIN_API_BASE` and `CUSTOMERS_CHAIN_API_TOKEN` are set, Customers writes:

- identity upserts
- successful login observations

This creates an immutable link between account lifecycle events and the token/payment events written by Billing.

## Configuration

Core runtime variables:

- `CUSTOMERS_HOST`
- `CUSTOMERS_PORT`
- `CUSTOMERS_SECRET_KEY`
- `CUSTOMERS_APP_TOKENS`
- `CUSTOMERS_AUTH_MODE` = `local`, `oidc`, or `mixed`
- `CUSTOMERS_PASSWORD_MIN_LENGTH`
- `CUSTOMERS_ALLOW_SETUP`
- `CUSTOMERS_SESSION_COOKIE_NAME`
- `CUSTOMERS_COOKIE_DOMAIN`
- `CUSTOMERS_COOKIE_SAMESITE`
- `CUSTOMERS_SECURE_COOKIES`
- `CUSTOMERS_ENFORCE_HTTPS`
- `CUSTOMERS_CORS_ORIGINS`
- `CUSTOMERS_STATE_DIR`

Database configuration:

- `CUSTOMERS_DB_DSN`
- `CUSTOMERS_DB_HOST`
- `CUSTOMERS_DB_PORT`
- `CUSTOMERS_DB_NAME`
- `CUSTOMERS_DB_USER`
- `CUSTOMERS_DB_PASSWORD`
- `CUSTOMERS_DB_SSLMODE`
- `CUSTOMERS_DB_CONNECT_TIMEOUT`
- `CUSTOMERS_DB_POOL_MIN`
- `CUSTOMERS_DB_POOL_MAX`
- `CUSTOMERS_DB_POOL_TIMEOUT`

OIDC and SSO:

- `CUSTOMERS_OIDC_ENABLED`
- `CUSTOMERS_OIDC_EXCHANGE_ENABLED`
- `CUSTOMERS_OIDC_ISSUER`
- `CUSTOMERS_OIDC_CLIENT_ID`
- `CUSTOMERS_OIDC_CLIENT_SECRET`
- `CUSTOMERS_OIDC_REDIRECT_URI`
- `CUSTOMERS_OIDC_SCOPE`
- `CUSTOMERS_OIDC_ALLOWED_AUDIENCES`
- `CUSTOMERS_OIDC_ALLOWED_REDIRECT_URIS`
- `CUSTOMERS_OIDC_ADMIN_DOMAINS`
- `CUSTOMERS_OIDC_ADMIN_GROUPS`
- `CUSTOMERS_SSO_TTL`
- `CUSTOMERS_SSO_STORE`
- `CUSTOMERS_SSO_REDIS_URL`
- `CUSTOMERS_SSO_REDIS_PREFIX`

Audit integration:

- `CUSTOMERS_CHAIN_API_BASE`
- `CUSTOMERS_CHAIN_API_TOKEN`
- `CUSTOMERS_CHAIN_APP_ID`
- `CUSTOMERS_CHAIN_TIMEOUT`

## Local development

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

Run with the file-backed store:

```bash
export CUSTOMERS_SECRET_KEY='change-me'
export CUSTOMERS_APP_TOKENS='refiner=dev-refiner-token,billing=dev-billing-token'
python -m customers_service
```

Health check:

```bash
curl http://127.0.0.1:5010/api/health
```

## Container build

```bash
podman build -t ghcr.io/neuralmimicry/customers:latest -f Containerfile .
```

## Continuum deployment

Tenant playbook:

- `/home/pbisaacs/Developer/swarmhpc/swarmhpc/ansible/continuum_tenant_customers_site.yml`

Role:

- `roles/continuum_tenant_customers`

Deployment defaults assume:

- internal service URL `http://customers.customers.svc.cluster.local:5010`
- shared Postgres service `postgres.postgres.svc.cluster.local:5432`
- generated app tokens for `refiner` and `billing`
- optional nmchain token loaded from `.secrets/nmchain/<inventory-host>/customers_api_token`
- persistent NFS-backed state PVC for local-store fallback and SSO artifacts

## Interoperability contract

For the split platform to be fully functional:

- Refiner should point `REFINER_CUSTOMERS_API_BASE` at Customers
- Billing should point `BILLING_CUSTOMERS_API_BASE` at Customers
- Refiner and Billing should use the Customers-generated app tokens for their protected internal routes
- nmchain should use Customers for session resolution, not Refiner

See also:

- `/home/pbisaacs/Developer/neuralmimicry/rag_demo/SERVICE_SPLIT_ARCHITECTURE.md`
