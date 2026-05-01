# Customers

Customers is NeuralMimicry's dedicated identity service.
It owns user registration, login, logout, browser sessions, optional authenticator-app 2FA, passkey sign-in, SSO/OIDC exchange, profile management, and voice-token lifecycle.

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
- admin-managed local user creation and password resets
- password verification and login throttling
- authenticator-app 2FA enrolment and verification for local accounts
- passkey registration, passkey sign-in, and passkey lifecycle management for local accounts
- self-service password changes
- browser session cookies
- SSO token issue/exchange
- OIDC login and callback handling
- user profile reads and updates
- group and service catalog state
- delegated group memberships and service grants
- hierarchical team ownership and membership metadata
- team invitations, acceptance/rejection, and leaving a team
- voice-token issue, list, revoke, and internal resolution

Customers does not own:

- job execution
- token balances or payment settlement
- speech recognition

## Team model

Customers keeps the top-level identity role model intentionally small:

- `admin`
- `user`

Team collaboration is tracked separately from those global roles:

- a user can create a team they own
- admins can create nested teams through `parent_id`
- a team owner can invite another existing user into that team
- the invitee can accept or reject the invitation
- an active team member can later leave the team and still keep their individual user account

Session, profile, and internal credential responses now include additive team/group context so downstream services can consume it without a second identity lookup.
Profile and session responses also carry the validated `settings` block used by Refiner's Control Room so the public contract stays stable when auth/profile routes are proxied through Customers.

## Authorisation model

Customers is now the shared authorisation source of truth for the commercial stack as well as identity.

Built-in groups:

- `user`
- `admin`

Every account still has a top-level role (`user` or `admin`), and that role is treated as an implicit membership in the matching built-in group.
Additional explicit group memberships are stored separately and can use one of two membership roles:

- `member`
- `manager`

Service accounts are first-class principals for backend-to-backend calls.
They:

- are stored separately from human users
- can join explicit groups and inherit only those group grants
- can be issued normal Customers bearer tokens
- resolve through `/api/session` with `identity_type: service_account` and `role: service_account`

Service accounts do not inherit the built-in `user` group or any human fallback grants.

Service access is managed through a service catalog plus group-scoped grants.
Each service has a public visibility level:

- `none`
- `request`
- `observe`
- `use`
- `control`

Delegation rules:

- platform admins can manage the entire group tree
- group managers can manage the group they manage plus descendant groups
- built-in system groups (`user`, `admin`) stay reserved for platform admins
- child group direct grants are bounded by the parent group's effective grant for the same service
- child groups do not inherit new services automatically; they must be granted explicitly, and those grants cannot exceed the parent

This lets NeuralMimicry delegate billing/admin/customer capabilities hierarchically without letting a lower level exceed the one above it.

Session/profile/internal identity payloads now include:

- `group_memberships`
- `manageable_groups`
- `visible_groups`
- `service_access`
- `visible_services`

Downstream services consume those resolved fields directly instead of reimplementing group and service policy.

## API surface

HTML routes:

- `GET /login`
- `GET /register`
- `GET /setup`
- `GET /logout`
- `GET /oidc/login`
- `GET /oidc/callback`
- `GET /sso`

Public JSON routes:

- `GET /api/health`
- `GET /api/version`
- `GET /api/auth/config`
- `POST /api/setup`
- `POST /api/register`
- `POST /api/login`
- `POST /api/login/mfa/totp`
- `POST /api/logout`
- `GET /api/session`
- `GET|POST /api/profile`
- `POST /api/profile/password`
- `POST /api/profile/mfa/totp/start`
- `POST /api/profile/mfa/totp/verify`
- `POST /api/profile/mfa/totp/disable`
- `POST /api/profile/passkeys/register/options`
- `POST /api/profile/passkeys/register/verify`
- `DELETE /api/profile/passkeys/<credential_id>`
- `POST /api/passkeys/authenticate/options`
- `POST /api/passkeys/authenticate/verify`
- `GET|POST /api/users`
- `POST /api/users/<username>/password`
- `GET /api/services`
- `GET|POST /api/groups`
- `GET /api/groups/<group_key>`
- `POST /api/groups/<group_key>/members`
- `DELETE /api/groups/<group_key>/members/<username>`
- `POST /api/groups/<group_key>/grants`
- `DELETE /api/groups/<group_key>/grants/<service_key>`
- `GET|POST /api/service-accounts`
- `GET /api/service-accounts/<service_account_id>`
- `POST /api/service-accounts/<service_account_id>/tokens`
- `DELETE /api/service-accounts/<service_account_id>/tokens/<token_id>`
- `POST /api/service-accounts/<service_account_id>/disable`
- `GET|POST /api/teams`
- `GET /api/teams/<team_id>`
- `POST /api/teams/<team_id>/invite`
- `POST /api/teams/<team_id>/leave`
- `POST /api/team-invitations/<invitation_id>/accept`
- `POST /api/team-invitations/<invitation_id>/reject`
- `POST /api/sso/issue`
- `POST /api/oidc/exchange`
- `GET /api/authz/nginx`
- `GET|POST /api/voice/tokens`
- `DELETE /api/voice/tokens/<token_id>`

Internal JSON routes protected by trusted internal bearer tokens:

- `POST /api/internal/voice/resolve`
- `POST /api/internal/credentials/verify`
- `GET /api/internal/users/<username>`

## Storage model

Customers supports two backends:

- Postgres-backed central store for production
- file-backed store for fallback and local development

The production default in the Continuum deployment is the shared tenant Postgres service:

- host: `postgres.postgres.svc.cluster.local`
- port: `5432`
- database: `continuum` by default unless overridden through the shared auth host vars

That keeps user/session/voice-token records in the cluster relational store rather than per-pod local files.
The same user metadata record now also holds validated profile settings defaults, so Refiner and Customers can share one source of truth for profile-backed LLM, assistant, solver, and UI preferences.

Relevant tables created in Postgres include:

- `nm_users`
- `nm_teams`
- `nm_team_memberships`
- `nm_groups`
- `nm_group_memberships`
- `nm_service_catalog`
- `nm_group_service_grants`
- `nm_service_accounts`
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
- `CUSTOMERS_SELF_REGISTRATION_ENABLED`
- `CUSTOMERS_AUTH_CHALLENGE_TTL`
- `CUSTOMERS_TOTP_ISSUER`
- `CUSTOMERS_PASSKEY_RP_ID`
- `CUSTOMERS_PASSKEY_RP_NAME`
- `CUSTOMERS_PASSKEY_ALLOWED_ORIGINS`
- `CUSTOMERS_BOOTSTRAP_GROUPS`
- `CUSTOMERS_BOOTSTRAP_SERVICE_CATALOG`
- `CUSTOMERS_BOOTSTRAP_GROUP_SERVICE_GRANTS`
- `CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNTS`
- `CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNT_TOKENS`
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

Customers targets Python 3.13.

Create a virtual environment and install the package:

```bash
python3.13 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

Run with the file-backed store:

```bash
export CUSTOMERS_SECRET_KEY='change-me'
export CUSTOMERS_APP_TOKENS='refiner=dev-refiner-token,billing=dev-billing-token'
export CUSTOMERS_BOOTSTRAP_GROUPS='[{"key":"user","name":"User","system":true},{"key":"admin","name":"Admin","system":true}]'
export CUSTOMERS_BOOTSTRAP_SERVICE_CATALOG='[{"service_key":"refiner","display_name":"Refiner","public_access_level":"request"},{"service_key":"billing","display_name":"Billing","public_access_level":"none"}]'
export CUSTOMERS_BOOTSTRAP_GROUP_SERVICE_GRANTS='[{"group_key":"user","service_key":"refiner","access_level":"use"},{"group_key":"user","service_key":"billing","access_level":"use"}]'
export CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNTS='[{"service_account_id":"conductor-sync","display_name":"Conductor Sync","service_key":"conductor","groups":["admin"]}]'
export CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNT_TOKENS='[{"service_account_id":"conductor-sync","token":"dev-conductor-service-token","label":"bootstrap-conductor"}]'
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
- generated app tokens for `refiner` and `billing` remain available for compatibility allow-lists
- Customers bootstraps managed backend service accounts and writes their bearer tokens under `.secrets/customers/<inventory-host>/<service>_access_token`
- Customers uses its own Customers-issued service-account token for nmchain by default
- persistent NFS-backed state PVC for local-store fallback and SSO artifacts

## Interoperability contract

For the split platform to be fully functional:

- Refiner should point `REFINER_CUSTOMERS_API_BASE` at Customers
- Billing should point `BILLING_CUSTOMERS_API_BASE` at Customers
- Refiner and Billing should use their own Customers-issued service-account tokens for protected internal routes
- nmchain should use Customers for session resolution, not Refiner

See also:

- `/home/pbisaacs/Developer/neuralmimicry/rag_demo/SERVICE_SPLIT_ARCHITECTURE.md`
