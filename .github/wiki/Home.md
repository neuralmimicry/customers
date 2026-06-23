# Customers — Wiki Home

**Customers** is the dedicated identity service for the NeuralMimicry platform. It owns user registration, authentication, browser sessions, optional 2FA (TOTP), passkey sign-in, SSO token issue/exchange, OIDC login, profile management, and voice-token lifecycle.

> ☕ [Support NeuralMimicry on Crowdfunder](https://www.crowdfunder.co.uk/p/qr/aWggxwPW?utm_campaign=sharemodal&utm_medium=referral&utm_source=shortlink)

---

## Quick navigation

| Page | Description |
|---|---|
| [Getting Started](Getting-Started) | Run Customers locally |
| [API Reference](API-Reference) | Auth, profile, SSO, passkey, voice-token endpoints |
| [Service Access Contract](Service-Access-Contract) | `service_access` claims and how they propagate |
| [OIDC Integration](OIDC-Integration) | Configuring OIDC login and SPA token exchange |
| [Configuration](Configuration) | Environment variables reference |
| [Contributing](Contributing) | Running tests, PR guidelines |

---

## Responsibilities

Customers owns:
- First-user bootstrap and local account creation
- Password verification and login throttling
- Authenticator-app 2FA enrolment and verification
- Passkey registration and sign-in (WebAuthn)
- Browser session cookies
- SSO token issue and exchange
- OIDC login handling and callback
- User profile reads and updates
- Group memberships, service grants, and team ownership

## Service access contract

All NeuralMimicry services consume the `service_access` contract issued by Customers. Claims follow `<service>:<level>` where level is `observe`, `use`, or `control`.

Service-account bearer tokens are used for backend-to-backend calls. They carry only their explicitly granted `service_access` entries and never receive human-fallback grants.

## Default port

`127.0.0.1:5010`

## Get involved

- 🐛 [Report a bug or request a feature](https://github.com/neuralmimicry/customers/issues)
- 💬 [Join the discussion](https://github.com/neuralmimicry/customers/discussions)
- 📧 Direct support: [info@neuralmimicry.ai](mailto:info@neuralmimicry.ai) · **£1,000/day + VAT**
- 🌐 [neuralmimicry.ai](https://neuralmimicry.ai)
