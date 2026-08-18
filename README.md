# PQC Management API

NestJS control plane for the [PQC mTLS Gateway](https://github.com/PQC-RA/pqc-mtls-gateway).
Manages the post-quantum PKI and gateway policy:

- **Certificates** – sign ML-DSA-65 CSRs against the intermediate CA, list,
  inspect, and revoke (CRL regeneration), enrollment tokens.
- **Policy / routes** – per-client routing config, pushed to the gateway control
  plane over an HMAC-authenticated channel; persisted and re-pushed on startup.
- **CRL / audit / monitoring / health.**

## Authentication & authorization

All `/api/admin/*` routes are protected by a **global** `JwtAuthGuard`
(`APP_GUARD`) – every route is authenticated by default; a route is only public
if it carries `@Public()`. The gateway mints a short-lived RS256 JWT from the
verified mTLS client certificate and injects it as `Authorization: Bearer ...`.

The guard:
- verifies the RS256 signature against the gateway JWKS (by `kid`),
- pins `issuer` and `audience`,
- **authorizes by certificate fingerprint** against an explicit allowlist
  (`ADMIN_CERT_FINGERPRINTS`) – never by a cert subject field, so an enrollee
  cannot self-authorize by requesting `OU=admin` in a CSR. Authorization
  **fails closed** when the allowlist is empty.

### Role-based access control (RBAC)

The resolved fingerprint maps to a **role**, decided server-side from the
allowlists (never from a JWT claim):

- `ADMIN_CERT_FINGERPRINTS` → **admin** – read + write (every route).
- `AUDITOR_CERT_FINGERPRINTS` → **auditor** – read-only; blocked on
  `POST`/`PUT`/`DELETE`/`PATCH` (403).
- A fingerprint in neither list is denied (fail-closed).

Mutating routes carry `@Roles('admin')`; read routes carry no role requirement
and are open to both roles. `RolesGuard` runs as a global guard after
`JwtAuthGuard`. The caller can read its own identity/role via `GET
/admin/whoami`.

### Anti-CSRF

`CsrfGuard` (global, after auth) protects state-changing methods on
JWT-protected routes.

The primary defence is the custom `X-PQC-CSRF` header, which every such request
must carry non-empty or be rejected with 403. A cross-site page cannot set it:
CORS is locked to an explicit allowlist so the preflight is refused, and a plain
`<form>` cannot set custom headers at all.

`Origin` is pinned on top of that **when present**. Browsers always send it on
state-changing requests, so an `Origin` outside the `CONSOLE_ORIGIN` allowlist
(which defaults to `CORS_ALLOWED_ORIGINS`) is rejected. A request with no
`Origin` is a non-browser client and is authorised by the header alone, so admin
CLI tooling authenticated by its mTLS certificate keeps working.

`@Public()` routes are exempt.

### Admin-action audit trail

Every control-plane mutation (enrollment-token create/revoke, CSR enroll, cert
revoke, policy create/update/delete, CRL renew) is recorded to a tamper-evident
NDJSON log (`ADMIN_AUDIT_LOG`, default `/var/lib/pqc-mgmt/admin-actions.log`)
with a SHA-256 hash chain (`prev_hash` → `hash`). Entries capture the actor
(`sub`/`fpr`/`role`), action, target, **sanitized** params (never full tokens,
CSRs, or private material), and result. Read it via `GET
/admin/audit/admin-actions`. This is distinct from `GET /admin/audit/logs`,
which tails the gateway's Lua **data-plane** request log.

**Exception – `POST /admin/certs/sign` is `@Public()`**: this endpoint requires
no JWT or mTLS client certificate. It is reached via the dedicated enrollment
server on **port 8443** (nginx `ssl_verify_client` is not set there). The
single-use enrollment token is the sole authorization. See the enrollment token
design below.

## Enrollment token design

Tokens are issued by an admin (`POST /admin/certs/enrollment-tokens?cn=<CN>`)
and carry an `allowedCn` constraint set at creation time. When an operator
submits a CSR + token to `POST /admin/certs/sign`, the API:

1. Verifies the CSR self-signature.
2. Extracts the CN from the CSR subject.
3. Atomically checks the CN against the token's `allowedCn` (Redis Lua script
   or Node.js in-memory fallback). A CN mismatch returns 403 **without
   consuming the token** – the token remains valid for the legitimate operator.
4. Signs the CSR with the intermediate CA.

A stolen token cannot be used for a different CN, preventing routing-identity
hijacking.

## Relationship to the gateway

This repository publishes its own container image, and the gateway's
`docker-compose.yml` pins that image by digest. Neither repository needs to be
checked out inside the other: clone whichever you are working on.

```bash
git clone https://github.com/PQC-RA/pqc-mtls-gateway.git
git clone https://github.com/PQC-RA/pqc-mtls-management-api.git
```

> The management API is meant to run **behind the gateway** (it trusts the
> gateway-minted JWT). It binds to `127.0.0.1:3000` in compose; do not expose it
> directly.

## Local development

```bash
pnpm install
pnpm start:dev          # watch mode
pnpm test               # unit tests
pnpm test:e2e           # e2e tests
pnpm build              # production build (dist/)
```

OpenSSL 3.6 (with ML-DSA/ML-KEM) must be available at `/opt/openssl-3.6.2/bin/openssl`
(or set `OPENSSL_BIN`) for the cert-signing/revocation code paths.

## Configuration (env)

See `.env.example` for the full annotated list. Key variables:

| Var | Default | Purpose |
|---|---|---|
| `ADMIN_CERT_FINGERPRINTS` | *(empty → deny all)* | SHA-256 fingerprints (hex, no colons) → role **admin** (read+write) |
| `AUDITOR_CERT_FINGERPRINTS` | *(empty)* | SHA-256 fingerprints → role **auditor** (read-only) |
| `ADMIN_CERT_FINGERPRINTS_FILE` / `AUDITOR_CERT_FINGERPRINTS_FILE` | *(unset)* | mounted-secret variants (take precedence) |
| `CONSOLE_ORIGIN` | *(falls back to `CORS_ALLOWED_ORIGINS`; empty → deny all mutations)* | allowed Origin(s) for the anti-CSRF guard |
| `ADMIN_AUDIT_LOG` | `/var/lib/pqc-mgmt/admin-actions.log` | tamper-evident admin-action audit log (writable volume) |
| `JWT_EXPECTED_ISSUER` | `pqc-gateway` | required JWT `iss` |
| `JWT_EXPECTED_AUDIENCE` | `pqc-mtls-management-api` | required JWT `aud` |
| `GATEWAY_JWKS_URI` | `http://gateway:8081/.well-known/jwks.json` | gateway JWKS |
| `CORS_ALLOWED_ORIGINS` | *(deny)* | comma-separated browser origins |
| `REDIS_URL` | *(in-memory)* | durable enrollment-token store (required in production) |
| `PKI_*` path overrides | see `src/common/config/pki.config.ts` | CA directory, OpenSSL binary, CRL and renew-script paths. The defaults match the layout the gateway's compose file mounts |
| `NODE_EXTRA_CA_CERTS` | *(unset)* | trust anchor for the gateway's internal TLS. Required for the JWKS fetch to verify; compose sets it to the internal CA |

## API docs

Swagger UI is served at `/api/docs` when the app is running.

## Security notes

- No secrets are committed. PKI/keys are mounted from the host at runtime.
- In production, set `REDIS_URL` (the in-memory token store refuses to start
  under `NODE_ENV=production` because single-use is not durable/cross-instance).
