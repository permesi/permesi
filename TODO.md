# Roadmap & TODO

Authoritative tracker for planned milestones, open security/stabilization findings, and completed work. See the [Documentation Index](docs/README.md) for design and operations guides.

## Open Findings from the 2026-11 Stabilization Review

Confirmed during the OpenBao 2.7 and PostgreSQL 19 stabilization and left open because each changes a trust boundary, default, or user-visible flow:

- [ ] **Error diagnostics hygiene:** Upstream OpenBao error bodies (KV, TOTP, Transit, and the login and renewal calls) are copied into error messages and can reach logs/spans. Map them to fixed codes.
- [ ] **JWKS cache window during signing-key rotation:** A warmed replica can serve an older key set for one cache TTL while issuing tokens with a new `kid`, and HTTP `max-age` is not capped by remaining cache life.
- [ ] **`/token` pool holding across OpenBao calls:** `/token` holds its PostgreSQL transaction and pool connection across OpenBao signing calls, bounded only by the handler timeout. Fetch signing metadata first and gate exchanges below `max_connections`.
- [ ] **HTTP/2 header deadline:** Requests after the first on an HTTP/2 connection have no header-read deadline in either service (hyper offers one for HTTP/1 only), so an open stream with an unfinished header block is not timed out. Bound it at the ingress, or add a deadline when the server library supports one.
- [ ] **Smaller hardening items:** declare the session cookie as an OpenAPI security scheme on every cookie-authorized operation (none declares one today); paginate `GET /v1/users`; reduce per-request session auth DB checkouts/writes; zeroize OPAQUE seed, MFA pepper, and TOTP keys in memory; remove unused Genesis `tokens` indexes.
- [ ] **Deployment follow-ups:** Run the browser upgrade qualification once an OpenBao-era release exists to upgrade from; track OpenBao's migration of `api_proxy` from `bao agent` to `bao proxy`; exercise native Kubernetes auth against a live cluster.

## Planned Milestones

### OAuth 2.0 & OIDC

- [ ] **Introspection & immediate access-token revocation:** Define authenticated resource-server caller/disclosure policy and revocation semantics for already-issued JWTs.
- [ ] **Client credentials (M2M) grant:** Define explicit service-principal and resource policy; confidential secret management alone does not authorize machine grants.
- [ ] **Device authorization flow:** Durable device state, user approval, polling/expiry limits, and replay/tenant-boundary tests.
- [ ] **Administrator grant management & consent history:** Define tenant-manager authority, historical grant visibility, and refresh-family management without widening consent.
- [ ] **Formal OIDC conformance & broader interoperability:** Additional client libraries/browsers, formal OIDC conformance suite, and key-retirement/cache-window testing.

### Authentication, Tenants & Operations

- [ ] **Registration follow-ups:** CAPTCHA integration, distributed signup analytics/alerts, pending-account/outbox retention, and incident recovery policy.
- [ ] **Authentication operational follow-ups:** Multi-host load/fault benchmarks, aggregated outcome dashboards, and independent OpenBao exchange-key provisioning/rotation decoupled from the permanent OPAQUE seed.
- [ ] **Tenant create/edit authority ordering:** Evaluate locked active-membership/role revalidation during concurrent role revocation, matching the existing deletion boundary.
- [ ] **Tenant mutation UX follow-ups:** Optional expected-account check on final submit, immutable UUID conditions for slug-addressed child deletion, recoverable capability refresh, and reconciliation after ambiguous `DELETE` timeouts.
- [ ] **Fair hierarchical coordination & load testing:** Prevent overlapping subtree readers from starving ancestor writes under sustained load; add sanitized operational metrics and alerts.
- [ ] **Tenant isolation (RLS):** Evaluate PostgreSQL Row-Level Security on org-scoped tables as defense in depth.
- [ ] **Audit log viewer:** Dashboard view for `admin_attempts` and lifecycle audit trails.
- [ ] **Passkey browser follow-ups:** Validate transient user activation for asynchronous first-click passkey login preparation across Firefox and Safari.

### Testing, CI & Maintenance

- [ ] **Scenario & cross-browser expansion:** Browser WebAuthn/passkey and MFA/account-switching scenarios, Firefox/Safari coverage, multi-host/network-partition tests, and in-flight crash/response-loss coverage.
- [ ] **CI runtime & provenance follow-ups:** Profile remaining slow test groups, evaluate signed build manifests/checksums, and evaluate exact-commit cross-branch reuse policy.
- [ ] **OpenAPI operation-ID cleanup:** Resolve the pre-existing WebAuthn `register_finish` operation-ID collision between MFA and passkey enrollment with client compatibility handled separately.
- [ ] **Transitive maintenance advisories:** Track upstream removal of `paste` (via Leptos) and `astral-tokio-tar` (via `testcontainers`), and move `opaque-ke` from `5.0.0-pre.0` to a stable 5.0 release when published.

## Completed Milestones

- [x] **Database ownership & least privilege:** Non-superuser service owners, canonical explicit runtime grants, immutable saved-consent bindings, and `ON DELETE RESTRICT` foreign keys protecting retained receipt/refresh history ([database hardening](docs/database-hardening.md)).
- [x] **Registration & verification security:** Reserved-domain denial by default, public/restricted/closed admission, pending-only single-use verification, credential-free logging, and outbox/TLS SMTP delivery with durable leases ([registration security](docs/registration-security.md)).
- [x] **Auditable account suspension & containment:** Recently authenticated operator suspension/reactivation, atomic session/proof/grant/refresh retirement, database-clock login proof cutoff, and append-only audit ([account containment](docs/account-containment.md)).
- [x] **Operator privilege lifecycle:** Two-operator request/approval workflow with sole-bootstrap exception, immediate disable, session-bound cross-replica admin elevation with designation revision binding, and append-only audit ([operator designation](docs/operator-designation.md)).
- [x] **Read-only platform tenant inspection:** Global operator `/v1/admin/orgs` hierarchy browsing with active-ancestry filtering and bounded pagination ([admin tenant inspection](docs/admin-tenant-inspection.md)).
- [x] **Durable OPAQUE & WebAuthn exchanges:** Shared XChaCha20-Poly1305 AEAD-sealed PostgreSQL state, hashed references, atomic single-attempt consumption, discoverable passkey enforcement, and cross-replica support ([OPAQUE](docs/opaque-exchanges.md), [WebAuthn](docs/webauthn-exchanges.md)).
- [x] **Password/MFA lifecycle & lockout:** Atomic full/limited session and refresh revocation on password rotation/recovery, 10-minute recency rechecks on factor mutations, single-use TOTP time steps, and PostgreSQL-backed primary-login MFA challenge attempt limits ([MFA lifecycle](docs/mfa-lifecycle.md)).
- [x] **Authentication admission & transport trust:** Shared HMAC per-subject and per-purpose pending quotas, explicit trusted-proxy CIDR / Unix-proxy IP verification, bounded DB waits, and sanitized outcome tracing ([authentication operations](docs/authentication-operations.md)).
- [x] **Tenant resource lifecycle & bounded mutations:** Explicit bottom-up soft deletion, capability-aware typed confirmations with inline OPAQUE reauthentication, and configurable lock/handler deadlines with cancellation-safe transaction startup ([resource lifecycle](docs/resource-lifecycle.md), [mutation deadlines](docs/tenant-mutation-deadlines.md)).
- [x] **OAuth/OIDC foundation, token exchange, refresh & UserInfo:** Client/scope management, `<resource>:<action>` convention, confidential Argon2id secrets with overlap rotation, Authorization Code + S256 PKCE, transactional OpenBao RS256 `/token`, `/jwks.json` and discovery, rotating refresh families with reuse revocation, `POST /revoke`, `GET`/`POST /userinfo`, and Connected apps user grant revocation ([OAuth foundation](docs/oauth-foundation.md), [token exchange](docs/oauth-token-exchange.md), [refresh tokens](docs/oauth-refresh-tokens.md)).
- [x] **Isolated multi-replica OAuth/HA scenario runner:** Standalone `permesi-oauth-scenario` binary with 3–5 replicas, 40 protocol/security/lifecycle/HA/interop cases (including `openidconnect-rs` and Better Auth fixtures), rolling restarts, replica outages, and `pidfd_open` recovery ([OAuth scenarios](docs/oauth-scenarios.md)).
- [x] **CI, browser, WASM & contract gates:** Required hosted Chromium/PostgreSQL browser gate, strict native and `wasm32-unknown-unknown` Clippy, OpenAPI byte-for-byte drift check, fixture profiling, cached build-identity checks, hosted timing helper, and `rustls-pki-types` PEM parsing ([CI & testing](docs/ci-and-testing.md)).
