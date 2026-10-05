# TODO

This is the authoritative milestone checklist. README summarizes the implemented status;
[OAuth documentation](docs/oauth-foundation.md#roadmap) describes milestone dependencies
and completion boundaries. Completed entries require passing checks and review evidence.

- [ ] Audit Logs: Implement a view to see `admin_attempts` and other audit trails directly in the dashboard.
- [x] OAuth foundation: application-owned public/confidential clients, redirect and scope allow-lists, delegated scope registry, tenant-bound grant persistence, and session-authenticated management APIs.
- [x] OAuth configuration console: nested application navigation, client lifecycle, redirect allow-lists, scope registry, and client scope assignment; system OIDC entries remain read-only.
- [x] Tenant resource lifecycle: explicit bottom-up soft deletion, owner-only recent-authenticated organization deletion, transactional creation/deletion races, typed console confirmations, and accessible Material Symbols scope actions. Database/browser checks and three independent Claude/Herdr review rounds pass; bounded coordination and permission-aware control visibility remain follow-ups.
- [ ] Tenant management capabilities: add a server-issued capability contract for permission-aware destructive-action visibility without exposing raw membership roles. Backend authorization remains mandatory.
- [x] OIDC issuer/resource-audience configuration and shared Vault signing-key lifecycle/JWKS, with preparatory discovery metadata.
- [x] Authorization Code + S256 PKCE: validated `/authorize`, existing-session login/MFA resume, explicit tenant/resource binding, minimal consent/saved grants, and PostgreSQL-backed hashed single-use codes with transactional cross-replica redemption; security, database, browser, and independent Claude/Herdr reviews pass.
- [x] Confidential-client credentials: create/rotate/revoke APIs and console, bounded Argon2id verification, tenant ACLs, PostgreSQL overlap state, cross-replica/race tests, and independent Claude/Herdr review. Repository checks and four independent Claude/Herdr reviews pass; this does not implement the `client_credentials` grant.
- [ ] Token exchange and access tokens: implement real `POST /token`, public-client S256 and confidential-client authentication, transactional code redemption/issuance with a transaction-owning authentication guard (or equivalent enforced matching proof), token-endpoint authentication throttling, and Vault-signed tokens with explicit issuer/resource audience and tenant claims. Depends on credential management; complete with negative, rollback, replay and concurrency coverage.
- [ ] OIDC ID tokens and complete discovery: bind client audience/nonce/auth_time, finish issuer/mix-up protections and accurate token-endpoint/auth-method metadata. Depends on working token exchange; current discovery stays preparatory until validated interoperability.
- [ ] Authorization UX: show signed-in account and callback host, provide safe restart handling for expired requests, and add account-switching policy. Preserve durable request bindings and tenant consent; complete with browser regressions.
- [ ] Frontend WASM lint gate: resolve the existing browser-only Clippy backlog and add it to CI without suppressing production lints. Native workspace Clippy and WASM build/browser checks remain required.
- [ ] OAuth operations: test Firefox/Safari and multi-replica load/lock behavior, add hierarchical coordination or bounded deadline/retry for ancestor mutations that overlapping readers can starve, and define sanitized metrics and alerts without secret/request leakage. Depends on the exercised protocol milestones; record actual coverage and limits.
- [ ] Refresh tokens: hashed storage, rotation/reuse detection, grant-family revocation, and tenant/consent revalidation. Depends on token exchange; complete with concurrent rotation/replay tests. Keep `offline_access` rejected until policy and issuance work.
- [ ] Broader consent/grants UI and management: expose tenant-bound saved authority and revocation without widening consent; add authorized API/browser coverage.
- [ ] UserInfo, introspection and token revocation: define authenticated caller/claim disclosure policy after token issuance exists; add protocol/security tests.
- [ ] Device authorization: define durable device state, approval and polling/expiry limits; add replay and tenant-boundary tests.
- [ ] Client credentials/M2M grant: define service-principal/resource policy and implement its token grant separately; confidential secret management alone does not authorize machines.
- [ ] Tenant Isolation: Evaluate PostgreSQL RLS for org-scoped tables as defense in depth for the shared-database multi-tenant model.
