# TODO

- [ ] Audit Logs: Implement a view to see `admin_attempts` and other audit trails directly in the dashboard.
- [x] OAuth foundation: application-owned public/confidential clients, redirect and scope allow-lists, delegated scope registry, tenant-bound grant persistence, and session-authenticated management APIs.
- [x] OAuth configuration console: nested application navigation, client lifecycle, redirect allow-lists, scope registry, and client scope assignment; system OIDC entries remain read-only.
- [x] OIDC issuer/resource-audience configuration and shared Vault signing-key lifecycle/JWKS, with preparatory discovery metadata.
- [ ] Complete interoperable OIDC discovery with the real `/token` endpoint and token issuance; current metadata explicitly remains preparatory.
- [x] Authorization Code + S256 PKCE: validated `/authorize`, existing-session login/MFA resume, explicit tenant/resource binding, minimal consent/saved grants, and PostgreSQL-backed hashed single-use codes with transactional cross-replica redemption; security, database, browser, and independent Claude/Herdr reviews pass.
- [ ] Token endpoint: confidential client authentication/credential rotation, code redemption, and signed access/ID tokens.
- [ ] Refresh tokens: hashed storage, rotation/reuse detection, tenant and consent revalidation.
- [ ] Consent/grants UI and management; introspection, revocation, device flow, and client credentials remain future work.
- [ ] Tenant Isolation: Evaluate PostgreSQL RLS for org-scoped tables as defense in depth for the shared-database multi-tenant model.
