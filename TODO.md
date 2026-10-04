# TODO

- [ ] Audit Logs: Implement a view to see `admin_attempts` and other audit trails directly in the dashboard.
- [x] OAuth foundation: application-owned public/confidential clients, redirect and scope allow-lists, delegated scope registry, tenant-bound grant persistence, and session-authenticated management APIs.
- [ ] OIDC discovery and signing-key lifecycle/JWKS with explicit issuer and audience configuration.
- [ ] Authorization Code + PKCE: authorization request validation, tenant/resource authorization, consent policy, and single-use codes before exposing `/authorize`.
- [ ] Token endpoint: confidential client authentication/credential rotation, code redemption, and signed access/ID tokens.
- [ ] Refresh tokens: hashed storage, rotation/reuse detection, tenant and consent revalidation.
- [ ] Consent/grants UI and management; introspection, revocation, device flow, and client credentials remain future work.
- [ ] Tenant Isolation: Evaluate PostgreSQL RLS for org-scoped tables as defense in depth for the shared-database multi-tenant model.
