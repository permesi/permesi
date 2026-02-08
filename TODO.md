# TODO

- [ ] Security/AuthZ: Replace placeholder `Principal::allows` allow-all logic with deny-by-default server-side role checks (`user_roles`/`platform_operators`), wire users endpoints to authenticated principal extraction, and add forbidden-path regression tests.
- [ ] Security/AuthN/AuthZ: Fix `/v1/users*` auth extraction so unauthenticated/unauthorized requests return `401/403` (or `404` where intentionally hidden), never `500` for missing `Principal` extension.
- [ ] Security/AuthZ: Populate `Principal.scopes` from verified server-side data and define the `/v1/users*` permission matrix (`users:write`, `users:delete`, `users:assign-role`, `platform:admin`) so only intended operators/admins can use global user-management endpoints.
- [ ] Audit Logs: Implement a view to see `admin_attempts` and other audit trails directly in the dashboard.
- [ ] OIDC Core: Implement OpenID Connect authorization flows (client registration, discovery documents).
