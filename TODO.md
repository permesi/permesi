# TODO

- Decide admin token format (PASETO public vs JWT) and finalize header name for admin capability tokens.
- Define Vault key management details (key path, rotation strategy, JWKS/public-key fetch endpoint or static public key).
- Specify admin token claims (aud, sub, exp/iat/nbf, cap, optional session binding sid) and TTL policy.
- Implement admin guard middleware requiring both session auth and X-Permesi-Admin-Token.
- Add verification logic: signature, audience, expiry, sub == session user_id, optional sid binding.
- Wire admin guard into admin-only endpoints (platform maintenance actions).
- Add tests for admin token validation (missing/invalid/expired/sub mismatch/sid mismatch).
- Document the admin token minting flow in README (operator uses Vault/CLI to mint short-lived token).
- Add frontend support for org/project/env/app flows (API client + UI routes in apps/web).
