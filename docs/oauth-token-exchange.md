# Authorization-code token exchange

`POST /token` exchanges an issued authorization code for a Vault-signed RS256 access
token and, when `openid` was granted, an OIDC ID token. It implements only
`grant_type=authorization_code`. Refresh tokens, UserInfo, introspection, revocation
and the client-credentials machine grant remain separate milestones. `offline_access`
continues to be rejected. This implementation does not claim OIDC certification.

Send `application/x-www-form-urlencoded` with `grant_type`, `code`, the exact original
`redirect_uri` and `code_verifier`. Public clients also send their public `client_id`.
Confidential clients authenticate with HTTP Basic: form-encode the client ID and
secret separately, join them with a colon, and standard-base64 encode the result,
as specified by [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1).
A repeated nonempty body ID must match the Basic ID. Empty parameters are absent;
unrecognized extensions are ignored as RFC 6749 requires. Body client secrets,
duplicate parameters, multiple authentication headers, ambiguous encoding, scope,
and tenant overrides are rejected. Unimplemented resource/audience extensions are ignored;
the issuer's configured resource audience always applies. Ignored extensions never affect
the code's saved authority. Session cookies and internal Principal permissions confer no token authority.
S256 remains mandatory for both client types; neither secrets nor rotation bypass PKCE.
Native/back-channel clients use this endpoint independently of browser sessions. Browser
cross-origin access follows the existing configured CORS boundary; no wildcard is added.

The service owns one PostgreSQL transaction from current client authentication through
redemption, signing, hash-only receipt insertion and commit. Current/retiring secret
verification is bounded Argon2id, followed by shared client/credential/ancestor locks
and an expiration check. The code redeemer locks its hash row, verifies exact client,
redirect, S256, expiry, unused state, configured issuer/audience, active user/membership,
tenant ancestry, original grant and current scope edges. The HTTP form never selects
the organization. Those locks remain held through signing and commit, coordinating
with management revocation and lifecycle changes across replicas. A private transaction
guard prevents detaching or substituting authentication proofs.

Only committed tokens enter the response. Signing, deadline or receipt failures before
commit roll back consumption. A disconnected or timed-out COMMIT can have succeeded
without returning a response; retry then fails as `invalid_grant` and the client must
start a new authorization. Codes and unique issuance receipts prevent a second winner,
including concurrent exchanges on different processes. PostgreSQL stores SHA-256 code
and token hashes, receipt JTI/context and bounded timestamps, never bearer plaintext.
The runtime role can read/insert receipts but cannot update/delete/truncate them;
privileged cleanup removes expired receipts after seven days. Redirect retirement does
not erase receipts. Normal APIs revoke grants and soft-delete resources; physical grant/user
deletion through privileged SQL can cascade receipts. Their direct runtime privileges do
not remove the broader existing runtime role's trust boundary. No process-local map,
filesystem or sticky session supplies authority.

Access tokens follow the [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) shape:
`typ=at+jwt`, fixed `alg=RS256`, public `kid`, `iss`, user `sub`, resource `aud`, `iat`,
`exp`, random `jti`, public `client_id`, exact space-delimited granted `scope`, and one
`organization_id`, `application_id` and `grant_id`. Resource servers must verify the
signature, fixed algorithm/type, exact issuer/resource audience, expiry, tenant/resource
context and required delegated scopes. These JWTs never authenticate internal Permesi
management APIs. They contain pseudonymous identifiers, not profile/email attributes.

ID tokens use `typ=JWT`, the public client ID as audience, bound user/issuer, original
session `auth_time`, issued/expiration times, exact nonce and the RS256 `at_hash` of the
returned access token, following [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).
They are absent when `openid` was not granted. Profile/email/UserInfo disclosure is
not implemented; registry entries alone do not promise those claims. Access and identity
audiences/types are distinct and must not be substituted for each other.

Each exchange fetches shared Vault metadata afresh, selects an explicit current
RSA-2048 version, derives its published thumbprint `kid`, asks transit to sign with
SHA-256/PKCS#1 v1.5, and locally verifies every returned signature/version. It never
uses a cached active signing version or exports private keys. Signing reads never write
the public JWKS cache, so delayed metadata cannot replace a newer refresh. Ordinary JWKS reads
retain the bounded public cache. On an unknown kid, clients can request `/jwks.json`
with `Cache-Control: no-cache` or `max-age=0`; that forces a fresh read under a separate
shared `jwks_refresh` IP budget. Directive names are case-insensitive; repeated header
fields and quoted zero are accepted. Retained old versions verify already-issued tokens.
Runtime Vault policy adds signing permission only; rotation/export/retirement remain
operator actions. Apply the repository policy/schema updates before deploying this
binary, using the existing operator workflow; repository tests change only fresh stacks.

Discovery advertises `/token`, `client_secret_basic` and public `none`, only the
authorization-code grant and S256. Trusted authorization responses, including errors,
also carry the configured `iss`; clients must validate it alongside unchanged state,
as specified by [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html). Untrusted
redirects still receive direct errors. Registrations containing reserved response query
keys (`code`, `state`, `error`, `error_description`, `error_uri`, `iss`), including
encoded equivalents, are rejected; pre-existing conflicting rows fail authorization
directly without redirecting. Response parameters never carry tenant/scopes/user
metadata. Treat duplicate callback protocol parameters as invalid and remove code/state
from client URLs promptly; application/proxy logs must exclude bearer material.

All token responses are `no-store` with `Pragma: no-cache` and no Location. Errors
use value-free OAuth JSON. Invalid grants/requests return 400; failed Basic authentication
returns 401 with a Basic challenge; shared budget exhaustion returns 429; unavailable
exchange dependencies return 503. PostgreSQL/HMAC IP and client/IP-pair budgets
apply to the independent `token_exchange` action before hashing/signing. Token budgets
are independently configured, preserving login policy. A known client ID cannot exhaust
all users' allowance across other IPs. Missing IPs share a sentinel; the existing trusted
proxy boundary must sanitize forwarding headers. Storage failures fail closed. No automatic exchange
retry is performed.

Runtime settings are clap-defined and revalidated at dispatch:

| Environment variable / CLI flag | Default | Bounds |
| --- | --- | --- |
| `PERMESI_OAUTH_TOKEN_RATE_WINDOW_SECONDS` / `--oauth-token-rate-window-seconds` | 60 s | 1–3600 s |
| `PERMESI_OAUTH_TOKEN_RATE_IP_ATTEMPTS` / `--oauth-token-rate-ip-attempts` | 120 | 1–100000 |
| `PERMESI_OAUTH_TOKEN_RATE_CLIENT_IP_ATTEMPTS` / `--oauth-token-rate-client-ip-attempts` | 30 | 1–100000 |
| `PERMESI_OAUTH_ACCESS_TOKEN_TTL_SECONDS` / `--oauth-access-token-ttl-seconds` | 300 s | 1–3600 s |
| `PERMESI_OIDC_ID_TOKEN_TTL_SECONDS` / `--oidc-id-token-ttl-seconds` | 300 s | 1–3600 s |
| `PERMESI_OAUTH_TOKEN_TIMEOUT_MS` / `--oauth-token-timeout-ms` | 5000 ms | 1–30000 ms |
| `PERMESI_OAUTH_TOKEN_MAX_BODY_BYTES` / `--oauth-token-max-body-bytes` | 8192 bytes | 1024–65536 bytes |

The existing explicit issuer/resource audience, code TTL, lock timeout, credential
policy and JWKS TTL remain applicable. All replicas must use the same deployment
policy. Signed JWTs remain usable until their expiration unless a resource server
independently revalidates current grant/resource authority. Disabling a client or
deleting an application blocks new issuance; it does not remotely erase a signed token.
Likewise replay is denied, but automatic revocation of already-issued JWTs on code
replay is deferred with resource-server/introspection policy. Keep short lifetimes and
retain verification keys through token lifetimes, downstream caches and rollback windows.

Run `just oauth-scenario-build`, then `target/debug/permesi-oauth-scenario --suite token`
for the disposable real-service checks. See [scenario coverage](oauth-scenarios.md)
for HTTP/SQL/browser distinctions, artifacts and cleanup. Unit/router tests additionally
exercise deadline/signing rollback, expired codes, inactive membership, wrong bindings,
claim verification and concurrent single-use issuance with real PostgreSQL/Vault.

Primary validation passed `just test` (534 tests), the all-feature workspace suite
(564 tests), formatting/Clippy, schema bootstrap and idempotent reapplication with
runtime privilege checks, OpenAPI consistency, release WASM/native Web checks,
Chromium console and both real PostgreSQL browser tests, all 22 isolated scenarios
and seven process-harness checks. Terraform formatting passed without applying
infrastructure changes.

Two independent reviews used Herdr/OMP with `xai-oauth/grok-4.7`. The first reported
one high finding in callback response-key collisions, two medium findings in unknown
token parameters/empty optional IDs and delayed signing reads overwriting newer JWKS,
and one low finding in case-sensitive refresh directives. All four were independently
verified and fixed. Each regression group failed on the original implementation and
passed after correction. The second review inspected the corrected complete diff,
including fixed-issuer unknown-kid refresh in the test client, and reported no confirmed
defects. Execution evidence comes from the primary run; the reviewer did not rerun the suites.

Suspected error-envelope rewriting was rejected because mounted middleware preserves
OAuth JSON; suspected guaranteed rollback after interrupted commit was rejected because
commit acknowledgement can be ambiguous, while code/receipt uniqueness still denies replay.
Collapsing redeemer database failures to value-free `invalid_grant` preserves the existing
helper contract. Existing forwarding-header trust, broader runtime SQL privileges,
ancestor writer starvation and finite-lifetime JWT revocation remain explicit boundaries.
