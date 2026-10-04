# OAuth/OIDC foundation

Permesi implements identity/authentication, sessions, organization authorization,
and OAuth registration management. It does not implement an OAuth authorization
server protocol yet. Applications retain their existing logical-tenant meaning and
own multiple clients, each with an immutable public/confidential classification.
For example one production Crono application can own crono-web, crono-cli, and
crono-worker with independent configuration. Classification alone enables no flow;
a confidential worker needs future client authentication and client-credentials
policy before it can obtain tokens.

The Rust `oauth` module owns client types, scope tokens, redirect validation, grant
context, and transactional persistence. HTTP adapters require a full session,
resolve active organization membership using existing policy, check owner/admin
for writes, and resolve the complete active application ancestry before invoking
that layer. Global platform capabilities do not bypass org checks. Non-members,
inactive memberships, unauthorized writes, wrong ancestry, and foreign-client IDs
return 404; missing/partial sessions return 401. Database details and submitted
security configuration are excluded from error logs.

## Persistence and identifiers

`oauth_clients` belongs to `applications`. The internal `id` and public `client_id`
are independently generated UUIDv4 values. The public value is suitable for exposure
and remains globally unique after deletion; it is never a credential. Names are
unique among non-deleted clients in an application. Client type, identifiers, and
application binding cannot change through the API. Disabled clients remain visible
to managers for remediation; deleted clients are hidden. The reusable active-client
loader rejects disabled/deleted clients and any deleted ancestor.

`oauth_client_redirect_uris` stores exact URI strings with per-client uniqueness.
`oauth_scopes` stores case-sensitive tokens, descriptions, and a protocol/application
kind in each application. Fixed protocol records are seeded for existing/new
applications. `oauth_client_scopes` connects registrations to that application's
registry using composite foreign keys. These prevent cross-application assignments,
even through direct SQL. API scope deletion removes dependent allow-list and grant
edges; recreating the name creates a new ID and does not restore client authority.

`oauth_client_secrets` anticipates rotation with revocable Argon2id PHC hashes and
a composite foreign key restricting secrets to confidential clients. No code writes
secrets in this phase, and the format constraint is not a password-hash verifier.
Future issuance must generate high-entropy random values, return plaintext only once
at creation/rotation, validate hashes and parameters, and never log or include secrets
or hashes in registration DTOs. Client authentication method and grant-type policy
will be configured explicitly in the token phase; public clients must never be
silently upgraded to confidential by possession of a supplied value.

`oauth_grants` binds one user, client, application, and explicit owning organization.
A membership foreign key and ancestry/lifecycle trigger reject an unrelated tenant
context at grant creation. The trigger share-locks the client, all ancestors, and
membership before accepting the grant, serializing consent with lifecycle and
membership mutations while allowing concurrent consent writers. Keep consent
transactions short; future parent lifecycle operations that also lock clients must
lock top-down. `oauth_grant_scopes` references both the grant context and
the client's configured scope edges, preventing arbitrary or foreign scopes. One
non-revoked grant per user/client/organization is permitted. Revocation is permanent;
reauthorization must create a new grant. Revoking still succeeds after membership
suspension or lifecycle changes. There is no grant-writing
API, consent UI, or implicit grant creation in registration management.

Identity and organization authorization are separate trust boundaries. A user's
membership in several organizations never expands one grant to all of them. The
chosen resource context is the exact client application within its owning organization;
cross-organization/resource delegation is intentionally unsupported by this phase.
Future issuance and refresh must recheck active membership, independent resource
authority, all lifecycle states, and consent. Parent resources have no move API;
any future hierarchy move must invalidate grants and enforce their tenant context.
Persisted membership or consent alone never proves current authorization.

Disabling/deleting a client revokes its credentials and saved grants. Re-enabling
does not restore either. Replacing redirect or scope allow-lists revokes saved
consent conservatively and commits atomically under a client lock. Failed validation
rolls back every change, including revocation. An empty scope allow-list delegates
no authority, and an empty redirect allow-list permits no interactive redirect flow.
Future token revocation and cache policy must account for these configuration changes;
no access or refresh token behavior is implied by this foundation.

Apply the additive canonical `db/sql/02_permesi.sql` script to an existing database
as the role that owns its existing tables with `ON_ERROR_STOP=1` before deploying the
new binary. The owner of the public schema alone may not own those tables. Reapplication
seeds missing protocol scopes and preserves existing registrations. No RLS is added.

## Management API

The base is
`/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth`.
Applications currently have no slug, so `app_id` is the existing application UUID.
Client paths use the public `client_id`; scope paths use registry UUIDs.

| Method | Suffix | Behavior |
| --- | --- | --- |
| POST, GET | `/clients` | Create or list client registrations |
| GET, PATCH, DELETE | `/clients/{client_id}` | Inspect, update name/disabled state, or soft-delete |
| GET, PUT | `/clients/{client_id}/redirect-uris` | Inspect or atomically replace exact redirects |
| GET, PUT | `/clients/{client_id}/scopes` | Inspect or atomically replace delegated scope names |
| POST, GET | `/scopes` | Define an API scope or list API/protocol entries |
| PATCH, DELETE | `/scopes/{scope_id}` | Update API description or delete API authority |

Client creation accepts `name`, `client_type`, and optional `redirect_uris`/`scopes`
arrays (default empty). PATCH accepts `name` and/or `disabled`; classification is
immutable. PUT payloads contain `redirect_uris` or `scopes`; an empty array removes
that allow-list. Scope creation accepts `name` and optional `description`; only the
description may be patched. Unknown request fields are rejected. Responses expose
reviewed registration/registry fields, never credential hashes or internal permissions.
Configuration errors and JSON parsing errors return 400. Payload deserialization
errors such as unknown fields return 422; the parser also classifies invalid enum
shapes as 400. Missing JSON content type returns 415, and uniqueness conflicts
return 409. OpenAPI registers these management endpoints
under `oauth-clients` and `oauth-scopes` without protocol placeholders.

## Redirect and scope policy

Redirect registration uses the existing URL parser to validate structure while
retaining original bytes for storage and exact comparison, following
[RFC 9700 §2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1).
It accepts absolute HTTPS for either client type. Only public clients may register
HTTP with canonical `127.0.0.1` or `[::1]` authorities. It rejects fragments,
wildcards, userinfo, whitespace/control characters, backslashes, non-ASCII URIs,
malformed percent escapes, parser-repaired authorities, relative URIs, other HTTP
hosts, and private-use schemes. URIs are capped at 2048 bytes and duplicate original
strings are rejected. Percent-encoded literal characters are not wildcard patterns.
There is no prefix, host-only, case-folded, decoded, or normalized URI comparison.

Loopback ports currently match exactly, too. Native-client application metadata,
private-use schemes, and the
[RFC 8252 loopback ephemeral-port exception](https://www.rfc-editor.org/rfc/rfc8252.html#section-7.3)
must be introduced deliberately before native authorization is supported.
`localhost` DNS names and production HTTP are rejected; use HTTPS for web development
or a public client's canonical loopback IP registration.

Scope names follow the case-sensitive printable ASCII scope-token syntax from
[RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3), capped at
128 bytes. Tokens are not trimmed or lowercased. `resource:action` is encouraged but
not required. Whitespace, controls, quotes, backslashes, empty tokens, and duplicates
are rejected. `openid`, `profile`, `email`, `address`, `phone`, and `offline_access`
are server-defined protocol entries; case variants cannot be defined as API scopes.
The internal `platform:` and `users:` namespaces are also reserved to prevent
misleading overlap with Permesi capabilities.

`Principal.scopes` remains the existing internal permission field. OAuth tokens
are distinct `OAuthScope` values with no Principal conversion. The pure requested-scope
helper fails unless every requested token belongs to both the configured client
allow-list and the independently verified tenant/user authority set. Protocol scopes
require additional OIDC policy: for example
[`offline_access` consent rules](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess).
The helper alone does not authorize claims, issue tokens, or validate consent.

## Next phase

Implement explicit issuer/audience configuration and signing-key rotation with OIDC
discovery/JWKS first. Then build Authorization Code + S256 PKCE validation and
single-use, short-lived code persistence with client, exact redirect, session,
tenant, nonce, and granted-scope binding. Build `/authorize` only when that state
machine can enforce authorization and consent. Introduce `/token` with explicit
confidential-client authentication, atomic redemption, access/ID token claim policy,
and fail-closed checks of current registration/tenant state. Public clients must
use PKCE, and client allow-lists remain an upper bound rather than consent.

Add refresh-token rotation with hashed storage, reuse detection, grant-family
revocation, and tenant/consent revalidation next, followed by consent/grants UI.
Machine-to-machine authorization needs a distinct service-principal and resource
policy; do not manufacture a user consent grant for a worker. Device flow,
introspection, token revocation endpoints, and client credentials token flow remain
out of scope. No `/authorize`, `/token`, discovery, or JWKS route is exposed here.
