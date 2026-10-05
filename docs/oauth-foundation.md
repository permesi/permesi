# OAuth/OIDC foundation

Permesi implements identity/authentication, sessions, organization authorization,
OAuth registration management, and Authorization Code + S256 PKCE. Token issuance
is still deferred; the authorization phase exposes no `/token`. Applications retain their existing logical-tenant meaning and
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

`oauth_client_secrets` stores salted Argon2id PHC hashes for confidential clients only.
The composite foreign key enforces that classification; plaintext is never persisted.
The service issues 256 random bits in canonical `pcs.<credential-uuid>.<base64url>` form,
returns plaintext once, and validates Argon2id v19, supported costs, salt and output
before verification. Registration/metadata DTOs never include hashes or secrets.
A supplied value cannot upgrade a public client to confidential. Client authentication
method and grant-type policy still belong to the upcoming token phase.

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
suspension or lifecycle changes. Registration management still creates no implicit grants. The authorization
flow records consent only after a bound full session explicitly allows the exact
validated request; saved grants may skip that minimal screen.

Identity and organization authorization are separate trust boundaries. A user's
membership in several organizations never expands one grant to all of them. The
chosen resource context is the exact client application within its owning organization;
cross-organization/resource delegation is intentionally unsupported by this phase.
Authorization and transactional code redemption recheck active membership,
resource ancestry, all lifecycle states, and consent. Future token issuance and
refresh must preserve those checks. Parent resources have no move API;
any future hierarchy move must invalidate grants and enforce their tenant context.
Persisted membership or consent alone never proves current authorization.

Disabling/deleting a client revokes its credentials and saved grants. Re-enabling
does not restore either. Replacing redirect or scope allow-lists revokes saved
consent conservatively and commits atomically under a client lock. Failed validation
rolls back every change, including revocation. An empty scope allow-list delegates
no authority, and an empty redirect allow-list permits no interactive redirect flow.

Tenant resources now support explicit [bottom-up soft deletion](resource-lifecycle.md).
An application requires all its OAuth clients to be explicitly deleted first, including
disabled registrations. This preserves the existing atomic client/credential/consent
revocation service. Scope registry metadata never prevents application deletion. Empty
environments, projects and organizations can then be removed without recursive cascades;
organization deletion requires its owner and the existing recent-authentication policy.
Creation and deletion coordinate through transaction-owned PostgreSQL parent locks.
Deleted ancestry cannot authorize outstanding requests or redeem old codes.
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
128 bytes. Tokens are not trimmed or lowercased. Permesi's application convention is
`<resource>:<action>`: the resource is the thing being protected and the action is
the operation being delegated. For example, `jobs:read` means delegated permission
to read jobs, and `runs:cancel` delegates cancellation of runs. Actions are defined
by the application; `approve`, `invite`, and `manage` are as valid as `read` or `write`.
The canonical persisted/wire value is still just `name`, not separate resource/action
columns. `ApplicationScope` validates the convention without interpreting action semantics.
Whitespace, controls, quotes, backslashes, empty tokens, and duplicates
are rejected. `openid`, `profile`, `email`, `address`, `phone`, and `offline_access`
are server-defined protocol entries; case variants cannot be defined as API scopes.
The internal `platform:` and `users:` namespaces are also reserved to prevent
misleading overlap with Permesi capabilities.

Application registrations must now contain exactly one colon and two nonempty parts.
Colon-free names (`jobs`, `custom.scope+value`), multi-part names (`urn:example:scope`),
and empty parts (`:read`, `jobs:`, `jobs::read`) are rejected. This is a deliberate
Permesi convention, not an OAuth requirement. OAuth scope tokens themselves remain
opaque, and protocol scopes are system-managed exceptions. Any valid single-colon
application name is interpreted according to this convention; actions are free-form
OAuth-safe strings, not a vocabulary inferred by the server.

This tightens the previous API, which allowed opaque application names. Before
upgrading another installation, audit existing application names for this format.
No rows, assignments, or grants are automatically renamed or deleted. Nonconforming
rows remain visible for explicit cleanup but cannot be newly assigned to clients.
Existing assignments remain until explicitly removed; the console shows unsupported
configured names with removal-only controls and requires removing them before Save.
Create replacement scopes and update client configuration deliberately. The database
schema remains unchanged, retaining its OAuth-token constraints and one name column.

The console creates conventional names from Resource and Action fields, previews
the composed token, and still submits `{name, description}`. Lists show derived
resource/action labels; client allow-lists group conventional names by exact resource,
with immutable OIDC entries in a separate group. No action list is
hard-coded. `users:invite` remains reserved under the existing internal namespace
policy; an application-specific resource such as `members:invite` is allowed.
These are OAuth delegated scopes, completely separate from Permesi internal
permissions such as `platform:admin` and `users:write`. Client assignment establishes
only the maximum scopes a client may request; it does not grant those permissions
to a user or prove tenant authorization.

`Principal.scopes` remains the existing internal permission field. OAuth tokens
are distinct `OAuthScope` values with no Principal conversion. The pure requested-scope
helper fails unless every requested token belongs to both the configured client
allow-list and the independently verified tenant/user authority set. Protocol scopes
require additional OIDC policy: for example
[`offline_access` consent rules](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess).
The helper alone does not authorize claims, issue tokens, or validate consent.

## Authorization Code + PKCE

`GET /authorize` validates an active public client identifier, the complete active
application/environment/project/organization ancestry and the exact registered
redirect before it trusts any redirect destination. It supports `response_type=code`
and query responses. Scopes are explicit, space-delimited, case-sensitive registry
names; empty tokens and duplicates fail. Each requested token must be in the client's
allow-list. OIDC claim scopes require `openid`; this phase requires a nonempty nonce
with `openid` and rejects a nonce without it. `offline_access` is rejected because
refresh issuance/consent policy is not implemented. S256 is mandatory for both public
and confidential clients, with canonical 43-character base64url SHA-256 challenges.
There is no plain fallback or omitted-method downgrade. Verifiers must have 43–128
ASCII unreserved characters and their S256 result is compared in constant time,
following [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html).

A request can optionally supply `organization_id`; it must equal the organization
resolved from the client's application hierarchy. Without it, the same exact owning
organization is resolved and persisted server-side. Active organization membership
is the current application-resource access policy, matching existing organization
reads. It permits consent only within that application and organization, never across
all of a user's memberships. There is no role-to-OAuth-scope mapping: platform operators
and internal `Principal.scopes` confer no delegated authority. Application APIs remain
responsible for their object/operation authorization; future finer application policy
must be checked here and during redemption instead of inventing delegation from
internal permissions.

`oauth_authorization_requests` snapshots registry IDs and names, exact redirect,
PKCE, state, nonce, application/organization and issuer/resource audience in PostgreSQL.
A random host-only Secure/HttpOnly/SameSite=Lax `__Host-permesi_oauth` cookie binds the
browser to its stored request using a SHA-256 hash. Without a full session the backend
redirects to the existing Web `/login?oauth_request=<opaque UUID>&oauth_expires=<milliseconds>`
route. The frontend retains the locator and a nonauthoritative cleanup deadline in
session storage across login/MFA, returning to `/authorize/resume` only from that flow
when a full session exists. MFA enrollment and recovery-driven re-enrollment wait until
users acknowledge their one-time recovery codes before resuming. Expired locators and navigation outside login/MFA clear both
values, so an abandoned request cannot redirect a later ordinary console login. Changing
the browser deadline never changes PostgreSQL expiry. The cookie and
server snapshot enforce integrity; modifying the locator cannot change authority.
Deploy the Web API base URL against the same issuer origin, over HTTPS. All replicas
must share PostgreSQL, session/OPAQUE configuration and issuer/resource audience.
Existing process-local login handshakes retain their existing operational constraints;
no OAuth request/code state depends on them or requires sticky routing.

The first authorized full session is bound permanently by user and session hash.
Resume and consent recheck an active user/session, active membership, every ancestor,
redirect and every original registry ID. Deleting/recreating a scope cannot revive the
snapshot. The minimal backend consent page shows the application/client, organization
and registry descriptions, with readable system OIDC labels. Its scope set is read-only.
The only form inputs are request locator, random CSRF capability and Allow/Cancel;
unknown form fields fail, and CSRF is bound to that browser and full session. All display
text is escaped and scripts, framing and external resources are prohibited. Consent
responses are never cached. Their CSP omits `form-action`: Chromium applies it to POST
redirects and cannot match registered IPv6 literal callbacks. The server, not CSP,
authorizes the exact registered redirect; the fixed form action and fully escaped display
fields cannot submit scopes or inject another form. Consent uses `Referrer-Policy:
same-origin` so native POSTs carry the real issuer Origin even in browsers without Fetch
Metadata. Other responses use `no-referrer`, including every redirect, so client callbacks
receive no issuer referrer. Opaque `Origin: null` posts still require browser-provided
`Sec-Fetch-Site: same-origin` in addition to browser/session/CSRF proofs. Foreign and
cross-site opaque origins are rejected; non-browser callers omitting Origin require all
stored proofs. Repeated completed consent POSTs return a generic, friendly 400 page
instructing the user to restart from the application, without reissuing a code.
`prompt=consent` requires a new explicit decision. `prompt=none` uses saved consent
only and returns `login_required` or `consent_required` when interaction is needed.
Other prompt values, response modes, Request Objects/URIs, claims requests, resource/
audience overrides, max_age, ID-token hints and ACR selection are rejected in this phase.
Unknown extensions are ignored, but known duplicate parameters fail without redirect.

Saved `oauth_grants` remain tenant-bound. An active grant can skip consent only when
it covers all requested registry IDs. Explicit Allow adds exactly those IDs to saved
consent; prior saved authority never enlarges a new code. Cancel permanently completes
the request and returns `access_denied`. Client allow-lists are always maximum authority,
never consent. Configuration changes revoke saved grants under existing client locks.
Client/ancestry/membership and scope checks run independently of the saved grant.

Issuance generates 256 OS-random bits encoded as unpadded base64url and persists only
SHA-256 in `oauth_authorization_codes`. Code rows bind the exact user, client, application,
organization, grant, redirect, scope IDs/names, PKCE, nonce, issuer/resource audience and
session authentication time. Request completion and code insertion commit together;
a unique request key prevents issuing twice. Composite grant foreign keys and snapshot
validation triggers prevent tenant/binding/scope mutation, and consumption is irreversible.
Database timestamps enforce expiry. Defaults are 120 seconds for codes and 600 seconds
for requests, configurable within 1–300 and 1–1800 seconds respectively. Expired requests
and codes are removed by the existing cleanup job after seven days.

`redeem_authorization_code` is a transaction-owned domain helper, not an HTTP endpoint.
It requires the caller's exact public client, redirect, organization and typed verifier,
locks current client/ancestry and code state, verifies issuer/audience, expiry, unused state,
S256, active user/membership and current consent/scope edges, then performs a guarded
consumption UPDATE. A caller-owned transaction lets the next token service commit
consumption and token persistence/issuance together; rollback restores the code after
failed issuance. Two service instances with separate pools can issue/resume/redeem against
the same database. Concurrent committed redemptions have one winner. Future confidential
client authentication must happen before invoking this helper; it does not authenticate
clients or issue tokens. Wrong bindings do not consume a valid code. A future token
service must also handle replay-associated token revocation as required by its token policy.

Start, resume and consent share the PostgreSQL-backed IP limiter's independent
`authorize` action and existing auth IP/window settings. Each stored request also uses
a keyed request-locator/browser-digest counter with the existing account/window budget. Counters contain
HMAC tags, not raw locators or IPs; failures return direct 429 and consume no login budget.
Existing trusted-proxy IP extraction policy is unchanged; without sanitized forwarding
headers all traffic shares the existing sentinel bucket. Shared client/ancestor locks
permit independent users to proceed concurrently while excluding management writes.
Race-safe grant insertion and row locks serialize consent only for the relevant grant;
configured transaction-local lock and statement timeouts bound PostgreSQL waits. The
future token HTTP adapter must apply its own request/client throttling before redemption.

Unknown/inactive clients and unregistered redirects receive direct errors with no Location.
After redirect trust is established, supported protocol errors return through that exact
registered URI with `error` and unchanged `state`. Successful redirects add only `code`
and unchanged `state`, preserving the original URI/query bytes. No scopes, user IDs,
organization IDs, nonce or raw metadata are returned. SQL failures return generic direct
500 responses. Diagnostics log only SQLSTATE class under the existing request route/span,
never SQL/error text, parameters, raw codes, verifiers, cookies or submitted authorization
values. Client callback handlers must immediately remove codes from URLs and protect
their own referrers/logs. Proxy/access logs must also exclude sensitive query/Location data.

## OIDC configuration and key lifecycle

`PERMESI_OIDC_ISSUER` / `--oidc-issuer` accepts one explicit canonical HTTPS origin,
without path, trailing slash, userinfo, query or fragment. `PERMESI_OAUTH_AUDIENCE` /
`--oauth-audience` is the explicit delegated access-token resource audience; future ID
tokens use the requesting public client ID as `aud`, not this resource audience. Both
must be configured together; without them protocol routes return 503 while management
remains available. Clap validates values and dispatch validates them again. TTL settings
are `PERMESI_OAUTH_CODE_TTL_SECONDS` / `--oauth-code-ttl-seconds` and
`PERMESI_OAUTH_REQUEST_TTL_SECONDS` / `--oauth-request-ttl-seconds`.
`PERMESI_OAUTH_LOCK_TIMEOUT_MS` / `--oauth-lock-timeout-ms` defaults to 1000 ms and
accepts 1–10000 ms; transaction-local lock and statement deadlines apply to every
authorization/redemption transaction and credential operation. Existing client writers
apply the statement deadline to ownership/lock coordination and restore the database's
previous statement policy afterwards so bulk consent revocation can finish. Their
individual lock waits retain the configured limit.

`PERMESI_OIDC_SIGNING_KEY` / `--oidc-signing-key` selects a single transit key name,
default `oidc-signing`, under the existing configured Vault transit mount. Terraform
provisions a distinct nonexportable, nondeletable RSA-2048 key with 30-day automatic
rotation. Runtime has read-only key access and cannot rotate, retire, export or sign.
Private key material stays in Vault. Startup fails if enabled OAuth cannot load a usable
key. `/jwks.json` converts all retained shared Vault public versions to RS256 JWKs and
uses RFC 7638 thumbprints as stable `kid` values. A per-replica single-flight cache absorbs
concurrent reads; it contains only public response data, never authoritative signing or
authorization state. `PERMESI_OIDC_JWKS_CACHE_TTL_SECONDS` / `--oidc-jwks-cache-ttl-seconds`
defaults to 30 seconds, bounded to 1–300. Refresh failures are briefly cached and fail
closed after expiry, never returning stale keys. Positive discovery/JWKS HTTP responses
use the same public max-age; failures remain no-store. Public metadata never consumes
login or database rate-limit budgets: discovery is static, and the single-flight cache
bounds Vault reads to at most one per cache interval on each replica, including failures.
There are no local
signing keys or local authoritative active-version caches. Selecting a different
key/mount requires the corresponding operator-provisioned read policy.

Operators can rotate the transit key using the existing Vault management workflow;
old public versions remain published for verification. Do not trim/retire previous
versions until all future signed-token lifetimes and downstream cache windows expire,
including rollback requirements. Runtime cannot perform these operations. The token
phase must publish new versions across replica/HTTP cache windows before signing,
pin the signing version and derive the matching published kid; signing permissions and token claim/lifetime configuration will be added then. Admission-token
PASERK keys and internal admin signing keys are separate trust domains.

`/.well-known/openid-configuration` advertises the configured issuer, working authorization
endpoint, JWKS URI, code/query/S256 support and prepared RS256/public-subject policy.
It explicitly lists only the authorization-code grant and no implemented token endpoint
authentication methods, avoiding Discovery defaults that imply implicit/client-secret
support. It intentionally omits `/token`, UserInfo and refresh features. This is pre-token metadata,
not a complete interoperable OpenID Provider: [OIDC Discovery §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
requires a token endpoint for code flow. This limitation must be removed when the real
safe token endpoint exists; no fake endpoint or invented token capability is exposed.

## Confidential-client credentials

Let `C` denote the existing application-scoped client path ending in
`/oauth/clients/{client_id}`. `GET C/secrets` lists current and unexpired retiring
metadata (`id`, `created_at`, `expires_at`). `POST C/secrets` accepts strictly `{}`
and creates an initial credential. `POST C/secrets/rotate` accepts only
`{"current_secret_id":"<uuid>"}`; both issuance routes return 201 with `credential`,
one-time `client_secret`, and optional `previous` metadata. `DELETE C/secrets/{secret_id}`
soft-revokes an owned credential at transaction commit and returns 204, including repeated
revocation. Wrong tenant/client IDs return 404. All credential responses use `no-store`.

Reads require the existing full session and active organization membership; writes
require owner/admin. The service rechecks active user/membership, organization roles
and complete client ancestry inside its transaction. Platform permissions provide no
bypass. Public clients cannot receive credentials; disabled clients cannot create or
rotate, but owned records remain revocable. Existing disable/delete operations revoke
all credentials; re-enabling restores none. Mutations reject untrusted browser Origins
and use shared PostgreSQL per-user/client counters with HMAC subjects and the existing
configured account-attempt/window limits. Revocation has an independent counter, so
exhausting issuance/rotation attempts does not block emergency revocation. Client
existence and tenant authorization are checked before consuming counters. These budgets
do not substitute for future token-endpoint authentication throttling.

Transaction-scoped PostgreSQL advisory locks coordinate each public client across
replicas: authorization/authentication readers take shared locks and mutations take
exclusive locks before authority row locks. Mutations first resolve immutable ownership
inside the selected application, so a foreign client ID cannot join another tenant's
exclusive queue. They reload authority after acquiring the lock. Queued writers prevent new readers from
bypassing revocation. Row locks still protect current authority and ancestry. Metadata
reads do not lock client or credential rows. A partial unique index permits
one non-revoked current credential; an overlap trigger permits one unexpired retiring
credential. Rotation atomically sets the old deadline and inserts the replacement.
A stale expected ID or another live overlap returns 409 without changing credentials.
Revoke the retiring credential to rotate immediately, or wait for its deadline.
PostgreSQL time determines expiration, not the browser clock. Identity/hash/creation
fields are immutable under updates, revocation cannot be undone by updates, and an
existing deadline may only shorten. New records start live with database-assigned creation
time; the first retirement cannot exceed the 3600-second policy ceiling. Runtime roles
cannot directly delete or truncate credential history; parent-row FK cascades still remove
it, including through the role's broader existing privileges.
This is defense in depth, not protection against a compromised schema owner or the
runtime role's broader existing write privileges; least-privilege/RLS work remains pending.

The overlap default is 900 seconds, configurable from 1 to 3600 with
`--oauth-client-secret-grace-seconds` / `PERMESI_OAUTH_CLIENT_SECRET_GRACE_SECONDS`.
Argon2id defaults are 19456 KiB, two iterations and parallelism one, with two hashing
workers. Configure `--oauth-client-secret-memory-kib` (19456–65536),
`--oauth-client-secret-iterations` (2–6), `--oauth-client-secret-parallelism` (1–4),
and `--oauth-client-secret-hash-workers` (1–8); corresponding environment names use
`PERMESI_OAUTH_CLIENT_SECRET_` followed by `MEMORY_KIB`, `ITERATIONS`, `PARALLELISM`,
and `HASH_WORKERS`. Clap and dispatch revalidate bounds even when OIDC is disabled.
Transaction-local lock and whole-statement deadlines reuse `--oauth-lock-timeout-ms`;
SQLSTATE 55P03/57014 return 503 for credential operations and the existing client
patch/delete/redirect/scope writers during coordination. Those writers restore the
database's prior statement policy after taking client authority locks, allowing bulk
consent revocation to finish while individual lock attempts remain bounded. Pool acquisition
is separately bounded by the existing SQLx pool policy. A short transaction rejects inaccessible/stale
states before hashing, releases its locks, and the final mutation reloads authority.
Hashing uses bounded blocking workers;
permits are acquired after database preflight/candidate lookup, immediately before
blocking work, and remain held through cancellation until that worker finishes.
Saturation returns 503 instead of queuing unbounded work. Capacity is local to a replica,
while credential validity and rotation state are exclusively PostgreSQL-backed.

The console shows current/retiring IDs and deadlines, confirms mutations, and provides
one-time copy/disclosure. Dismissal/navigation clears plaintext; browser storage and
URLs contain none. An ambiguous issuance failure refreshes metadata without retrying.
If an unreceived current credential exists, revoke it and create another; the previous
retiring credential retains its original deadline. This explicit recovery does not
recover or silently reissue the lost plaintext.

The internal verification helper returns client/application/organization authentication
proof only. It hashes before taking authority locks, then reloads and share-locks the
active client, ancestors and credential and checks expiration after acquiring locks.
The proof currently carries no transaction lifetime: the future `/token` integration
must enforce a transaction-owning guard or an equivalent matching-proof requirement.
Callers must retain the same transaction through future authorization-code redemption
and token issuance, and apply endpoint throttling first. Credentials confer no user
consent or delegated scopes. No `/token` or client authentication method is advertised yet.
Random credential IDs allow early rejection before hashing; timing may distinguish a live
locator from an unknown one, but does not prove possession of its random secret. The
future token endpoint must apply shared authentication throttling before verification.

## Roadmap

[TODO.md](../TODO.md) is the authoritative completion checklist. This document explains
boundaries and dependencies; README and the frontend documentation link back to it.
A milestone is complete only after its implementation, required checks and independent
review pass. Presently token issuance and interoperable OpenID Provider discovery remain pending.

After credential management, implement real `/token` exchange with confidential-client
authentication and mandatory S256 for public clients. Keep code consumption and token
persistence in one transaction, enforce confidential authentication with a matching
proof tied to that transaction, and throttle client authentication before hashing. Sign
access tokens through Vault with explicit issuer, resource audience and tenant/resource claims. Add rollback, replay, concurrent redemption
and cross-replica coverage before claiming access-token support.

Next add OIDC ID tokens bound to client audience, nonce and auth_time, issuer/mix-up
protections and complete accurate discovery/auth-method metadata. Validate that milestone
against actual token behavior; the preparatory document cannot claim interoperability.
Refresh tokens follow separately with hashed storage, rotation/reuse detection,
grant-family revocation and current tenant/consent revalidation. `offline_access` stays
rejected until refresh policy and issuance are implemented.

Authorization UX should show the signed-in account and callback host and provide a safe
restart path for expired requests, with account-switching policy and browser regressions.
Operational work includes Firefox/Safari coverage, multi-replica load tests for shared
locks/MultiXact behavior, and sanitized metrics/alerts. Ancestor rows still use ordinary
share locks: overlapping readers across clients in a subtree can starve organization,
project, environment or application updates/deletions. Existing ancestor writers lack
the client-level advisory coordination and consistent deadlines. The operations milestone
must add hierarchical coordination or bounded deadline/retry before claiming sustained-load
lifecycle guarantees. Those row locks continue to protect current ancestry during authorization.
Record coverage actually exercised;
local Chromium tests do not establish cross-browser or production load behavior.

Broader tenant-bound grants/consent management, UserInfo, introspection, token revocation,
device flow and client credentials/M2M remain pending. M2M requires explicit service-principal
and resource policy; possession of a confidential credential must not manufacture a user
grant. Audit UI and database least-privilege/RLS remain tracked separately in TODO.md.

## Review boundaries and deferred policy

The confidential-credential milestone passed four independent Claude security reviews
through Herdr. Confirmed medium findings in reader/writer starvation, foreign-tenant
coordination and bulk revocation deadlines were fixed with PostgreSQL regressions.
Lower-severity findings in CPU-permit ordering, revocation quotas, lifecycle constraints
and missing negative coverage were also resolved. No critical or high findings remain.
The latent transaction-owning authentication proof belongs to `/token`; inherited
ancestor-row starvation belongs to the operations milestone as described above.

Final primary validation passed `just test` (484 tests), all-feature workspace tests
(514), default/all-feature workspace builds, required formatting/Clippy, Web native and
release WASM builds, Chromium console tests, the separately exercised real-PostgreSQL
browser consent test, schema bootstrap/verification and OpenAPI byte consistency.
There are 21 PostgreSQL credential test groups plus crypto/config/native Web coverage.
Claude independently reran 60 OAuth tests, 24 authorization tests, formatting, Clippy
and OpenAPI consistency. The existing browser-target Clippy backlog is reproduced at
HEAD and tracked separately; Chromium coverage does not imply Firefox/Safari or load coverage.

A lost COMMIT acknowledgement can remain ambiguous if PostgreSQL committed before the
caller observed success; the review's earlier claim that cancellation always rolls back
was rejected for that reason. Metadata refresh and explicit revoke/create recovery handle
this case without automatically retrying issuance or recovering plaintext. Informational
trade-offs retained deliberately include early rejection of random credential locators,
brief membership locks for reads, and plaintext destruction on disclosure dismissal.


Independent Claude review through Herdr reproduced the cross-origin consent CSP defect
and identified client-lock/throttling and uncached Vault-read availability issues. The
corrected design uses script-free consent navigation, bounded shared transactions,
race-safe grants, shared quotas and a single-flight public JWKS cache. Regression tests
exercise both IPv4/IPv6 cross-origin browser callbacks, concurrent grants/redemption,
expired/abandoned login handles, recovery-code acknowledgement before OAuth resume,
browser-bound per-request budgets, database-independent metadata, cache coalescing/expiry
and value-free SQL diagnostics. Three review rounds independently verified every accepted
fix; the final review reports no remaining critical, high, medium or low findings. The
primary default/all-feature workspace suites and Claude's targeted Rust/browser suites
pass. No confirmed finding was rejected as a false positive.

The code phase deliberately requires an OIDC nonce even though Core makes it optional
for code flow, trading compatibility for explicit future ID-token replay binding. RFC 9207
issuer response parameters are not advertised or implemented yet; the token milestone
must complete provider metadata and mix-up defenses before claiming interoperability.
Account switching, consent account/callback-host presentation and broader grants UX remain
separate work; inactive tenant membership fails closed now. Existing broad database runtime
privileges are outside this change: SQL constraints defend normal writes and browser input,
not an already compromised database runtime role. Least privilege/RLS need a workspace-wide
review because that role can also write identity/session tables. Key retirement remains an
operator decision using signed-token lifetimes and cache windows; no automatic destructive
trimming is introduced. Chromium is covered locally; Firefox/Safari are not claimed tested.

The request budget incorporates both the opaque request ID and browser-binding digest
before its existing HMAC subject transform, so a leaked locator cannot exhaust another
browser's counter. Authorization IP quotas still count each start/resume/consent step;
NAT-heavy deployments should size the existing configured budgets accordingly. Public
metadata is served without those quotas or PostgreSQL access, while the public-key cache
coalesces upstream refreshes and bounds a Vault outage using its existing 30-second
transport timeout and negative cache. Shared client/ancestor locks need load testing for
PostgreSQL MultiXact churn at higher concurrency. This phase does not claim load testing.
The browser expiry is only a cleanup hint compared with its wall clock; severe clock skew
can require restarting the flow after login, while PostgreSQL remains the expiry authority.
Consent's same-origin referrer contains the incoming request parameters until it leaves
the issuer; reverse-proxy log configuration must exclude query strings and Referer values.
No authorization code is present in that referrer. Terraform was validated without plan
or apply; an operator must verify that any future mount-description change is an in-place
tune before applying it to preserve existing TOTP keys.

Two final informational items remain deliberately outside the secure code-state design.
Intermediate, uncommitted development schemas briefly supported an `oidc_metadata` rate
counter; a developer who applied that intermediate version must discard only those
obsolete counters before reapplying the canonical action constraint. No committed schema
or normal upgrade has that action, and canonical schema reapplication with live grants
and codes passes. Invalid resume locators still show a generic value-free JSON 400,
including browser-mismatched handles; consent replay already has a friendly HTML restart
page. A unified resume/error presentation is deferred to the broader authorization UX
milestone because it grants no authority and reveals no stored context.
