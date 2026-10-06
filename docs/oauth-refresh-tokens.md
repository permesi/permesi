# Refresh-token families

`POST /token` supports `grant_type=refresh_token` alongside authorization-code
exchange. Initial issuance requires `openid offline_access`, a valid nonce and
`prompt=consent` at `/authorize`, plus the ordinary client allow-list, tenant membership
and explicit saved-grant checks. The consent page explains continued offline access.
Even previously saved consent cannot bypass this explicit prompt. Other code exchanges
return no refresh token. This is a deliberately strict subset of the
[OIDC offline-access policy](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess).

Send `application/x-www-form-urlencoded` with `grant_type=refresh_token`, the opaque
`refresh_token`, and optional `scope`. Public clients supply `client_id`; confidential
clients use the same current/retiring HTTP Basic secret authentication as code exchange.
A body identifier must agree with Basic authentication. Session cookies confer no
client authority. Mixed code/redirect/verifier inputs, body secrets, duplicate values
and browser tenant overrides fail closed. S256 remains mandatory for the initial code
exchange; a refresh token is a separate single-use proof, never a PKCE downgrade.

## Storage and transaction boundary

PostgreSQL stores an immutable family bound to the exact internal client, application,
organization, user, grant, registry IDs/names, issuer, audience, original authentication
time and user authorization revision. Each opaque token contains 256 OS-random bits;
only its SHA-256 hash, predecessor hash, family, issuance/expiry and consumption time
persist. No raw refresh token is logged or stored. Families are independent of code/request
retention, so pruning a short-lived code cannot remove a still-live refresh family.

Client authentication and active ancestry locks precede token lookup. Rotation then
locks the current user before the family and token, matching password/recovery lifecycle
writers. It rechecks active membership, unrevoked exact grant and every original scope's
current registry identity, allow-list and consent edge. The original family scope set
is never expanded. A supplied scope must be a nonempty, unique, case-sensitive subset
with OIDC protocol dependencies preserved. It narrows this access token; the replacement
refresh token retains the original consented family scope set, as
[RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) specifies.
Omitted scope restores that original set. Scope removal cannot be bypassed by requesting
a smaller subset of a stale family.

Consumption, successor insertion, Vault RS256 access signing and an immutable hash-only
issuance receipt commit together. SQL, signing, cancellation or deadline failures before
commit leave the original token usable. An uncertain COMMIT or lost response requires
fresh authorization; there is no retry grace window. Refresh responses omit ID tokens;
they do not fabricate a new login, nonce or authentication time. OIDC permits omitting
an ID token during refresh. The initial code response still includes its verified ID token.

Reusing a consumed token irreversibly revokes the entire family, including its newest
successor, and **commits that revocation** before returning value-free `invalid_grant`.
Concurrent A/B redemption has one successful rotation; the losing reuse then revokes
the winner's family. Clients must serialize refresh calls and atomically replace their
stored token. This follows the replay defense in
[RFC 9700 section 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).
Wrong client identifiers or failed secret authentication cannot consume or revoke another
client's family. Verified current-authority loss permanently revokes the presented family.

Database constraints protect exact grant/tenant bindings, original consent provenance,
positive/bounded lifetimes, one root and one unused token per family, unique predecessors,
immutable family metadata and irreversible consumed/revoked transitions. Runtime grants
permit only insertion/read and the transition columns; they forbid rewriting bindings or
deleting/truncating replay history. Privileged cleanup removes a family's entire lineage
seven days after its absolute expiration, retaining spent tokens while the family can live.
Physical privileged grant/user deletion can still cascade; normal tenant lifecycle is soft deletion.
Both schema reapplication and the bootstrap's final grant segment enforce these restrictions.
The isolated runner checks the transactional schema verifier after canonical bootstrap grants;
Vault integration checks the effective permissions of minted and replacement runtime users.
Owner-authorized cleanup resolves trusted `public` tables before explicitly searching
`pg_temp`, preventing runtime-created temporary tables and triggers from crossing the
function-owner boundary. Actual Vault credential tests exercise that rejection on both
initial and replacement connections, following PostgreSQL's
[security-definer search-path guidance](https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY).

## Lifetimes and user lifecycle

`--oauth-refresh-absolute-ttl-seconds` / `PERMESI_OAUTH_REFRESH_ABSOLUTE_TTL_SECONDS`
defaults to 2,592,000 seconds (30 days), bounded to 1–7,776,000 (90 days).
`--oauth-refresh-idle-ttl-seconds` / `PERMESI_OAUTH_REFRESH_IDLE_TTL_SECONDS` defaults
to 604,800 seconds (7 days), with the same bounds and dispatch requiring idle ≤ absolute.
Absolute expiry never extends. Each rotation caps idle expiry by the remaining family
lifetime and the stricter current idle policy. PostgreSQL supplies all issuance/expiry time.
The endpoint retains complete-request deadlines, shared IP/client-IP budgets, strict
body bounds, generic 400/401/429/503 errors, `no-store`/`no-cache` and no redirects.

Password rotation and successful MFA recovery revoke all user families in the same
identity-locked transaction as session revocation. They advance a server-controlled
user authorization revision, also bound to codes. A pre-transition code cannot create
new authority afterward. Schema reapplication is idempotent; pre-upgrade codes lacking
a revision fail closed, so finish or drain their short TTL before upgrading. Existing
sessions and permanent password/factor records are not rewritten by this schema change.

Family/grant revocation prevents future token issuance. Already signed access/ID JWTs
remain valid until their short expiry under the current offline verifier policy.
Immediate resource-server revocation, introspection, a public revocation endpoint,
UserInfo, refresh-family management UI and sender-constrained tokens remain separate work.
This implementation does not claim OIDC certification or cross-browser/multi-host load coverage.

## Validation

Run `cargo test --locked -p permesi --lib token::refresh` for real PostgreSQL/Vault HTTP
regressions. They cover independent replicas, narrowing and scope preservation, replay
and concurrent family revocation, wrong clients/tenant inputs, current authority and
ancestor rejection, explicit offline consent despite saved grants, confidential secret
overlap/revocation, separate idle/absolute TTL expiry, bearer-free tracing, signing
and password rollback, recovery/code revision invalidation, code cleanup and schema/runtime
history protection and real SQL lock ordering against password rotation.
Authorization fixtures use a database named `permesi` so canonical bootstrap grants run
without substitution. Password/issuance race observers recognize the revision-changing
password write while still requiring a real database blocker before releasing issuance.
Run `just oauth-scenario-build`, then
`target/debug/permesi-oauth-scenario --suite refresh` for actual Web offline consent and
runtime-role A/B rotation/replay/lifecycle cases. The full suite includes these cases.
Independent review and complete gate results are recorded once completed in TODO.md and
the scenario validation record; passing isolated cases alone is not a release assertion.
