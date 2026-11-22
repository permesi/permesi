# Isolated OAuth scenarios

The `permesi-oauth-scenario` workspace binary is an extensible integration foundation
for the OAuth roadmap. Its disposable PostgreSQL and OpenBao launch actual Permesi and
Genesis from an empty identity/tenant schema. It tests the compiled Web console and a
small owned callback client, rather than mocking an OAuth application. Accounts are
registered and verified through real admission-protected OPAQUE APIs; browser login
creates actual full sessions. No user, membership, session or grant is seeded directly.

## Running

On Linux with working local Podman (and Node 24 for the `full` and `interop` suites,
which include the Better Auth cases), install the Better Auth fixture dependencies
once and build the workspace artifacts:

```sh
just oauth-scenario-better-auth-setup   # required once on a clean checkout for full / interop suites
just oauth-scenario-build
```

Then run the desired suite or case:

```sh
target/debug/permesi-oauth-scenario --list
target/debug/permesi-oauth-scenario --suite smoke
target/debug/permesi-oauth-scenario --suite full
target/debug/permesi-oauth-scenario --replicas 5 --suite full --access-token-ttl-seconds 10
target/debug/permesi-oauth-scenario --replicas 5 --suite ha
target/debug/permesi-oauth-scenario --suite token
target/debug/permesi-oauth-scenario --suite refresh
target/debug/permesi-oauth-scenario --suite interop --access-token-ttl-seconds 10
target/debug/permesi-oauth-scenario --case redemption.bindings
target/debug/permesi-oauth-scenario --case authentication.shared_exchanges
target/debug/permesi-oauth-scenario --case authorization.consent --repeat 2 --seed 7
just oauth-scenario-better-auth
```

The binary also runs from another directory with explicit `--permesi-bin`,
`--genesis-bin` and `--web-dist` local artifact paths. `--scenario` selects a
version-one JSON manifest; the embedded default is
`tools/oauth_scenario/scenarios/default.json`. It creates one organization/project,
Development and Production environments, one application in each, four custom scopes
and public/confidential clients with different allow-lists. Public clients allow
`openid`, `profile` and one custom scope; requests use only `openid` and that custom
scope, proving the allow-list does not become consent. Refresh cases explicitly add
`offline_access` through management APIs and require visible `prompt=consent` approval. Every case creates a fresh
tenant; logged-in owner and non-member actors are shared within a repetition.
Repetitions start fresh stacks. No case depends on another case's grants or tenant mutations. Traffic resets to A
for every case; the topology-changing failover case always runs last in a repetition.
Token verification refreshes this issuer's fixed JWKS URL once when a cached set lacks
the returned kid; it never retries exchange or relaxes signature/claim/replay assertions.

Manifests accept resource names, environment slugs/tiers, applications and custom
scope names/descriptions. They reject unknown fields/versions, internal/protocol scope
names and ambiguous topology before startup. Bounds are one to eight environments,
at most one production environment, one to four apps per environment and two to sixteen
scopes per app; environment slugs use the API's 2–32 character bounds. Infrastructure addresses, callbacks, roles and credentials are not
manifest inputs. `--seed` affects fixture naming only; security material uses OS entropy.

## Runtime and reports

Every run owns UUID-labeled Podman containers/network, random loopback ports, private
files and fresh credentials. Dependency ports bind to `127.0.0.1`. Real service
processes use the existing same-host Unix-socket mode in a mode-0700 directory. A
test-only HTTPS gateway keeps one stable issuer while selecting three to five actual
replicas (`--replicas`, default three).
OAuth requests, sessions, grants, codes and encrypted OPAQUE exchanges use shared
PostgreSQL. Ordinary browser setup selects A; `authentication.shared_exchanges` deliberately
hands native login from A to B, reauthentication from B to C and replay/session-binding
rejections across all three using real runtime-role APIs. The failover case stops A
after request persistence and completes consent on B. At least as many independently
minted runtime database identities as configured replicas are required. Code and refresh
races synchronize requests across every configured socket and require exactly one
committed winner plus `invalid_grant` from every other participant. Offline authorization starts
on A, code exchange uses B and refresh rotation uses C. Both service databases use non-superuser schema ownership and canonical runtime policies;
see [database hardening](database-hardening.md) for rollout requirements.
This is multi-process state coverage on one host; see [High-availability topology and recovery](#high-availability-topology-and-recovery)
for rolling replacements, abrupt backend loss, and journaled process recovery.
Multi-host transport and load testing remain separate.

Service children receive explicit existing CLI inputs and fresh private credential
environments, with inherited deployment/proxy/OpenBao settings cleared. The runner
selects local Podman or verifies a local Unix Podman API for CI; remote TCP/Docker
engines are rejected. It never adopts existing resources or prunes the shared engine.
The run CA is trusted only by its native clients and disposable Chromium container.
TLS verification stays enabled. Chromium uses host networking to reach the owned
loopback listeners; this local test transport does not provide network sandboxing.
Build artifacts are trusted local inputs. `--expected-commit` (or
`PERMESI_SCENARIO_EXPECTED_COMMIT`) optionally
requires the runner and both services to match a full commit and workspace version
before startup; CI always sets it to the workflow SHA. Commit labels detect accidental stale/mixed builds and do not attest hostile executables.
See [cached build identity](ci-and-testing.md#cached-build-identity-and-commit-verification).
Cached dependency/browser images remain available; cleanup removes run containers,
networks and private files. The public HTTP loopback callback uses a different
hostname from the issuer, so issuer cookies do not travel to the client. Browser
worker content determines the image tag, preventing stale reuse between runner versions.

Default deadlines are readiness 90 seconds, HTTP 10 seconds, browser actions 15 seconds,
whole run 900 seconds and bounded cleanup. CLI ranges prevent unbounded configuration.
`--access-token-ttl-seconds` defaults to the product's 300 seconds and accepts 1–3600.
It passes the existing Permesi CLI/dispatch validation on every replica. Use 10 seconds
for the interoperability/full suite's real expiration case, as CI does; very short
lifetimes may expire positive controls during browser/network work. ID-token and
authorization-code lifetimes retain product defaults. No test changes stored timestamps.
`--auth-rate-limit-ip-attempts` defaults to 1,000 and accepts 1–100,000. It configures
the existing product CLI on every disposable replica and the effective value appears
in `report.json`. The full suite makes more than the production default's 100
authorization requests per window through one fixture identity, so it needs an explicit
bulk-test IP budget. The separate `--auth-rate-limit-account-attempts`,
`--oauth-token-rate-ip-attempts` and `--oauth-token-rate-client-ip-attempts`
also default to 1,000, accept 1–100,000 and appear in the report. Repeated owner
logins and all-replica token races otherwise exhaust the product's per-account
or per-client budget during a five-replica full run. These are finite fixture-only
settings passed through the existing Permesi CLI; production defaults,
account/action separation and pending-state quotas remain unchanged. Rate limiting
remains PostgreSQL-backed and enabled.
Use `--auth-rate-limit-ip-attempts 100` to reproduce the full suite's 429 negative control.
Dedicated product HTTP/database regressions independently verify rejection and outage
behavior with low budgets. The runner never resets counters or retries denied assertions.
Only readiness polls retry; assertions, secret issuance and mutations do not retry.
Startup failure, timeout, SIGINT and SIGTERM enter cleanup. Owned processes have
kill-on-drop fallback. SIGKILL or host failure cannot run destructors; use the
non-secret `ownership-<repetition>.json` to identify exact resources for recovery.
It records labeled container/network names, the private directory, and service/browser-controller
PIDs with Linux birth ticks. Each child/replacement is retained and atomically journaled
before awaiting readiness. Verify labels, PID birth ticks and the private socket path
before recovering a process. Before removing private files, verify the directory is
an owned mode-0700 directory under the temporary root with a matching `owner` marker.
A reused name or PID never establishes ownership. Host failure cannot guarantee a
last-write recovery record, and SIGKILL in the fork-to-journal interval remains a limitation.
Never use shared-engine prune/reset for recovery.

Reports default to `.tmp/oauth-scenarios/<run-id>/report.json` and `junit.xml`;
`--report-dir` changes the parent. Artifacts are published atomically with private file permissions.
JSON schema version one records case IDs, durations,
repetitions, configured replica count, assertion/infrastructure/harness/cleanup classifications, fixture/build
identities, resolved image IDs and explicit planned capabilities. Failure, blocked
selected cases or cleanup errors return nonzero. Screenshots, traces, browser logs,
HTTP payloads/headers and callback query strings are excluded. Errors use curated
static messages; third-party diagnostic strings are discarded. Positive browser
navigation failures distinguish protocol, rate-limit and dependency HTTP statuses
using fixed messages, without reporting URLs, request values or response bodies. Podman logging is
disabled and checked for every run container, including private browser IPC and OpenBao
dev output. Chromium CDP uses inherited pipes, with no host debugging TCP listener. Validate runner
ownership, startup failure, interruption, deadline expiry, injected cleanup failure,
repetitions and parallel isolation with
`just oauth-scenario-harness-test`, or select five replicas with
`just oauth-scenario-harness-test --replicas 5`.

## Coverage

| Stable case | Actual coverage |
| --- | --- |
| `foundation.provisioning` | Real accounts/login, manifest hierarchy/registry, immutable protocol scopes, actual console, accurate code/token discovery and public JWKS |
| `authorization.consent` | Real browser S256 consent, exact scopes/state/nonce/redirect/TTL, high-entropy code and hash-only row |
| `authentication.registration_policy` | Reserved-domain signup has no side effects; pending activation and verifier replay cross replicas, and mailbox links cannot reactivate disabled users |
| `authentication.account_containment` | Real operator suspension on A and reactivation on B permanently retire sessions, codes, grants, refresh families and pending proofs across every replica, while allowing fresh login/consent recovery |
| `authentication.shared_exchanges` | Real OPAQUE login A→B, reauthentication B→C, actual session verification and replay/same-user session-binding rejection across A/B/C |
| `ha.rolling_restart` | Replace every configured process with SIGTERM and a clean exit; preserve pending code/reauthentication, session identity and cross-incarnation OPAQUE/code replay rejection |
| `ha.replica_outage` | Abruptly stop the last backend; issuer returns 503 and direct exchange fails without consuming a code; surviving code/refresh races commit once and recovered replicas reject replay |
| `authorization.login_resume` | Anonymous durable request on A, actual Web login, resume/consent on B |
| `authorization.cancel_saved` | Cancellation without code, fresh saved-consent code/nonce/bindings, exact saved scopes, forced consent and added browser scope-field rejection |
| `authorization.validation` | Unknown/disabled/deleted clients; modified/prefix/foreign redirects; response type; unknown/disallowed/duplicate/internal scopes; missing/malformed/plain PKCE and missing nonce |
| `authorization.tenant_isolation` | Non-member/foreign management and authorization; browser tenant input cannot override client ancestry |
| `redemption.bindings` | Independent pool, another registered public client, second registered redirect, wrong tenant/verifier, rollback and committed replay |
| `redemption.expiration_race` | Barrier-synchronized transactions, one committed winner; pre-expiry rollback validation and real-issued code expiration |
| `credentials.lifecycle` | One-time create/rotate, metadata without plaintext, bounded overlap, revoke; public secret issuance denied |
| `authorization.replica_failover` | Persist on actual A, stop A, consent on actual B, internal redemption |
| `tenant.bottom_up_deletion` | Populated-parent conflicts, explicit client deletion, bottom-up soft deletion, inaccessible reads and revoked code authority |
| `authorization.client_disabled_during_consent` | Show consent on A, disable on B, submit on A: direct issuer error, zero codes, fresh-consent recovery after re-enable |
| `authorization.scope_removed_during_consent` | Remove requested scope on B before approval on A: `invalid_scope` through exact callback/state, zero codes, recovery after restoration |
| `authorization.redirect_removed_during_consent` | Remove exact callback on B before approval on A: direct issuer error without Location, zero codes, fresh-consent recovery |
| `redemption.client_disable_restore` | Initially usable code, committed disable/re-enable on B, revoked old grant remains unusable even after fresh consent |
| `redemption.scope_remove_restore` | Scope removal/restoration cannot revive old code; fresh grant/code has exact bindings, commits once and rejects replay |
| `redemption.redirect_remove_restore` | Callback removal/restoration cannot revive old code; fresh consent creates a different grant/code |
| `refresh.rotation_reuse` | Actual offline consent, A/B/C runtime-role rotation, independently verified narrowed JWT/context, hashed lineage and replay-family revocation |
| `refresh.replica_race` | Concurrent refresh on every configured replica, one committed issuance and losing-reuse revocation of the winning successor |
| `refresh.lifecycle` | Scope removal/restoration through management APIs cannot revive the old refresh family |
| `token.public_claims` | Browser code on A, runtime-role HTTP exchange on B, ignored extensions cannot replace saved nonce, independently verified signatures/issuer/audiences/nonce/auth_time/at_hash/tenant/scopes, committed hashes and internal-session rejection |
| `token.confidential_credentials` | HTTP Basic current/retiring credentials, missing/wrong/revoked secrets, mandatory S256 and valid retry controls |
| `token.validation` | Wrong verifier/redirect/client, duplicate and browser authority fields, valid retry, no ID token without openid |
| `token.replica_replay_race` | HTTP race on every configured private socket, exactly one committed receipt, replay rejection and independently verified winner |
| `token.signing_rollback_rotation` | Deny signing in owned OpenBao policy, code remains unconsumed/unexpired, restore and exchange; rotate actual shared key, forced B JWKS refresh verifies old/new tokens |

| Case | Interoperability assertion |
| --- | --- |
| `interop.public_client` | Real discovery, library-generated S256/state/nonce, browser consent on A, cookie-free exchange on B, verified ID token/at_hash and protected HTTPS jobs |
| `interop.confidential_client` | Library HTTP Basic encoding with a real issued secret, S256, client-audience ID verification and protected jobs |
| `interop.callback_identity_rejection` | Exact callback, state/issuer/duplicates/error/fragment rejection before exchange; wrong nonce/client, substituted access-token hash and tampered ID signature rejected with successful controls |
| `interop.resource_scope_tenant` | Allow-list never grants unrequested jobs scope; 403 without jobs:read, 404 for another owned organization/application, 401 for cookie-only/absent bearer |
| `interop.invalid_access_tokens` | Malformed/tampered/ID/algorithm/header/unknown-kid negatives, 16 concurrent unknown keys produce one refresh; client disable preserves issued JWT authority only until actual expiry |
| `interop.signing_key_rotation` | Rotate actual OpenBao authority; cached relying party refreshes public keys without retrying exchange, resource refreshes unknown kid once, old/new tokens remain verifiable |
| `interop.userinfo_cross_replica` | Browser consent on A and standard-client exchange on B; header-only GET/POST on C disclose only the issued subject and reject ID, malformed and missing Bearer tokens |
| `interop.better_auth_login` | Real Better Auth sign-in through the app, Permesi login/consent and the exact registered callback; verified linked subject, exact scopes and a usable local session |
| `interop.better_auth_state_reject` | A one-character state tamper on an actual callback is rejected with unchanged storage/issuance state; the same unmodified callback succeeds as a fresh valid control |
| `refresh.client_revocation` | Offline consent on A, exchange on B, rotation on C and hash-only revocation on A despite an incorrect type hint; unknown/repeated requests remain generic, successor fails on B |

`smoke` selects provisioning, consent and login resume. `security` selects shared
authentication exchanges, authorization/redemption negatives and failover. `lifecycle`
selects credentials/deletion and the six lifecycle revalidation cases. `token` selects
the five HTTP issuance cases and four refresh cases; `refresh` selects only those four
refresh cases. `interop` selects seven standard-client/resource cases and the two
Better Auth cases, including cross-replica `UserInfo` disclosure and rejection. `ha` selects
eight provisioning, OPAQUE, account-containment, code/refresh race, restart, outage and failover cases.
`full` selects all 40 cases. Every case restores explicitly stopped slots afterward,
including after assertion failure. Unexpected exits remain failures; recovery failure
blocks the remaining selection instead of silently testing a smaller topology.
Repeated `--case` flags select exact IDs independently of suite; unknown IDs fail.
Redemption is explicitly the existing transaction-owned internal domain API in the
runner process, using an isolated administrator pool. It tests domain bindings and
transactions, rather than runtime-role SQL permissions. The separate `token.*` cases test real `/token` with OpenBao-minted runtime database roles and confidential authentication.
Expiration waits the normal 120-second code TTL instead of modifying immutable code
fields or weakening product configuration.

Lifecycle mutations use the actual management APIs on B and a separate GET verifies
the committed configuration. Pending consent was displayed on A and is submitted on
A after the change. Direct failures are actual terminal browser responses with HTTP
400, no Location header, no intervening document redirect and an issuer URL; a timeout
or missing browser event cannot satisfy those assertions. The mounted service's shared
error middleware converts direct handler errors to its JSON envelope. Scope failure
may redirect only through the still-registered
callback, preserving state and excluding code/tenant/scope metadata and checking the configured RFC 9207 issuer parameter.

Issued-code cases first prove successful domain redemption in a rolled-back independent
transaction. They then require rejection during mutation, after restoration and after
fresh consent creates a different grant. Read-only SQL proves the original grant stays
revoked and the original deadline has not elapsed, excluding expiration as a false-pass
explanation. Disable/scope cases retain an unchanged, unconsumed code row. Redirect
replacement deletes registered URI rows, whose existing foreign keys cascade to pending
requests and codes; that case requires the original code hash to remain absent after
restoration and fresh consent. The new code has fresh state/nonce, exact
scope/user/client/application/organization/redirect bindings and normal TTL; it commits
once and rejects replay. Lifecycle rejection is also checked through `/token`; restored consent
first passes a rolled-back domain control, then actually issues signed tokens through the
runtime HTTP service. Invalid/expired/foreign codes never consume the original authority. SQL does not seed or mutate authority in these cases.

The CI `OAuth scenarios` matrix uses the same workflow's compiled Web artifact and native
services/runner built once by the required producer job from the checked-out SHA.
Both matrix members download the producer's executable archive from their own run.
The runner and harness subprocesses enforce the expected workflow commit before
starting infrastructure; mixed service versions or a stale runner block the run.
Separate three- and five-replica jobs run the
full suite and eight harness checks, upload distinct sanitized report artifacts, and
both participate in `CI OK`. Matrix fail-fast is disabled so one result cannot hide
the other. Existing database checks remain required in CI.
The separate required `Browser tests` job downloads that same frontend artifact and runs
`just web-test-browser-built`, covering the console fixtures and both real PostgreSQL
authorization/OPAQUE browser tests through an owned Podman runtime on a fresh hosted
browser machine. `just web-test-browser` builds locally before invoking the same helper.

## Standard client and protected resource fixture

`openidconnect-rs` 4.0.1 consumes real discovery/JWKS and produces authorization requests,
public exchanges and confidential HTTP Basic requests. State, nonce and PKCE verifier
stay in private typed memory. The adapter rejects callback destination/state/issuer
substitution and duplicate or error responses before exchange. Its verified HTTPS
transport permits only this run's fixed discovery, JWKS and token URLs, rejects
redirects/session cookies, and bounds request/response bodies. ID verification pins
RS256 and JWT type, signature, issuer, client audience, expiration, nonce and at_hash.
An unknown signing key permits one fixed-origin refresh and revalidation of the same
response; the single-use code exchange is never retried.

Every stack also owns a separate loopback HTTPS fixture serving
`GET /orgs/{organization_id}/apps/{application_id}/jobs`. This route belongs only to the
runner, not Permesi or its OpenAPI. Its independently implemented verifier uses public
JWKS and pins RS256/at+jwt, signature, issuer, resource audience and finite lifetime
before consulting tenant/application or jobs:read. Invalid bearer is 401, insufficient
scope is 403, and foreign tenant/application is a generic 404. Cookies and internal
session permissions never substitute for delegated authority. Interoperability cases
register jobs:read through the real management API when a custom manifest omits it.

Public key sets are limited to 32 RSA-2048–4096 keys, cached for 60 seconds with
single-flight refresh and a two-second unknown-key/failure cooldown. Token headers
cannot choose key URLs or relax algorithm/type policy. Unknown IDs never allocate
negative cache entries. Issued JWTs remain usable after client disable until expiration;
this fixture does not implement live grant lookup, introspection or immediate revocation.
Unit tests use ephemeral RSA keys to prove rejection of correctly signed bad issuer,
audience, time, nonce, hash, scope and JOSE controls. Separate tests cover transport
limits, failed/coalesced fetches and explicit/drop listener cleanup. The listener is
recorded as a non-secret resource origin and participates in bounded runtime cleanup.

## Better Auth interoperability fixture

`tools/better_auth_interop` pins the real Better Auth TypeScript library to 1.7.18
in an isolated npm package with its own generated lockfile, and runs a minimal
Node 24 HTTPS app whose genericOAuth plugin talks to the real per-run issuer. The
plugin performs discovery, S256 PKCE, nonce/state validation and
`requireIdTokenVerification`, selects `tokenEndpointAuth` `client_secret_basic`,
and requests `openid profile email` from a confidential client registered through
the ordinary management API. The trusted fixture `organization_id` rides only the
plugin's extra authorization parameters; library-managed state, nonce and PKCE
parameters stay reserved. Token and UserInfo work stays in the standard
`signIn.social`/`callback/:id` handlers and session implementation — no custom
`getToken`/`getUserInfo` adapters, mocked provider, minted tokens or pre-created
sessions. Permesi's ID tokens carry no profile claims, so the linked account's
verified email can only arrive through the real back-channel UserInfo request.

The runner spawns one fixture process per Better Auth case with a disposable
SQLite file (Node's built-in `node:sqlite`, migrated by the library) inside the
run's private directory, a cleared environment plus explicit run-generated
configuration, `NODE_EXTRA_CA_CERTS` trust for the back-channel, and
unconditional kill/reap cleanup including failed startup and cancellation.
Ownership precedes readiness: the child's PID and birth ticks are journaled
immediately after spawn, before the private ready handshake with the bound
port and callback path. The storage path is the child's single non-secret
process argument, keeping the private directory in `/proc/<pid>/cmdline` so
the recovery guard recognizes the child. The exact callback URI is
registered through management after the fixture binds its port and read back.
Missing or drifted package dependencies fail the selected cases with a static
setup error instead of counting as coverage. Fixture startup revalidates the
issuer's cached key set once with the documented `Cache-Control: no-cache`
refresh contract, because `/jwks.json` serves a bounded per-replica cache and
the preceding `interop.signing_key_rotation` case can otherwise leave fresh
clients verifying against retired key versions for up to the cache TTL; this
covers that specific suite precondition, not universal key rotation for
Better Auth clients. `interop.better_auth_login` drives a
real browser through the app, Permesi login/consent and the real callback, then
verifies the linked provider subject and a usable local session against the
expected fixture owner. `interop.better_auth_state_reject` uses a fresh
unauthenticated cookie jar to deliver an actual callback whose state is tampered
by one character, requires the library's exact `state_mismatch` rejection with
unchanged storage counts and no token issuance, and finishes with the same unmodified callback as a fresh valid control, so a fixture
that rejects everything cannot pass. The fixture README documents its environment inputs,
local invocation (`just oauth-scenario-better-auth`) and limits; the CI OAuth
scenario matrix installs the pinned fixture dependencies before the full suite.

## High-availability topology and recovery

The runner accepts `--replicas 3` through `--replicas 5` (default `3`). Each replica is a real Permesi process with its own private Unix socket and OpenBao-minted runtime database login, sharing one issuer, audience, PostgreSQL 19 instance, and OpenBao 2.7 instance. Replica selection is controlled exclusively by the harness; browser parameters and headers cannot choose a backend.

- **All-replica races:** Authorization-code and refresh-token races dispatch concurrently across every configured socket. Exactly one response must succeed; every other response must be an actual `invalid_grant` (never a network error or `503`). Losing refresh reuse revokes the entire family, including the winning successor, across every replica.
- **Rolling replacement (`ha.rolling_restart`):** Issues a code and starts login/reauthentication on a slot, sends `SIGTERM` and requires a bounded clean exit (5-second idle-replacement test budget), verifies surviving replicas preserve session/login state, then starts a replacement process with a distinct PID and birth-tick identity that redeems the pending code and completes reauthentication while rejecting replay. Repeats for every slot.
- **Abrupt outage (`ha.replica_outage`):** Stops the last backend before redemption. The stable issuer returns `503` for that slot and direct exchange fails without consuming the code in PostgreSQL; surviving replicas then race code and refresh redemption, and after recovery every replica rejects replay. This tests explicit survivor selection rather than production load-balancer failover.
- **Journaled process ownership & recovery:** Every service child, replacement, and host Chromium Podman controller has its handle retained and its PID/birth-tick identity atomically written to the secret-free `ownership-<repetition>.json` before readiness checks. Recovery requires Linux 5.3+ and Python 3.9+, opens a [`pidfd_open`](https://docs.python.org/3/library/os.html#os.pidfd_open) descriptor before verifying birth ticks and private command paths, and signals that descriptor to prevent PID-reuse races. Private directory removal requires an owned mode-`0700` directory with a matching `owner` marker; containers and networks are removed solely by exact ownership labels.
- **Harness & recovery tests:** Eight harness checks (`just oauth-scenario-harness-test`, optionally `--replicas 5`) exercise remote-engine rejection, partial startup, repeated `SIGTERM`, total deadline, injected cleanup failure, fresh repetitions, parallel stacks, and `SIGKILL` after a replica replacement. Six dependency-free Python recovery unit tests run via:

```sh
python3 -m unittest discover -s tools/oauth_scenario/tests -p '*_test.py'
```

**Scope limits:** This is single-host multi-process coverage. It does not establish multi-host network partitions, production throughput, PostgreSQL/OpenBao outage policies, mid-commit crash ambiguity, zero-downtime draining of in-flight requests, or host-power-loss journal durability. A brief `SIGKILL` window also remains between process spawn and journal publication.

## Extension contract and remaining work

Add future protocol stages as stable cases with documented preconditions, fresh
tenant/client/grant state, independently calculated assertions and negative coverage.
Extend both report formats and the coverage table above. Negative requests must reach
the actual API rather than merely exercise manifest validation. Keep runtime ownership,
bounded waits and secret-free reporting intact as scenarios grow.

Broader scenario coverage for WebAuthn/passkey browser flows, MFA-required variants,
Firefox/Safari, multi-host load/fault tests, additional third-party OIDC clients,
introspection/immediate JWT revocation, device authorization, and M2M grants remains
tracked in [TODO.md](../TODO.md). Current scenarios preserve default MFA policy and
require a genuine full session; they do not establish formal OIDC conformance.
