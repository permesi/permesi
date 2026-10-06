# Isolated OAuth scenarios

The `permesi-oauth-scenario` workspace binary is an extensible integration foundation
for the OAuth roadmap. Its disposable PostgreSQL and Vault launch actual Permesi and
Genesis from an empty identity/tenant schema. It tests the compiled Web console and a
small owned callback client, rather than mocking an OAuth application. Accounts are
registered and verified through real admission-protected OPAQUE APIs; browser login
creates actual full sessions. No user, membership, session or grant is seeded directly.

## Running

On Linux with working local Podman, run `just oauth-scenario-build`, then:

```sh
target/debug/permesi-oauth-scenario --list
target/debug/permesi-oauth-scenario --suite smoke
target/debug/permesi-oauth-scenario --suite full
target/debug/permesi-oauth-scenario --suite token
target/debug/permesi-oauth-scenario --suite interop --access-token-ttl-seconds 10
target/debug/permesi-oauth-scenario --case redemption.bindings
target/debug/permesi-oauth-scenario --case authentication.shared_exchanges
target/debug/permesi-oauth-scenario --case authorization.consent --repeat 2 --seed 7
```

The binary also runs from another directory with explicit `--permesi-bin`,
`--genesis-bin` and `--web-dist` local artifact paths. `--scenario` selects a
version-one JSON manifest; the embedded default is
`tools/oauth_scenario/scenarios/default.json`. It creates one organization/project,
Development and Production environments, one application in each, four custom scopes
and public/confidential clients with different allow-lists. Public clients allow
`openid`, `profile` and one custom scope; requests use only `openid` and that custom
scope, proving the allow-list does not become consent. Every case creates a fresh
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
test-only HTTPS gateway keeps one stable issuer while selecting actual replicas A/B.
OAuth requests, sessions, grants, codes and encrypted OPAQUE exchanges use shared
PostgreSQL. Ordinary browser setup selects A; `authentication.shared_exchanges` deliberately
starts native login/reauthentication on A and finishes on B using real runtime-role APIs. The failover case stops A
after request persistence and completes consent on B. This is multi-process state
coverage, not a claim of multi-host transport/load testing.

Service children receive explicit existing CLI inputs and fresh private credential
environments, with inherited deployment/proxy/Vault settings cleared. The runner
selects local Podman or verifies a local Unix Podman API for CI; remote TCP/Docker
engines are rejected. It never adopts existing resources or prunes the shared engine.
The run CA is trusted only by its native clients and disposable Chromium container.
TLS verification stays enabled. Chromium uses host networking to reach the owned
loopback listeners; this local test transport does not provide network sandboxing.
Build artifacts are trusted local inputs. Cached dependency/browser images remain
available; cleanup removes run containers, networks and private files. The public HTTP loopback callback uses a different
hostname from the issuer, so issuer cookies do not travel to the client. Browser
worker content determines the image tag, preventing stale reuse between runner versions.

Default deadlines are readiness 90 seconds, HTTP 10 seconds, browser actions 15 seconds,
whole run 900 seconds and bounded cleanup. CLI ranges prevent unbounded configuration.
`--access-token-ttl-seconds` defaults to the product's 300 seconds and accepts 1–3600.
It passes the existing Permesi CLI/dispatch validation on both replicas. Use 10 seconds
for the interoperability/full suite's real expiration case, as CI does; very short
lifetimes may expire positive controls during browser/network work. ID-token and
authorization-code lifetimes retain product defaults. No test changes stored timestamps.
Only readiness polls retry; assertions, secret issuance and mutations do not retry.
Startup failure, timeout, SIGINT and SIGTERM enter cleanup. Owned processes have
kill-on-drop fallback. SIGKILL or host failure cannot run destructors; use the
non-secret `ownership-<repetition>.json` to identify exact resources for recovery.
It records labeled container/network names, the private directory, and started service
PIDs with Linux birth ticks. Verify labels and PID birth ticks plus the private socket
path before recovering a resource; a reused name or PID never establishes ownership.
Never use shared-engine prune/reset for recovery.

Reports default to `.tmp/oauth-scenarios/<run-id>/report.json` and `junit.xml`;
`--report-dir` changes the parent. Artifacts are published atomically with private file permissions.
JSON schema version one records case IDs, durations,
repetitions, assertion/infrastructure/harness/cleanup classifications, fixture/build
identities, resolved image IDs and explicit planned capabilities. Failure, blocked
selected cases or cleanup errors return nonzero. Screenshots, traces, browser logs,
HTTP payloads/headers and callback query strings are excluded. Errors use curated
static messages; third-party diagnostic strings are discarded. Podman logging is
disabled and checked for every run container, including private browser IPC and Vault
dev output. Chromium CDP uses inherited pipes, with no host debugging TCP listener. Validate runner
ownership, startup failure, interruption, deadline expiry, injected cleanup failure,
repetitions and parallel isolation with
`just oauth-scenario-harness-test`.

## Coverage

| Stable case | Actual coverage |
| --- | --- |
| `foundation.provisioning` | Real accounts/login, manifest hierarchy/registry, immutable protocol scopes, actual console, accurate code/token discovery and public JWKS |
| `authorization.consent` | Real browser S256 consent, exact scopes/state/nonce/redirect/TTL, high-entropy code and hash-only row |
| `authentication.shared_exchanges` | Real OPAQUE login/reauthentication start on A and finish on B, actual session verification, replay rejection and same-user session binding |
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

| `token.public_claims` | Browser code on A, runtime-role HTTP exchange on B, ignored extensions cannot replace saved nonce, independently verified signatures/issuer/audiences/nonce/auth_time/at_hash/tenant/scopes, committed hashes and internal-session rejection |
| `token.confidential_credentials` | HTTP Basic current/retiring credentials, missing/wrong/revoked secrets, mandatory S256 and valid retry controls |
| `token.validation` | Wrong verifier/redirect/client, duplicate and browser authority fields, valid retry, no ID token without openid |
| `token.replica_replay_race` | Real A/B process HTTP race on pinned private sockets, exactly one committed receipt, replay rejection and independently verified winner |
| `token.signing_rollback_rotation` | Deny signing in owned Vault policy, code remains unconsumed/unexpired, restore and exchange; rotate actual shared key, forced B JWKS refresh verifies old/new tokens |

| Case | Interoperability assertion |
| --- | --- |
| `interop.public_client` | Real discovery, library-generated S256/state/nonce, browser consent on A, cookie-free exchange on B, verified ID token/at_hash and protected HTTPS jobs |
| `interop.confidential_client` | Library HTTP Basic encoding with a real issued secret, S256, client-audience ID verification and protected jobs |
| `interop.callback_identity_rejection` | Exact callback, state/issuer/duplicates/error/fragment rejection before exchange; wrong nonce/client, substituted access-token hash and tampered ID signature rejected with successful controls |
| `interop.resource_scope_tenant` | Allow-list never grants unrequested jobs scope; 403 without jobs:read, 404 for another owned organization/application, 401 for cookie-only/absent bearer |
| `interop.invalid_access_tokens` | Malformed/tampered/ID/algorithm/header/unknown-kid negatives, 16 concurrent unknown keys produce one refresh; client disable preserves issued JWT authority only until actual expiry |
| `interop.signing_key_rotation` | Rotate actual Vault authority; cached relying party refreshes public keys without retrying exchange, resource refreshes unknown kid once, old/new tokens remain verifiable |

`smoke` selects the first three cases, `security` selects authorization/redemption
negatives and failover, `lifecycle` selects credentials/deletion and the six lifecycle
revalidation cases, `token` selects the five HTTP issuance cases, `interop` selects the six
standard-client/resource cases, and `full` selects all twenty-eight cases.
Repeated `--case` flags select exact IDs independently of suite; unknown IDs fail.
Redemption is explicitly the existing transaction-owned internal domain API in the
runner process, using an isolated administrator pool. It tests domain bindings and
transactions, rather than runtime-role SQL permissions. The separate `token.*` cases test real `/token` with Vault-minted runtime database roles and confidential authentication.
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

The CI `OAuth scenarios` job uses the same workflow's compiled Web artifact and native
services/runner from the checked-out SHA, runs the full suite and harness checks,
uploads sanitized reports and participates in `CI OK`. Existing database checks remain required in CI.
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

## Extension contract and remaining work

Add future protocol stages as stable cases with documented preconditions, fresh
tenant/client/grant state, independently calculated assertions and negative coverage.
Extend both report formats and this coverage table. Negative requests must reach the
actual API rather than merely exercise manifest validation. Keep runtime ownership,
bounded waits and secret-free reporting intact as scenarios grow.

[Token exchange](oauth-token-exchange.md) now has real runtime-role HTTP scenarios,
independent RS256/claim verification, current/retiring credentials, rollback, replay,
concurrency and shared rotation. Next add refresh-family rotation/reuse/concurrency
coverage alongside its implementation. The six standard-library/resource scenarios
provide a narrow interoperability foundation; broader clients, formal OIDC conformance
and production resource-server revocation policy remain separately tracked.

Durable WebAuthn/passkey exchanges, MFA-required variants, richer consent/grants UX,
Firefox/Safari, multi-host/load/fault tests, broader third-party OIDC clients, UserInfo,
introspection/revocation, device flow and M2M remain in `TODO.md`. Current scenarios
preserve default MFA policy and require a genuine full session; they do not establish
the full MFA matrix or formal OIDC conformance.

## Validation and independent review

Local checks cover formatting, workspace Clippy, default/all-feature tests and builds,
PostgreSQL bootstrap/schema verification, regenerated OpenAPI consistency, native Web and
WASM builds, the broader Chromium console suite and both real PostgreSQL browser tests.
The runner now includes twenty-eight cases; its seven process checks cover startup/deadline
failure, repeated SIGTERM during cleanup, an injected removal failure, repetitions and
simultaneous runs. The eight-case lifecycle suite also passes two fresh-stack repetitions
from another working directory with explicit artifacts and an alternate manifest of
three environments and six applications.
The container-runtime action's fifteen fixture tests also run with the calling job's
Podman requirement enabled and disabled. Each fixture selects its own policy, and an
explicit hosted-runner case verifies that required Podman bypasses system Docker.
The first CI attempt exposed inherited runtime-policy inputs in these fixtures before
scenarios could run. Isolating each fixture's policy fixed the failure without changing
the runtime or weakening Docker-policy assertions. A focused Herdr/OMP review with the
same exact Grok provider/model independently passed both suites and found no defects.

The first independent Herdr/OMP review used `xai-oauth/grok-4.7` with xhigh thinking.
Three medium findings were accepted: host-visible CDP was replaced by inherited pipes,
container logging was disabled and verified, and saved-consent codes gained fresh
state/nonce and full persistence assertions. Four low findings were also fixed:
canonical environment slugs, complete immutable protocol registry checks, measured
credential overlap against validated CLI policy, and isolated case routing with
failover always last. Additional assertions cover displayed scope descriptions,
allow-list versus consent, registered-client/redirect negatives, barrier-synchronized
redemption and all standard private RSA JWK components.

The second-signal finding was rejected: Tokio keeps its installed Unix signal handler
when a receiver is dropped, and the real repeated-SIGTERM test completes cleanup.
The second independent review used the same exact provider/model and verified all seven
fixes and the signal finding's rejection, with no remaining confirmed defects. The
reviewer inspected the code and protocol contracts; the execution results above come
from the primary implementation run. Runtime-role token exchange was deferred in that
initial foundation and is implemented by the token milestone below. MFA variants, network
sandboxing/multi-host tests and pinned browser interoperability remain explicit follow-ups.

A separate independent Herdr/OMP review of the lifecycle extension used
`xai-oauth/grok-4.7` with xhigh thinking and found no confirmed actionable defects.
It checked real A/B routing, committed mutations/read-back, current consent and grant
validation, redirect cascades, pre-expiry negative controls, fresh exact-bound code
recovery and replay, browser response receipts, private IPC and the documented token
deferrals. The reviewer traced the mounted error middleware to verify the JSON direct
error contract. The execution evidence above comes from the primary run; this review
required no code corrections or second review.

The token milestone received two further independent Herdr/OMP reviews using
`xai-oauth/grok-4.7`. All four confirmed findings were fixed with regressions proven
to fail on the original implementation: callback parameter collisions, unknown token
extensions/empty optional identifiers, delayed signing-cache overwrites and case-sensitive
JWKS refresh. The corrected verifier refreshes the fixed issuer JWKS once on an unknown
kid without retrying exchange or relaxing assertions. The second review found no
confirmed defects. Primary execution passed all 22 cases, seven harness checks,
534 default/564 all-feature workspace tests and the browser/schema/OpenAPI gates.
See [token exchange](oauth-token-exchange.md) for the fixes and remaining trust boundaries.

The standard-client/resource milestone passed all 28 full-suite cases with zero cleanup
errors, all six interoperability cases again after review fixes, and twelve cases across
two fresh-stack interoperability repetitions with an alternate manifest omitting jobs:read.
All 22 runner unit tests, seven process checks, 549 default/579 all-feature workspace tests,
workspace formatting/Clippy, native/WASM builds, the Chromium console and both real
PostgreSQL browser tests, schema verification and unchanged OpenAPI comparisons passed.
Cargo audit passed the existing policy with three maintenance warnings; its RSA advisory
comment now accurately describes public-key verification and test-only private keys,
without changing the ignore list or enforcement.

Independent Claude reviews through Herdr applied the deep-code-review skill to the full
implementation and corrected diff. The first review confirmed a low-severity test defect:
unreachable destinations could make the transport-pinning test pass after removing its
guard. Reachable, counted HTTPS controls now prove rejection before I/O, including a
foreign origin whose CA is trusted by the test client. Accepted coverage improvements
also exercise missing ID-token type, known-key signature tampering in unit and live cases,
duplicate JSON members, resource audience arrays and tenant-versus-scope error precedence.
Mutation tests independently proved the guards fail when removed; the HTTP downgrade
control checks the policy failure itself so TLS rejection cannot mask a missing guard.

The second review independently killed the corresponding mutations, ran all 22 runner
tests under default/all features and all six live interoperability cases, and found no
remaining critical, high, medium or low findings. It also verified the cache-cancellation
regression: expired keys are cleared before refresh I/O, so cancelling a fetch cannot
renew stale authority. Informational observations are explicit fixture limits: a cold
cache with an unknown kid can make two bounded fetches, and repeated full runs with the
default 300-second token TTL may need a larger total deadline. Use the documented
ten-second TTL for expiration scenarios. These reviews do not claim formal OIDC
certification, broader browser/client coverage or production immediate revocation.

Two final focused Claude follow-ups independently verified the documentation evidence
and closed the remaining informational downgrade coverage gap. GET discovery/JWKS and
POST token requests now each fail the test when only that method's scheme guard is
weakened. The final review reported no confirmed findings at any severity; restored
default/all-feature runner tests, formatting and runner Clippy passed independently.

The browser-CI extension passes 549 default workspace tests, workspace formatting and
all-target/all-feature Clippy, the release WASM build, all three browser stages, the
container action's fifteen fixtures, Actionlint/ShellCheck, JavaScript syntax and
unchanged OpenAPI comparisons. Three independent Claude/Herdr review rounds resolved
three low findings: a renamed test could silently run zero cases, browser selection
documentation was inaccurate, and background-network suppression was overstated.
Exact ignored-test discovery, accurate browser documentation and explicit DNS rules
address these findings. Missing-test and admission-origin mutations fail as expected;
Claude's final review found no remaining actionable findings and independently passed
the browser helper against the downloaded GitHub frontend artifact. The prior
[baseline CI run](https://github.com/permesi/permesi/actions/runs/37353233392) passed
after retrying a transient PostgreSQL startup failure.

The [first hosted browser run](https://github.com/permesi/permesi/actions/runs/37361954328)
passed private Podman setup and exact test discovery, but Chromium did not create a
DevTools port file despite its successful version command; startup output was suppressed,
so the cause is unknown. Browser setup
now prefers native Chrome and probes headless startup in an empty private profile,
requiring both a valid port file and reachable loopback DevTools endpoint before
publishing the alias. Ten fixture regressions cover selection, fallback, unavailable
or unusable browsers, unterminated port files, invalid ports, HTTP readiness and
process/profile cleanup including delayed termination, and direct checks despite proxy
configuration. Reinstating
the original selector makes the readiness regression fail. The corrected hosted run
remains pending; the TODO stays unchecked until it passes. Live checks cannot be repeated
inside the primary session's current loopback-binding restriction; earlier full browser
validation remains valid for the unchanged test scripts. Claude independently ran the
live probe and console suite through the selected alias. Its startup review found four
low issues: an unterminated file could abort fallback, process cleanup and numeric port
validation lacked decisive assertions, and the startup comment suggested an unproven
cause. The fallback regression failed before the fix; the code, assertions and comment
have been corrected. The probe also explicitly bypasses proxies for its loopback check.
Claude's second startup review verified all fixes, repeated the live probe and console
suite, and found no remaining actionable findings. Removing the read guard, kill/wait,
port regex/bounds, or proxy bypass makes the affected regression fail. Delayed shutdown
verifies waiting for process retirement; it does not assert the precise kill-after duration.

The shared-OPAQUE phase adds `authentication.shared_exchanges` and passes all 29 full-suite
cases on the corrected gateway, with zero cleanup errors. Four independent Claude/Herdr
reviews verified real A/B routing, replay/session binding, PostgreSQL constraints and
transaction ordering. The initial gateway pinned OPAQUE requests to A; a real Unix-backend
routing regression now prevents that false cross-replica result. With corrected routing,
the old in-memory binary fails the native finish step and the shared-store binary passes.
Claude independently passed all seven process/harness checks and all three browser stages
against the final rebuilt native binaries and CSR assets.

Final workspace runs pass 581 default and 611 all-feature tests, including 29 real PostgreSQL
exchange regressions. The two ignored PostgreSQL browser tests were exercised separately.
Formatting, all-target/all-feature Clippy, release WASM/native builds, OpenAPI generation
and comparisons, fresh bootstrap/reapplication and runtime-privilege verification pass.
The final review's targeted reversions fail on the intended assertions for metadata
retargeting, early identity commits in both HTTP handlers, global-capacity serialization,
configured deadlines and pooled-setting leaks, and malformed reauthentication consumption.
No confirmed implementation defects remain; operational limits and hardening follow-ups
are explicit in [the exchange design](opaque-exchanges.md) and [TODO](../TODO.md).

The hosted browser run's failed-job retry also failed on the old published commit
`bf31d19`, again without a DevTools port file. The corrected browser selector and shared
OPAQUE changes remain local pending publication: SSH push authentication is unavailable,
and the normal HTTPS credential-helper fallback cannot resolve GitHub in the primary
session. This is not evidence of a successful corrected hosted run. The browser CI and
OPAQUE publication milestones remain unchecked until that run passes.
