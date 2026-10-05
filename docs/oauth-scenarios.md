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
target/debug/permesi-oauth-scenario --case redemption.bindings
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
OPAQUE pairs stay on A because those existing exchanges remain process-local. OAuth
requests, sessions, grants and codes use shared PostgreSQL. The failover case stops A
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
| `foundation.provisioning` | Real accounts/login, manifest hierarchy/registry, immutable protocol scopes, actual console, preparatory discovery and public JWKS |
| `authorization.consent` | Real browser S256 consent, exact scopes/state/nonce/redirect/TTL, high-entropy code and hash-only row |
| `authorization.login_resume` | Anonymous durable request on A, actual Web login, resume/consent on B |
| `authorization.cancel_saved` | Cancellation without code, fresh saved-consent code/nonce/bindings, exact saved scopes, forced consent and added browser scope-field rejection |
| `authorization.validation` | Unknown/disabled/deleted clients; modified/prefix/foreign redirects; response type; unknown/disallowed/duplicate/internal scopes; missing/malformed/plain PKCE and missing nonce |
| `authorization.tenant_isolation` | Non-member/foreign management and authorization; browser tenant input cannot override client ancestry |
| `redemption.bindings` | Independent pool, another registered public client, second registered redirect, wrong tenant/verifier, rollback and committed replay |
| `redemption.expiration_race` | Barrier-synchronized transactions, one committed winner; pre-expiry rollback validation and real-issued code expiration |
| `credentials.lifecycle` | One-time create/rotate, metadata without plaintext, bounded overlap, revoke; public secret issuance denied |
| `authorization.replica_failover` | Persist on actual A, stop A, consent on actual B, internal redemption |
| `tenant.bottom_up_deletion` | Populated-parent conflicts, explicit client deletion, bottom-up soft deletion, inaccessible reads and revoked code authority |

`smoke` selects the first three cases, `security` selects authorization/redemption
negatives and failover, `lifecycle` selects credentials/deletion, and `full` selects all.
Repeated `--case` flags select exact IDs independently of suite; unknown IDs fail.
Redemption is explicitly the existing transaction-owned internal domain API in the
runner process, using an isolated administrator pool. It tests domain bindings and
transactions, rather than runtime-role SQL permissions. It does not test HTTP `/token` or confidential-client authentication.
Expiration waits the normal 120-second code TTL instead of modifying immutable code
fields or weakening product configuration.

The CI `OAuth scenarios` job uses the same workflow's compiled Web artifact and native
services/runner from the checked-out SHA, runs the full suite and harness checks,
uploads sanitized reports and participates in `CI OK`. Existing database checks remain required in CI. The broader `just web-test-browser`
suite is validated locally; its separate CI gate remains tracked in `TODO.md`.

## Extension contract and remaining work

Add future protocol stages as stable cases with documented preconditions, fresh
tenant/client/grant state, independently calculated assertions and negative coverage.
Extend both report formats and this coverage table. Negative requests must reach the
actual API rather than merely exercise manifest validation. Keep runtime ownership,
bounded waits and secret-free reporting intact as scenarios grow.

Next implement real `/token`, atomic redemption/token persistence, confidential-client
authentication with current/retiring secrets, signed access tokens with explicit
issuer/resource audience, then OIDC ID tokens with client audience/nonce/auth_time and
complete discovery/mix-up protection. Add actual HTTP rollback, replay and concurrency
scenarios as those capabilities land. Refresh rotation/reuse detection follows separately.

Durable OPAQUE exchanges, MFA-required variants, richer consent/grants UX,
Firefox/Safari, multi-host/load/fault tests, key-rotation interoperability, UserInfo,
introspection/revocation, device flow and M2M remain in `TODO.md`. Current scenarios
preserve default MFA policy and require a genuine full session; they do not establish
the full MFA matrix or token/OIDC interoperability.

## Validation and independent review

Local checks cover formatting, workspace Clippy, default/all-feature tests and builds,
PostgreSQL bootstrap/schema verification, unchanged regenerated OpenAPI, native Web and
WASM builds, the broader Chromium console suite and both real PostgreSQL browser tests.
The runner passes all eleven cases; its seven process checks cover startup/deadline
failure, repeated SIGTERM during cleanup, an injected removal failure, repetitions and
simultaneous runs. Alternate manifests exercise multiple applications/environments.

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
from the primary implementation run. Runtime-role token exchange, MFA variants, network
sandboxing/multi-host tests, and pinned browser interoperability remain explicit
follow-ups rather than claims made by this foundation.
