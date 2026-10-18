# Tenant mutation and HA follow-up validation

This record covers the bounded tenant mutation change and the refresh-race oracle
correction following `d5548b2`. It separates source review, executed regression tests and
live HA provisioning. Earlier release evidence is not evidence for this follow-up.

## Regression evidence

The focused `tenant_mutation` run passes 14 tests with no fixture skips: twelve real
PostgreSQL regressions, clap/dispatch validation, and the OpenAPI contract assertion.
They cover all nine routes under locks and pool exhaustion, short pool-acquire deadlines,
foreign/nonmanager requests, direct storage deadlines, three/five reader pools, settings
restoration, live-query abort, BEGIN-acknowledgement cancellation through both tenant and
authentication callers, duplicate-name conflicts, bounded slug candidates and concurrent
name/slug changes. Rejection asserts unchanged hierarchy/role state where writes are attempted.

The BEGIN regression uses a fixture-owned loopback relay to withhold server replies after
warming a one-connection pool. An independent PostgreSQL connection confirms BEGIN has
executed before the caller is cancelled. With the original implementation, the test
observed an open transaction returned to the pool. With the shared startup helper, both
callers recover cleanly and a later session deletion is committed and visible from an
independent connection. The relay does not parse, record or print credentials or SQL bytes.

Other observed red/green regressions include duplicate names returning 503 instead of
409, a name-only update reverting a concurrent slug rename, and unbounded slug probing
succeeding beyond the configured candidate cap. The real PostgreSQL refresh-oracle test
fails with the old public/internal client comparison and passes with the registration join.
Temporary mutations removing SQL deadlines, extending the handler deadline, and disabling
deletion-specific server deadlines each fail the intended watchdog. Sources were restored
byte for byte after mutation checks. The deletion watchdog is shorter than the handler
budget, so handler cancellation alone cannot satisfy its server-deadline assertion.

## Independent review

AGY completed static Herdr review using `gemini-4-argon-high`. Its valid medium finding
was the duplicate-name retry defect, fixed with the observed regression above. Its second
source review found no remaining security/correctness defects in that revision. Claims
about authentication error mapping and broader lifecycle behavior were checked against
surrounding code and withdrawn. AGY ran no tests; its review preceded the subsequent
Claude corrections and does not certify them.

Claude independently inspected the combined diff, surrounding authority/locking paths,
schema, pool configuration and SQLx 0.9 source through a separate Herdr pane. It found one
medium and four low findings, with no critical/high findings:

- M1: cancellation during BEGIN could contaminate later requests' transactions. Confirmed
  against library source and actual PostgreSQL; shared transaction startup now closes
  that window across Permesi's production transaction callers.
- L1: misleading creator-name conflict text and an existing availability oracle. The text
  is neutral. The residual `(created_by, name)` policy is documented; changing its scope
  would change tenant/product semantics and is deferred explicitly.
- L2: unbounded suffix probing. Both create and rename now enforce the independently
  validated candidate cap and return 409, with a red/green PostgreSQL regression.
- L3: stale name-only updates could overwrite a concurrent slug rename. Updates now
  preserve the locked database value, with a red/green regression including slug reuse.
- L4: documentation overclaims and missing conflict descriptions. Cancellation and logging
  claims are narrowed, both name/slug conflicts are documented, and validation history is
  separated from the design document.

Coverage suggestions are addressed by the shorter deletion watchdog, short pool-acquire
ordering test, wire-level BEGIN cancellation test, nine-route OpenAPI assertions and
explicit cancellation during an independently observed live PostgreSQL query.

Unconfirmed broader concerns remain separate: current create/edit authority preflight can
race later role revocation; strengthening its authorization semantics requires a focused
follow-up. PostgreSQL fatal transaction/idle-timeout classification, aggregate contention
observability, sustained reader fairness, and the already documented process-spawn/journal
SIGKILL window are operational follow-ups, not newly confirmed bypasses. Cancelled SQL can
hold its pool permit until bounded server cleanup completes; no immediate cleanup guarantee
is made. No unrelated authorization policy, schema privilege or token semantics changed.

Claude's second static review verified the shared helper and all production callers,
closed M1/L1/L2/L3/L4, and reported no remaining critical/high/medium/low findings. A stale
OpenAPI artifact observed during that review was regenerated and rechecked. Its additional
configuration-test isolation suggestion was verified red/green with an invalid ambient
`PERMESI_TENANT_SLUG_ATTEMPTS=0`; the test now clears all three tenant variables using the
existing `temp_env` convention. Claude separately checked that test-only correction and
reported no remaining actionable findings. Both owned reviewer panes are closed.

The helper intentionally uses SQLx 0.9's doc-hidden owned-connection constructor; its
source comment and real BEGIN regression explain the upgrade dependency. A hung database
can retain an initialization task's existing pool permit until the socket recovers or
errors, as the old pool-return path could. HTTP deadlines do not promise immediate
connection recovery during network partitions.

## Validation status — October 18, 2026

| Gate | Executed result |
| --- | --- |
| `cargo test --locked --workspace --no-fail-fast` | 688 pass, zero failures, two browser tests intentionally ignored |
| `cargo test --locked --workspace --all-features --no-fail-fast` | 718 pass, zero failures, two browser tests intentionally ignored |
| PostgreSQL schema/runtime authority and Vault integration | Included in both successful workspace runs, including all seven database privilege regressions |
| `cargo test --locked -p permesi --lib tenant_mutation -- --nocapture` | 14 pass, no fixture skips; twelve PostgreSQL regressions plus configuration/OpenAPI checks |
| Final environment-isolation hygiene | Hostile-environment focused test passes after observed failure; subsequent complete default Permesi library run passes 442 with two browser tests ignored |
| `cargo test --locked -p permesi --lib -- --ignored` | Both actual PostgreSQL browser tests pass; rerun against the fresh release assets in the normal generated Web directory |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Pass after the final source/test changes |
| `cargo fmt --all -- --check` and `git diff --check` | Pass |
| `cargo build --locked -p permesi -p genesis -p permesi-oauth-scenario` | Pass with the production fixes |
| `cargo check --locked -p permesi_web --target wasm32-unknown-unknown` | Pass |
| Fresh Web release build and Chromium console smoke | Pass; keyboard, destructive actions, dark/mobile checks and no JavaScript exceptions |
| `just --tempdir /tmp openapi` and byte-for-byte artifact comparison | Pass for both services; nine added 503 responses, neutral organization conflicts, unchanged summaries/schemas, unchanged Genesis contract |
| Python recovery tests | All six pass |
| Local Git hooks | No active pre-commit/pre-push hooks or configured hook directory; only sample hooks are present |

The full workspace runs include the production fixes. The later environment-isolation
change affects only one test; its hostile-environment command, subsequent complete default
library run and strict all-feature lint pass. No production behavior changed afterwards.

Environment-prefixed and wrapped browser/test invocations encountered Podman runtime setup
failures. The direct Cargo commands above execute the actual PostgreSQL/browser tests
successfully without changing fixtures or assertions. Fresh console smoke uses the release
artifact, and that artifact was copied into the ordinary ignored `apps/web/dist` directory
before the final successful PostgreSQL browser run.

The initial five-replica standalone HA attempt stopped at provisioning because that
session's Podman runtime was read-only. After resuming with a writable runtime, the
corrected five-replica HA suite passed 7/7, and full three/five suites passed 34/34
each with zero cleanup errors. Both topologies passed all eight recovery harness checks.
The old hosted three/five matrix reached 32/34 scenarios. Corrected hosted run
`39103751747` passed 34/34 cases and all eight harness checks for each topology.
See [HA validation](oauth-ha-validation.md). CI also lacks an automated committed-versus-
generated OpenAPI drift gate; the manual byte-for-byte check passes and the gate is in TODO.

The first publication attempt was blocked by that session's protected Git directory:
staging failed with `Unable to create .../.git/index.lock: Read-only file system`.
After resuming with writable Git metadata, commit `2be597f` was signed, pushed to
`sandbox`, and verified by GitHub. Hosted run `39103751747` passed format, Web audit,
check, Clippy, coverage and schema checks. Its first two attempts had PostgreSQL
container-startup timeouts in concurrently running integration/unit jobs, without test
assertion failures. The exact Genesis integration target passed locally; hosted integration
passed on retry. Rerunning the unit job alone passed both workspace suites. The workflow
now orders these database-heavy jobs instead of starting both on the same runner host.
Hosted builds and browser checks passed. Both real scenario suites passed 34/34 on their
first execution, with zero cleanup errors. The three-replica harness passed all eight
checks; the five-replica harness failed its simultaneous-run check while both topology
jobs overlapped on the same host, then passed all eight checks when rerun alone. The
workflow follow-up serializes matrix members to reduce this host contention. Run
`39103751747` finished green on attempt four; the separate workflow scheduling commit
requires its own fresh CI result.
