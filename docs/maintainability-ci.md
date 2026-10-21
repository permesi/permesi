# Focused modules and CI measurement

The six authentication-view component split shipped in 0.4.2. This follow-up
separates the remaining responsibilities into modules, applies that convention to
scenario assertions and backend regressions, and reduces repeated CI work while
retaining the existing validation boundaries. Module size is a review signal;
cohesive responsibilities and understandable ownership determine where to split.

## Module boundaries

The security page composes password, authenticator, recovery-code, hardware-key and
passkey sections. Each section owns its reactive state, with smaller form views
receiving typed state handles. Credential timestamp presentation is shared.
Decorative authenticator menu symbols are hidden from accessible names while
their visible Edit/Delete labels remain available.
Passkey registration preparation, synchronous browser mediation, asynchronous
completion and credential-row confirmation have separate functions. Login has
separate password/passkey modules and one shared transition for applying the
server-issued full or limited session and choosing its existing destination.

Duplicate security-setting password proofs now use the existing OPAQUE
`reauthenticate` helper. Its generic proof-error wording is used consistently;
the admission-protected reauthentication endpoints and subsequent mutation order
remain the same. Passwords and challenges remain transient. Registration and
prepared-options login still create browser credential promises synchronously
inside their click handlers, before spawning asynchronous completion. First-click
login retains its existing prepare-await-then-mediate fallback; transient-activation
compatibility on additional browsers remains a follow-up. Browser support,
preparation and expiry checks do not
replace server-side session recency, credential ownership or protocol validation.

The OAuth runner groups provisioning/discovery, authorization validation,
redemption, client credentials and hierarchy lifecycle assertions into modules.
Its stable case IDs and real-service assertions remain unchanged. The passkey
self-service handler's existing regressions now live in a separate test module
with their existing test paths. Further backend/test decomposition should follow
the same responsibility-based convention when those areas are changed.

## CI baseline and changes

The successful candidate [run 39434547989](https://github.com/permesi/permesi/actions/runs/39434547989)
provides the baseline. Its default native test step took 33m10s, including about
1m18s of compilation; Permesi's library tests took 31m24s. The all-feature step
took 34m57s, including about 1m11s of compilation. This run also experienced long
dependency/runner waits and required a second attempt for the scenario harness.
These observations identify test execution and scheduling as major costs; they
do not establish a cache-related speedup or production performance.

Default and all-feature suites retain their existing commands and separate
coverage. Each now has an explicit `--no-run --timings` build step before execution.
GitHub step timings distinguish compilation from execution, and the unit job
uploads Cargo's HTML compilation reports even when execution fails. Native
check/lint/test and musl jobs use toolchain/environment/lockfile-aware dependency
caches. The reusable workflow's `cache` input defaults to false, so release callers
retain fresh native test builds; `build.yml` explicitly enables it. PR jobs restore
but do not save these caches.
Source changes still go through Cargo; production release artifact builds remain
uncached in the separate release workflow.

One required job builds native scenario services and the runner from the exact
workflow checkout. Both sequential three/five-replica matrix members download its
SHA-named archive from their own run. Packaging strips debugging sections only
from staged copies, preserving executable code/build identity and keeping the
compiled targets untouched. The archive preserves executable modes;
another branch's or workflow's artifact is never substituted. The required
`CI OK` check also depends on the producer, so a failed or skipped build cannot
leave the aggregate gate successful. The full scenarios and harnesses still run
for both topologies.

Superseded `sandbox` and `develop` workflows cancel only earlier runs of the same
workflow and branch. Other refs use independent run-specific groups, protecting
release-candidate and main-branch evidence from this cancellation policy. Existing
job cleanup hooks retire their own resources on cancellation. `CI_RUNNER` is
unchanged. Identical commits pushed to different branches still receive separate
checks; cross-branch result reuse requires a separate provenance and branch-gate
design.

## Validation and review

The local default workspace suite passes 721 tests and the all-feature suite
passes 751. Each normally ignores the two browser tests; both were subsequently
run explicitly through `just web-test-browser-built` and passed against real
PostgreSQL/OPAQUE flows. The expanded console smoke suite also passes: all five
security-setting mutation forms require password proof, rejected proof dispatches
no protected mutation or plaintext password, local password validation stops
early, and keyboard, mobile/dark-mode and credential-list behavior remain covered.

Formatting, strict native and WASM Clippy, native checks/builds, the Web release
build, exact CI `--no-run --timings` commands, OpenAPI drift and Actionlint with
ShellCheck pass. The named development database was stopped, so the canonical
bootstrap and schema verifier were run successfully against an owned disposable
PostgreSQL 18 instance instead. Seven recovery unit tests, 15 container-runtime
tests and ten browser-runtime tests pass.
The four moved passkey-handler regressions also pass a focused `--nocapture`
run, explicitly rejecting dependency skips and an empty filter. Mechanical body
comparisons preserve all 25 original top-level scenario functions and the moved
passkey-handler regression functions.

The full three- and five-replica suites each pass 36/36 cases with zero cleanup
errors after archive transport. Stripped copies additionally pass five focused
identity/rolling-restart/outage/UserInfo/failover cases on each topology, with zero
cleanup errors. Archive validation checks executable permissions, exact staged
bytes, unchanged `.text`/`.rodata`/`.data` sections and CLI build identity. Locally,
the archive falls from 236,825,209 to 40,531,248 bytes (82.9% smaller). Eight real
cleanup/isolation/restart harness checks pass on each topology, in addition to the
recovery unit tests.

Independent Herdr/OMP `xai-oauth/grok-4.7` review found no confirmed critical,
high, medium or low defect. It compared the existing and extracted session/proof/
gesture paths, moved assertions, CI gate, cache opt-in and artifact provenance.
Its suggestions are follow-ups rather than confirmed defects. Consumers
intentionally use the same-run download default. Current checkouts have Git
metadata and dependency caches omit workspace crates; cached Git-less builds need
separate environment-invalidation tests. Native Linux producers require `objcopy`,
now documented. First-click passkey login's existing asynchronous fallback is
preserved. No optional item is represented as a fixed defect.

The reviewer did not rerun long suites or claim browser-specific gesture coverage.
Its OpenAPI-evidence reservation was resolved by rerunning `just openapi-check`
with an explicitly recorded zero exit status; successful byte comparisons are
normally silent. Final Clippy checks use incremental compilation; fresh release
artifact builds remain separate. The final targeted Grok review approved the
documentation clarifications and restored pointer affordance on the passkey
sign-in button, independently ran `just openapi-check` successfully and reported
no new confirmed defects. The owned review pane was closed after completion.
This batch does not yet claim a hosted run or a measured CI wall-time improvement.

## Remaining work

Profile individual fixture groups and startup/teardown before changing database
test concurrency or introducing reuse. Any reuse must preserve fresh authority,
tenant isolation, rollback and ordering assertions. Compare several completed
hosted runs, separating execution from dependency/runner wait and recording retry
effects. Exact-commit cross-branch reuse, broader backend decomposition and
multi-host load/fault benchmarks remain tracked follow-ups. No hard file-length
quota, skipped security suite or broader shared test database is introduced here.
