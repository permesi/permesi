# CI, Module Boundaries & Build Provenance

This guide covers code-organization conventions, CI test/artifact structure, test-fixture profiling, cached build-identity verification, and hosted timing analysis. For workflow definitions and composite actions, see [.github/workflows/README.md](../.github/workflows/README.md).

## Module Organization Conventions

Module size is treated as a review signal rather than a rigid line-count quota; cohesive responsibilities and clear ownership determine where to split files:

- **Frontend (`apps/web`):** Routes compose focused section components rather than mixing ceremony, reactive state, and presentation logic.
  - The security settings page composes separate password, authenticator (TOTP), recovery-code, hardware-key, and passkey sections, each owning its reactive state and sharing credential timestamp formatting.
  - Security-setting password proofs reuse the shared OPAQUE `reauthenticate` helper so admission-protected reauthentication and mutation ordering remain consistent across flows.
  - Passkey registration preparation, synchronous browser mediation inside click handlers, asynchronous completion, and credential-row confirmation are separated into focused functions.
  - Login separates password and passkey modules while sharing a single post-authentication session-application transition.
- **Scenario runner (`tools/oauth_scenario`):** Assertions are grouped by responsibility (provisioning/discovery, authorization validation, redemption, client credentials, and hierarchy lifecycle) while preserving stable case IDs.
- **Backend tests (`services/permesi`):** Large handler test suites (such as passkey self-service regressions) live in dedicated test submodules alongside their handlers.

## CI Test Structure & Caching

The reusable native test workflow (`test.yml`) and primary pipeline (`build.yml`) separate compilation, unit/integration execution, and scenario runs so failures are localized and retries avoid redundant work:

- **Unit-test matrix:** Splits Permesi (`-p permesi`) from other workspace crates (`--workspace --exclude permesi`, which automatically covers new workspace members). Each group runs default library/binary tests followed by its complete `--all-features` suite (including standalone integration targets and doctests).
  - `max-parallel: 1` and four Rust test threads bound concurrent PostgreSQL/OpenBao container pressure within a single workflow run on shared runners.
  - `fail-fast: false` ensures both groups report results, and a failed group can be retried independently.
- **Separate compilation & execution timings:** Each test configuration runs an explicit `--no-run --timings` build step before test execution and uploads Cargo HTML timing reports even when tests fail.
- **Opt-in dependency caching vs. release builds:** `build.yml` calls `test.yml` with `cache: true` (enabling toolchain-, environment-, and lockfile-aware Cargo caches for lint, check, and native-test jobs; PR jobs restore without saving) and separately configures a `native-musl` cache on its own `build` job. The reusable `test.yml` `cache` input defaults to `false`. `release.yml` does not re-run `test.yml`; instead, its guard requires a passing exact-SHA `CI OK` check and then builds all release binaries, packages, frontend assets, and container images from source with no build cache.
- **Same-run scenario artifacts:** One `Build scenario binaries` job compiles `permesi`, `genesis`, and `permesi-oauth-scenario` from the workflow checkout, strips debug sections from staged copies, and archives them with executable modes preserved. Both the three- and five-replica scenario matrix jobs download that exact SHA-named archive from the same run.
- **Branch concurrency:** New pushes to `sandbox` or `develop` cancel superseded runs of the same workflow and branch; `main` and other refs use run-specific groups so release evidence is never canceled by development pushes.
- **Browser & WASM gates:** Native lint checks `permesi_web` for `wasm32-unknown-unknown` with denied Clippy warnings (`just clippy`). The required `Browser tests` job reuses the commit's compiled frontend artifact via `just web-test-browser-built` on a fresh hosted runner.

## Fixture Runtime Profiling

Integration tests spin up disposable PostgreSQL 19 and OpenBao 2.7.3 containers using `crates/test_support`. To profile fixture startup and teardown phases before tuning concurrency or container setup:

```sh
# Run 3 rounds (default) of 4 concurrent PostgreSQL 19 + OpenBao 2.7.3 pairs
just test-fixture-profile

# Run 1 to 10 rounds
just test-fixture-profile 5
```

Each pair measures container start/port discovery, PostgreSQL TCP readiness, canonical SQL bootstrap, OpenBao auth/transit setup, and explicit container removal separately:

- Stdout emits structured JSON with per-phase millisecond durations; build output goes to stderr.
- Container images should be pulled beforehand so engine initialization is outside the measured interval.
- Any startup, setup, or removal failure exits non-zero; an incomplete run never emits a valid profile.
- Both fixture helpers probe published loopback ports immediately after container readiness while retaining 60 bounded retries, PostgreSQL TCP readiness permits (max 4 concurrent startups, 30 s deadline), and OpenBao HTTP health checks.

## Cached Build Identity and Commit Verification

Both `services/permesi` and `services/genesis` share `services/build_identity.rs` in their build scripts to embed the build commit hash into `--version` and `/health`:

- **Precedence:** Explicit `BUILD_GIT_COMMIT_HASH` environment variable → discovered Git commit (via `git2`, requiring no `git` binary inside container builds) → `unknown`.
- **Cache invalidation:** Build scripts explicitly track `BUILD_GIT_COMMIT_HASH` addition, change, and removal as well as Git `HEAD`, loose/packed refs, and linked worktree markers.

Verify build-script invalidation locally (requires Python 3.11+, Git, and an already-fetched Cargo dependency graph):

```sh
just test-build-identity
```

`just test-build-identity` compiles disposable crates using the real service build scripts across Git-less builds (`BUILD_GIT_COMMIT_HASH` unset/A/B/empty/unknown/unset without cleaning target), loose refs, packed-ref updates, detached `HEAD`, and linked worktrees. Subprocesses run with a sanitized environment that strips caller Git redirection variables and isolates global/system Git configuration.

### Scenario Runner Commit Enforcement

`permesi-oauth-scenario` accepts `--expected-commit <40-hex-sha>` (or `PERMESI_SCENARIO_EXPECTED_COMMIT`):

```sh
target/debug/permesi-oauth-scenario \
  --expected-commit "$(git rev-parse HEAD)" \
  --replicas 5 \
  --suite ha
```

CI sets this to `github.sha` for both scenario suites and harness subprocesses. Before starting any container or service, the runner verifies that its own embedded identity and both service `--version` outputs match the expected commit and workspace version. Mismatched, shortened, or `unknown` identities fail closed and mark every selected repetition blocked without starting infrastructure.

Self-reported commit labels detect accidental stale or mixed build artifacts; they are not cryptographic attestation of untrusted executables and rely on same-run artifact custody. Release artifact verification uses signed checksums, Sigstore Cosign, and GitHub build-provenance attestations as documented in [CONTRIBUTING.md](../CONTRIBUTING.md#releasing).

## Hosted Timing Reports

To inspect GitHub Actions queue delays, runner assignments, and per-step durations without downloading logs or artifacts, use `just ci-timings` (requires Python 3.11+ and authenticated `gh` with Actions read access):

```sh
just ci-timings <run-id>

# Compare two runs and save JSON output
python3 scripts/ci-timings.py <run-id-a> <run-id-b> > .tmp/ci-comparison.json

# Run the timing helper's unit tests
python3 scripts/test-ci-timings.py
```

Key options and behavior:

- `--attempt <n>` selects a specific run attempt; by default every attempt is reported separately.
- `--repo owner/repository` targets a different GitHub repository.
- Paginates every jobs page and uses execution timestamps to exclude carried-over jobs from partial retries.
- Records runner name, labels, release delay (from attempt start, including job dependencies), assignment delay (job creation to first executing step), execution duration, and per-step durations.
- Preserves workflow/attempt status and conclusion (including failed or in-progress runs with `null` durations).

Interpretation notes:

- Runner names identify execution slots, not necessarily distinct physical hosts, so they cannot by themselves justify increasing fixture concurrency.
- Parallel job durations cannot be summed to represent workflow wall time.
- Compare the explicit `--no-run --timings` compilation steps and test-execution steps separately; single-run observations are not controlled hardware benchmarks.
