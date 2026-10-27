# GitHub Actions Workflows

This directory contains the CI/CD workflows for the Permesi workspace.

## Runner Configuration (`CI_RUNNER`)

Most workflows are configured to use a flexible runner selection logic:

```yaml
runs-on: ${{ vars.CI_RUNNER || 'self-hosted' }}
```

Native scenario producers run on Linux and require GNU binutils (`objcopy`) in
addition to the Rust toolchain. Missing tooling fails the producer and required
aggregate check.

### How to use:

1.  **Default (Self-Hosted):** By default (when the variable is unset), workflows will attempt to run on a **self-hosted** runner. This is preferred for performance and cost.
2.  **Fallback (GitHub-Hosted):** If the self-hosted runner is unavailable or you wish to use GitHub's infrastructure, define a Repository Variable named `CI_RUNNER` with the value `ubuntu-latest`.
    *   Navigate to: `Settings` > `Secrets and variables` > `Actions` > `Variables`.
    *   Create or update `CI_RUNNER`.
3.  **Exceptions:**
    *   `test.yml` pull-request jobs are hardcoded to use `ubuntu-latest` for safer execution of untrusted PR code.
    *   `coverage.yml`: This workflow is hardcoded to use `ubuntu-latest` for stable tool/runtime behavior.
    *   `build.yml` browser tests use `ubuntu-latest` for a fresh browser host. A job-local `chromium` alias prefers native Google Chrome and falls back to Chromium; the step probes headless startup and prints the selected version.
    *   `deploy.yml`: This workflow is hardcoded to use `ubuntu-latest` for production releases to ensure a clean, standardized environment for final artifacts and deployments.
    *   `schemathesis.yml`: This workflow is hardcoded to use `ubuntu-latest` so API contract checks always run on GitHub-hosted runners.

Verify runner usage with `just ci-timings <run-id>`. This read-only metadata report
records actual job assignments and step durations, separating retry attempts and
retaining incomplete/failed status. Runner names do not establish independent
physical hosts. See [timing reports](../../docs/ci-runtime-provenance.md#hosted-timing-reports)
before interpreting queue or wall-time differences as a speedup.

## Workflow Overview

- **`test.yml`**: Handles formatting, strict native and browser-target WASM Clippy, dependency auditing for the web app, and
  unit/integration tests. A separate hosted OpenAPI drift job generates both service
  contracts and compares them byte-for-byte with the committed artifacts; failure
  blocks the reusable test workflow and `CI OK`. Web auditing includes development/build dependencies so
  source-map and stylesheet-tooling advisories are covered. The unit job runs default
  library/binary tests, then the complete all-feature workspace suite. Each configuration
  has a separate `--no-run --timings` compilation step, so job step durations distinguish
  compilation from execution; HTML compilation reports are uploaded even on test failure.
  Cached build-identity regressions compile the actual service build scripts in
  disposable Git-less/Git/worktree crates after the native suites; no live services
  are required for this check.
  Development lint/check/native-test jobs use toolchain/environment/lockfile-aware
  dependency caches; PR jobs restore but do not save those caches. The reusable
  `cache` input defaults to false, preserving release callers' fresh native test
  builds; `build.yml` opts in. The separate
  default integration job selects standalone `tests/` targets with `--test '*'` and
  continues across test binaries with `--no-fail-fast`, preserving Permesi results
  when a Genesis dependency fails. Both database-heavy test jobs cap Rust test threads
  at four so concurrent fixtures do not saturate the shared self-hosted machine;
  each test keeps its own race assertions. The shared PostgreSQL fixture also limits
  simultaneous startup through TCP readiness and allows 30 seconds for a starting
  container to accept connections. The lint job installs `wasm32-unknown-unknown` and
  checks `permesi_web` with the same denied warnings as the native workspace. Locally,
  `just clippy` runs both targets after `just web-setup` installs the browser target.
  Coverage still runs the full default workspace.
- **`security-audit.yml`**: Audits the locked Rust dependency graph for vulnerabilities, unsound
  advisories, and yanked crates when Cargo dependency files change, on manual runs, and weekly so
  newly published RustSec advisories are detected without duplicating the normal test workflow.
- **`build.yml`**: Compiles the Rust services and builds the Leptos frontend. The frontend build clears the
  `apps/web/dist` output and runs a full `cargo clean -p permesi_web` so self-hosted runners do not
  reuse stale build artifacts when deploying Cloudflare Pages. On the `develop` branch it also packages and
  pushes `ghcr.io/permesi/permesi:develop`, `ghcr.io/permesi/genesis:develop`, and `ghcr.io/permesi/web:develop`.
  The service image builds inject `github.sha` as `BUILD_GIT_COMMIT_HASH` because the Docker build context
  excludes `.git`, and the binaries would otherwise report an unknown commit.
  Its required `Browser tests` job downloads the same run's `frontend-dist` artifact and invokes
  `just web-test-browser-built` without rebuilding WASM or running npm installation. It runs the console
  fixture suite and explicitly executes the ignored real PostgreSQL browser tests for
  authorization consent/redirects, OPAQUE organization-deletion reauthentication and
  read-only platform tenant inspection. The inspection test follows the admin dashboard
  through foreign resources and checks that ordinary owner controls remain available.
  Node 24, pinned
  Just 1.58.0 and zsh run on the hosted job; the existing container action requires a private Podman
  API and owns dependency cleanup. The thirty-minute job timeout bounds setup and execution. Backend
  test names are checked by exact discovery before execution, so a renamed or missing test fails the job.
  The browser action tests its selection policy, then requires an empty private profile with a
  host-visible DevTools port file and reachable loopback endpoint. A version-capable binary that
  cannot launch headless is rejected; another installed candidate is tried before setup fails.
  Probes contain no authentication data and their processes/profiles are retired before tests.
  Fixtures override API and admission origins to loopback. Browser resolver rules block
  non-loopback hostname lookups; a separate flag requests reduced background service traffic.
  Browser profiles, credentials, request dumps and screenshots are not uploaded. `CI OK` depends on this job
  alongside tests, service/frontend builds and OAuth scenarios, so failure, cancellation or skipping
  the browser gate cannot produce a successful aggregate check.
  OAuth scenarios run as a required three/five-replica matrix with fail-fast disabled.
  A required `Build scenario binaries` job checks out the exact workflow SHA and builds
  the services and runner once. Both matrix members download its SHA-named artifact from
  their own workflow run; a tar archive preserves executable modes. Packaging strips
  only debugging sections from staged copies to reduce transfer size. The scenario
  job sets `PERMESI_SCENARIO_EXPECTED_COMMIT` to the workflow SHA for both full suites
  and harness subprocesses; runner and service identities must match exactly before
  infrastructure startup. Self-reported labels do not replace same-run artifact trust.
  Executable code and build identity remain intact. Source is never
  replaced by an artifact from another branch or workflow. The matrix remains sequential
  to bound local fixture pressure. Each matrix member runs all current full-suite cases,
  recovery unit tests and harness checks, including rolling
  replacements, backend loss and SIGKILL recovery of a replacement process. Sanitized
  report artifact names include the replica count. Harness failures identify the
  source line and exception class without printing captured subprocess output. This covers one-host process/state
  availability and does not establish multi-host load or network-failure behavior.
  New `sandbox`/`develop` runs cancel superseded runs on the same branch. Other refs,
  including release candidates and `main`, use independent run-specific groups; these
  runs cannot be cancelled by development pushes. Different branches still run their
  own checks, even for an identical SHA. `CI_RUNNER` selection and the aggregate failure
  policy are unchanged. See [measurement and remaining work](../../docs/maintainability-ci.md).
- **`schemathesis.yml`**: Runs OpenAPI contract checks with Schemathesis as a post-deploy verification.
  It runs manually via `workflow_dispatch` and is intended to be triggered after deployment settles.
  It waits for each service `/health` endpoint (up to 10 minutes for genesis), verifies the deployed
  commit hash matches the selected workflow ref SHA (`github.sha`), and then runs GET-only checks.
  Base URLs are resolved from the selected run branch
  (`develop` -> `*.permesi.dev`, all others -> `*.permesi.com`).
  Commit metadata parsing in the `/health` verification step requires `python3` on the runner.
- **`coverage.yml`**: Generates and uploads code coverage reports.
- **`frontend.yml`**: Handles integrity checks (signing) and deployment of the web frontend to Cloudflare Pages.
- **`deploy.yml`**: The release pipeline, in modes set by its guard job. A manual run on a branch is a release candidate (started by `just deploy`, or by `just release-dry-run` on any branch): it tests and builds everything once, from source with no build cache, the musl archives, the Debian packages, the signed production web build and the three images (pushed to GHCR only as `:sha-<commit>`, with `github.sha` injected so `/health` and CLI build metadata carry the commit), keylessly signs each immutable image digest and pushes its OCI build-provenance attestation, records them in a `release-manifest` artifact, and attests the build provenance of the release files. A pushed `X.Y.Z` tag builds nothing: after checking the signed tag and its named candidate run, it verifies each manifest digest's Cosign signature against this workflow's exact identity and OIDC issuer, then publishes exactly the manifest's files as the GitHub release, with notes made from the commit subjects since the previous release, adds the version tag (and `latest`) to the tested image digests, deploys the signed web build to Cloudflare Pages, dispatches Helm through `.github/actions/dispatch-helm`, and publishes the committed API docs. A manual run on `main` with `publish: X.Y.Z` recovers a tag whose publishing failed. The production steps check `.github/actions/release-is-latest` right before they act and queue across runs (`queue: max`), so an older tag never rolls production back.
- **`dispatch-helm-release.yml`**: Manual (or `workflow_call`) entry point that sends the `repository_dispatch` event to `permesi/permesi-helm` through the same `.github/actions/dispatch-helm` composite action the release uses; the payload carries the image digests so Helm can pin exact artifacts.

## Hardening

Actions are referenced by their major version tag (`actions/checkout@v7`), not by a
commit SHA: fixes within a major version arrive on their own, and a moved tag changes
the code a workflow runs, so only actions whose maintainers are trusted belong here.
`sigstore/cosign-installer` has no major tag and is referenced by its exact version.
`.github/dependabot.yml` proposes new major versions once a week, grouped into one pull
request into `sandbox` (never `main`, which only holds releases), for the workflows and
the composite actions. A separate weekly Cargo group watches the OPAQUE, WebAuthn
and OAuth-client parent libraries involved in the crypto-bigint launch blocker.
Those proposals also target `sandbox`; protocol compatibility aliases remain
under manual control and the audit must pass before a production release.
GitHub reads Dependabot configuration from the default branch, so a prepared
watch on `sandbox` becomes active only after that configuration is promoted.
No checkout keeps the GitHub token (`persist-credentials:
false`), the reusable workflows are read-only by default, and every Cargo command uses
`--locked`. The release workflow uses no build cache.

## Required Secrets

- **`PERMESI_HELM_APP_PRIVATE_KEY`**: GitHub App private key PEM used to mint a short-lived installation token in `.github/actions/dispatch-helm` (from `deploy.yml` and `dispatch-helm-release.yml`).

## Required Variables

- **`PERMESI_HELM_APP_ID`**: Numeric GitHub App ID used by `.github/actions/dispatch-helm`.

## Composite Actions

### `ensure-musl-toolchain`

Native Linux builds reuse an installed `musl-gcc` without invoking sudo. When the
compiler is missing, Debian package installation requires root or an existing
noninteractive sudo policy; the action never prompts or changes that policy.
Prefer provisioning `musl-dev` and `musl-tools` in the runner image/bootstrap so
the build user does not need installation privileges. A missing or broken
toolchain fails with provisioning guidance. A C/header/static-link probe verifies
the compiler before Cargo, and both development and fresh release builds use the
same action with a five-minute setup limit. Test its decisions without host
package changes using `python3 .github/actions/ensure-musl-toolchain/test_runtime.py`.
The format job runs these regressions and the metadata helper's tests.

### `ensure-browser-runtime`

Browser jobs use `./.github/actions/ensure-browser-runtime` to select native Google
Chrome or fall back to Chromium. A private empty profile must publish a valid
DevTools port and answer a direct loopback readiness request before setup exports
the job-local alias. Failed probes print startup diagnostics and retire their
processes and profiles before the next candidate is tried. Test selection,
fallback, port validation and cleanup locally with
`python3 .github/actions/ensure-browser-runtime/test_runtime.py`.

### `ensure-container-runtime`

Container jobs use `./.github/actions/ensure-container-runtime` to verify the API
used by testcontainers before exporting `DOCKER_HOST` and `CONTAINER_TOOL`.
GitHub-hosted runners use their existing system Docker API. Self-hosted runners
use Podman, installing it when missing and configuring a private `XDG_RUNTIME_DIR`.

Each self-hosted job starts its own Podman service with no inactivity timeout on
a private Unix socket under `/run/user/<uid>` (or the `/tmp` fallback). Runtime,
runroot, and libpod temporary state stay there so rootless networking can access
them under the host's AppArmor policy. Image storage and network configuration
live in a separate private directory under `RUNNER_TEMP`. Each job owns its pause
process, so stale host state and another job's cleanup cannot affect it.
`CONTAINER_HOST` routes Podman CLI steps to the same engine tests use through
`DOCKER_HOST`. Required images use fully qualified names, with bounded pull retries
before setup exports a usable runtime.

Setup probes the exact API endpoint; local `podman info` alone cannot establish
socket readiness. Hard links to the runner user's existing bus and systemd socket
keep DNS available when Netavark remounts `/run` inside its network namespace.
The host bus address is also exported for clients that use it.

The Node 24 action registers a post hook that removes its containers, networks,
volumes, and images through explicitly scoped engine commands, stops its recorded
API process, and deletes its directories from the job's user namespace. This
removes files owned by subordinate UIDs that ordinary runner cleanup cannot delete.
Setup never migrates shared Podman state or removes another job's service or
socket, and cleanup never runs `podman system reset`. Runner maintenance handles
shared migrations while jobs are stopped and orphaned resources after a runner
crash or host reboot, when action post hooks cannot execute.

Python 3 is required on runners for the action's readiness, concurrent isolation,
and hosted-runtime regressions. Run them locally with
`python3 .github/actions/ensure-container-runtime/test_runtime.py`.

If a future workflow needs containers, add this action as a step instead of copying the setup
script.

### `rust-toolchain`

Installs a Rust toolchain with `rustup` (preinstalled on GitHub-hosted runners, installed
when missing) and makes it the default, with optional targets and components, so no
third-party toolchain action runs in these workflows. It validates the toolchain name
before use.

### `release-is-latest`

Answers whether a tag is the highest promoted release right now: the highest `X.Y.Z` tag that is
a GitHub-verified annotated tag whose commit is on `main` and carries that version in
`Cargo.toml`. Every production step in `deploy.yml` (GitHub's Latest release, the `latest` image
tag, Cloudflare Pages, Helm, the docs) calls it right before acting, so an older tag never rolls
production back. Any GitHub API error fails the step instead of changing the answer.

### `dispatch-helm`

Validates a release's version, source commit and image digests, mints a GitHub App token and sends
the `permesi-release` repository dispatch to `permesi/permesi-helm`. Used by `deploy.yml`'s Helm
job and by `dispatch-helm-release.yml`.

The automatic release always supplies all three lowercase `sha256:<64 hex>`
digests and sets `tag_only: 'false'`. The manual and reusable dispatch workflow
accepts the same full-digest inputs by default. A legacy tag-only release requires
the caller to explicitly select the boolean `tag_only` input and leave **all three**
digest inputs empty. Empty inputs alone never authorize tag-only dispatch; partial
digest sets and tag-only acknowledgement combined with any digest fail before a
GitHub App token is minted. The generated payload always includes a JSON boolean
`client_payload.tag_only`, the normalized image tags and exact service repositories.

For an intentional legacy release, run
`gh workflow run dispatch-helm-release.yml -f version=vX.Y.Z -f source_sha=<40-hex-commit> -f tag_only=true`
or select the tag-only checkbox in the manual workflow UI. Reusable workflow callers
must pass `tag_only: true` explicitly; omitting it with empty digests is rejected.

Run the local sender/receiver regression matrix with
`python3 scripts/test-dispatch-helm.py --receiver ../permesi-helm/scripts/ci/release-event.sh -v`
(Bash, jq and PyYAML required). It executes the action's real validation and JSON
generation blocks, captures curl locally without any dispatch, then runs the
supplied Helm receiver against valid and malformed payloads, including injection inputs.
