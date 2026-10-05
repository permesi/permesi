# GitHub Actions Workflows

This directory contains the CI/CD workflows for the Permesi workspace.

## Runner Configuration (`CI_RUNNER`)

Most workflows are configured to use a flexible runner selection logic:

```yaml
runs-on: ${{ vars.CI_RUNNER || 'self-hosted' }}
```

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

## Workflow Overview

- **`test.yml`**: Handles formatting, linting (clippy), dependency auditing for the web app, and
  unit/integration tests. The unit job runs every library and binary test, including
  the database-backed handler suites. The integration job runs standalone `tests/`
  targets with `--test '*'`; `--tests` would repeat the library and binary suites,
  doubling database work on self-hosted runners. Coverage still runs the full workspace.
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
  fixture suite and explicitly executes both normally ignored real PostgreSQL browser tests for
  authorization consent/redirects and OPAQUE organization-deletion reauthentication. Node 24, pinned
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
- **`schemathesis.yml`**: Runs OpenAPI contract checks with Schemathesis as a post-deploy verification.
  It runs manually via `workflow_dispatch` and is intended to be triggered after deployment settles.
  It waits for each service `/health` endpoint (up to 10 minutes for genesis), verifies the deployed
  commit hash matches the selected workflow ref SHA (`github.sha`), and then runs GET-only checks.
  Base URLs are resolved from the selected run branch
  (`develop` -> `*.permesi.dev`, all others -> `*.permesi.com`).
  Commit metadata parsing in the `/health` verification step requires `python3` on the runner.
- **`coverage.yml`**: Generates and uploads code coverage reports.
- **`frontend.yml`**: Handles integrity checks (signing) and deployment of the web frontend to Cloudflare Pages.
- **`deploy.yml`**: The release pipeline, in modes set by its guard job. A manual run on a branch is a release candidate (started by `just deploy`, or by `just release-dry-run` on any branch): it tests and builds everything once, from source with no build cache, the musl archives, the Debian packages, the signed production web build and the three images (pushed to GHCR only as `:sha-<commit>`, with `github.sha` injected so `/health` and CLI build metadata carry the commit), records them in a `release-manifest` artifact, and attests the build provenance of the release files. A pushed `X.Y.Z` tag builds nothing: after checking the signed tag and its named candidate run, it publishes exactly the manifest's files as the GitHub release, with notes made from the commit subjects since the previous release, adds the version tag (and `latest`) to the tested image digests, deploys the signed web build to Cloudflare Pages, dispatches Helm through `.github/actions/dispatch-helm`, and publishes the committed API docs. A manual run on `main` with `publish: X.Y.Z` recovers a tag whose publishing failed. The production steps check `.github/actions/release-is-latest` right before they act and queue across runs (`queue: max`), so an older tag never rolls production back.
- **`dispatch-helm-release.yml`**: Manual (or `workflow_call`) entry point that sends the `repository_dispatch` event to `permesi/permesi-helm` through the same `.github/actions/dispatch-helm` composite action the release uses; the payload carries the image digests so Helm can pin exact artifacts.

## Hardening

Actions are referenced by their major version tag (`actions/checkout@v7`), not by a
commit SHA: fixes within a major version arrive on their own, and a moved tag changes
the code a workflow runs, so only actions whose maintainers are trusted belong here.
`sigstore/cosign-installer` has no major tag and is referenced by its exact version.
`.github/dependabot.yml` proposes new major versions once a week, grouped into one pull
request into `sandbox` (never `main`, which only holds releases), for the workflows and
the composite actions. No checkout keeps the GitHub token (`persist-credentials:
false`), the reusable workflows are read-only by default, and every Cargo command uses
`--locked`. The release workflow uses no build cache.

## Required Secrets

- **`PERMESI_HELM_APP_PRIVATE_KEY`**: GitHub App private key PEM used to mint a short-lived installation token in `.github/actions/dispatch-helm` (from `deploy.yml` and `dispatch-helm-release.yml`).

## Required Variables

- **`PERMESI_HELM_APP_ID`**: Numeric GitHub App ID used by `.github/actions/dispatch-helm`.

## Composite Actions

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
