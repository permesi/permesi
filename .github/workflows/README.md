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

### `ensure-container-runtime`

Container jobs use `./.github/actions/ensure-container-runtime` to verify the API
used by testcontainers before exporting `DOCKER_HOST` and `CONTAINER_TOOL`.
GitHub-hosted runners use their existing system Docker API. Self-hosted runners
use Podman, installing it when missing and configuring `XDG_RUNTIME_DIR` and
`DBUS_SESSION_BUS_ADDRESS` for rootless operation.

Each self-hosted job starts its own Podman service with no inactivity timeout on
a private Unix socket under `RUNNER_TEMP`. Setup probes that exact API endpoint;
local `podman info` alone cannot establish socket readiness. A failed startup
cleans up only its own process and directory, while successful services remain
available across steps until the runner's job cleanup. Setup never migrates
shared Podman state or removes another job's service or socket; migrations are
runner maintenance and must run while jobs are stopped.

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
