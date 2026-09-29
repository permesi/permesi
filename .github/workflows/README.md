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
  unit/integration tests.
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

Every action is pinned to a full commit SHA, with its version in a comment.
`.github/dependabot.yml` proposes updates once a week, grouped into one pull request into
`sandbox` (never `main`, which only holds releases), for the workflows and the composite
actions. No checkout keeps the GitHub token (`persist-credentials: false`), the
reusable workflows are read-only by default, and every Cargo command uses `--locked`.
The release workflow uses no build cache.

## Required Secrets

- **`PERMESI_HELM_APP_PRIVATE_KEY`**: GitHub App private key PEM used to mint a short-lived installation token in `.github/actions/dispatch-helm` (from `deploy.yml` and `dispatch-helm-release.yml`).

## Required Variables

- **`PERMESI_HELM_APP_ID`**: Numeric GitHub App ID used by `.github/actions/dispatch-helm`.

## Composite Actions

### `ensure-container-runtime`

Some CI jobs need a working container runtime so they can run Postgres in Podman (for example, the
DB schema verification job). GitHub-hosted runners already include Docker, but this repo uses
Podman and also runs on self-hosted runners where Podman may not be installed or configured.

The `./.github/actions/ensure-container-runtime` composite action centralizes that setup so we
don’t duplicate it across multiple workflows and jobs. It:

- Installs Podman and its dependencies when missing.
- Sets `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` so rootless Podman can use netavark.
- Starts the Podman system service if the socket is missing.
- Exports `DOCKER_HOST` for compatibility with tools that expect a Docker socket.
- Runs `podman info` to validate the runtime.

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
