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
    *   `deploy.yml`: This workflow is hardcoded to use `ubuntu-latest` for production releases to ensure a clean, standardized environment for final artifacts and deployments.

## Workflow Overview

- **`test.yml`**: Handles formatting, linting (clippy), and unit/integration tests.
- **`build.yml`**: Compiles the Rust services and builds the Leptos frontend. The frontend build clears the
  `apps/web/dist` output and runs a full `cargo clean -p permesi_web` so self-hosted runners do not
  reuse stale build artifacts when deploying Cloudflare Pages.
- **`schemathesis.yml`**: Runs OpenAPI contract checks with Schemathesis as a post-deploy verification.
  It is triggered only by a successful `Deploy` workflow run (`workflow_run`), waits for `/health`,
  verifies the deployed commit hash matches the deploy run SHA, and then runs GET-only checks.
  Base URLs are resolved from the deployed branch (`develop` -> `*.permesi.dev`, all others -> `*.permesi.com`).
  Commit metadata parsing in the `/health` verification step requires `python3` on the runner.
- **`coverage.yml`**: Generates and uploads code coverage reports.
- **`frontend.yml`**: Handles integrity checks (signing) and deployment of the web frontend to Cloudflare Pages.
- **`deploy.yml`**: Orchestrates tagged releases by building Rust binaries, building the Leptos frontend dist, and publishing Debian packages, release tarballs, and container images. It also runs the frontend deploy workflow.

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
