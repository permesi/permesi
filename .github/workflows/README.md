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
- **`build.yml`**: Compiles the Rust services and builds the Leptos frontend.
- **`coverage.yml`**: Generates and uploads code coverage reports.
- **`frontend.yml`**: Handles integrity checks (signing) and deployment of the web frontend to Cloudflare Pages.
- **`deploy.yml`**: Orchestrates tagged releases by building Rust binaries, building the Leptos frontend dist, and publishing Debian packages, release tarballs, and container images. It also runs the frontend deploy workflow.
