# Repository Guidelines

These notes keep contributors aligned on how this Rust workspace is organized and how to land changes safely.

## Project Structure & Module Organization
- Workspace members: `services/permesi` (core IAM/OIDC), `services/genesis` (edge admission mint), `crates/admission_token` (shared contract + helpers), `apps/web` (Leptos CSR frontend).
- API artifacts live in `docs/openapi/*.json`; diagrams sit in `docs/architecture.mmd`.
- Each service keeps code under `src/` with `bin/` entrypoints, `cli/` utilities, and `vault/` helpers; SQL/schema assets live in `services/permesi/sql/`.
- Frontend assets live under `apps/web` with `Trunk.toml` and `public/` for static files; build output is static `dist/` (Cloudflare Pages).

## Build, Test, and Development Commands
- `cargo build -p permesi` / `cargo build -p genesis`: compile individual services.
- `just web` / `just web-build` / `just web-check`: run the Leptos frontend (Trunk-managed).
- `cargo test --workspace`: run all unit/integration tests.
- `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings`: formatting and lint gates used in CI.
- Regenerate OpenAPI: `cargo run -p permesi --bin openapi > docs/openapi/permesi.json` and similarly for `genesis`.
- Container builds: `podman build -f services/permesi/Dockerfile -t permesi:dev .` (and `genesis` analog).

## Coding Style & Naming Conventions
- Rust 2024 edition; defaults to `rustfmt`.
- Clippy is strict (`all` + `pedantic` deny). Avoid `unwrap`, `expect`, and panics; prefer `?` and typed errors.
- Do not add `#[allow(...)]` in production code; only acceptable inside test modules when needed.
  Exception: a dedicated `openapi_doc` submodule may include `#![allow(clippy::needless_for_each)]`
  to wrap `#[derive(OpenApi)] pub struct ApiDoc` (the lint is emitted from the derive macro).
- File/module names stay `snake_case`; types `UpperCamelCase`; constants `SCREAMING_SNAKE_CASE`.
- Keep functions small; prefer builder-style constructors for configs and explicit structs over loose maps.

## Testing Guidelines
- Tests live alongside code via `#[cfg(test)]` modules; mirror the public API shape.
- Name tests `<unit>_<behavior>` (e.g., `admission_token_rejects_expired()`).
- Cover edge cases around token validation (`exp`, `aud`, `iss`), PASERK keyset loading, and rate/risk controls.
- Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features`, and `cargo test --workspace` before PRs; add regression tests with every bug fix.

## Vault AppRole CLI Usage
- `--vault-url` must point to the AppRole login endpoint, e.g. `https://vault.tld:8200/v1/auth/<approle>/login`.
- `--vault-role-id` is required.
- Provide either `--vault-secret-id` or `--vault-wrapped-token`; wrapped tokens are unwrapped into a secret_id before login.
- Env equivalents: `GENESIS_VAULT_*` and `PERMESI_VAULT_*` (see `services/genesis/src/cli/commands/mod.rs` and `services/permesi/src/cli/commands/mod.rs`).

## Commit & Pull Request Guidelines
- Commit messages are short and imperative; scoped prefixes are common (`chore(workspace): ...`, `fix: ...`).
- PRs should state problem, approach, and impact; link issues when available.
- Include evidence of validation (commands run, screenshots/logs for CLI output if relevant) and note OpenAPI or SQL updates.
- Keep diffs minimal; update docs when behavior or endpoints change.

## Security & Configuration Tips
- Never commit secrets or tokens; keep PASERK/telemetry credentials in env vars or your secret manager.
- Prefer `rustls` defaults; avoid disabling TLS verification.
- Admission token verification is offline—do not add cross-service calls on the hot path without discussion.
- Container runtime policy: use `podman`, not `docker`, for local images/containers.
