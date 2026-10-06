# AGENTS.md

These guidelines are mandatory for contributors and for any AI coding agent operating in this repository. The goal is to land changes safely, keep security invariants intact, and keep the workspace consistent over time.

## Agent Contract (Read First)
- Follow this file strictly. If a request conflicts with these rules, explain the conflict and propose a compliant alternative.
- Keep diffs minimal: do not refactor, rename, reorder, or “clean up” unrelated code.
- Do not change authentication, authorization, token semantics, or trust boundaries unless explicitly requested.
- Do not weaken validation, scope checks, rate/risk controls, TLS verification, or logging hygiene.
- If you are unsure about an invariant, prefer asking for context or leaving behavior unchanged with a clear note.
- Do not hardcode configuration values. All runtime config for `permesi` and `genesis` must be defined in
  `services/permesi/src/cli/commands/mod.rs` or `services/genesis/src/cli/commands/mod.rs`, validated by clap,
  and then filtered/validated again in the corresponding `services/*/src/cli/dispatch/mod.rs`.

## Project Structure & Module Organization
- Workspace members:
  - `services/permesi`: core IAM/OIDC
  - `services/genesis`: edge admission mint
  - `crates/admission_token`: shared contract + helpers
  - `crates/vault_client`: shared Vault connectivity
  - `crates/service_utils`: shared service utilities
  - `crates/test_support`: local integration fixtures
  - `apps/web`: Leptos CSR frontend
  - `tools/oauth_scenario`: isolated OAuth integration runner
- Workspace releases use a single shared version via `[workspace.package]`; tags apply to the full workspace state.
- API artifacts live in `docs/openapi/*.json`; diagrams sit in `docs/architecture.mmd`.
- Each service keeps code under `src/` with `bin/` entrypoints, `cli/` utilities, and `vault/` helpers.
- SQL/schema assets live in `db/sql/`.
- Frontend assets live under `apps/web` with `Trunk.toml` and `public/`; build output is static `dist/` (Cloudflare Pages).

## Documentation Requirements
Documentation is mandatory. Code that changes behavior or flow without corresponding documentation updates is incomplete.

Style:
- Write documentation as concise narrative paragraphs.
- Do not use checklist-style labels repeated on every item (for example, repeated "Purpose / Context / Rationale / Security / ...").

Module-level docs (`//!`):
- Must describe the end-to-end flow and responsibilities.
- Must explain why the design exists (trade-offs, constraints, invariants).
- Must highlight security/trust boundaries where relevant.
- For protocol or multi-step flows, include a short "Flow Overview" section.

Item-level docs (`///`):
- Concise by default (1–5 lines).
- Focus on non-obvious behavior, invariants, and side effects.
- Expand only when the item is security-critical, protocol-related, or correctness-sensitive.
- Avoid duplication: do not restate module-level rationale on every struct or function.
- When you add or substantially change a function, add a short `///` doc comment describing intent, key invariants, and any authorization or data-exposure behavior.

Detailed item docs are required for:
- Cryptography and token handling
- Authentication/authorization transitions and role/scope decisions
- Protocol state machines or multi-step flows
- Parsing/validation/fallback precedence and unsafe assumptions

Authorization helper rule:
- Functions like `can_*`, `is_*`, `*_allowed`, `*_authorized` are access-control decisions.
- They must be side-effect free.
- Their docs must state what they authorize and which roles/scopes/claims are required.
- Never trust client-provided roles/permissions; enforce scope server-side based on verified tokens and server data.

## Build, Test, and Development Commands
- Build: `cargo build -p permesi` / `cargo build -p genesis`
- Telemetry: OTLP trace export is behind the default-off `telemetry` Cargo feature. Container images, release artifacts, and the `just` dev recipes build with `--features telemetry`; keep both the default and `--all-features` builds compiling and tested.
- Frontend: `just web` / `just web-build` / `just web-check`
- Dev: `just start` (starts infra + services in a `permesi-dev` Herdr workspace, falling back to a `tmux` session named `permesi`; `PERMESI_MUX` forces a choice; backends run over HTTPS/TLS, matching production/k8s). `just infra` starts only the infra for running services in your own terminals, `just attach` reattaches, and `just logs <service>` reads a pane without attaching. Use `just start-socket` for the opt-in same-host Unix-socket flow; `just start-http` is an alias of `just start`. Run `just doctor` on a new host; for a stack on a remote VM, `scripts/dev-remote --start <vm>` (run on the laptop) pushes a laptop-issued TLS cert, forwards `PERMESI_HTTPS_PORT` and starts the session.
- Just entrypoint is `.justfile`; recipe modules are split under `.justfiles/*.just` and imported from `.justfile`.
- Verify link helper: `just signup-verify-url`
- Tests: `cargo test --workspace`
- Lint/format gates (run after any change):
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features`

OpenAPI regeneration:
- `just openapi` regenerates both service artifacts; use `just openapi-permesi` or `just openapi-genesis` for one service.

Container builds (local):
- `podman build -f services/permesi/Dockerfile -t permesi:dev .` (and `genesis` analog)

## Database Inspection (psql)
- Connect: `podman exec -it postgres-permesi psql -U postgres -d permesi`
- List tables: `\dt`
- List enums: `\dT+`
- Describe table: `\d users`

## Coding Style & Naming Conventions
- Rust 2024 edition; defaults to `rustfmt`.
- Use native `async fn` in traits (stable since Rust 1.75); do not add or use the `async-trait` crate. When dynamic dispatch would make a native async trait object-unsafe, prefer a concrete type or enum when practical.
- Clippy is strict (`all` + `pedantic` deny). Avoid `unwrap`, `expect`, and panics; prefer `?` and typed errors.
- Do not add `#[allow(...)]` in production code; only acceptable inside test modules when needed.
- File/module names `snake_case`; types `UpperCamelCase`; constants `SCREAMING_SNAKE_CASE`.
- Keep functions small; prefer explicit structs over loose maps; use builder-style constructors for configs where appropriate.
- Group imports from the same crate/namespace (e.g., `use std::{...};`) rather than many single-line imports.

## Frontend UX Conventions
- Clickable text or icon-only controls must include `cursor-pointer` and a visible hover state so users get a clear affordance.

## Testing Guidelines
- Tests live alongside code via `#[cfg(test)]` modules; mirror the public API shape.
- Name tests `<unit>_<behavior>` (e.g., `admission_token_rejects_expired()`).
- Cover edge cases around token validation (`exp`, `aud`, `iss`), PASERK keyset loading, and rate/risk controls.
- Add regression tests with every bug fix.
- For security-sensitive changes, cover relevant malformed, missing, expired, replayed, mismatched, unauthorized and cross-tenant inputs. Assert the actual rejection and unchanged protected state; a skipped dependency, empty test filter or setup failure does not establish security coverage.

## Vault Bootstrap (Terraform)
- Vault bootstrap (policies, AppRole roles, transit keys, database engine) lives in `vault/contrib/terraform` (see `vault/contrib/terraform/README.md`).
- Terraform state (`.terraform/`, `terraform.tfstate*`, `terraform.tfvars`) is local-only and should remain untracked.

## Vault Connectivity & AppRole Usage
- `--vault-url` (or `PERMESI_VAULT_URL` / `GENESIS_VAULT_URL`) supports two modes:
  - **TCP Mode**: Starts with `http://` or `https://`. Requires `--vault-role-id` and either `--vault-secret-id` or `--vault-wrapped-token`. The app performs AppRole login and manages token/lease renewals.
  - **Agent Mode**: Starts with `/` or `unix://`. Points to a Vault Agent `api_proxy` socket. No role/secret IDs required; the app delegates authentication and renewals to the Agent (which must be configured with `use_auto_auth_token = true`).
- Wrapped tokens provided via `--vault-wrapped-token` are unwrapped into a `secret_id` before login (TCP mode only).

## Commit & Pull Request Guidelines
- Use short, plain imperative commit subjects. Never use conventional prefixes such as `feat:`, `chore:`, `fix:`, `docs:` or scoped variants.
- PRs should state problem, approach, and impact; link issues when available.
- Include evidence of validation (commands run, screenshots/logs for CLI output if relevant) and note OpenAPI or SQL updates.
- Keep diffs minimal; update docs when behavior or endpoints change.

## Security & Configuration Tips
- Never commit secrets or tokens; keep PASERK/telemetry credentials in env vars or your secret manager.
- Do not log secrets, tokens, passwords, or verification links.
- Prefer `rustls` defaults; do not disable TLS verification.
- Admission token verification is offline—do not add cross-service calls on the hot path without discussion.
- Container runtime policy: use `podman`, not `docker`, for local images/containers.

## Security Engineering / Daybreak

This repository and its associated owned development/test infrastructure are authorized targets for defensive security analysis. When available on the approved Codex identity and product surface, Daybreak Blue may be enabled for security development, review, testing and defensive analysis. Make full use of that capability: authentication, authorization, tokens, cryptography, protocols and attack-resistant behavior are legitimate engineering subjects. Verify availability rather than claiming unconfirmed access; Daybreak does not replace existing tool permissions or environment controls. Authorization is limited to Permesi and its owned/test infrastructure, never unrelated third-party systems without explicit authorization.

For a security-sensitive change, evaluate relevant security properties as well as functional behavior. Select checks based on the changed code, not a mechanical checklist. Consider authentication and session management; authorization, scopes versus internal permissions, RBAC, tenant/organization isolation, privilege escalation, confused deputies and IDOR/BOLA; OAuth 2.x/OIDC flows, issuance, client authentication, JWT validation and algorithm handling, refresh-token lifecycle, PKCE, state, nonce and exact redirect validation. Where applicable, examine input validation, injection, SSRF, CSRF, XSS, secrets/credentials, cryptographic usage, sensitive-data exposure, credential/token logging, replay, security-state races, dependency advisories and unsafe or fail-open defaults.

Trace authentication and authorization end-to-end through surrounding callers, middleware, persistence and failure paths. Identify the trust boundary, attacker-controlled input, trusted identity/principal and actual server-side authorization decision. Test whether validation can be bypassed or state replayed, forged, substituted or confused between users, clients, organizations or environments. Check that failures close the boundary and that logs, errors, URLs, persistence and telemetry do not expose sensitive values. Construct realistic abuse cases when useful, and use the negative-test guidance above to seek bypasses rather than only confirm happy paths.

Prefer established protocol/library primitives and verify assumptions against their actual behavior and relevant specifications. Prefer systemic fixes: resolve a shared weakness in the responsible abstraction, middleware, validation, authorization boundary, API type, protocol or reusable component rather than patching each caller. Keep the fix focused and preserve secure defaults and the existing validation rules. Follow the Agent Contract: report and propose fixes that would change authentication, authorization, token or trust-boundary semantics beyond the requested scope. Report significant security issues discovered outside the immediate diff clearly; avoid unrelated large refactors unless necessary to resolve the vulnerability within the authorized task.
