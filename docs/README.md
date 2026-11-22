# Permesi Documentation

This directory holds the engineering, security, protocol, and operational documentation for Permesi.

## Getting Started

- [Project Overview & Quick Start](../README.md) — Local development stack (`just start`), remote VM workflow, workspace layout, and common commands.
- [Setup & Deployment Guide](../SETUP.md) — Production prerequisites (PostgreSQL 19 and OpenBao 2.7), database bootstrap, Terraform provisioning, systemd/Quadlet deployment, and initial operator bootstrap.
- [Contributing Guide](../CONTRIBUTING.md) — Development workflow, required checks (`just test`, native/WASM Clippy, OpenAPI drift), commit rules, and release process.
- [Changelog](../CHANGELOG.md) — Release history and operator-facing changes.
- [Roadmap & Open Findings](../TODO.md) — Planned milestones and tracked security/engineering follow-ups.

## Architecture & Data Model

- [System Architecture](architecture.md) — Split-trust design (`genesis` edge mint + `permesi` core authority), local PASERK verification, cryptography, multi-replica state, and authority boundaries.
- [Tenant Resource Lifecycle](resource-lifecycle.md) — Organization → Project → Environment → Application hierarchy, explicit bottom-up soft deletion, role capabilities, and console behavior.
- [Bounded Tenant Mutations](tenant-mutation-deadlines.md) — Configurable handler/lock deadlines, cancellation-safe PostgreSQL transaction startup, and organization slug candidate caps.
- [Database Ownership & Runtime Authority](database-hardening.md) — Non-superuser service ownership, explicit least-privilege runtime grants, retained authorization history (`ON DELETE RESTRICT`), and rollout requirements.

## Authentication & Identity Lifecycle

- [Shared OPAQUE Exchanges](opaque-exchanges.md) — Cross-replica password login and reauthentication backed by AEAD-sealed PostgreSQL state (`opaque_exchanges`).
- [Shared WebAuthn Ceremonies](webauthn-exchanges.md) — Cross-replica passkey registration/discoverable login and hardware security-key MFA backed by sealed PostgreSQL state (`webauthn_exchanges`).
- [Password & MFA Session Lifecycle](mfa-lifecycle.md) — Atomic session/proof/refresh revocation on password rotation and recovery, factor completion guards, 10-minute recency checks, and primary-login MFA challenge lockouts.
- [Registration & Verification Security](registration-security.md) — Public/restricted/closed signup admission, reserved-domain denial, atomic pending-only verification, and outbox / TLS SMTP delivery.
- [Authentication Admission & Operations](authentication-operations.md) — Cluster-wide pending-state quotas, per-subject HMAC caps, transport/proxy IP trust, 429/503 responses, outcome tracing, and XChaCha20-Poly1305 key lifetime policy.

## OAuth 2.0 & OpenID Connect

- [OAuth/OIDC Foundation](oauth-foundation.md) — Client registrations, exact redirect and `<resource>:<action>` scope policies, Authorization Code + S256 PKCE, OIDC discovery/JWKS, confidential-client credentials, and implemented vs. planned scope.
- [Authorization-Code Token Exchange](oauth-token-exchange.md) — Transactional `POST /token`, RS256 access (`at+jwt`) and ID tokens, `GET`/`POST /userinfo`, OpenBao signing and `/jwks.json` refresh, and token rate-limit configuration.
- [Refresh-Token Families & Revocation](oauth-refresh-tokens.md) — Hashed rotating refresh families, reuse-triggered family revocation, `POST /revoke`, absolute/idle lifetimes, and offline JWT revocation boundaries.

## Platform Administration & Governance

- [Account Suspension & Containment](account-containment.md) — Operator account suspension and reactivation, atomic authority retirement, database-clock proof cutoffs, and append-only lifecycle auditing.
- [Platform-Operator Designation](operator-designation.md) — Two-operator request/approval lifecycle, sole-bootstrap exception, immediate disable, and elevation token revision checks.
- [Read-Only Platform Tenant Inspection](admin-tenant-inspection.md) — Global `/v1/admin/orgs` hierarchy browsing for enabled platform operators without widening tenant write authority.

## Testing, Scenarios & CI

- [Isolated OAuth & HA Scenarios](oauth-scenarios.md) — Disposable multi-replica (`3`–`5`) integration runner (`permesi-oauth-scenario`), 40-case coverage matrix, rolling restarts, replica outages, interoperability fixtures (`openidconnect-rs` and Better Auth), and process recovery.
- [CI, Module Boundaries & Build Provenance](ci-and-testing.md) — Frontend/test module organization, CI job/matrix/cache structure, fixture phase profiling (`just test-fixture-profile`), cached build identity (`just test-build-identity`), and hosted timing reports (`just ci-timings`).

## Component Guides & API Contracts

- [Permesi Service](../services/permesi/README.md) — Core IAM/OIDC CLI flags, OpenBao modes, API conventions, tenant creation flow, and Schemathesis setup.
- [Genesis Service](../services/genesis/README.md) — Edge admission mint CLI flags, `/token` and `/paserk.json` routes, header capture, and daily partition rollover.
- [Web Console](../apps/web/README.md) — Leptos CSR frontend layout, routes, OAuth/tenant UI conventions, Tailwind build, and Chromium browser tests.
- [SQL Schemas & Bootstrap](../db/sql/README.md) — Canonical PostgreSQL 19 scripts, bootstrap order, and grant verification queries.
- [OpenBao Operations](../openbao/README.md) — Local dev/persistent OpenBao setup, Terraform-provisioned resources, AppRole/Agent/Kubernetes auth, and transit key pruning.
- [OpenBao Terraform Module](../openbao/contrib/terraform/README.md) — Production OpenBao provisioning, PKI/Agent templates, and systemd unit examples.
- [GitHub Actions Workflows](../.github/workflows/README.md) — CI/CD workflow architecture, runner selection, composite actions, and release recovery.
- [Better Auth Interoperability Fixture](../tools/better_auth_interop/README.md) — Isolated Node 24 / Better Auth OIDC test fixture.
- **OpenAPI Specifications**: [permesi.json](openapi/permesi.json) · [genesis.json](openapi/genesis.json) · [Published API Docs (Redoc)](https://permesi.github.io/permesi/)
- **Architecture Diagrams**: Editable [D2](https://d2lang.com/) sources paired with maintained SVG illustrations live in [diagrams/](diagrams/) (use `d2` as a starting point when updating illustrations).
