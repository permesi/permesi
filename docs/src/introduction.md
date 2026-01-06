# Introduction

Permesi is a modern, security-first Identity Engine designed for high-trust environments. It employs a **Split-Trust Architecture** to separate network noise and edge concerns from core identity logic.

## Core Philosophies

1. **Split Trust**: Separate the edge admission (Genesis) from the core identity store (Permesi).
2. **Offline Verification**: Use PASERK/PASETO for zero-token and admission token verification without cross-service network calls on the hot path.
3. **No Persisted Admin Secrets**: Administrative actions require short-lived, Vault-backed session elevation.
4. **Rust First**: Built with Rust for safety, performance, and a small footprint.

## Workspace Layout

The project is organized as a Cargo workspace:

- `services/permesi`: Core IAM / OIDC authority.
- `services/genesis`: Edge admission token mint.
- `crates/admission_token`: Shared admission token contract + sign/verify helpers.
- `apps/web`: CSR-only Leptos admin console (Trunk + Tailwind, static `dist/`).

## Trust Boundaries

Permesi is designed with clear trust boundaries to ensure that even a compromise of the edge service (Genesis) does not automatically compromise the core identity store.

- **Internet**: Untrusted environment where users and clients reside.
- **Edge (Genesis)**: The "Bouncer". Handles raw traffic, rate limiting, and issues Admission Tokens.
- **Core (Permesi)**: The "Authority". Manages users, organizations, and OIDC flows. Verifies tokens offline.
- **Data Plane**: System of record for audit logs and persistent state.