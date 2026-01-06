# Genesis (The Bouncer)

`genesis` is the edge admission service for Permesi. It handles the initial point of contact for users and clients, ensuring that only legitimate requests reach the core identity logic.

## Overview

`genesis` is a stateless HTTP service that:

- Issues short-lived **Admission Tokens** (PASETO v4.public signed via Vault Transit).
- Publishes its public keys as a **PASERK keyset** at `GET /paserk.json`.
- Persists minted token IDs (`jti`) and request metadata in Postgres for short-term validation/auditing.
- Acts as the **Zero Token** mint for user-facing auth flows.

## Admission Flow

1. Client requests admission from `genesis`.
2. `genesis` returns a signed Admission Token (short-lived PASETO).
3. Client presents that token to `permesi`.
4. `permesi` verifies it offline (`sig` + `exp` + `aud` + `iss`) using the PASERK keyset.

## HTTP API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/token?client_id=<uuid>` | Mints an Admission Token and stores `jti` + metadata in Postgres |
| `GET` | `/paserk.json` | PASERK keyset derived from the configured signing key |
| `GET` | `/health` | Checks Postgres connectivity; returns build info |

## Configuration

### Admission Token Signing

- **Vault Transit**: Uses a `transit/genesis` mount and an `ed25519` key named `genesis-signing`.
- **Claims**:
    - `iss`: Issuer identity (default: `https://genesis.permesi.dev`).
    - `aud`: Audience (default: `permesi`).
    - `exp`: Expiration (default: 120 seconds).

## Database & Retention

Genesis uses a time-partitioned table for tokens:

- **UUIDv7**: Used for time-ordered, native PostgreSQL token IDs.
- **Partitioning**: Tokens are range-partitioned by time. Old partitions are dropped rather than rows being deleted to avoid bloat.
- **Retention**: Controlled via `genesis_tokens_rollover(retention_days, premake_days)`.