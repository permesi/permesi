# genesis

[![Deploy](https://github.com/permesi/genesis/actions/workflows/deploy.yml/badge.svg)](https://github.com/permesi/genesis/actions/workflows/deploy.yml)
[![Test & Build](https://github.com/permesi/genesis/actions/workflows/build.yml/badge.svg)](https://github.com/permesi/genesis/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/permesi/genesis/graph/badge.svg?token=KLKV2M5JCT)](https://codecov.io/gh/permesi/genesis)

Token Zero generator (edge admission token mint).

<img src="genesis.svg" height="400">

## Overview

`genesis` is an HTTP service that:

- Issues short-lived **Admission Tokens** (RS256-signed JWTs)
- Publishes its public keys as **JWKS** at `GET /jwks.json` so `permesi` can verify tokens offline
- Persists minted token IDs (`jti`) and request metadata in Postgres for short-term validation/auditing
- Uses Vault (AppRole) to obtain DB credentials and keeps Vault leases renewed at runtime

## Vault requirement

Vault is required in production for AppRole auth, dynamic DB creds, and transit encryption. Running without Vault is not supported.
See the canonical checklist in `../../README.md#vault-dependency` and the Vault ops notes in `../../vault/README.md`.
TL;DR:
- Run Vault in HA with tested failover.
- Use auto-unseal or keep a documented unseal runbook.
- Alert on health, sealed state, and token/lease renew failures.

In the workspace “Split-Trust” flow:

1. Client requests admission from `genesis`
2. `genesis` returns a signed Admission Token (short-lived JWT)
3. Client presents that token to `permesi`
4. `permesi` verifies it offline (`sig` + `exp` + `aud` + `iss`) using the JWKS

## HTTP API

Implemented routes (see `services/genesis/src/genesis/mod.rs`):

| Method | Path | Notes |
|---|---|---|
| `GET` | `/token?client_id=<uuid>` | Mints an Admission Token and stores `jti` + metadata in Postgres |
| `GET` | `/jwks.json` | JWKS derived from the configured signing key |
| `GET` | `/health` | Checks Postgres connectivity; returns build info; sets `X-App` header |
| `OPTIONS` | `/health` | Health preflight |
| `GET` | `/headers` | Debug: echoes request headers |
| `POST` | `/verify` | Validates JWT + checks `jti` exists in Postgres within TTL |

Note: `POST /verify` is implemented, but is not currently included in the generated OpenAPI spec.

## Configuration

### Service / CLI

CLI args (also available via env vars):

- `GENESIS_PORT` (default: `8080`)
- `GENESIS_DSN` (required) base DSN; username/password are overwritten with Vault DB creds (e.g. `postgres://postgres@localhost:5432/genesis`)
- `GENESIS_VAULT_URL` (required) AppRole login URL (example: `https://vault.tld:8200/v1/auth/<approle>/login`)
- `GENESIS_VAULT_ROLE_ID` (required)
- `GENESIS_VAULT_SECRET_ID` (required unless `GENESIS_VAULT_WRAPPED_TOKEN` is set)
- `GENESIS_VAULT_WRAPPED_TOKEN` (optional; alternative to secret-id)
- `GENESIS_LOG_LEVEL` (optional) numeric or string log level (e.g. `info`) / `-v` flags

AppRole CLI example (direct secret_id):

```sh
cargo run -p genesis --bin genesis -- \
  --port 8080 \
  --dsn "postgres://postgres@localhost:5432/genesis" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$GENESIS_ROLE_ID" \
  --vault-secret-id "$GENESIS_SECRET_ID"
```

AppRole CLI example (wrapped token):

```sh
cargo run -p genesis --bin genesis -- \
  --port 8080 \
  --dsn "postgres://postgres@localhost:5432/genesis" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$GENESIS_ROLE_ID" \
  --vault-wrapped-token "$GENESIS_WRAPPED_TOKEN"
```

Startup behavior:

- Logs into Vault (direct secret-id or unwrap wrapped token)
- Fetches DB creds from Vault and injects them into the DSN
- Starts the HTTP server
- Spawns background renew loops for the Vault token and the DB lease; repeated renewal failures trigger graceful shutdown

### Admission Token Signing

Signing key configuration (required):

- `GENESIS_ADMISSION_PRIVATE_KEY_PEM` (required if no path is provided)
- `GENESIS_ADMISSION_PRIVATE_KEY_PATH` (required if no inline PEM is provided)

Claim defaults (optional):

- `GENESIS_ADMISSION_ISS` (default: `https://genesis.permesi.dev`) — JWT `iss` (“issuer”): the identity/URL that `permesi` expects minted the token.
- `GENESIS_ADMISSION_AUD` (default: `permesi`) — JWT `aud` (“audience”): who the token is intended for (usually the service name); `permesi` must match this.
- `GENESIS_ADMISSION_KID` (default: `genesis-1`) — JWT header `kid` (“key id”): selects which JWKS key verifies the signature (useful for key rotation).

### Header Capture

`GET /token` captures request metadata (IP/country/UA). Header selection is currently controlled via:

- `GENESIS_COUNTRY_HEADER` (used to select headers; defaults to Cloudflare `CF-Connecting-IP` / `CF-IPCountry`)

## Database & Retention

Schema lives in `services/genesis/sql/schema.sql`:

- `clients(id, name, uuid)` maps a stable client UUID to a small integer id
- `tokens(id ulid, client_id)` stores minted token IDs (`jti`) as ULIDs
- `metadata(id ulid, ip_address, country, user_agent)` stores request metadata per token

`TOKEN_EXPIRATION` is currently 120 seconds.

### Why ULID?

Helps find(group) tokens for the same period of time but still unique.

```sql
> select id, id::timestamp from tokens;
+----------------------------+-------------------------+
| id                         | id                      |
|----------------------------+-------------------------|
| 01HQAS6A6SGD3Z1V7VF86Q0B6P | 2024-02-23 10:46:47.769 |
| 01HQAS6A6SV2A93NMKH0S03CD1 | 2024-02-23 10:46:47.769 |
| 01HQAS6A6S8ZRMC0RZP8DEQ1Q5 | 2024-02-23 10:46:47.769 |
| 01HQAS6A6S1Q8TT1E8XE1J7JS8 | 2024-02-23 10:46:47.769 |
+----------------------------+-------------------------+

```

Expire tokens by time using `pg_cron`

```sql
SELECT cron.schedule('*/30 * * * *', $$DELETE
FROM tokens
WHERE id::timestamp < NOW() - INTERVAL '120 seconds'$$);
```

Update the database of the cron job with the following SQL command:

```sql
UPDATE cron.job SET database='genesis' WHERE jobid=5;
```

Check the cron.job table with the following SQL command:

```sql
SELECT * FROM cron.job;
+-------+--------------+------------------------------------------------------+-----------+----------+----------+----------+--------+---------+
| jobid | schedule     | command                                              | nodename  | nodeport | database | username | active | jobname |
|-------+--------------+------------------------------------------------------+-----------+----------+----------+----------+--------+---------|
| 2     | 0 0 * * *    | DELETE                                               | localhost | 5432     | postgres | postgres | True   | <null>  |
|       |              |     FROM cron.job_run_details                        |           |          |          |          |        |         |
|       |              |     WHERE end_time < now() - interval '7 days'       |           |          |          |          |        |         |
| 5     | */30 * * * * | DELETE                                               | localhost | 5432     | genesis  | postgres | True   | <null>  |
|       |              | FROM tokens                                          |           |          |          |          |        |         |
|       |              | WHERE id::timestamp < NOW() - INTERVAL '120 seconds' |           |          |          |          |        |         |
+-------+--------------+------------------------------------------------------+-----------+----------+----------+----------+--------+---------+
```

Check the status of the cron job with the following SQL command:

```sql
SELECT * FROM cron.job_run_details order by start_time DESC limit 5;
```

## TODO / Roadmap

The repository-level docs describe `genesis` as “the edge / bouncer”. The following pieces are
either not implemented yet in this service or need hardening:

- Add strict rate limiting (per IP / per `client_id`) and configurable policies
- Add PoW (proof-of-work) challenge flow for abuse prevention
- Improve issuance semantics (explicit allow/deny for unknown `client_id`, avoid silent fallbacks)
- Include `POST /verify` in OpenAPI
- Split header configuration (separate env vars for IP header vs country header selection)
- Add structured audit logging around issuance/validation and optionally export metrics
