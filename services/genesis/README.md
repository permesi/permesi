# genesis

[![Deploy](https://github.com/permesi/genesis/actions/workflows/deploy.yml/badge.svg)](https://github.com/permesi/genesis/actions/workflows/deploy.yml)
[![Test & Build](https://github.com/permesi/genesis/actions/workflows/build.yml/badge.svg)](https://github.com/permesi/genesis/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/permesi/genesis/graph/badge.svg?token=KLKV2M5JCT)](https://codecov.io/gh/permesi/genesis)

Token Zero generator (edge admission token mint).

<img src="genesis.svg" height="400">

## Overview

`genesis` is an HTTP service that:

- Issues short-lived **Admission Tokens** (PASETO v4.public signed via Vault Transit)
- Publishes its public keys as a **PASERK keyset** at `GET /paserk.json` so `permesi` can verify tokens offline
- Persists minted token IDs (`jti`) and request metadata in Postgres for short-term validation/auditing
- Uses Vault (AppRole) to obtain DB credentials and keeps Vault leases renewed at runtime
- Acts as the **Zero Token** mint for user-facing auth flows; `permesi` validates these tokens offline via the PASERK keyset

## Vault requirement

Vault is required in production for AppRole auth, dynamic DB creds, and transit encryption. Running without Vault is not supported.
See the canonical checklist in `../../README.md#vault-dependency` and the Vault ops notes in `../../vault/README.md`.
TL;DR:
- Run Vault in HA with tested failover.
- Use auto-unseal or keep a documented unseal runbook.
- Alert on health, sealed state, and token/lease renew failures.

In the workspace “Split-Trust” flow:

1. Client requests admission from `genesis`
2. `genesis` returns a signed Admission Token (short-lived PASETO)
3. Client presents that token to `permesi`
4. `permesi` verifies it offline (`sig` + `exp` + `aud` + `iss`) using the PASERK keyset
5. For auth POSTs (OPAQUE signup/login, verify/resend), `permesi` validates a short-lived zero token offline.

## HTTP API

Implemented routes (see `services/genesis/src/genesis/mod.rs`):

| Method | Path | Notes |
|---|---|---|
| `GET` | `/token?client_id=<uuid>` | Mints an Admission Token and stores `jti` + metadata in Postgres |
| `GET` | `/paserk.json` | PASERK keyset derived from the configured signing key |
| `GET` | `/health` | Checks Postgres connectivity; returns build info; sets `X-App` header |
| `OPTIONS` | `/health` | Health preflight |
| `GET` | `/headers` | Debug: echoes request headers |

Note: there is no public token introspection endpoint. `jti` + metadata are persisted for audit
and potential future revocation tooling.
The `/token` response includes `Cache-Control: no-store` to discourage intermediaries from caching
admission tokens.

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

Local dev note: when running the workspace frontend (Trunk on `:8080`), use `--port 8000` to avoid collisions.

AppRole CLI example (direct secret_id):

```sh
cargo run -p genesis --bin genesis -- \
  --port 8000 \
  --dsn "postgres://postgres@localhost:5432/genesis" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$GENESIS_ROLE_ID" \
  --vault-secret-id "$GENESIS_SECRET_ID"
```

AppRole CLI example (wrapped token):

```sh
cargo run -p genesis --bin genesis -- \
  --port 8000 \
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

- Vault Transit key `genesis-signing` (type `ed25519`) under the `transit/genesis` mount by default.
- Private keys never leave Vault; `genesis` calls `/v1/transit/genesis/sign/genesis-signing` per token mint (mount configurable).

Claim defaults (optional):

- `GENESIS_ADMISSION_ISS` (default: `https://genesis.permesi.dev`) — `iss` (“issuer”): the identity/URL that `permesi` expects minted the token.
- `GENESIS_ADMISSION_AUD` (default: `permesi`) — `aud` (“audience”): who the token is intended for (usually the service name); `permesi` must match this.
- `iat` / `exp` are RFC3339 timestamps in the PASETO payload.
- `kid` format: PASERK public key ID (`k4.pid...`), embedded in the PASETO footer.
- `GENESIS_TRANSIT_MOUNT` (default: `transit/genesis`) — Vault Transit mount used for signing/PASERK.

### Header Capture

`GET /token` captures request metadata (IP/country/UA). Header selection is currently controlled via:

- `GENESIS_IP_HEADER` (defaults to Cloudflare `CF-Connecting-IP`)
- `GENESIS_COUNTRY_HEADER` (defaults to Cloudflare `CF-IPCountry`)

## Database & Retention

Schema lives in `services/genesis/sql/schema.sql`:

- `clients(id, name, uuid, is_reserved)` maps a stable client UUID to a small integer id; by default
  clients are reserved and must be explicitly marked non-reserved for production use
- `tokens(id uuidv7, client_id, created_at, ip_address, country, user_agent, metadata)` stores minted token IDs plus request metadata; `metadata` is JSONB for dynamic fields
The schema can optionally seed a `__test_only__` client marked non-reserved for local testing.
For production, leave the seed disabled (the default).

Load the schema with:

```sh
psql "$GENESIS_DSN" -v ON_ERROR_STOP=1 -f services/genesis/sql/schema.sql
```

Vault-managed DB credentials require bootstrap roles and grants. The canonical SQL for those roles
lives in `db/sql/00_init.sql`; run it (with production passwords) against your Postgres instance
before enabling the Vault database secrets engine.

If you want the test-only seed client, apply the seed file after the schema:

```sh
psql "$GENESIS_DSN" -v ON_ERROR_STOP=1 -f services/genesis/sql/seed_test_client.sql
```

That file `\ir`-includes `services/genesis/sql/partitioning.sql`, so it will attempt to set up
pg_cron-based partition maintenance when the extension is available. If you want to manage
partitioning separately, run `partitioning.sql` manually and omit the include.

`TOKEN_EXPIRATION` is currently 120 seconds.

Production bootstrap:

- Apply `services/genesis/sql/schema.sql` (idempotent base schema). It includes
  `partitioning.sql`, so pg_cron jobs are created when available.
- If you prefer to manage partitions separately, run `services/genesis/sql/partitioning.sql`
  on its own and omit the include.

`db/sql/` is used for local dev containers and is not intended as a production schema source.

### Why UUIDv7?

UUIDv7 is time-ordered like ULID but native in PostgreSQL 18 (`uuidv7()`), so we avoid a custom extension.

Tokens include a `created_at` column and are range-partitioned by time. For long-term retention,
drop whole partitions instead of deleting rows to avoid bloat.

`services/genesis/sql/partitioning.sql` provides a pg_cron-based maintenance function that:

- Creates daily partitions ahead of time
- Drops partitions older than the retention window

Once that job is running in production, remove the `tokens_default` partition so all rows land in
date partitions and retention is enforced by dropping old partitions.

You can also run the maintenance manually (for system cron or ad-hoc runs):

```sh
psql "$GENESIS_DSN" -v ON_ERROR_STOP=1 -c "SELECT genesis_tokens_rollover(7, 2);"
```

`7` is the retention window in days (drop partitions older than 7 days), and `2` is how many
future daily partitions to pre-create.

This function is safe to call from system cron: it is idempotent and guarded by an advisory lock.

Why this approach:

- Dropping whole partitions avoids table/index bloat that comes from large `DELETE` operations.
- A small retention window keeps the token store lightweight while still supporting audit/forensics.
- `tokens_default` is a bootstrap safety net for missing partitions; remove it once rollover is in place
  so missing partitions fail fast and retention works as intended.

pg_cron setup (one-time):

- Ensure `pg_cron` is installed and add it to `shared_preload_libraries`, then restart Postgres.
- Run `services/genesis/sql/partitioning.sql` in the `genesis` database.
- Verify the job exists: `SELECT * FROM cron.job WHERE jobname = 'genesis_tokens_rollover';`

Production checklist:

- Apply `services/genesis/sql/schema.sql`.
- Apply `services/genesis/sql/partitioning.sql`.
- Verify partitions exist: `\dt tokens_*` (psql) or query `pg_inherits`.
- Drop the default partition once rollover is active:
  `DROP TABLE IF EXISTS tokens_default;`

Quick audit query (shows partition names):

```sql
SELECT c.relname AS partition
FROM pg_class c
JOIN pg_inherits i ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'tokens'
ORDER BY 1;
```

Newcomer notes:

- `tokens_default` is only a bootstrap safety net; remove it once rollover is creating partitions.
  If left in place, rows can accumulate there and will not be pruned by retention.
- Retention is enforced by dropping partitions, not by per-row deletes.
- `genesis_tokens_rollover(7, 2)` means "keep 7 days, precreate 2 days ahead"; adjust for your workload.
- If `pg_cron` is not enabled, run the rollover function from system cron or manually.

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
- Optional internal-only token introspection/revocation tooling (auth + rate limits)
- Split header configuration (separate env vars for IP header vs country header selection)
- Add structured audit logging around issuance/validation and optionally export metrics
