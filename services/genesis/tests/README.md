# Genesis Integration Tests

## Overview
The Genesis integration test (`integration_token.rs`) is self-contained and spins up
Postgres 18 + Vault dev-mode containers using the `test_support` crate. It configures
Vault AppRole + transit + database secrets, runs the Genesis binary, then exercises
`/token` and `/paserk.json` and verifies the token is persisted.

## Why This Harness Exists
- We need real Vault + Postgres interactions (token minting, DB role creation, transit signing).
- The same pattern can be reused for Permesi tests later.
- The test logs are intentionally enabled by default so failures in CI show context.

## What The Test Does
- Creates a shared container network (via testcontainers).
- Starts Postgres 18 and applies `db/sql/01_genesis.sql`, which seeds the default client UUID.
- Starts Vault in dev mode and configures:
  - AppRole auth and a policy for transit + database + renew endpoints.
  - Transit mount/key (defaults to `transit/genesis` + `genesis-signing`).
  - Database engine and a role for Genesis.
- Launches the Genesis binary with a wrapped AppRole secret-id.
- Calls `/token` and `/paserk.json`, verifies the PASETO, and checks the token row
  is persisted for the expected client UUID.

## Defaults And Inputs
Test defaults (unless overridden by env vars):
- Client UUID: `00000000-0000-0000-0000-000000000000` (seeded in `db/sql/01_genesis.sql`).
- Transit mount: `transit/genesis` (override with `GENESIS_TRANSIT_MOUNT`).
- Transit key name: `genesis-signing`.
- Database engine mount: `database`.
- Database config name and role name: `genesis`.
- Postgres user/password/db: `postgres` / `postgres` / `postgres`.
- Vault root token: `root-token` (dev mode only).

The test process launches `genesis` roughly as:
```
genesis --port <random_port> \
  --dsn <postgres_dsn> \
  --vault-url <vault_login_url> \
  --vault-role-id <role_id> \
  --vault-wrapped-token <wrapped_secret_id>
```

## Vault API Calls (Setup)
The test configures Vault using HTTP calls (no CLI needed). Endpoints:
- `POST /v1/sys/auth/approle` to enable AppRole.
- `PUT /v1/sys/policies/acl/genesis` to write the policy.
- `POST /v1/auth/approle/role/genesis` to create the AppRole.
- `GET /v1/auth/approle/role/genesis/role-id` to read `role_id`.
- `POST /v1/auth/approle/role/genesis/secret-id` to mint secret_id (wrapped + unwrapped).
- `POST /v1/sys/mounts/<transit_mount>` to enable transit.
- `POST /v1/<transit_mount>/keys/genesis-signing` to create the Ed25519 key.
- `POST /v1/sys/mounts/database` to enable the database engine.
- `POST /v1/database/config/genesis` to configure the Postgres connection.
- `POST /v1/database/roles/genesis` to create the dynamic DB role.

The policy allows:
- `transit/<mount>/keys/genesis-signing` (read)
- `transit/<mount>/sign/genesis-signing` (update)
- `database/creds/genesis` (read)
- `auth/token/renew-self` (update)
- `sys/leases/renew` (update)

### Vault Payload Examples
All requests include `X-Vault-Token: root-token`. Wrapped `secret_id` creation
adds `X-Vault-Wrap-TTL: 300s`.

Enable AppRole:
```json
{"type":"approle"}
```

Create AppRole:
```json
{
  "token_policies": ["genesis"],
  "secret_id_ttl": "1h",
  "token_ttl": "1h",
  "token_max_ttl": "4h"
}
```

Enable transit mount (example: `transit/genesis`):
```json
{"type":"transit"}
```

Create transit key:
```json
{"type":"ed25519"}
```

Enable database engine:
```json
{"type":"database"}
```

Database config (`/v1/database/config/genesis`):
```json
{
  "plugin_name": "postgresql-database-plugin",
  "allowed_roles": "genesis",
  "connection_url": "postgresql://{{username}}:{{password}}@postgres-<id>:5432/postgres?sslmode=disable",
  "username": "postgres",
  "password": "postgres"
}
```

Database role (`/v1/database/roles/genesis`):
```json
{
  "db_name": "genesis",
  "creation_statements": [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT CONNECT ON DATABASE \"postgres\" TO \"{{name}}\";",
    "GRANT USAGE ON SCHEMA public TO \"{{name}}\";",
    "GRANT SELECT ON TABLE clients TO \"{{name}}\";",
    "GRANT INSERT ON TABLE tokens TO \"{{name}}\";",
    "GRANT INSERT ON TABLE tokens_default TO \"{{name}}\";"
  ],
  "default_ttl": "1h",
  "max_ttl": "4h"
}
```

## Schema Applied In Tests
The helper loads `db/sql/01_genesis.sql` and splits statements by `;`.
It skips the `\\ir /db/sql/partitioning.sql` include (not needed for tests).
Key items in the schema:
- `clients` table with a seeded UUID `00000000-0000-0000-0000-000000000000`.
- `tokens` table partitioned by range with a default partition.
- Basic indices on tokens for IP and country.

## Token Verification And DB Assertions
The test verifies:
- `/token` returns a valid admission PASETO signed by Vault transit.
- `/paserk.json` returns a valid PASERK keyset; the token verifies with:
  - `expected_issuer`: `GENESIS_ADMISSION_ISS` or `https://genesis.permesi.dev`
  - `expected_audience`: `GENESIS_ADMISSION_AUD` or `permesi`
  - `expected_action`: `admission`
  - TTL bounds: 60..=180 seconds
- `claims.sub` matches the client UUID used in the request.
- `claims.jti` is a UUID and exists in `tokens`, joined to `clients.uuid`.

## Running Locally
From the repo root:
```
cargo test -p genesis --test integration_token
```
No `just dev-start` needed; the test spins up its own Postgres + Vault containers.

### Podman Notes
We prefer Podman. testcontainers talks to the Docker API, so point it at the Podman
socket before running tests:
```
export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
systemctl --user start podman.socket
```
If `DOCKER_HOST` is not set, the test harness will try to detect a Podman socket
automatically. If it cannot find one, it fails with a message telling you what to set.

### CI Notes
In GitHub Actions or other CI, ensure a Docker API socket is available before
running the tests. If Docker is not present, start a Podman service and set
`DOCKER_HOST` to the Podman socket.

## Debugging Tips
- Keep containers around by setting `TESTCONTAINERS_COMMAND=keep` and rerun the test.
  You can then inspect them with `podman ps` and `podman logs`.
- If you set `GENESIS_TRANSIT_MOUNT`, the test will configure Vault using that mount.
- Use `RUST_LOG=debug` to see more of Genesis and Vault client logs.
