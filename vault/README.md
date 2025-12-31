# Vault (dev)

Local dev Vault runs as a container built from `vault.Dockerfile` and bootstrapped by `vault/bootstrap.sh`.
The bootstrap script provisions the auth + secrets engines that `services/permesi` and `services/genesis`
expect (AppRole, transit, and database creds).

## Quick start

- Start Postgres: `just postgres` (creates the `genesis` and `permesi` databases if missing)
- Start Vault: `just vault` (or `just dev-start`)

Vault prints the root token plus AppRole `role_id` / `secret_id` values for both services.
Tip: if you missed the startup output, you can recover it from logs:

```sh
podman logs vault | rg "Login URL|genesis RoleID|genesis SecretID|permesi RoleID|permesi SecretID"
```

## What gets provisioned

- **AppRole auth**: mounted at `auth/${VAULT_APPROLE_MOUNT}` (default `auth/approle`)
  - Roles: `permesi`, `genesis`
  - Policies: `permesi`, `genesis`
- **Transit (permesi)**: mounted at `${VAULT_TRANSIT_MOUNT}` (default `transit/permesi`)
  - Key: `${VAULT_TRANSIT_KEY}` (default `users`, type `chacha20-poly1305`)
- **Transit (genesis)**: mounted at `${VAULT_GENESIS_TRANSIT_MOUNT}` (default `transit/genesis`)
  - Key: `${VAULT_GENESIS_TRANSIT_KEY}` (default `genesis-signing`)
- **KV v2 (OPAQUE seed)**: mounted at `${VAULT_KV_MOUNT}` (default `kv`)
  - Secret: `${VAULT_OPAQUE_SECRET_PATH}` (default `permesi/opaque`)
  - Field: `opaque_seed_b64` (base64-encoded 32 bytes)
- **Database creds (Postgres)**: mounted at `${VAULT_DATABASE_MOUNT}` (default `database`)
  - Connections: `genesis` (DB `${VAULT_POSTGRES_DATABASE_GENESIS}`), `permesi` (DB `${VAULT_POSTGRES_DATABASE_PERMESI}`)
  - Roles (Vault database roles): `genesis`, `permesi`

Note: Postgres roles/users are created **on-demand** when credentials are requested:
`vault read database/creds/genesis` or `vault read database/creds/permesi`.

## Common commands

- Root login: `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault status`
- AppRole login (example): `vault write auth/approle/login role_id=<ROLE_ID> secret_id=<SECRET_ID>`
- Fetch DB creds: `vault read database/creds/genesis`
- Read OPAQUE seed: `vault kv get ${VAULT_KV_MOUNT}/${VAULT_OPAQUE_SECRET_PATH}`
- Print dev exports from Vault logs: `just vault-env`
- Write dev exports into `.envrc` (overwrites it): `just vault-envrc`
- Print Vault exports plus local dev endpoints: `just dev-env`
- Write Vault exports plus local dev endpoints into `.envrc`: `just dev-envrc` (runs `direnv allow` if available)

## Transit key retention (optional)

To keep only the latest two versions for a transit key (for example, the genesis signing key),
run the pruning script on a schedule (cron/systemd timer):

> see current versions: `vault read -format=json transit/genesis/keys/genesis-signing | jq -r '.data.keys | keys[]' | sort -n`


```sh
VAULT_ADDR=http://127.0.0.1:8200 \
VAULT_TOKEN=dev-root \
VAULT_TRANSIT_MOUNT=transit/genesis \
VAULT_TRANSIT_KEY=genesis-signing \
VAULT_TRANSIT_KEEP_VERSIONS=2 \
./vault/prune_transit_versions.sh
```

Note: Vault requires `deletion_allowed=true` on the key config for version deletes:

```sh
vault write transit/genesis/keys/genesis-signing/config deletion_allowed=true
```

## Getting `role_id` and `secret_id`

When you run `just vault`, the bootstrap script prints the `role_id` and a freshly-generated `secret_id`
for both `permesi` and `genesis`.

If you need to fetch/regenerate them manually (requires a token with permission to manage AppRoles, e.g.
the dev root token), use:

- Read `permesi` RoleID:
  - `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault read -field=role_id auth/${VAULT_APPROLE_MOUNT}/role/permesi/role-id`
- Create a new `permesi` SecretID (generates a new one each time):
  - `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault write -field=secret_id -f auth/${VAULT_APPROLE_MOUNT}/role/permesi/secret-id`

- Read `genesis` RoleID:
  - `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault read -field=role_id auth/${VAULT_APPROLE_MOUNT}/role/genesis/role-id`
- Create a new `genesis` SecretID:
  - `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault write -field=secret_id -f auth/${VAULT_APPROLE_MOUNT}/role/genesis/secret-id`

### Wrapped SecretID (optional)

Both services support passing a wrapped token instead of a raw SecretID.
To generate a wrapped SecretID token (example: 5 minute wrap TTL):

- `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault write -wrap-ttl=5m -field=wrapping_token -f auth/${VAULT_APPROLE_MOUNT}/role/permesi/secret-id`

Then pass that wrapping token to the service via `*_VAULT_WRAPPED_TOKEN`.

## Configuration knobs

The most useful env vars (all have defaults in `vault.Dockerfile` and/or `vault/bootstrap.sh`):

- `VAULT_APPROLE_MOUNT`, `VAULT_TRANSIT_MOUNT`, `VAULT_TRANSIT_KEY`, `VAULT_GENESIS_TRANSIT_MOUNT`, `VAULT_GENESIS_TRANSIT_KEY`, `VAULT_TRANSIT_AUTO_ROTATE_PERIOD`, `VAULT_DATABASE_MOUNT`
- `VAULT_KV_MOUNT`, `VAULT_OPAQUE_SECRET_PATH`, `VAULT_OPAQUE_SEED_B64`
- `VAULT_POSTGRES_HOST`, `VAULT_POSTGRES_PORT`, `VAULT_POSTGRES_USERNAME`, `VAULT_POSTGRES_PASSWORD`
- `VAULT_POSTGRES_DATABASE_GENESIS`, `VAULT_POSTGRES_DATABASE_PERMESI`, `VAULT_POSTGRES_SSLMODE`
- `VAULT_POSTGRES_REASSIGN_OWNER` (role used for `REASSIGN OWNED BY ... TO ...` during revocation)

If the Vault container can’t reach Postgres, adjust `VAULT_POSTGRES_HOST` (the default is
`host.containers.internal`, which depends on your Podman setup).

## Vault requirement

Vault is required in production for AppRole auth, dynamic DB creds, and transit encryption. Running without Vault is not supported.
Rotation in production is typically operator-driven; the dev bootstrap defaults to a 30d auto-rotate period.

Production readiness checklist:
- HA cluster with tested failover.
- Automated unseal or a documented unseal runbook.
- Backups plus restore drills (e.g., raft snapshots or storage backups).
- Monitoring and alerts for health, sealed state, and token/lease renew failures.
