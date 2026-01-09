# Vault (dev)

Local dev Vault runs as a container using the `hashicorp/vault:latest` image and is configured using **Terraform** from the host.

- **Dev-only (in-memory)**: `just vault` runs Vault in dev mode and configures it via Terraform.
- **Persistent (recommended)**: `just vault-persist-ready` runs Vault in server mode with `vault/config.hcl` and configures it via Terraform.

The Terraform configuration in `vault/contrib/terraform` provisions the auth + secrets engines that `services/permesi` and `services/genesis` expect (AppRole, transit, and database creds). `just start` uses the persistent path by default.

## Prerequisites

- **Terraform**: Required to provision the Vault instance.
- **Podman**: Required to run the Vault container.

## Quick start

- Start Postgres: `just postgres` (creates the `genesis`/`permesi` databases, Vault root DB roles `vault_genesis`/`vault_permesi`, and runtime roles `genesis_runtime`/`permesi_runtime`)
- Start persistent Vault + Terraform bootstrap: `just vault-persist-ready` (also used by `just start`)
- Start dev-only Vault (no persistence): `just vault`
- Stop all dev services: `just stop`
- Restart everything: `just restart`
- Reset everything (Vault + Postgres data): `just reset` (deletes the databases; use for a clean slate)

## Dev-only Vault (no persistence)

Use this when you do not need data to survive restarts. It starts in dev mode, auto-unseals, and wipes data when the container stops. The root token is fixed to `dev-root`. The AppRole IDs and **Operator Token** are retrieved from Terraform state.

## Persistent dev Vault (recommended)

The persistent mode keeps Vault data in a Podman volume and stores init keys in a gitignored file. This is what `just start` uses.

- Start + init + unseal + Terraform bootstrap: `just vault-persist-ready` (also used by `just start`)
- Stop Vault: `just vault-stop`
- Reset data + keys + TF state (prompts): `just vault-reset`
- Keys file (keep safe): `vault/keys.json` (gitignored)
- Data volume: `permesi-vault-data`

To reset a persistent Vault, stop the container and remove the data volume plus `vault/keys.json` and the Terraform state files.

Persistent bootstrapping outputs the AppRole `role_id` / `secret_id` and the **Operator Token** values to the terminal. They are also available in your environment if you use `just dev-envrc`.

## Operator Token (Admin Claim)

To test the **Platform Operator** claim flow (bootstrapping the first admin or elevating privileges), 
you need a Vault token with the `permesi-operators` policy. The root token (`dev-root`) will **not** work.

The Terraform setup provisions the policy, and the `just` recipes generate a long-lived (24h) token with this policy.

- **Environment**: Available as `$PERMESI_OPERATOR_TOKEN` in your shell if you run `just dev-envrc` (or `just start`).

Copy this token into the "Vault token" field at `/admin/claim` to become an operator.

## What gets provisioned (via Terraform)

The resources are defined in `vault/contrib/terraform/`:

- **AppRole auth**: mounted at `auth/approle`
  - Roles: `permesi`, `genesis`
  - Policies: `permesi`, `genesis`
- **Transit (permesi)**: mounted at `transit/permesi`
  - Key: `users` (type `chacha20-poly1305`)
- **Transit (genesis)**: mounted at `transit/genesis`
  - Key: `genesis-signing` (type `ed25519`)
- **KV v2 (OPAQUE seed)**: mounted at `secret/permesi`
  - Secret: `opaque`
  - Field: `opaque_seed_b64` (base64-encoded 32 bytes)
- **Database creds (Postgres)**: mounted at `database`
  - Connections: `genesis`, `permesi`
  - Roles: `genesis`, `permesi`
  - Root users (managed outside Vault): `vault_genesis`, `vault_permesi` (rotated by Vault)
  - Runtime roles (managed in Postgres): `genesis_runtime`, `permesi_runtime` (grants live here; Vault-minted users are members)
- **Operator Policy**: `permesi-operators` (used for admin claim/elevation).

Note: Postgres roles/users are created **on-demand** when credentials are requested:
`vault read database/creds/genesis` or `vault read database/creds/permesi`.

## Common commands

- Root login: `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root vault status`
- Write dev exports into `.envrc`: `just vault-envrc`
- Write Vault exports plus local dev endpoints into `.envrc`: `just dev-envrc` (runs `direnv allow` if available)

## Terraform usage

You can run Terraform manually if you need to inspect or modify the configuration:

```bash
cd vault/contrib/terraform
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=$(jq -r .root_token ../keys.json)
terraform apply
```

## Transit key retention (optional)

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
