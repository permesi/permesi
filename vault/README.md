# Vault (dev)

Local dev Vault runs as the `permesi-vault` container (pinned `docker.io/hashicorp/vault:2.0`, on the `permesi-net` network) and is configured using **Terraform** from the host.

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
- **PKI (TLS certificates)**: mounted at `pki-root` and `pki-int`
  - Runtime roles: `permesi-runtime`, `genesis-runtime`
  - Bootstrap roles: `permesi-bootstrap`, `genesis-bootstrap`
  - Cert auth roles: `permesi-agent`, `genesis-agent`
### Permesi Configuration Secrets

- Path: `secret/permesi/config`
- Fields:
  - `opaque_server_seed` (base64-encoded 32 bytes)
  - `mfa_recovery_pepper` (base64-encoded string)

Used by the `permesi` service to initialize OPAQUE authentication and MFA recovery code hashing.
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
- `VAULT_KV_MOUNT`, `VAULT_CONFIG_SECRET_PATH`, `VAULT_OPAQUE_SERVER_SEED`, `VAULT_MFA_RECOVERY_PEPPER`
- `VAULT_POSTGRES_HOST`, `VAULT_POSTGRES_PORT`, `VAULT_POSTGRES_USERNAME`, `VAULT_POSTGRES_PASSWORD`
- `VAULT_POSTGRES_DATABASE_GENESIS`, `VAULT_POSTGRES_DATABASE_PERMESI`, `VAULT_POSTGRES_SSLMODE`
- `VAULT_POSTGRES_REASSIGN_OWNER` (role used for `REASSIGN OWNED BY ... TO ...` during revocation)

If the Vault container can’t reach Postgres, adjust `VAULT_POSTGRES_HOST` (the default is
`host.containers.internal`, which depends on your Podman setup).

## Vault requirement

Vault is required in production for authentication, dynamic DB creds, and transit encryption. Running without Vault is not supported.
Rotation in production is typically operator-driven; the dev bootstrap defaults to a 30d auto-rotate period.

Production readiness checklist:
- HA cluster with tested failover.
- Automated unseal or a documented unseal runbook.
- Backups plus restore drills (e.g., raft snapshots or storage backups).
- Monitoring and alerts for health, sealed state, and token/lease renew failures.

## Native Kubernetes authentication

Both services support opt-in direct Kubernetes login independently of Vault Agent.
Agent remains the recommended Kubernetes deployment profile when PKI templates are
needed; native auth does not render inbound TLS bundles or rotate PKI material.
The default `--vault-auth-method auto` retains socket-to-Agent and TCP-to-AppRole
selection. Explicit `approle` and `kubernetes` require a TCP Vault URL and never
fall back to another method. For Kubernetes, configure an HTTP(S) Vault origin
(HTTPS with verified trust in production), not an AppRole login endpoint.

Set `<PREFIX>_VAULT_AUTH_METHOD=kubernetes` and
`<PREFIX>_VAULT_KUBERNETES_ROLE` for each workload (`PERMESI` or `GENESIS`).
`<PREFIX>_VAULT_KUBERNETES_AUTH_MOUNT` defaults to `kubernetes`; it is a relative
mount such as `cluster/kubernetes`, not `/v1/auth/...`, and forbids empty/traversal
segments and URL query/fragment syntax. `<PREFIX>_VAULT_KUBERNETES_TOKEN_PATH`
defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`. Each environment
setting has an equivalent `--vault-*` flag. Kubernetes mode rejects all AppRole
credentials; Kubernetes-only settings are rejected in other modes.

Provision separate least-privilege Vault roles for the two services, bound to the
exact ServiceAccount name, namespace, and audience. Attach the existing
service-specific transit/KV/database policies, not an operator/admin policy.
Configure renewable service tokens with a positive TTL; batch/nonrenewable tokens
cannot satisfy the application renewal contract. Vault receives `{role,jwt}` at
`/v1/auth/<mount>/login`; JWTs, issued tokens and raw remote login errors are not
included in application diagnostics. Login redirects are refused.

Disable the application's broad ServiceAccount automount and mount an explicit
read-only projected `serviceAccountToken` with an audience matching the Vault role
and an appropriate expiration. Mount the directory rather than a `subPath` file
so Kubernetes can replace the projection. Point the token-path flag at that file.
Only the **Vault server's reviewer ServiceAccount** needs TokenReview privileges
(typically `system:auth-delegator`); the application ServiceAccount needs no
TokenReview or Secret-read privileges. Configure Vault's Kubernetes auth backend
with its cluster API/trust/reviewer identity, separately from application roles.

Startup reads the JWT afresh and refuses missing, unreadable or empty files and
tokens without a usable renewable lease. The existing application worker renews
the resulting Vault token. At max TTL, revocation or repeated renewal failure,
the service shuts down fail-closed after its bounded retries and normal drain.
Configure Kubernetes/supervisor restart so the next process reads the latest
projection, logs in again and fetches new dynamic database credentials. This is
**restart-based reauthentication**, not seamless hot token replacement: a live
process does not swap token clones, pools or operator-token precedence. Revoked
database credentials likewise require restart/reacquisition. Account for restart
availability with replicas and tested readiness/drain behavior.
