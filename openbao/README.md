# OpenBao (dev)

Local dev OpenBao runs as the `permesi-openbao` container (pinned `docker.io/openbao/openbao:2.7.3`, on the `permesi-net` network) and is configured using **Terraform** from the host.

- **Dev-only (in-memory)**: `just openbao` runs OpenBao in dev mode and configures it via Terraform.
- **Persistent (recommended)**: `just openbao-persist-ready` runs OpenBao in server mode with `openbao/config.hcl` and configures it via Terraform.

The Terraform configuration in `openbao/contrib/terraform` provisions the auth + secrets engines that `services/permesi` and `services/genesis` expect (AppRole, transit, and database creds). `just start` uses the persistent path by default.

## Prerequisites

- **Terraform**: Required to provision the OpenBao instance.
- **Podman**: Required to run the OpenBao container.

## Quick start

- Start Postgres: `just postgres` (creates the `genesis`/`permesi` databases, OpenBao root DB roles `openbao_genesis`/`openbao_permesi`, and runtime roles `genesis_runtime`/`permesi_runtime`)
- Start persistent OpenBao + Terraform bootstrap: `just openbao-persist-ready` (also used by `just start`)
- Start dev-only OpenBao (no persistence): `just openbao`
- Stop all dev services: `just stop`
- Restart everything: `just restart`
- Reset everything (OpenBao + Postgres data): `just reset` (deletes the databases; use for a clean slate)

## Dev-only OpenBao (no persistence)

Use this when you do not need data to survive restarts. It starts in dev mode, auto-unseals, and wipes data when the container stops. The root token is fixed to `dev-root`. The AppRole IDs and **Operator Token** are retrieved from Terraform state.

## Persistent dev OpenBao (recommended)

The persistent mode keeps OpenBao data in a Podman volume (single-node Raft storage, see `openbao/config.hcl`) and stores init keys in a gitignored file. This is what `just start` uses. Both modes load `openbao/audit.hcl`, because OpenBao only accepts audit devices declared in its configuration.

- Start + init + unseal + Terraform bootstrap: `just openbao-persist-ready` (also used by `just start`)
- Stop OpenBao: `just openbao-stop`
- Reset data + keys + TF state (prompts): `just openbao-reset`
- Keys file (keep safe): `openbao/keys.json` (gitignored)
- Data volume: `permesi-openbao-data`

To reset a persistent OpenBao, stop the container and remove the data volume plus `openbao/keys.json` and the Terraform state files.

Persistent bootstrapping outputs the AppRole `role_id` / `secret_id` and the **Operator Token** values to the terminal. They are also available in your environment if you use `just dev-envrc`.

## Operator Token (Admin Claim)

To test the **Platform Operator** claim flow (bootstrapping the first admin or elevating privileges),
you need an OpenBao token with the `permesi-operators` policy. The root token (`dev-root`) will **not** work.

The Terraform setup provisions the policy, and the `just` recipes generate a long-lived (24h) token with this policy.

- **Environment**: Available as `$PERMESI_OPERATOR_TOKEN` in your shell if you run `just dev-envrc` (or `just start`).

Copy this token into the "OpenBao token" field at `/admin/claim` to become an operator.

## What gets provisioned (via Terraform)

The resources are defined in `openbao/contrib/terraform/`:

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
  - Root users (managed outside OpenBao): `openbao_genesis`, `openbao_permesi` (rotated by OpenBao)
  - Runtime roles (managed in Postgres): `genesis_runtime`, `permesi_runtime` (grants live here; OpenBao-minted users are members)
- **Operator Policy**: `permesi-operators` (used for admin claim/elevation).

Note: Postgres roles/users are created **on-demand** when credentials are requested:
`bao read database/creds/genesis` or `bao read database/creds/permesi`.

## Common commands

- Root login: `BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao status`
- Write dev exports into `.envrc`: `just openbao-envrc`
- Write OpenBao exports plus local dev endpoints into `.envrc`: `just dev-envrc` (runs `direnv allow` if available)

## Terraform usage

You can run Terraform manually if you need to inspect or modify the configuration:

```bash
cd openbao/contrib/terraform
export VAULT_ADDR=http://127.0.0.1:8200   # the hashicorp/vault provider reads VAULT_*
export VAULT_TOKEN=$(jq -r .root_token ../../keys.json)
terraform apply
```

## Transit key retention (optional)

To keep only the latest two versions for a transit key (for example, the genesis signing key),
run the pruning script on a schedule (cron/systemd timer):

> see current versions: `bao read -format=json transit/genesis/keys/genesis-signing | jq -r '.data.keys | keys[]' | sort -n`


```sh
BAO_ADDR=http://127.0.0.1:8200 \
BAO_TOKEN=dev-root \
OPENBAO_TRANSIT_MOUNT=transit/genesis \
OPENBAO_TRANSIT_KEY=genesis-signing \
OPENBAO_TRANSIT_KEEP_VERSIONS=2 \
./openbao/prune_transit_versions.sh
```

Note: OpenBao requires `deletion_allowed=true` on the key config for version deletes:

```sh
bao write transit/genesis/keys/genesis-signing/config deletion_allowed=true
```

## Getting `role_id` and `secret_id`

When you run `just openbao`, the bootstrap script prints the `role_id` and a freshly-generated `secret_id`
for both `permesi` and `genesis`.

If you need to fetch/regenerate them manually (requires a token with permission to manage AppRoles, e.g.
the dev root token), use:

- Read `permesi` RoleID:
  - `BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao read -field=role_id auth/${OPENBAO_APPROLE_MOUNT}/role/permesi/role-id`
- Create a new `permesi` SecretID (generates a new one each time):
  - `BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao write -field=secret_id -f auth/${OPENBAO_APPROLE_MOUNT}/role/permesi/secret-id`

- Read `genesis` RoleID:
  - `BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao read -field=role_id auth/${OPENBAO_APPROLE_MOUNT}/role/genesis/role-id`
- Create a new `genesis` SecretID:
  - `BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao write -field=secret_id -f auth/${OPENBAO_APPROLE_MOUNT}/role/genesis/secret-id`

### Wrapped SecretID (optional)

Both services support passing a wrapped token instead of a raw SecretID.
To generate a wrapped SecretID token (example: 5 minute wrap TTL):

- `BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao write -wrap-ttl=5m -field=wrapping_token -f auth/${OPENBAO_APPROLE_MOUNT}/role/permesi/secret-id`

Then pass that wrapping token to the service via `*_OPENBAO_WRAPPED_TOKEN`.

## Configuration knobs

The `just` recipes read `OPENBAO_APPROLE_MOUNT` (default `approle`) when they mint SecretIDs. Everything
else (database host, credentials, SSL mode and PKI URLs) is a Terraform variable; see
`openbao/contrib/terraform/variables.tf`. In local dev the database host defaults to the
`postgres-permesi` container on the shared `permesi-net` network.

## OpenBao requirement

OpenBao is required in production for authentication, dynamic DB creds, and transit encryption. Running without OpenBao is not supported.
Rotation in production is typically operator-driven; the dev bootstrap defaults to a 30d auto-rotate period.

Production readiness checklist:
- HA cluster with tested failover.
- Automated unseal or a documented unseal runbook.
- Backups plus restore drills (e.g., raft snapshots or storage backups).
- Monitoring and alerts for health, sealed state, and token/lease renew failures.

## Native Kubernetes authentication

Both services support opt-in direct Kubernetes login independently of OpenBao Agent.
Agent remains the recommended Kubernetes deployment profile when PKI templates are
needed; native auth does not render inbound TLS bundles or rotate PKI material.
The default `--openbao-auth-method auto` retains socket-to-Agent and TCP-to-AppRole
selection. Explicit `approle` and `kubernetes` require a TCP OpenBao URL and never
fall back to another method. For Kubernetes, configure an HTTP(S) OpenBao origin
(HTTPS with verified trust in production), not an AppRole login endpoint.

Set `<PREFIX>_OPENBAO_AUTH_METHOD=kubernetes` and
`<PREFIX>_OPENBAO_KUBERNETES_ROLE` for each workload (`PERMESI` or `GENESIS`).
`<PREFIX>_OPENBAO_KUBERNETES_AUTH_MOUNT` defaults to `kubernetes`; it is a relative
mount such as `cluster/kubernetes`, not `/v1/auth/...`, and forbids empty/traversal
segments and URL query/fragment syntax. `<PREFIX>_OPENBAO_KUBERNETES_TOKEN_PATH`
defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`. Each environment
setting has an equivalent `--openbao-*` flag. Kubernetes mode rejects all AppRole
credentials; Kubernetes-only settings are rejected in other modes.

Provision separate least-privilege OpenBao roles for the two services, bound to the
exact ServiceAccount name, namespace, and audience. Attach the existing
service-specific transit/KV/database policies, not an operator/admin policy.
Configure renewable service tokens with a positive TTL; batch/nonrenewable tokens
cannot satisfy the application renewal contract. OpenBao receives `{role,jwt}` at
`/v1/auth/<mount>/login`; JWTs, issued tokens and raw remote login errors are not
included in application diagnostics. Login redirects are refused.

Disable the application's broad ServiceAccount automount and mount an explicit
read-only projected `serviceAccountToken` with an audience matching the OpenBao role
and an appropriate expiration. Mount the directory rather than a `subPath` file
so Kubernetes can replace the projection. Point the token-path flag at that file.
Only the **OpenBao server's reviewer ServiceAccount** needs TokenReview privileges
(typically `system:auth-delegator`); the application ServiceAccount needs no
TokenReview or Secret-read privileges. Configure OpenBao's Kubernetes auth backend
with its cluster API/trust/reviewer identity, separately from application roles.

Startup reads the JWT afresh and refuses missing, unreadable or empty files and
tokens without a usable renewable lease. The existing application worker renews
the resulting OpenBao token. At max TTL, revocation or repeated renewal failure,
the service shuts down fail-closed after its bounded retries and normal drain.
Configure Kubernetes/supervisor restart so the next process reads the latest
projection, logs in again and fetches new dynamic database credentials. This is
**restart-based reauthentication**, not seamless hot token replacement: a live
process does not swap token clones, pools or operator-token precedence. Revoked
database credentials likewise require restart/reacquisition. Account for restart
availability with replicas and tested readiness/drain behavior.
