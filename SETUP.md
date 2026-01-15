# Setup & Deployment Guide

This guide describes how to set up the Permesi IAM stack. It remains agnostic of your specific orchestration (systemd, Podman, Kubernetes) and focuses on the core requirements: **Postgres 18** and **HashiCorp Vault**.

## 1. Prerequisites

- **Postgres 18**: The primary data store.
- **HashiCorp Vault**: Used for secret storage and cryptographic operations (Transit engine).
- **Terraform**: Required to provision and configure the Vault instance.
- **Container Runtime**: Podman, to run the pre-built service images.
- **Web Server**: (Nginx, HAProxy, or similar) To serve the static frontend assets.

---

## 2. Artifacts & Images

Permesi provides production-ready artifacts for every release. You do not need to compile code.

- **Genesis Service**: `ghcr.io/permesi/genesis` ([Package Info](https://github.com/orgs/permesi/packages/container/package/genesis))
- **Permesi Service**: `ghcr.io/permesi/permesi` ([Package Info](https://github.com/orgs/permesi/packages/container/package/permesi))
- **Frontend (Web Console)**: Download the `permesi-web-dist-[version].tar.gz` from the [Latest Releases](https://github.com/permesi/permesi/releases).

---

## 3. Database Configuration (Postgres 18)

Permesi requires a Postgres 18 instance. You can find the initialization and service schemas in the repository under `db/sql/`.

1.  **Create Vault database roles**: `db/sql/00_init.sql` creates the databases (`permesi`, `genesis`), the Vault root DB roles (`vault_permesi`, `vault_genesis`), and the runtime roles used for dynamic creds (`permesi_runtime`, `genesis_runtime`). It also applies the service schemas and the test seed client.

    This file ships with a `change-me` placeholder password. For production, edit the passwords
    and remove the `seed_test_client.sql` include (or use the file as a template for your own
    bootstrap SQL), then run:

    ```sh
    psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/00_init.sql
    ```

2.  **Load service schemas** (only if you did not run `db/sql/00_init.sql`):

    ```sh
    psql "$GENESIS_DSN" -v ON_ERROR_STOP=1 -f db/sql/01_genesis.sql
    psql "$PERMESI_DSN" -v ON_ERROR_STOP=1 -f db/sql/02_permesi.sql
    ```

    The Genesis schema can optionally seed a test-only client. To enable it, apply
    `db/sql/seed_test_client.sql` after the schema.

3.  **Connectivity**: Ensure the services can reach the DB via a standard DSN:
    `postgres://<user>:<pass>@<host>:<port>/permesi`

4.  **Load pg_cron jobs** (see the pg_cron setup section below):

    ```sh
    psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/cron_jobs.sql
    ```

5.  **Verify the setup**:

    ```sh
    psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/check.sql
    ```

6.  **Verify Vault DB connectivity** (after Terraform applies):

    ```sh
    export VAULT_ADDR="https://vault.example.com:8200"
    export VAULT_TOKEN="your-root-token"
    vault read database/creds/permesi
    vault read database/creds/genesis
    ```

    These reads are safe in production; they only request short-lived credentials.

### pg_cron setup (one-time)

Permesi uses `pg_cron` for scheduled maintenance tasks when available:

- Genesis partition rollover (`genesis_tokens_rollover()` from `db/sql/partitioning.sql`)
- Permesi token cleanup (`cleanup_expired_tokens()` from `db/sql/02_permesi.sql`)
- Job registration is centralized in `db/sql/cron_jobs.sql` (run against `postgres`)

To enable `pg_cron` (copy/paste recipe):

1. Install the extension package for your Postgres version:

```sh
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install postgresql-18-cron

# RHEL/Fedora
sudo dnf install postgresql18-contrib

# macOS (Homebrew)
brew install postgresql@18
```

2. Enable `pg_cron` in `postgresql.conf` and restart Postgres (cron is centralized in the
   `postgres` database):

```
shared_preload_libraries = 'pg_cron'
cron.database_name = 'postgres'
```

3. Restart Postgres (example):

```sh
sudo systemctl restart postgresql
```

4. Ensure the maintenance functions exist (run after schemas are loaded). The Genesis schema
   already includes `db/sql/partitioning.sql`; only run it separately if you opted out of the
   include:

```sh
psql "$GENESIS_DSN" -v ON_ERROR_STOP=1 -f db/sql/partitioning.sql
```

5. Register cron jobs from the `postgres` database:

```sh
psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/cron_jobs.sql
```

If `pg_cron` is not enabled, you can run the maintenance functions from system cron or manually.
For a one-off cleanup in Permesi, run `db/sql/maintenance.sql` against the `permesi` database.

### Reset / Uninstall (dev/test only)

If you need to remove everything created by the bootstrap SQL (databases, schemas, roles),
run the reset script against the `postgres` database as a superuser:

```sh
psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/reset_all.sql
```

This terminates active connections, drops the `genesis` and `permesi` databases, and removes
the Vault root and runtime roles. It is destructive and cannot be undone.

---

## 4. Vault Configuration (Terraform)

Vault is central to the security of the stack. We provide a **Terraform** configuration in `vault/contrib/terraform` that automates the setup of secret engines, transit keys, policies, and AppRoles.

Using Terraform is the recommended way to ensure your configuration is consistent, reproducible, and easy to maintain.

### Running Terraform
```bash
cd vault/contrib/terraform
terraform init
terraform apply
```

Refer to the `vault/README.md` for details on the specific resources provisioned.

### AppRole login sanity check (CLI)

To verify your AppRole credentials and the login endpoint, run:

```sh
export VAULT_ADDR="https://vault.example.com:8200"
vault write -format=json auth/approle/login \
  role_id="$PERMESI_ROLE_ID" \
  secret_id="$PERMESI_SECRET_ID"
```

If you use wrapped SecretIDs, unwrap first:

```sh
vault unwrap -format=json "$PERMESI_WRAPPED_TOKEN"
```

### Vault Proxy (AppRole SecretID minting)

For automated SecretID minting on service restart, use a local-only **vault proxy**. The proxy
uses its own AppRole credentials to authenticate, then forwards requests and injects its token.
See **Vault proxy (AppRole) refresher** below for a copy/paste config that uses a Unix socket.

### Quadlet example (systemd)

Below is a tuned Quadlet setup that mints fresh SecretIDs via `ExecStartPre` and writes a
runtime-only environment file per service. This keeps static config in `/root/permesi.env`
and `/root/genesis.env`, while short-lived SecretIDs live in service-specific tmpfs paths.

`/root/permesi.env` (static, long-lived values; required values shown first):
```
PERMESI_DSN=postgres://postgres@localhost:5432/permesi
PERMESI_VAULT_URL=http://127.0.0.1:8200/v1/auth/approle/login
PERMESI_VAULT_ROLE_ID=<permesi_role_id>
PERMESI_ADMISSION_PASERK_URL=https://genesis.example.com/paserk.json
PERMESI_ADMISSION_ISS=https://genesis.example.com
PERMESI_ADMISSION_AUD=permesi
PERMESI_FRONTEND_BASE_URL=https://permesi.example.com
```
The admission and frontend settings are optional but recommended for typical deployments.
For reference: Issuer (`ISS`) identifies the token issuer, and audience (`AUD`) is the expected
intended recipient of the token.

`/root/genesis.env` (static, long-lived values; required values shown first):
```
GENESIS_DSN=postgres://postgres@localhost:5432/genesis
GENESIS_VAULT_URL=http://127.0.0.1:8200/v1/auth/approle/login
GENESIS_VAULT_ROLE_ID=<genesis_role_id>
```

`/root/permesi-pre-start.sh` (writes the SecretID to tmpfs, permesi only):
```bash
#!/usr/bin/env bash
set -euo pipefail

umask 077
install -d -m 0700 /run/permesi

vault_proxy_socket="/run/vault/proxy.sock"
permesi_secret_id="$(
  curl --unix-socket "${vault_proxy_socket}" -fsS -X POST \
    http://localhost/v1/auth/approle/role/permesi/secret-id \
    | jq -er '.data.secret_id'
)"

cat > /run/permesi/secrets.env <<EOF
PERMESI_VAULT_SECRET_ID=${permesi_secret_id}
EOF

chmod 0600 /run/permesi/secrets.env
```

`/root/genesis-pre-start.sh` (writes the SecretID to tmpfs, genesis only):
```bash
#!/usr/bin/env bash
set -euo pipefail

umask 077
install -d -m 0700 /run/genesis

vault_proxy_socket="/run/vault/proxy.sock"
genesis_secret_id="$(
  curl --unix-socket "${vault_proxy_socket}" -fsS -X POST \
    http://localhost/v1/auth/approle/role/genesis/secret-id \
    | jq -er '.data.secret_id'
)"

cat > /run/genesis/secrets.env <<EOF
GENESIS_VAULT_SECRET_ID=${genesis_secret_id}
EOF

chmod 0600 /run/genesis/secrets.env
```

Quadlet unit (`permesi.container`):
```
[Unit]
Description=permesi
After=network.target
Wants=network.target
Requires=vault.service
Requires=vault-proxy.service

[Container]
Image=ghcr.io/permesi/permesi:latest
Network=host
AutoUpdate=registry
EnvironmentFile=/root/permesi.env
EnvironmentFile=/run/permesi/secrets.env

[Service]
Restart=always
ExecStartPre=/root/permesi-pre-start.sh

[Install]
WantedBy=default.target
```

Quadlet unit (`genesis.container`):
```
[Unit]
Description=genesis
After=network.target
Wants=network.target
Requires=vault.service
Requires=vault-proxy.service

[Container]
Image=ghcr.io/permesi/genesis:latest
Network=host
AutoUpdate=registry
EnvironmentFile=/root/genesis.env
EnvironmentFile=/run/genesis/secrets.env

[Service]
Restart=always
ExecStartPre=/root/genesis-pre-start.sh

[Install]
WantedBy=default.target
```

Notes:
- Bind the Vault proxy to a Unix socket (recommended) or `127.0.0.1`, and keep its policy limited to
  `auth/approle/role/*/secret-id`.
- Keep `/root/permesi.env`, `/root/genesis.env`, and the pre-start scripts owned by root and
  `0600`/`0700` permissions.
- `GENESIS_VAULT_URL` / `PERMESI_VAULT_URL` must point to the **main Vault login endpoint**
  (`/v1/auth/approle/login`). The proxy is only used by the pre-start scripts to mint
  SecretIDs; services still authenticate directly with Vault.

#### Vault proxy (AppRole) refresher

The proxy is a Vault **proxy** process using AppRole to authenticate. It needs its own **vault-proxy
RoleID** and **vault-proxy SecretID** (separate from the service AppRoles). Terraform creates the
policy and AppRole; you fetch the RoleID and generate a SecretID. If you are not using Terraform,
create the `vault-proxy` policy and AppRole manually before continuing.

Each service still has its own AppRole **RoleID** (set in `/root/permesi.env` and `/root/genesis.env`).
The proxy only mints **SecretIDs** for those service roles at runtime. Do not reuse the proxy
RoleID/SecretID for the services.

Quick setup outline (Terraform users):

1. Fetch the `vault-proxy` RoleID:

   ```sh
   cd vault/contrib/terraform
   terraform output -raw vault_proxy_role_id > /etc/vault/proxy-role-id
   chown vault:vault /etc/vault/proxy-role-id
   chmod 0400 /etc/vault/proxy-role-id
   ```

2. Generate the `vault-proxy` SecretID:

   ```sh
   vault write -field=secret_id -f auth/approle/role/vault-proxy/secret-id > /etc/vault/proxy-secret-id
   chown vault:vault /etc/vault/proxy-secret-id
   chmod 0400 /etc/vault/proxy-secret-id
   ```

3. Configure the proxy to read those files and auto-renew its token:

   ```hcl
   # /etc/vault/proxy.hcl
   vault { address = "https://vault.example.com:8200" }

   auto_auth {
     method "approle" {
       mount_path = "auth/approle"
       config = {
         role_id_file_path   = "/etc/vault/proxy-role-id"
         secret_id_file_path = "/etc/vault/proxy-secret-id"
         remove_secret_id_file_after_reading = false
       }
     }
   }

   listener "unix" {
     address = "/run/vault/proxy.sock"
     mode = "0600"
   }

   cache { use_auto_auth_token = true }
   api_proxy { use_auto_auth_token = true }
   ```

   Example systemd unit:

   ```ini
   [Unit]
   Description=Vault Proxy (Permesi)
   After=network.target
   Wants=network.target

   [Service]
   User=vault
   Group=vault
   ExecStart=/usr/bin/vault proxy -config=/etc/vault/proxy.hcl
   RuntimeDirectory=vault
   RuntimeDirectoryMode=0750
   Restart=always
   RestartSec=2s

   [Install]
   WantedBy=multi-user.target
   ```

The proxy renews its token automatically; you only replace the SecretID when it expires based on
your AppRole settings.
The proxy policy is intentionally minimal, so `auth/token/lookup-self` will return `permission denied`;
use SecretID minting as the health check instead.

Note: `vault-proxy` should use a **multi-use SecretID** (for example `secret_id_num_uses=100`).
If it is set to single-use, the proxy will succeed once and then get 403s on restart.

#### Vault proxy rotation (recommended)

To avoid lockouts on proxy restarts, rotate the **vault-proxy SecretID** on a schedule. Terraform
creates a dedicated `vault-proxy-rotate` policy that only allows minting SecretIDs for the
`vault-proxy` AppRole. Create a periodic token with that policy and store it on disk.

Create the rotation token (example):

```sh
vault policy read vault-proxy-rotate
vault token create -policy=vault-proxy-rotate -period=24h -orphan -field=token \
  > /etc/vault/proxy-rotate.token
chmod 0400 /etc/vault/proxy-rotate.token
```

Keep `/etc/vault/proxy-rotate.token` root-owned and readable only by root.
If the rotation script fails with `No such file or directory`, create this token first.

Rotation script (`/usr/local/sbin/vault-proxy-rotate.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
VAULT_ADDR="https://vault.example.com:8200"
TOKEN_PATH="/etc/vault/proxy-rotate.token"
SECRET_ID_PATH="/etc/vault/proxy-secret-id"
ROLE_NAME="vault-proxy"

# 1. Check if the rotation token exists
if [[ ! -f "$TOKEN_PATH" ]]; then
    echo "ERROR: Missing ${TOKEN_PATH}." >&2
    echo "Create it with: vault token create -policy=vault-proxy-rotate -period=24h" >&2
    exit 1
fi

VAULT_TOKEN="$(cat "$TOKEN_PATH" | tr -d '\n\r ')"
export VAULT_ADDR
export VAULT_TOKEN

# 2. Renew the rotation token for another 12-hour window
# We use 18h to ensure it doesn't expire exactly when the next timer starts
echo "Renewing rotation token..."
curl -fsS -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -X POST -d '{"increment": "64800"}' "${VAULT_ADDR}/v1/auth/token/renew-self" > /dev/null

# 3. Generate the new SecretID (Valid for 24h per server config)
echo "Generating new SecretID..."
umask 077
NEW_SECRET_ID=$(curl -fsS -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -X POST "${VAULT_ADDR}/v1/auth/approle/role/${ROLE_NAME}/secret-id" |
    jq -er '.data.secret_id')

# 4. Atomic write to the SecretID file
install -o vault -g vault -m 0400 /dev/null "${SECRET_ID_PATH}.new"
printf '%s' "$NEW_SECRET_ID" >"${SECRET_ID_PATH}.new"
mv "${SECRET_ID_PATH}.new" "$SECRET_ID_PATH"

# 5. Signal Vault Proxy to re-authenticate
if systemctl is-active --quiet vault; then
    echo "Signaling Vault Agent to reload credentials (SIGHUP)..."
    systemctl kill -s SIGHUP vault
else
    echo "Vault service is not running. Starting it..."
    systemctl start vault
fi

echo "Rotation successful."
```

Systemd unit (`/etc/systemd/system/vault-proxy-rotate.service`):

```ini
[Unit]
Description=Rotate Vault proxy SecretID (Permesi)
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vault-proxy-rotate.sh
```

Systemd timer (`/etc/systemd/system/vault-proxy-rotate.timer`):

```ini
[Unit]
Description=Rotate Vault proxy SecretID (weekly)

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```sh
systemctl daemon-reload
systemctl enable --now vault-proxy-rotate.timer
```

Sanity check (the proxy user must read the AppRole files):

```sh
sudo -u vault head -c 8 /etc/vault/proxy-role-id && echo
sudo -u vault wc -c /etc/vault/proxy-secret-id
```

If your infrastructure supports auth methods like **TLS cert**, **Kubernetes**, or cloud
auth (AWS/GCP/Azure), prefer those for the proxy and avoid SecretIDs entirely.

### Manual Configuration Recipe (Reference)

If you cannot use Terraform, this section provides the manual steps to configure an equivalent Vault instance.

### A. Enable Secret Engines and Auth Methods
```bash
# Enable AppRole for service authentication
vault auth enable approle

# Enable Transit for user data and token signing
vault secrets enable -path=transit/permesi transit
vault secrets enable -path=transit/genesis transit

# Enable KV v2 for OPAQUE server seeds
vault secrets enable -path=secret/permesi kv-v2

# (Optional) Enable Database engine if using Vault-managed DB credentials
vault secrets enable database
```

### B. Configure Transit Keys
Permesi uses ChaCha20-Poly1305 for user data, while Genesis uses Ed25519 for signing admission tokens.

```bash
# Permesi data encryption key
vault write transit/permesi/keys/users type=chacha20-poly1305
vault write transit/permesi/keys/users/config auto_rotate_period=30d

# Genesis admission signing key
vault write transit/genesis/keys/genesis-signing type=ed25519
vault write transit/genesis/keys/genesis-signing/config auto_rotate_period=30d
```

### C. Configure OPAQUE Seed
Permesi requires a persistent 32-byte base64-encoded seed for the OPAQUE protocol.
If this seed changes, all existing OPAQUE registrations will no longer validate; users
will need to re-register or reset their credentials.

```bash
$ SEED=$(openssl rand -base64 32)
$ PEPPER=$(openssl rand -base64 32)
$ vault kv put secret/permesi/config opaque_server_seed="$SEED" mfa_recovery_pepper="$PEPPER"
```

### D. Define Service Policies
Create the following policies to grant the services the minimum required permissions.

**`permesi` policy:**
```bash
vault policy write permesi - <<EOF
path "transit/permesi/encrypt/users" { capabilities = ["update"] }
path "transit/permesi/decrypt/users" { capabilities = ["update"] }
path "transit/permesi/keys/users"    { capabilities = ["read"] }
path "secret/permesi/data/opaque"    { capabilities = ["read"] }
path "database/creds/permesi"        { capabilities = ["read"] }
path "auth/token/renew-self"         { capabilities = ["update"] }
path "sys/leases/renew"              { capabilities = ["update"] }
EOF
```

**`genesis` policy:**
```bash
vault policy write genesis - <<EOF
path "transit/genesis/sign/genesis-signing" { capabilities = ["update"] }
path "transit/genesis/keys/genesis-signing" { capabilities = ["read"] }
path "database/creds/genesis"               { capabilities = ["read"] }
path "auth/token/renew-self"                { capabilities = ["update"] }
path "sys/leases/renew"                     { capabilities = ["update"] }
EOF
```

**`permesi-operators` policy:**
```bash
vault policy write permesi-operators - <<EOF
path "auth/token/lookup-self" { capabilities = ["read"] }
EOF
```

### E. AppRole Setup
Each service needs an AppRole to authenticate and receive its policy-restricted token.

```bash
# Create the roles
vault write auth/approle/role/permesi token_policies=permesi token_ttl=1h token_max_ttl=4h
vault write auth/approle/role/genesis token_policies=genesis token_ttl=1h token_max_ttl=4h

# Retrieve RoleIDs (Keep these for service config)
vault read -field=role_id auth/approle/role/permesi/role-id
vault read -field=role_id auth/approle/role/genesis/role-id

# Generate SecretIDs (Keep these for service config)
vault write -f -field=secret_id auth/approle/role/permesi/secret-id
vault write -f -field=secret_id auth/approle/role/genesis/secret-id
```

---

## 5. Service Configuration

Both services are configured via environment variables.

### Common Vault Variables
- `VAULT_URL`: The full URL to the Vault AppRole login endpoint (e.g., `https://vault.internal/v1/auth/approle/login`).
- `VAULT_ROLE_ID`: The RoleID for the specific service.
- `VAULT_SECRET_ID`: The SecretID for the specific service.

### Service Specifics
- **Genesis**: Requires `GENESIS_DSN`.
- **Permesi**: Requires `PERMESI_DSN` and `PERMESI_ADMISSION_PASERK_URL` (the endpoint where Genesis publishes its public key).

---

## 6. Frontend Deployment

The frontend is a static bundle that runs entirely in the browser.

1.  **Download**: Get the latest `permesi-web-dist.tar.gz` from the release page.
2.  **Extract**: Unpack the archive into your web server's root directory (e.g., `/var/www/permesi`).
3.  **Configure**: The frontend reads its configuration from `config.js` in the extracted folder.
    - Edit `config.js` and set `PERMESI_API_HOST` to the public URL of your Permesi backend.
4.  **Serve**: Configure your web server to serve the directory. Ensure it handles Single Page Application (SPA) routing by redirecting unknown paths to `index.html`.

---

## 7. Initial Platform Bootstrap

Once the services are running:

1.  **Generate Operator Token**: Create a short-lived Vault token with the `permesi-operators` policy:
    ```bash
    vault token create -policy=permesi-operators -period=24h
    ```
2.  **Claim Admin**:
    - Visit `https://your-domain.com/console/admin/claim`.
    - Provide the Vault token.
    - This process will promote your user account to a **Platform Operator**.
3.  **Elevate**: Whenever you need to perform sensitive tasks, use the "Elevate" feature with a fresh Vault token to gain temporary admin privileges.
