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

Vault is central to the security of the stack. We provide a **Terraform** configuration in `vault/contrib/terraform` that automates the setup of secret engines, transit keys, policies, cert-auth roles, and the Vault-managed PKI hierarchy for future service certificates.

Using Terraform is the recommended way to ensure your configuration is consistent, reproducible, and easy to maintain.

### Running Terraform
```bash
cd vault/contrib/terraform
terraform init
terraform apply
```

Refer to the `vault/README.md` for details on the specific resources provisioned.

### Terraform tests
Terraform tests run in the module directory and validate the PKI + cert-auth wiring at plan time:

```bash
cd vault/contrib/terraform
terraform init
terraform test
```

### Cert auth sanity check (CLI)

To verify cert-auth roles and TLS client material, run:

```sh
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_CACERT="/etc/permesi/bootstrap/ca_cert.pem"
export VAULT_CLIENT_CERT="/etc/permesi/bootstrap/cert_file.pem"
export VAULT_CLIENT_KEY="/etc/permesi/bootstrap/key_file.pem"

vault login -method=cert -path=auth/cert name=permesi-agent
```

Repeat with the Genesis bootstrap certificate and the `genesis-agent` role.

### Vault Agent sidecar (cert auth)

Use Vault Agent as a sidecar to authenticate via cert auth and render templates. This removes the
need for a local proxy and lets you generate TLS material from a single config. The minimal agent
configs in `vault/contrib/terraform/README.md` already include cert-auth and TLS templates.

Keep the agent running continuously so it can renew the cert-auth token and re-issue TLS
certificates before the 24h TTL expires. If the agent stops long enough for the runtime certs or
auth token to expire, the services will lose TLS material and can get stuck until the agent is
restarted with valid bootstrap certificates.

Run the agent as a long-lived service so it can renew tokens and rotate certificates:

```sh
vault agent -config=/etc/vault.d/vault.hcl
```

### Quadlet example (systemd)

Below is a tuned Quadlet setup that assumes Vault Agent writes TLS material under `/run/permesi`
and `/run/genesis`.

`/root/permesi.env` (static, long-lived values; required values shown first):
```
PERMESI_DSN=postgres://postgres@localhost:5432/permesi
PERMESI_VAULT_URL=https://vault.example.com:8200
PERMESI_ADMISSION_PASERK_URL=https://genesis.permesi.localhost:8000/paserk.json
PERMESI_ADMISSION_ISS=https://genesis.permesi.localhost
PERMESI_ADMISSION_AUD=permesi
PERMESI_FRONTEND_BASE_URL=https://permesi.example.com
```
The admission and frontend settings are optional but recommended for typical deployments.
For reference: Issuer (`ISS`) identifies the token issuer, and audience (`AUD`) is the expected
intended recipient of the token.

`/root/genesis.env` (static, long-lived values; required values shown first):
```
GENESIS_DSN=postgres://postgres@localhost:5432/genesis
GENESIS_VAULT_URL=https://vault.example.com:8200
```

Both services require Vault-issued TLS material and must trust a single Vault PKI CA shared by the services. Defaults are:
`/run/permesi/tls.crt`, `/run/permesi/tls.key`, `/run/permesi/ca.pem` and
`/run/genesis/tls.crt`, `/run/genesis/tls.key`, `/run/genesis/ca.pem`.
Override paths with:
`PERMESI_TLS_CERT_PATH`, `PERMESI_TLS_KEY_PATH`, `PERMESI_TLS_CA_PATH` and
`GENESIS_TLS_CERT_PATH`, `GENESIS_TLS_KEY_PATH`, `GENESIS_TLS_CA_PATH`.
If your PASERK URL is served by a different CA (for example, HAProxy with mkcert),
set `PERMESI_ADMISSION_PASERK_CA_PATH` to that CA bundle. For direct Genesis access,
use the Vault-issued Genesis CA bundle.
Permesi also needs `PERMESI_ADMISSION_PASERK_URL` to locate the Genesis `/paserk.json` endpoint
over HTTPS.

Genesis serves public zero-token endpoints used by the frontend, and it is expected to sit
behind Cloudflare or HAProxy for scale and edge protection.

Quadlet unit (`permesi.container`):
```
[Unit]
Description=permesi
After=network.target
Wants=network.target
Requires=vault.service
Requires=vault-agent-permesi.service

[Container]
Image=ghcr.io/permesi/permesi:latest
Network=host
AutoUpdate=registry
EnvironmentFile=/root/permesi.env

[Service]
Restart=always

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
Requires=vault-agent-genesis.service

[Container]
Image=ghcr.io/permesi/genesis:latest
Network=host
AutoUpdate=registry
EnvironmentFile=/root/genesis.env

[Service]
Restart=always

[Install]
WantedBy=default.target
```

Notes:
- Keep `/root/permesi.env` and `/root/genesis.env` owned by root with `0600` permissions.
- **Agent Mode**: Set `PERMESI_VAULT_URL` to a socket path (e.g., `/run/vault/proxy.sock`). AppRole credentials (`VAULT_ROLE_ID`, etc.) are not needed. Ensure Vault Agent is configured with `use_auto_auth_token = true` in its `api_proxy` stanza. This is the preferred mode as it avoids writing secrets to disk.
- **TCP Mode**: If using AppRole without an Agent, ensure `VAULT_ROLE_ID` and `VAULT_SECRET_ID` (or `VAULT_WRAPPED_TOKEN`) are provided in the environment files.


### Manual Configuration Recipe (Reference)

If you cannot use Terraform, this section provides the manual steps to configure an equivalent Vault instance.

### A. Enable Secret Engines and Auth Methods
```bash
# Enable cert auth for Vault Agent and bootstrap workflows
vault auth enable cert

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

### E. Cert Auth Setup
Create cert-auth roles for the Vault Agent bootstrap certificates so the agent can authenticate
and render templates (TLS material, wrapped tokens, or other secrets as needed). The roles should
use `permesi-pki-issue-only` and `genesis-pki-issue-only` policies with `allowed_dns_sans` that
match the bootstrap certificates. Mirror the configuration in `vault/contrib/terraform/auth_cert.tf`.

At minimum, enable cert auth and add two roles bound to the intermediate CA chain and DNS SANs:

```bash
vault auth enable cert

vault write auth/cert/certs/permesi-agent \
  display_name="permesi-agent" \
  policies="permesi-pki-issue-only" \
  certificate=@/path/to/pki-int.pem \
  allowed_dns_sans="api.permesi.localhost"

vault write auth/cert/certs/genesis-agent \
  display_name="genesis-agent" \
  policies="genesis-pki-issue-only" \
  certificate=@/path/to/pki-int.pem \
  allowed_dns_sans="genesis.permesi.localhost"
```

---

## 5. Service Configuration

Both services are configured via environment variables.

### Common Vault Variables
- `VAULT_URL`: The Vault API endpoint. Supports two modes:
  - **TCP**: `https://vault.internal:8200` (Requires `role-id` and `secret-id`).
  - **Agent**: `/run/vault/proxy.sock` or `unix:///run/vault/proxy.sock` (Recommended; requires Vault Agent with `api_proxy`).
- `VAULT_WRAPPED_TOKEN`: A short-lived wrapped token provided by Vault Agent (TCP mode only).
- `VAULT_ROLE_ID`: AppRole RoleID (TCP mode only).
- `VAULT_SECRET_ID`: AppRole SecretID (TCP mode only).

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
