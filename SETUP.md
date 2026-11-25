# Setup & Deployment Guide

This guide describes how to set up the Permesi IAM stack. It remains agnostic of your specific orchestration (systemd, Podman, Kubernetes) and focuses on the core requirements: **Postgres 19** and **OpenBao**. For architecture, security policies, and feature guides, see the [Documentation Index](docs/README.md).

## 1. Prerequisites

- **Postgres 19**: The primary data store.
- **OpenBao**: Used for secret storage and cryptographic operations (Transit engine).
- **OpenTofu** (1.11 or later; 1.13 is tested): Required to provision and configure the OpenBao instance.
- **Container Runtime**: Podman, to run the pre-built service images.
- **Web Server**: (Nginx, HAProxy, or similar) To serve the static frontend assets.

---

## 2. Artifacts & Images

Permesi provides production-ready artifacts for every release. You do not need to compile code.

- **Genesis Service**: `ghcr.io/permesi/genesis` ([Package Info](https://github.com/orgs/permesi/packages/container/package/genesis))
- **Permesi Service**: `ghcr.io/permesi/permesi` ([Package Info](https://github.com/orgs/permesi/packages/container/package/permesi))
- **Frontend (Web Console)**:
  - Container image: `ghcr.io/permesi/web`
  - Static artifact: `permesi-web-dist-[version].tar.gz` from the [Latest Releases](https://github.com/permesi/permesi/releases).

---

## 3. Database Configuration (Postgres 19)

Permesi requires a Postgres 19 instance. You can find the initialization and service schemas in the repository under `db/sql/`.

PostgreSQL 19 warns at login when a role's password expires within `password_expiration_warning_threshold` (7 days by default). OpenBao creates the services' database users with a `VALID UNTIL` only hours ahead, so every new pooled connection would log that warning. Set `password_expiration_warning_threshold = 0` in `postgresql.conf` on servers the services connect to with password authentication.

1.  **Create OpenBao database roles**: `db/sql/00_init.sql` creates the databases (`permesi`, `genesis`), the OpenBao root DB roles (`openbao_permesi`, `openbao_genesis`), and the runtime roles used for dynamic creds (`permesi_runtime`, `genesis_runtime`). It also applies the service schemas and the test seed client.

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

6.  **Verify OpenBao DB connectivity** (after OpenTofu applies):

    ```sh
    export BAO_ADDR="https://openbao.example.com:8200"
    export BAO_TOKEN="your-root-token"
    bao read database/creds/permesi
    bao read database/creds/genesis
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
sudo apt-get install postgresql-19-cron

# RHEL/Fedora
sudo dnf install postgresql19-contrib

# macOS (Homebrew)
brew install postgresql@19
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
the OpenBao root and runtime roles. It is destructive and cannot be undone.

---

## 4. OpenBao Configuration (OpenTofu)

OpenBao is central to the security of the stack. We provide an **OpenTofu** module in `openbao/contrib/opentofu` that automates the setup of secret engines, transit keys, policies, cert-auth roles, and the OpenBao-managed PKI hierarchy for future service certificates. It is the recommended way to keep the configuration consistent, reproducible, and easy to maintain.

The module writes its state only encrypted. The data key comes from a Transit key on the same OpenBao, `transit/opentofu/keys/permesi-state`, which the module cannot manage itself, so create it once before the first apply. The PostgreSQL root passwords are write-only: they reach OpenBao but never the state or a saved plan.

### Running OpenTofu
```bash
cd openbao/contrib/opentofu
# The API-compatible hashicorp/vault provider reads VAULT_*; the state key provider reads BAO_*.
export VAULT_ADDR="https://openbao.example.com:8200" VAULT_TOKEN="your-root-token"
export BAO_ADDR="$VAULT_ADDR" BAO_TOKEN="$VAULT_TOKEN"
bao secrets enable -path=transit/opentofu transit
bao write -f transit/opentofu/keys/permesi-state type=aes256-gcm96
tofu init -lockfile=readonly
tofu apply
```

The provider lock file is committed, so `-lockfile=readonly` installs exactly the reviewed provider builds. Losing the Transit key makes the state unreadable; it is backed up with OpenBao itself, and the module's [README](openbao/contrib/opentofu/README.md#state-encryption) covers recovery, other key providers and migrating an existing Terraform state.

Refer to [openbao/README.md](openbao/README.md) for provisioned resources and its [production readiness checklist](openbao/README.md#production-readiness-checklist) (HA failover, auto-unseal, backups/restore drills, and renewal alerts).

### OpenTofu tests
`just openbao-tofu-test` checks formatting, validates the module and runs `tofu test` against mocked providers, so the plan-time assertions on PKI, cert auth, database TLS, write-only passwords and quota paths need no server. `just openbao-tofu-test-live` provisions throwaway OpenBao and PostgreSQL containers from zero and checks every engine the services use, including the refusals between Permesi and Genesis, that neither service can use the state key, and a re-apply after OpenBao rotates the root passwords.

### Cert auth sanity check (CLI)

To verify cert-auth roles and TLS client material, run:

```sh
export BAO_ADDR="https://openbao.example.com:8200"
export BAO_CACERT="/etc/permesi/bootstrap/ca_cert.pem"
export BAO_CLIENT_CERT="/etc/permesi/bootstrap/cert_file.pem"
export BAO_CLIENT_KEY="/etc/permesi/bootstrap/key_file.pem"

bao login -method=cert -path=auth/cert name=permesi-agent
```

Repeat with the Genesis bootstrap certificate and the `genesis-agent` role.

### OpenBao Agent sidecar (cert auth)

Use OpenBao Agent as a sidecar to authenticate via cert auth and render templates. This removes the
need for a local proxy and lets you generate TLS material from a single config. The minimal agent
configs in `openbao/contrib/opentofu/README.md` already include cert-auth and TLS templates.

Keep the agent running continuously so it can renew the cert-auth token and re-issue TLS
certificates before the 24h TTL expires. If the agent stops long enough for the runtime certs or
auth token to expire, the services will lose TLS material and can get stuck until the agent is
restarted with valid bootstrap certificates.

Run the agent as a long-lived service so it can renew tokens and rotate certificates:

```sh
bao agent -config=/etc/openbao/agent.hcl
```

### Quadlet example (systemd)

Below is a tuned Quadlet setup that assumes OpenBao Agent writes TLS material under `/run/permesi`
and `/run/genesis`.

`/root/permesi.env` (static, long-lived values; required values shown first):
```
PERMESI_DSN=postgres://postgres@localhost:5432/permesi
PERMESI_OPENBAO_URL=https://openbao.example.com:8200
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
GENESIS_OPENBAO_URL=https://openbao.example.com:8200
```

Both services require OpenBao-issued TLS material and must trust a single OpenBao PKI CA shared by the services. Defaults are:
`/run/permesi/tls.bundle.pem` and `/run/genesis/tls.bundle.pem`.
Override paths with:
`PERMESI_TLS_PEM_BUNDLE` and `GENESIS_TLS_PEM_BUNDLE`.
Before enabling admission, initialize its authority in the core KV mount using
`scripts/admission-authority initialize 1` with the bootstrap operator identity for a fresh key. For an existing install, initialize with its active Transit version and set the same `GENESIS_ADMISSION_SIGNING_VERSION`.
The local OpenBao recipe performs the initial create with compare-and-set.

Genesis serves public zero-token endpoints used by the frontend, and it is expected to sit
behind Cloudflare or HAProxy for scale and edge protection.

Quadlet unit (`permesi.container`):
```
[Unit]
Description=permesi
After=network.target
Wants=network.target
Requires=openbao.service
Requires=openbao-agent-permesi.service

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
Requires=openbao.service
Requires=openbao-agent-genesis.service

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
- **Agent Mode**: Set `PERMESI_OPENBAO_URL` to a socket path (e.g., `/run/openbao/proxy.sock`). AppRole credentials (`OPENBAO_ROLE_ID`, etc.) are not needed. Ensure OpenBao Agent is configured with `use_auto_auth_token = true` in its `api_proxy` stanza. This is the preferred mode as it avoids writing secrets to disk.
- **TCP Mode**: If using AppRole without an Agent, ensure `OPENBAO_ROLE_ID` and `OPENBAO_SECRET_ID` (or `OPENBAO_WRAPPED_TOKEN`) are provided in the environment files.


### Manual Configuration Recipe (Reference)

If you cannot use OpenTofu, this section provides the manual steps to configure an equivalent OpenBao instance.

### A. Enable Secret Engines and Auth Methods
```bash
# Enable cert auth for OpenBao Agent and bootstrap workflows
bao auth enable cert

# Enable Transit for TOTP secret protection and token signing
bao secrets enable -path=transit/permesi transit
bao secrets enable -path=transit/genesis transit

# Enable KV v2 for OPAQUE server seeds
bao secrets enable -path=secret/permesi kv-v2

# (Optional) Enable Database engine if using OpenBao-managed DB credentials
bao secrets enable database
```

### B. Configure Transit Keys
Permesi uses ChaCha20-Poly1305 to protect TOTP data-encryption keys, while Genesis uses Ed25519 for signing admission tokens.

```bash
# Permesi TOTP protection key
bao write transit/permesi/keys/totp type=chacha20-poly1305
bao write transit/permesi/keys/totp/config auto_rotate_period=30d

# Genesis admission signing key
bao write transit/genesis/keys/genesis-signing type=ed25519
bao write transit/genesis/keys/genesis-signing/config auto_rotate_period=30d
```

### C. Configure OPAQUE Seed
Permesi requires a persistent 32-byte base64-encoded seed for the OPAQUE protocol.
If this seed changes, all existing OPAQUE registrations will no longer validate; users
will need to re-register or reset their credentials.

```bash
$ SEED=$(openssl rand -base64 32)
$ PEPPER=$(openssl rand -base64 32)
$ bao kv put secret/permesi/config opaque_server_seed="$SEED" mfa_recovery_pepper="$PEPPER"
```

### D. Define Service Policies
Create the following policies to grant the services the minimum required permissions.

**`permesi` policy:**
```bash
bao policy write permesi - <<EOF
path "auth/token/lookup-self" { capabilities = ["read"] }
path "transit/permesi/encrypt/totp" { capabilities = ["update"] }
path "transit/permesi/decrypt/totp" { capabilities = ["update"] }
path "transit/permesi/keys/totp"    { capabilities = ["read"] }
path "transit/permesi/datakey/plaintext/totp" { capabilities = ["update"] }
path "secret/permesi/data/config"   { capabilities = ["read"] }
path "database/creds/permesi"        { capabilities = ["read"] }
path "auth/token/renew-self"         { capabilities = ["update"] }
path "sys/leases/renew" {
  capabilities = ["update"]
  required_parameters = ["lease_id"]
  allowed_parameters = {
    "lease_id"  = ["database/creds/permesi/*"]
    "increment" = []
  }
}
EOF
```

**`genesis` policy:**
```bash
bao policy write genesis - <<EOF
path "transit/genesis/sign/genesis-signing" { capabilities = ["update"] }
path "transit/genesis/keys/genesis-signing" { capabilities = ["read"] }
path "database/creds/genesis"               { capabilities = ["read"] }
path "auth/token/renew-self"                { capabilities = ["update"] }
path "sys/leases/renew" {
  capabilities = ["update"]
  required_parameters = ["lease_id"]
  allowed_parameters = {
    "lease_id"  = ["database/creds/genesis/*"]
    "increment" = []
  }
}
EOF
```

**`permesi-operators` policy:**
```bash
bao policy write permesi-operators - <<EOF
path "auth/token/lookup-self" { capabilities = ["read"] }
EOF
```

### E. Cert Auth Setup
Create cert-auth roles for the OpenBao Agent bootstrap certificates so the agent can authenticate
and render templates (TLS material, wrapped tokens, or other secrets as needed). The roles should
use `permesi-pki-issue-only` and `genesis-pki-issue-only` policies with `allowed_dns_sans` that
match the bootstrap certificates. Mirror the configuration in `openbao/contrib/opentofu/auth_cert.tf`.

At minimum, enable cert auth and add two roles bound to the intermediate CA chain and DNS SANs:

```bash
bao auth enable cert

bao write auth/cert/certs/permesi-agent \
  display_name="permesi-agent" \
  policies="permesi-pki-issue-only" \
  certificate=@/path/to/pki-int.pem \
  allowed_dns_sans="api.permesi.localhost"

bao write auth/cert/certs/genesis-agent \
  display_name="genesis-agent" \
  policies="genesis-pki-issue-only" \
  certificate=@/path/to/pki-int.pem \
  allowed_dns_sans="genesis.permesi.localhost"
```

---

## 5. Service Configuration

Both services are configured via environment variables.

### Common OpenBao Variables
Each service reads its own copy of these, prefixed with `PERMESI_` or `GENESIS_` (for example `PERMESI_OPENBAO_URL`). Unprefixed names are not read.
- `<PREFIX>_OPENBAO_URL`: The OpenBao API endpoint. Supports two modes:
  - **TCP**: `https://openbao.internal:8200` (requires a RoleID and a SecretID or wrapped token).
  - **Agent**: `/run/openbao/proxy.sock` or `unix:///run/openbao/proxy.sock` (Recommended; requires OpenBao Agent with `api_proxy`).
- `<PREFIX>_OPENBAO_WRAPPED_TOKEN`: A short-lived wrapped token provided by OpenBao Agent (TCP mode only).
- `<PREFIX>_OPENBAO_ROLE_ID`: AppRole RoleID (TCP mode only).
- `<PREFIX>_OPENBAO_SECRET_ID`: AppRole SecretID (TCP mode only).

### Service Specifics
- **Genesis**: Requires `GENESIS_DSN`.
- **Permesi**: Requires `PERMESI_DSN` and read access to the core KV admission authority.

Permesi enforces authentication limits in PostgreSQL across replicas. The
defaults use a 600-second window, 100 attempts per IP/action, 10 attempts per
account/action, and cluster-wide per-purpose pending-state ceilings (10,000 login,
1,000 reauthentication, 1,000 per registration purpose, and 1,000 MFA, with 16
pending rows per subject/purpose). Override them with
`PERMESI_AUTH_RATE_LIMIT_WINDOW_SECONDS`, `PERMESI_AUTH_RATE_LIMIT_IP_ATTEMPTS`,
`PERMESI_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS`, `PERMESI_AUTH_MAX_PENDING_STATES`,
and `PERMESI_AUTH_PENDING_*`. Forwarded client-IP headers are trusted only when
explicitly configured via `PERMESI_AUTH_TRUSTED_PROXIES` (or
`PERMESI_AUTH_TRUST_UNIX_PROXY` for a restricted same-host Unix edge); see
[authentication operations](docs/authentication-operations.md).

---

## 6. Frontend Deployment

The frontend is a static bundle that runs entirely in the browser. You can deploy it either as static files or from the published `ghcr.io/permesi/web` image.

1.  **Download**: Get the latest `permesi-web-dist.tar.gz` from the release page.
2.  **Extract**: Unpack the archive into your web server's root directory (e.g., `/var/www/permesi`).
3.  **Configure**: The frontend reads runtime overrides from `config.js` in the extracted folder.
    - Set `api_base_url` and `token_base_url` to your public endpoints.
4.  **Serve**: Configure your web server to serve the directory. Ensure it handles Single Page Application (SPA) routing by redirecting unknown paths to `index.html`.

---

## 7. Initial Platform Bootstrap

Once the services are running:

1.  **Generate Operator Token**: Create a short-lived OpenBao token with the `permesi-operators` policy:
    ```bash
    bao token create -policy=permesi-operators -period=24h
    ```
2.  **Claim Admin**:
    - Visit `https://your-domain.com/console/admin/claim`.
    - Provide the OpenBao token.
    - This process will promote your user account to a **Platform Operator**.
3.  **Elevate**: Whenever you need to perform sensitive tasks, use the "Elevate" feature with a fresh OpenBao token to gain temporary admin privileges.
