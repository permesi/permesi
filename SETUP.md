# Setup & Deployment Guide

This guide describes how to set up the Permesi IAM stack. It remains agnostic of your specific orchestration (systemd, Podman, Kubernetes) and focuses on the core requirements: **Postgres 18** and **HashiCorp Vault**.

## 1. Prerequisites

- **Postgres 18**: The primary data store.
- **HashiCorp Vault**: Used for secret storage and cryptographic operations (Transit engine).
- **Terraform**: Required to provision and configure the Vault instance.
- **Container Runtime**: (Podman or Docker) To run the pre-built service images.
- **Web Server**: (Nginx, HAProxy, or similar) To serve the static frontend assets.

---

## 2. Artifacts & Images

Permesi provides production-ready artifacts for every release. You do not need to compile code.

- **Genesis Service**: `ghcr.io/permesi/genesis` ([Package Info](https://github.com/orgs/permesi/packages/container/package/genesis))
- **Permesi Service**: `ghcr.io/permesi/permesi` ([Package Info](https://github.com/orgs/permesi/packages/container/package/permesi))
- **Frontend (Web Console)**: Download the `permesi-web-dist-[version].tar.gz` from the [Latest Releases](https://github.com/permesi/permesi/releases).

---

## 3. Database Configuration (Postgres 18)

Permesi requires a Postgres 18 instance. You can find the initialization schemas in the repository under `db/sql/`.

1.  **Initialize Schema**: Run the scripts in order:
    - `00_init.sql`: Creates the databases (`permesi`, `genesis`).
    - `01_genesis.sql`: Genesis service schema.
    - `02_permesi.sql`: Permesi service schema.
2.  **Connectivity**: Ensure the services can reach the DB via a standard DSN:
    `postgres://<user>:<pass>@<host>:<port>/permesi`

---

## 4. Vault Configuration (Terraform)

Vault is central to the security of the stack. We provide a **Terraform** configuration in `vault/contrib/terraform` that automates the setup of secret engines, transit keys, policies, and AppRoles.

Using Terraform is the recommended way to ensure your configuration is consistent, reproducible, and easy to maintain.

### Running Terraform
```bash
cd vault/contrib/terraform
terraform init
terraform apply -var="database_password=YOUR_POSTGRES_PASSWORD"
```

Refer to the `vault/README.md` for details on the specific resources provisioned.

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
vault secrets enable -path=kv kv-v2

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

```bash
# Generate a seed and store it
SEED=$(head -c 32 /dev/urandom | base64)
vault kv put kv/permesi/opaque opaque_seed_b64="$SEED"
```

### D. Define Service Policies
Create the following policies to grant the services the minimum required permissions.

**`permesi` policy:**
```bash
vault policy write permesi - <<EOF
path "transit/permesi/encrypt/users" { capabilities = ["update"] }
path "transit/permesi/decrypt/users" { capabilities = ["update"] }
path "transit/permesi/keys/users"    { capabilities = ["read"] }
path "kv/data/permesi/opaque"        { capabilities = ["read"] }
path "database/creds/permesi"        { capabilities = ["read"] } # Only if using DB engine
path "auth/token/renew-self"         { capabilities = ["update"] }
path "sys/leases/renew"              { capabilities = ["update"] }
EOF
```

**`genesis` policy:**
```bash
vault policy write genesis - <<EOF
path "transit/genesis/sign/genesis-signing" { capabilities = ["update"] }
path "transit/genesis/keys/genesis-signing" { capabilities = ["read"] }
path "database/creds/genesis"               { capabilities = ["read"] } # Only if using DB engine
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
