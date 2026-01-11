# Permesi Vault Configuration with Terraform

This Terraform module provides a production-ready configuration for HashiCorp Vault to support the Permesi and Genesis services.

## Features

- **AppRole**: Configures roles for both `permesi` and `genesis`.
- **Transit**: Sets up encryption/decryption keys for user data (`users`) and admission token signing (`genesis-signing`).
- **KV Store**: Generates and stores a persistent 32-byte OPAQUE seed under `secret/permesi/opaque`.
- **Database Engine**: Configures dynamic Postgres credentials for both services, including lease renewals that extend the Postgres role expiration and automated rotation of the Vault root database credentials.
- **Policies**: Implements least-privilege policies for services and operators.

Terraform state is sensitive in this module. It can contain values such as the Postgres root passwords and the generated OPAQUE seed. Use an encrypted remote backend (or tightly lock down local state files), and never commit `.tfstate` files or variable files containing secrets.

## Usage

1. **Set Vault Authentication**:
   ```bash
   export VAULT_ADDR="https://your-vault:8200"
   export VAULT_TOKEN="your-root-token"
   ```

   Use a real TLS certificate and keep TLS verification enabled. For private PKI, set `VAULT_CACERT` (or `VAULT_CAPATH`) instead of disabling verification.

2. **Configure Variables**:
   You can provide required variables in two ways:

   This module is security-sensitive. In production, keep Vault TLS verification enabled, use Postgres TLS (`database_sslmode = "verify-full"` or `"verify-ca"`) and ensure Vault trusts the database CA. For service authentication, AppRole SecretIDs are single-use with a 1-hour TTL (`secret_id_num_uses = 1`, `secret_id_ttl = 3600` in `approle.tf`), so ensure your automation can mint fresh SecretIDs (or tune `approle.tf` to match your rotation process).

   For the database secrets engine, Vault needs a dedicated Postgres "root" user per connection. Those users should be non-superuser roles with `LOGIN` + `CREATEROLE`, be able to terminate sessions during revocation (`pg_signal_backend`), and own the target database objects they grant privileges on. Local dev uses `db/sql/00_init.sql` to create `vault_permesi` and `vault_genesis` with these properties. The file ships with a `change-me` placeholder password; for production, edit it (or use it as a template) to set strong, unique passwords before running it as a superuser.

   This module uses a "runtime role" pattern: Vault-minted login roles only receive membership in a NOLOGIN role (`permesi_runtime` / `genesis_runtime`) which holds the database/schema/table grants. This keeps privileges centralized (one place to audit/change) and avoids short-lived users owning persistent database objects. Ensure the Vault root users can `GRANT` those runtime roles (by owning them or via `WITH ADMIN OPTION`).

   **Option A: Environment Variables**
   Prefix any variable name with `TF_VAR_`:
   ```bash
   export TF_VAR_database_host="db.internal"
   export TF_VAR_permesi_database_username="vault_permesi"
   export TF_VAR_permesi_database_password="change-me"
   export TF_VAR_genesis_database_username="vault_genesis"
   export TF_VAR_genesis_database_password="change-me"
   ```

   **Option B: `terraform.tfvars` file**
   Create a file named `terraform.tfvars` (this file is ignored by git):
   ```hcl
   database_host     = "localhost"
   permesi_database_username = "vault_permesi"
   permesi_database_password = "change-me"
   genesis_database_username = "vault_genesis"
   genesis_database_password = "change-me"
   # Local/dev only; for production use "verify-full" (or at least "verify-ca").
   database_sslmode  = "disable"
   ```

3. **Initialize and Apply**:
   ```bash
   terraform init
   terraform apply
   ```

4. **Vault audit log path**:
   This module enables a file audit device at `/var/log/vault/audit.log`. Ensure the Vault
   service user can write to that path (for example, create `/var/log/vault` and `chown` it
   to the Vault user) before applying.

## Post-Deployment

### 1. Retrieve Service Credentials
Terraform outputs the `RoleID` for both services. To complete the configuration, generate a `SecretID` for each role.

For production, prefer response-wrapped SecretIDs (short-lived wrapping tokens) so you never have to handle the raw SecretID in logs or shells:

```bash
# Get permesi RoleID (or check terraform output)
vault read auth/approle/role/permesi/role-id

# Generate permesi SecretID as a wrapped token (recommended)
vault write -wrap-ttl=10m -f auth/approle/role/permesi/secret-id -field=wrapping_token

# Repeat for genesis
vault write -wrap-ttl=10m -f auth/approle/role/genesis/secret-id -field=wrapping_token
```

### 2. Generate Platform Operator Token
To perform the initial "Admin Claim" in the Permesi web console, you need a token with the `permesi-operators` policy:

```bash
vault token create -policy=permesi-operators -period=2h -field=token
```

### 3. Verification
You can verify the configuration via the Vault CLI:
```bash
# Check Transit keys
vault read transit/permesi/keys/users
vault read transit/genesis/keys/genesis-signing

# Check OPAQUE seed
vault kv get secret/permesi/opaque
```
