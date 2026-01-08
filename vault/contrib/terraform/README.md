# Permesi Vault Configuration with Terraform

This Terraform module provides a production-ready configuration for HashiCorp Vault to support the Permesi and Genesis services.

## Features

- **AppRole**: Configures roles for both `permesi` and `genesis`.
- **Transit**: Sets up encryption/decryption keys for user data (`users`) and admission token signing (`genesis-signing`).
- **KV Store**: Generates and stores a persistent 32-byte OPAQUE seed.
- **Database Engine**: Configures dynamic Postgres credentials for both services.
- **Policies**: Implements least-privilege policies for services and operators.

## Usage

1. **Set Vault Authentication**:
   ```bash
   export VAULT_ADDR="https://your-vault:8200"
   export VAULT_TOKEN="your-root-token"
   ```

2. **Configure Variables**:
   You can provide required variables in two ways:

   **Option A: Environment Variables**
   Prefix any variable name with `TF_VAR_`:
   ```bash
   export TF_VAR_database_password="secure_password"
   export TF_VAR_database_host="db.internal"
   ```

   **Option B: `terraform.tfvars` file**
   Create a file named `terraform.tfvars` (this file is ignored by git):
   ```hcl
   database_host     = "localhost"
   database_username = "postgres"
   database_password = "secure_password"
   ```

3. **Initialize and Apply**:
   ```bash
   terraform init
   terraform apply
   ```

## Post-Deployment

### 1. Retrieve Service Credentials
Terraform outputs the `RoleID` for both services. To complete the configuration, you must manually generate a `SecretID` for each:

```bash
# Get permesi RoleID (or check terraform output)
vault read auth/approle/role/permesi/role-id

# Generate permesi SecretID
vault write -f auth/approle/role/permesi/secret-id

# Repeat for genesis
vault write -f auth/approle/role/genesis/secret-id
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
vault kv get kv/permesi/opaque
```
