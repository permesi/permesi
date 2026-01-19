# Permesi Vault Configuration with Terraform

This Terraform module provides a production-ready configuration for HashiCorp Vault to support the Permesi and Genesis services.

## Features

- **AppRole**: Configures roles for both `permesi` and `genesis`.
- **Transit**: Sets up encryption/decryption keys for user data (`users`) and admission token signing (`genesis-signing`).
- **KV Store**: Generates and stores a persistent 32-byte OPAQUE seed under `secret/permesi/opaque`.
- **Database Engine**: Configures dynamic Postgres credentials for both services, including lease renewals that extend the Postgres role expiration and automated rotation of the Vault root database credentials.
- **Policies**: Implements least-privilege policies for services and operators.
- **PKI (TLS certificates)**: Establishes a root + intermediate PKI hierarchy, service-scoped issuance roles, and cert-auth roles for Vault Agent-based certificate delivery.

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

   For PKI, set the issuing/CRL URLs to routable endpoints served by Vault. The defaults in `variables.tf` and `terraform.tfvars.example` are placeholders (`*.example.invalid`) and must be overridden for real deployments. The PKI hierarchy uses ECDSA P-256 by default to keep interoperability strong with HAProxy and Cloudflare. If you want to move to Ed25519 later, update the PKI key parameters in `vault/contrib/terraform/pki.tf` only after confirming downstream compatibility.

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
   pki_root_issuing_certificates_url = "https://vault.example.invalid/v1/pki-root/ca"
   pki_root_crl_distribution_points_url = "https://vault.example.invalid/v1/pki-root/crl"
   pki_int_issuing_certificates_url = "https://vault.example.invalid/v1/pki-int/ca"
   pki_int_crl_distribution_points_url = "https://vault.example.invalid/v1/pki-int/crl"
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

### 4. PKI Bootstrap and Vault Agent cert auth
The PKI hierarchy provides short-lived runtime roles (`permesi-runtime`, `genesis-runtime`) and longer-lived bootstrap roles (`permesi-bootstrap`, `genesis-bootstrap`) intended only for Vault Agent cert-auth onboarding. Bootstrap certificates should be rotated on a slower cadence and never used directly for service TLS. Vault must be configured to accept cert-auth logins and trust the issuing chain used by the bootstrap certificates.

Vault Agent renders templates when the underlying secret changes. For PKI templates, that means the first render issues a certificate, and subsequent renders happen when the agent renews and re-issues the certificate before the TTL expires. Keep the agent running continuously so it can renew its auth token and rotate certificates on schedule.
If the agent is stopped long enough for the cert-auth token and runtime certificates to expire, it
cannot re-issue certs until restarted with valid bootstrap certificates.

Example bootstrap issuance (run with an operator token):
```bash
vault write pki-int/issue/permesi-bootstrap \
  common_name="api.permesi.localhost" \
  ttl=168h --format=json


vault write pki-int/issue/genesis-bootstrap \
  common_name="genesis.permesi.localhost" \
  ttl=168h --format=json
```

Minimal Vault Agent configs (one per service) to authenticate via cert auth and render runtime TLS certificates. Update paths and Vault address to match your host layout. Run the agent as a long-lived service (for example, `vault agent -config=/etc/vault.d/vault.hcl`) so it can renew tokens and rotate certificates before TTLs expire.

`permesi`:
```hcl
vault {
  address = "https://vault.example.invalid:8200"
  ca_cert = "/etc/permesi/bootstrap/ca_cert.pem"
  client_cert = "/etc/permesi/bootstrap/cert_file.pem"
  client_key  = "/etc/permesi/bootstrap/key_file.pem"
}

auto_auth {
  method "cert" {
    mount_path = "auth/cert"
    config = {
      name        = "permesi-agent"
      ca_cert     = "/etc/permesi/bootstrap/ca_cert.pem"
      client_cert = "/etc/permesi/bootstrap/cert_file.pem"
      client_key  = "/etc/permesi/bootstrap/key_file.pem"
      reload      = "true"
    }
  }

api_proxy {
  use_auto_auth_token = true
}

listener "unix" {
  address      = "/run/permesi/agent.sock"
  socket_mode  = "0660"
  socket_user  = "permesi"
  socket_group = "permesi"

  tls_disable = true
}

cache {}

template {
  destination = "/run/permesi/tls.crt"
  contents = "{{ with secret \"pki-int/issue/permesi-runtime\" \"common_name=api.permesi.localhost\" \"alt_names=api.permesi.localhost\" \"ttl=24h\" }}{{ .Data.certificate }}{{ end }}"
}

template {
  destination = "/run/permesi/tls.key"
  perms = "0600"
  contents = "{{ with secret \"pki-int/issue/permesi-runtime\" \"common_name=api.permesi.localhost\" \"alt_names=api.permesi.localhost\" \"ttl=24h\" }}{{ .Data.private_key }}{{ end }}"
}

template {
  destination = "/run/permesi/ca.pem"
  contents = "{{ with secret \"pki-int/issue/permesi-runtime\" \"ttl=24h\" \"alt_names=api.permesi.localhost\" \"common_name=api.permesi.localhost\" }}{{ range .Data.ca_chain }}{{ . }}\n{{ end }}{{ end }}"
}
```

`genesis`:
```hcl
vault {
  address = "https://vault.example.invalid:8200"
  ca_cert = "/etc/genesis/bootstrap/ca_cert.pem"
  client_cert = "/etc/genesis/bootstrap/cert_file.pem"
  client_key  = "/etc/genesis/bootstrap/key_file.pem"
}

auto_auth {
  method "cert" {
    mount_path = "auth/cert"
    config = {
      name        = "genesis-agent"
      ca_cert     = "/etc/genesis/bootstrap/ca_cert.pem"
      client_cert = "/etc/genesis/bootstrap/cert_file.pem"
      client_key  = "/etc/genesis/bootstrap/key_file.pem"
      reload      = "true"
    }
  }

  sink "file" {
    config = { path = "/run/genesis/vault-token" }
  }
}

api_proxy {
  use_auto_auth_token = true
}

listener "unix" {
  address      = "/run/genesis/agent.sock"
  socket_mode  = "0660"
  socket_user  = "genesis"
  socket_group = "genesis"

  tls_disable = true
}

cache {}

template {
  destination = "/run/genesis/tls.crt"
  contents = "{{ with secret \"pki-int/issue/genesis-runtime\" \"common_name=genesis.permesi.localhost\" \"alt_names=genesis.permesi.localhost\" \"ttl=24h\" }}{{ .Data.certificate }}{{ end }}"
}

template {
  destination = "/run/genesis/tls.key"
  perms = "0600"
  contents = "{{ with secret \"pki-int/issue/genesis-runtime\" \"common_name=genesis.permesi.localhost\" \"alt_names=genesis.permesi.localhost\" \"ttl=24h\" }}{{ .Data.private_key }}{{ end }}"
}

template {
  destination = "/run/genesis/ca.pem"
  contents = "{{ with secret \"pki-int/issue/genesis-runtime\" \"common_name=genesis.permesi.localhost\" \"alt_names=genesis.permesi.localhost\" \"ttl=24h\" }}{{ range .Data.ca_chain }}{{ . }}\n{{ end }}{{ end }}"
}
```

Example systemd units (one per service; adjust paths and domains as needed):

```ini
[Unit]
Description=Vault Agent (Permesi)
After=network.target
Wants=network.target

[Service]
User=vault
Group=vault
ExecStart=/usr/bin/vault agent -config=/etc/vault.d/permesi.hcl
Restart=always
RestartSec=2s
RuntimeDirectory=permesi
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

```ini
[Unit]
Description=Vault Agent (Genesis)
After=network.target
Wants=network.target

[Service]
User=vault
Group=vault
ExecStart=/usr/bin/vault agent -config=/etc/vault.d/genesis.hcl
Restart=always
RestartSec=2s
RuntimeDirectory=genesis
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

## Tests
Terraform tests in `vault/contrib/terraform/tests` validate the PKI and cert-auth wiring at plan time. Run them from this directory with:
```bash
terraform init
terraform test
```
