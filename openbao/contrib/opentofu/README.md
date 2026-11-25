# Permesi OpenBao Configuration with OpenTofu

This OpenTofu module provides a production-ready configuration for OpenBao to support the Permesi and Genesis services.

## Features

- **AppRole**: Configures roles for both `permesi` and `genesis`.
- **Transit**: Sets up the TOTP protection key (`totp`) and admission token signing key (`genesis-signing`).
- **KV Store**: Generates and stores the persistent OPAQUE seed and MFA recovery pepper under `secret/permesi/config`.
- **Database Engine**: Configures dynamic Postgres credentials for both services, including lease renewals that extend the Postgres role expiration and automated rotation of the OpenBao root database credentials. The root passwords are write-only attributes from ephemeral variables, so they never reach the state or a saved plan.
- **Policies**: Implements least-privilege policies for services and operators.
- **PKI (TLS certificates)**: Establishes a root + intermediate PKI hierarchy, service-scoped issuance roles, and cert-auth roles for OpenBao Agent-based certificate delivery. Runtime certificates are server-only (`client_flag = false`); only the longer-lived bootstrap certificates carry `ClientAuth` and can log in to cert auth.

## State encryption

The state still holds sensitive values: the generated OPAQUE seed and MFA recovery pepper, AppRole role IDs and the PKI certificates. The module therefore declares OpenTofu state encryption in `main.tf`: every state and saved-plan write is AES-GCM encrypted under a data key from the OpenBao Transit key `transit/opentofu/keys/permesi-state`, fetched with `BAO_ADDR` and `BAO_TOKEN` (the key provider also accepts `VAULT_TOKEN`). Without a token that may use that key, `tofu plan`, `output` and `show` fail instead of reading the state. Saved plans are `enforced`, so a plan is never written in the clear.

The key must exist before the first `tofu init`, and the module does not manage it, because a module cannot manage the key that protects its own state. Create it once with `bao secrets enable -path=transit/opentofu transit` and `bao write -f transit/opentofu/keys/permesi-state type=aes256-gcm96`; `just openbao-tofu-apply` does this in development. Grant the operator who runs OpenTofu `update` on `transit/opentofu/datakey/plaintext/permesi-state` and `transit/opentofu/decrypt/permesi-state`, and nothing else on that mount. No service policy grants it.

Losing the Transit key makes the state unrecoverable, so it is covered by the same backups and restore drills as OpenBao. The state only describes that OpenBao, so losing both together loses nothing you could still use. To keep the state key outside the OpenBao it configures (another OpenBao, a cloud KMS or a PBKDF2 passphrase), set `TF_ENCRYPTION`: its blocks override the ones in `main.tf` with the same name, and a `state` block given there must repeat `method`. Keep never committing `.tfstate` files or variable files that contain secrets.

**Migrating an existing Terraform state.** OpenTofu reads a local `terraform.tfstate` written by Terraform, but the module used to live in `openbao/contrib/terraform`, and its untracked state stays there after the move. Applying without it would start from an empty state against an OpenBao that is already provisioned. Create the state key first (above), then move the state and run both `init` and the first `apply` with a one-time unencrypted fallback, because `init` already reads the state:

```bash
mv ../terraform/terraform.tfstate terraform.tfstate
export TF_ENCRYPTION='method "unencrypted" "migrate" {}
state {
  method = method.aes_gcm.state
  fallback {
    method = method.unencrypted.migrate
  }
}'
tofu init -lockfile=readonly
tofu apply
unset TF_ENCRYPTION
```

The apply writes the state back encrypted. Then delete every plaintext leftover: `terraform.tfstate.backup` here if `jq 'has("encrypted_data")' terraform.tfstate.backup` prints `false` (it holds the previous unencrypted state), and `../terraform/terraform.tfstate.backup`, `../terraform/.terraform` and the old directory itself. `just openbao-tofu-apply` does all of this in development, and refuses to choose when both directories hold a state.

The first apply also moves the root passwords to write-only attributes. OpenBao verifies a connection whenever its password is sent, so if it has already rotated a root password, sending the stale bootstrap password fails that apply without changing anything. In that case add `-var permesi_database_password_version=0` and/or `-var genesis_database_password_version=0` for each rotated connection, and keep that value. Raise a connection's version only after resetting its root password in PostgreSQL; the versions are separate so that recovering one service does not resend the other's stale password.

## Usage

1. **Set OpenBao Authentication**:
   ```bash
   export VAULT_ADDR="https://your-openbao:8200"
   export VAULT_TOKEN="your-root-token"
   export BAO_ADDR="$VAULT_ADDR" BAO_TOKEN="$VAULT_TOKEN"
   ```

   This module uses the API-compatible `hashicorp/vault` provider, which keeps its `vault_*` resource names and reads `VAULT_ADDR`/`VAULT_TOKEN` rather than the `BAO_*` variables of the `bao` CLI. The state encryption key provider reads `BAO_ADDR`/`BAO_TOKEN`. Use a real TLS certificate and keep TLS verification enabled. For private PKI, set `VAULT_CACERT` (or `VAULT_CAPATH`) instead of disabling verification.

2. **Configure Variables**:
   You can provide required variables in two ways:

   This module is security-sensitive. In production, keep OpenBao TLS verification enabled, use Postgres TLS (`database_sslmode = "verify-full"` or `"verify-ca"`) and ensure OpenBao trusts the database CA. For service authentication, AppRole SecretIDs are single-use with a 1-hour TTL (`secret_id_num_uses = 1`, `secret_id_ttl = 3600` in `approle.tf`), so ensure your automation can mint fresh SecretIDs (or tune `approle.tf` to match your rotation process).

   For PKI, set the issuing/CRL URLs to routable endpoints served by OpenBao. The defaults in `variables.tf` and `terraform.tfvars.example` are placeholders (`*.example.invalid`) and must be overridden for real deployments. The PKI hierarchy uses ECDSA P-256 by default to keep interoperability strong with HAProxy and Cloudflare. If you want to move to Ed25519 later, update the PKI key parameters in `openbao/contrib/opentofu/pki.tf` only after confirming downstream compatibility.

   For the database secrets engine, OpenBao needs a dedicated Postgres "root" user per connection. Those users should be non-superuser roles with `LOGIN` + `CREATEROLE`, be able to terminate sessions during revocation (`pg_signal_backend`), and own the target database objects they grant privileges on. Local dev uses `db/sql/00_init.sql` to create `openbao_permesi` and `openbao_genesis` with these properties. The file ships with a `change-me` placeholder password; for production, edit it (or use it as a template) to set strong, unique passwords before running it as a superuser.

   This module uses a "runtime role" pattern: OpenBao-minted login roles only receive membership in a NOLOGIN role (`permesi_runtime` / `genesis_runtime`) which holds the database/schema/table grants. This keeps privileges centralized (one place to audit/change) and avoids short-lived users owning persistent database objects. Ensure the OpenBao root users can `GRANT` those runtime roles (by owning them or via `WITH ADMIN OPTION`).

   **Option A: Environment Variables**
   Prefix any variable name with `TF_VAR_`:
   ```bash
   export TF_VAR_database_host="db.internal"
   # database_sslmode defaults to verify-full; OpenBao must trust the database CA.
   export TF_VAR_permesi_database_username="openbao_permesi"
   export TF_VAR_permesi_database_password="change-me"
   export TF_VAR_genesis_database_username="openbao_genesis"
   export TF_VAR_genesis_database_password="change-me"
   ```

   **Option B: `terraform.tfvars` file**
   Create a file named `terraform.tfvars` (this file is ignored by git):
   ```hcl
   database_host     = "localhost"
   permesi_database_username = "openbao_permesi"
   permesi_database_password = "change-me"
   genesis_database_username = "openbao_genesis"
   genesis_database_password = "change-me"
   # Local/dev only; for production use "verify-full" (or at least "verify-ca").
   database_sslmode  = "disable"
   pki_root_issuing_certificates_url = "https://openbao.example.invalid/v1/pki-root/ca"
   pki_root_crl_distribution_points_url = "https://openbao.example.invalid/v1/pki-root/crl"
   pki_int_issuing_certificates_url = "https://openbao.example.invalid/v1/pki-int/ca"
   pki_int_crl_distribution_points_url = "https://openbao.example.invalid/v1/pki-int/crl"
   ```

3. **Initialize and Apply** (after creating the state key, see [State encryption](#state-encryption)):
   ```bash
   tofu init -lockfile=readonly
   tofu apply
   ```

   `.terraform.lock.hcl` is committed with checksums for every platform, and `-lockfile=readonly` refuses any provider build that does not match it. After changing a provider version, run `tofu init -upgrade` and commit the updated lock file.

4. **OpenBao audit device**:
   OpenBao does not allow audit devices to be enabled through the API, so this module does not
   manage one. Declare it in the server configuration instead (see `openbao/audit.hcl` for the
   development example) and make sure the OpenBao service user can write to the log path.


## Post-Deployment

### 1. Retrieve Service Credentials
OpenTofu outputs the `RoleID` for both services. To complete the configuration, generate a `SecretID` for each role.

For production, prefer response-wrapped SecretIDs (short-lived wrapping tokens) so you never have to handle the raw SecretID in logs or shells:

```bash
# Get permesi RoleID (or check tofu output)
bao read auth/approle/role/permesi/role-id

# Generate permesi SecretID as a wrapped token (recommended)
bao write -wrap-ttl=10m -f auth/approle/role/permesi/secret-id -field=wrapping_token

# Repeat for genesis
bao write -wrap-ttl=10m -f auth/approle/role/genesis/secret-id -field=wrapping_token
```

### 2. Generate Platform Operator Token
To perform the initial "Admin Claim" in the Permesi web console, you need a token with the `permesi-operators` policy:

```bash
bao token create -policy=permesi-operators -period=2h -field=token
```

### 3. Verification
You can verify the configuration via the OpenBao CLI:
```bash
# Check Transit keys
bao read transit/permesi/keys/totp
bao read transit/genesis/keys/genesis-signing

# Check OPAQUE seed
bao kv get secret/permesi/config
```

The former `transit/permesi/keys/users` key belonged to the retired reversible
password flow. The Permesi application policy no longer permits access to that
key, and OpenTofu deliberately leaves deletion as a separate operator action:
an ordinary configuration apply must not make old backups or rollback data
irreversibly unreadable.

Once every active deployment runs the OPAQUE-only authentication code, no
legacy credential migration is required, and the backup-retention decision has
been approved, permanently retire the key with an authorized operator token:

```bash
bao write transit/permesi/keys/users/config deletion_allowed=true
bao delete transit/permesi/keys/users
```

Verify deletion with `bao read transit/permesi/keys/users`; it must return a
not-found response. Transit key deletion cannot be reversed. Database backups
that contain old ciphertext cease to expose a recoverable credential after the
key is deleted, but they also cannot be used to restore the retired login flow.
There is no in-application ciphertext-to-OPAQUE migration path: the original
OPAQUE schema transition re-created the user table, and current releases cannot
authenticate or migrate a legacy encrypted credential. Any required account
transition must therefore be completed through a separately reviewed reset or
re-enrollment process before deleting the key.

### 4. PKI Bootstrap and OpenBao Agent cert auth
The PKI hierarchy provides short-lived runtime roles (`permesi-runtime`, `genesis-runtime`) and longer-lived bootstrap roles (`permesi-bootstrap`, `genesis-bootstrap`) intended only for OpenBao Agent cert-auth onboarding. Bootstrap certificates should be rotated on a slower cadence and never used directly for service TLS. OpenBao must be configured to accept cert-auth logins and trust the issuing chain used by the bootstrap certificates.

OpenBao Agent renders templates when the underlying secret changes. For PKI templates, that means the first render issues a certificate, and subsequent renders happen when the agent renews and re-issues the certificate before the TTL expires. Keep the agent running continuously so it can renew its auth token and rotate certificates on schedule.
If the agent is stopped long enough for the cert-auth token and runtime certificates to expire, it
cannot re-issue certs until restarted with valid bootstrap certificates.

Example bootstrap issuance (run with an operator token):
```bash
bao write pki-int/issue/permesi-bootstrap \
  common_name="api.permesi.localhost" \
  ttl=168h --format=json


bao write pki-int/issue/genesis-bootstrap \
  common_name="genesis.permesi.localhost" \
  ttl=168h --format=json
```

Minimal OpenBao Agent configs (one per service) to authenticate via cert auth and render runtime TLS certificates. Update paths and OpenBao address to match your host layout. Run the agent as a long-lived service (for example, `bao agent -config=/etc/openbao/agent.hcl`) so it can renew tokens and rotate certificates before TTLs expire.

`permesi`:
```hcl
# OpenBao Agent keeps the upstream stanza name for the server connection.
vault {
  address = "https://openbao.example.invalid:8200"
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
}

api_proxy {
  use_auto_auth_token = true
}

listener "unix" {
  address      = "/run/permesi/agent.sock"
  # The Agent keeps ownership and shares the socket with the service's group.
  # OpenBao applies socket_mode only when both socket_user and socket_group are
  # set, and an unprivileged Agent can only assign its own user and a group it
  # belongs to (the unit below runs it with Group=permesi).
  socket_mode  = "0660"
  socket_user  = "openbao"
  socket_group = "permesi"

  tls_disable = true
}

cache {}

template {
  destination = "/run/permesi/tls.bundle.pem"
  # Note: set to 0640 or 0600 to protect the private key.
  perms = "0640"
  contents = <<EOH
{{- with secret "pki-int/issue/permesi-runtime" "ttl=24h" "common_name=api.permesi.localhost" -}}
{{ .Data.private_key }}
{{ .Data.certificate }}
{{- range .Data.ca_chain }}
{{ . }}
{{- end }}
{{- end -}}
EOH
}
```

The requested names must be allowed by the PKI role: the module ships `api.permesi.localhost` and `genesis.permesi.localhost` (`local.permesi_dns_sans` / `local.genesis_dns_sans` in `pki.tf`). Change those locals to your production names, and the cert-auth roles follow.

`genesis`:
```hcl
# OpenBao Agent keeps the upstream stanza name for the server connection.
vault {
  address = "https://openbao.example.invalid:8200"
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
    config = { path = "/run/genesis/openbao-token" }
  }
}

api_proxy {
  use_auto_auth_token = true
}

listener "unix" {
  address      = "/run/genesis/agent.sock"
  # The Agent keeps ownership and shares the socket with the service's group.
  # OpenBao applies socket_mode only when both socket_user and socket_group are
  # set, and an unprivileged Agent can only assign its own user and a group it
  # belongs to (the unit below runs it with Group=genesis).
  socket_mode  = "0660"
  socket_user  = "openbao"
  socket_group = "genesis"

  tls_disable = true
}

cache {}

template {
  destination = "/run/genesis/tls.bundle.pem"
  perms = "0640"
  contents = <<EOH
{{- with secret "pki-int/issue/genesis-runtime" "ttl=24h" "common_name=genesis.permesi.localhost" -}}
{{ .Data.private_key }}
{{ .Data.certificate }}
{{- range .Data.ca_chain }}
{{ . }}
{{- end }}
{{- end -}}
EOH
}
```

Example systemd units (one per service; adjust paths and domains as needed):

Each Agent unit owns its service's runtime directory and runs as the `openbao` user with the service's group, so the socket (`0660`) and the rendered TLS bundle (`0640`) are readable by the service and by nobody else. The service units in `contrib/systemd` therefore do not declare `RuntimeDirectory` themselves.

```ini
[Unit]
Description=OpenBao Agent (Permesi)
After=network.target
Wants=network.target

[Service]
User=openbao
Group=permesi
ExecStart=/usr/bin/bao agent -config=/etc/openbao/permesi.hcl
Restart=always
RestartSec=2s
RuntimeDirectory=permesi
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

```ini
[Unit]
Description=OpenBao Agent (Genesis)
After=network.target
Wants=network.target

[Service]
User=openbao
Group=genesis
ExecStart=/usr/bin/bao agent -config=/etc/openbao/genesis.hcl
Restart=always
RestartSec=2s
RuntimeDirectory=genesis
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

For reboot safety, keep the bootstrap cert/key on persistent disk and rotate them before expiration at the same paths referenced by `client_cert` and `client_key` in the agent config. `reload = "true"` allows OpenBao Agent to pick up refreshed files, and `Restart=always` helps it recover after host restarts, but an expired bootstrap certificate will still block `auth/cert/login` until a valid replacement is written.

In practice, automate bootstrap re-issuance (for example with a systemd timer), atomically replace the bootstrap files, and restart or reload the OpenBao Agent. This prevents outages when a VM reboots after the previous bootstrap certificate has expired.

## Tests
`just openbao-tofu-test` runs `tofu fmt -check`, `tofu validate` and the plan-time assertions in `tests/pki.tftest.hcl`: PKI and cert-auth wiring, verified database TLS by default, write-only root passwords and the stored form of the auth quota paths. The test mocks both providers and initializes without a backend, so it needs no OpenBao server, token or state key; CI runs the same checks in the OpenTofu Module job.

`just openbao-tofu-test-live` runs `tests/live_quotas.py` and `tests/live_provision.py` against throwaway Podman containers, never the dev stack. The second provisions OpenBao (with TLS) and PostgreSQL (with password authentication) from zero. It checks that the state and a saved plan are encrypted, that the state holds no root password and cannot be read without a token, and that the next plan is empty. It then checks, for each service, AppRole login, the configuration secret, dynamic database credentials, its Transit keys, its runtime and bootstrap PKI roles and cert-auth login, and that the other service's credentials, keys, names and cert-auth role, as well as the OpenTofu state key, are refused. It ends by letting OpenBao rotate both root passwords and checking that a further plan and apply change nothing.

### OIDC public signing-key lifecycle

The Permesi transit mount also owns a separate nonexportable RSA-2048 `oidc-signing`
key, automatically rotated every 30 days with deletion disabled. The Permesi runtime
policy reads public key metadata and signs through the specific transit signing path;
export/rotation/retirement remain operator-only. Operators retain
old versions for verification and must account for configured token lifetimes, downstream
caches and rollback before trimming. The binary uses explicit issuer/audience settings
and reads retained public versions through a bounded single-flight JWKS response cache.
Exchanges select the current shared version explicitly and verify its signature; unknown-kid clients can force a rate-limited JWKS refresh. A different runtime
key/mount requires matching provisioning and policy changes. Deploying token exchange requires applying the signing policy update through the normal operator workflow. Repository tests provision fresh stacks and never apply infrastructure changes.

### Admission authority and eviction

Core operators own the KV v2 record `secret/permesi/data/admission-authority`.
OpenTofu provisions read access. The record itself lives outside OpenTofu
and the Helm release. Restrict write, delete, undelete, metadata and mount
administration to the core operator boundary. Route the reader to authoritative
core storage. Restoring an older OpenBao backup requires restoring the current
withdrawal floor before exposing admission.

For an existing Transit key, inspect its current signer version and initialize with
that version before upgrading the first core replica. Configure Genesis to use the
same version during rollout. Confirm admission on every replica, including a
signup or login, since core readiness deliberately survives an admission outage.
For a new key at version one, initialize with `scripts/admission-authority initialize 1`.
For isolated installations, pass `--reader-socket /absolute/path/to/agent.sock`
to initialization and publication. The core-side Agent needs only read access to
`transit/genesis/keys/genesis-signing` on the edge OpenBao. It sends no core
credential to that endpoint. Every runtime verifier reads the approved public bytes
from core OpenBao independently of edge PostgreSQL, OpenBao and Genesis.

For planned rotation, create the next Transit version and run
`scripts/admission-authority publish VERSION`. Confirm each core replica accepts
the published key before rolling Genesis with `GENESIS_ADMISSION_SIGNING_VERSION`
set to that version. Two approved versions permit overlap. Publication and
withdrawal compare-and-set the KV revision. Conflicts require rereading current
state. To evict existing signatures, use `scripts/admission-authority withdraw VERSION`.
This can suspend all admission before the replacement signer is available.

On suspected compromise, disable reissuance first. Isolate the affected workload,
remove its Kubernetes login binding, revoke its issued tokens and unconsumed
wrapping and SecretID credentials, revoke its certificate and dynamic SQL leases,
and terminate its sessions. Where identities are shared, establish independent
credentials for healthy siblings before fencing the shared identity. A compromised
host also requires node isolation, invalidation of the node credentials and
controlled reenrollment. Inventory the highest Transit version reachable by the
old signer, including staged versions, then advance beyond it. A previous
application digest is eligible for rollback only after it enforces withdrawal.
Drain legacy replicas and check every serving replica with the same unexpired
token before declaring eviction complete.

The signing, credential, runtime and bootstrap PKI, certificate-login and AppRole quotas apply per reachable OpenBao node
and source IP. Restrict edge egress and size the rate times both counts against
the shared service budget. Keep management and core reads on a separately
budgeted path. Existing isolated endpoints require equivalent constraints.

The fresh-bootstrap regression applies the six Genesis quotas and their
prerequisites to an empty disposable OpenBao. It verifies the stored paths,
auth roles, rate and interval. `just openbao-tofu-test-live` runs it with the
pinned OpenBao image by digest, using Podman and OpenTofu. Intermediate signing depends on
the generated root issuer, including during a targeted quota apply.
