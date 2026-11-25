# Plan-time assertions against mocked providers: no OpenBao server or token is
# needed, so `just openbao-tofu-test` runs anywhere OpenTofu is installed.
mock_provider "vault" {}
mock_provider "random" {}

variables {
  permesi_database_password = "test-only"
  genesis_database_password = "test-only"
}

run "pki_roles_and_cert_auth" {
  command = plan

  assert {
    condition     = var.database_sslmode == "verify-full" && strcontains(vault_database_secret_backend_connection.permesi.postgresql[0].connection_url, "sslmode=verify-full") && strcontains(vault_database_secret_backend_connection.genesis.postgresql[0].connection_url, "sslmode=verify-full")
    error_message = "Database connections must default to verified TLS."
  }

  assert {
    condition     = alltrue([for c in [vault_database_secret_backend_connection.permesi, vault_database_secret_backend_connection.genesis] : c.postgresql[0].password == null && c.postgresql[0].password_wo_version == 1])
    error_message = "Database root passwords must be write-only, sent once on a fresh install."
  }

  assert {
    condition     = alltrue([for k in ["cert", "approle"] : endswith(vault_quota_rate_limit.genesis[k].path, "/")])
    error_message = "Auth quota paths must match the trailing slash OpenBao stores, or every apply replaces them."
  }

  assert {
    condition     = vault_mount.pki_root.path == "pki-root"
    error_message = "Expected pki_root mount at pki-root."
  }

  assert {
    condition     = vault_mount.pki_int.path == "pki-int"
    error_message = "Expected pki_int mount at pki-int."
  }

  assert {
    condition     = toset(vault_pki_secret_backend_role.permesi_runtime.allowed_domains) == toset(["api.permesi.localhost"])
    error_message = "Permesi runtime role must only allow the permesi DNS SANs."
  }

  assert {
    condition     = vault_pki_secret_backend_role.permesi_runtime.ttl == "86400"
    error_message = "Permesi runtime role must default to 24h."
  }

  assert {
    condition     = vault_pki_secret_backend_role.permesi_runtime.max_ttl == "259200"
    error_message = "Permesi runtime role must cap TTL at 72h."
  }

  assert {
    condition     = toset(vault_pki_secret_backend_role.genesis_runtime.allowed_domains) == toset(["genesis.permesi.localhost"])
    error_message = "Genesis runtime role must only allow the genesis DNS SANs."
  }

  assert {
    condition     = alltrue([for role in [vault_pki_secret_backend_role.permesi_runtime, vault_pki_secret_backend_role.genesis_runtime] : role.client_flag == false && toset(role.ext_key_usage) == toset(["ServerAuth"])])
    error_message = "Runtime certificates must be server-only so they cannot authenticate to cert auth."
  }

  assert {
    condition     = alltrue([for role in [vault_pki_secret_backend_role.permesi_bootstrap, vault_pki_secret_backend_role.genesis_bootstrap] : contains(role.ext_key_usage, "ClientAuth")])
    error_message = "Bootstrap certificates are the only ones allowed to authenticate to cert auth."
  }

  assert {
    condition     = vault_pki_secret_backend_role.permesi_bootstrap.ttl == "604800"
    error_message = "Permesi bootstrap role must default to 7 days."
  }

  assert {
    condition     = contains(vault_cert_auth_backend_role.permesi_agent.token_policies, "permesi-agent") && contains(vault_cert_auth_backend_role.permesi_agent.token_policies, "permesi")
    error_message = "Permesi cert-auth role must use the permesi-agent and permesi policies."
  }

  assert {
    condition     = contains(vault_cert_auth_backend_role.genesis_agent.token_policies, "genesis-agent") && contains(vault_cert_auth_backend_role.genesis_agent.token_policies, "genesis")
    error_message = "Genesis cert-auth role must use the genesis-agent and genesis policies."
  }
}
