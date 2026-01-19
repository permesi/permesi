variables {
  permesi_database_password = "test-only"
  genesis_database_password = "test-only"
}

run "pki_roles_and_cert_auth" {
  command = plan

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
    condition     = vault_pki_secret_backend_role.permesi_runtime.ttl == "24h"
    error_message = "Permesi runtime role must default to 24h."
  }

  assert {
    condition     = vault_pki_secret_backend_role.permesi_runtime.max_ttl == "72h"
    error_message = "Permesi runtime role must cap TTL at 72h."
  }

  assert {
    condition     = toset(vault_pki_secret_backend_role.genesis_runtime.allowed_domains) == toset(["genesis.permesi.localhost"])
    error_message = "Genesis runtime role must only allow the genesis DNS SANs."
  }

  assert {
    condition     = vault_pki_secret_backend_role.permesi_bootstrap.ttl == "168h"
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
