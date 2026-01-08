resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

resource "vault_approle_auth_backend_role" "permesi" {
  backend        = vault_auth_backend.approle.path
  role_name      = "permesi"
  token_policies = [vault_policy.permesi.name]
  token_ttl      = 3600
  token_max_ttl  = 14400
  secret_id_ttl  = 86400 # 24 hours
  bind_secret_id = true
}

resource "vault_approle_auth_backend_role_secret_id" "permesi" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.permesi.role_name
}

resource "vault_approle_auth_backend_role" "genesis" {
  backend        = vault_auth_backend.approle.path
  role_name      = "genesis"
  token_policies = [vault_policy.genesis.name]
  token_ttl      = 3600
  token_max_ttl  = 14400
  secret_id_ttl  = 86400 # 24 hours
  bind_secret_id = true
}

resource "vault_approle_auth_backend_role_secret_id" "genesis" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.genesis.role_name
}

output "permesi_role_id" {
  value = vault_approle_auth_backend_role.permesi.role_id
}

output "permesi_secret_id" {
  value     = vault_approle_auth_backend_role_secret_id.permesi.secret_id
  sensitive = true
}

output "genesis_role_id" {
  value = vault_approle_auth_backend_role.genesis.role_id
}

output "genesis_secret_id" {
  value     = vault_approle_auth_backend_role_secret_id.genesis.secret_id
  sensitive = true
}
