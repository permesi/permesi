resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

resource "vault_approle_auth_backend_role" "permesi" {
  backend                 = vault_auth_backend.approle.path
  role_name               = "permesi"
  token_policies          = [vault_policy.permesi.name]
  token_no_default_policy = true
  token_ttl               = 3600
  token_max_ttl           = 14400
  secret_id_num_uses      = 1
  secret_id_ttl           = 3600 # 1 hour
  bind_secret_id          = true
}

resource "vault_approle_auth_backend_role" "genesis" {
  backend                 = vault_auth_backend.approle.path
  role_name               = "genesis"
  token_policies          = [vault_policy.genesis.name]
  token_no_default_policy = true
  token_ttl               = 3600
  token_max_ttl           = 14400
  secret_id_num_uses      = 1
  secret_id_ttl           = 3600 # 1 hour
  bind_secret_id          = true
}

resource "vault_approle_auth_backend_role" "vault_proxy" {
  backend                 = vault_auth_backend.approle.path
  role_name               = "vault-proxy"
  token_policies          = [vault_policy.vault_proxy.name]
  token_no_default_policy = true
  token_ttl               = 3600
  token_max_ttl           = 14400
  secret_id_num_uses      = 0     # multiple applications may use the same secret ID
  secret_id_ttl           = 86400 # 24 hours
  bind_secret_id          = true
}

output "permesi_role_id" {
  value = vault_approle_auth_backend_role.permesi.role_id
}

output "genesis_role_id" {
  value = vault_approle_auth_backend_role.genesis.role_id
}

output "vault_proxy_role_id" {
  value = vault_approle_auth_backend_role.vault_proxy.role_id
}
