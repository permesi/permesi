resource "vault_auth_backend" "cert" {
  type = "cert"
  path = "cert"
}

resource "vault_cert_auth_backend_role" "permesi_agent" {
  backend                 = vault_auth_backend.cert.path
  name                    = "permesi-agent"
  certificate             = vault_pki_secret_backend_root_sign_intermediate.permesi_int.certificate_bundle
  allowed_dns_sans        = local.permesi_dns_sans
  token_policies          = [vault_policy.permesi_agent.name, vault_policy.permesi.name]
  token_no_default_policy = true
  token_ttl               = 3600
  token_max_ttl           = 14400
}

resource "vault_cert_auth_backend_role" "genesis_agent" {
  backend                 = vault_auth_backend.cert.path
  name                    = "genesis-agent"
  certificate             = vault_pki_secret_backend_root_sign_intermediate.permesi_int.certificate_bundle
  allowed_dns_sans        = local.genesis_dns_sans
  token_policies          = [vault_policy.genesis_agent.name, vault_policy.genesis.name]
  token_no_default_policy = true
  token_ttl               = 3600
  token_max_ttl           = 14400
}
