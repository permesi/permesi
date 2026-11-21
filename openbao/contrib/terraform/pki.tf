locals {
  pki_root_path = "pki-root"
  pki_int_path  = "pki-int"

  permesi_dns_sans = ["api.permesi.localhost"]
  genesis_dns_sans = ["genesis.permesi.localhost"]
}

# ----------------------------------------------------------------------------
# PKI mounts
# ----------------------------------------------------------------------------
resource "vault_mount" "pki_root" {
  path                  = local.pki_root_path
  type                  = "pki"
  description           = "Permesi root CA (offline issuer)"
  max_lease_ttl_seconds = 315360000 # 10 years
}

resource "vault_mount" "pki_int" {
  path                  = local.pki_int_path
  type                  = "pki"
  description           = "Permesi intermediate CA (online issuer)"
  max_lease_ttl_seconds = 94608000 # 3 years
}

# ----------------------------------------------------------------------------
# Root + Intermediate CA
# ----------------------------------------------------------------------------
resource "vault_pki_secret_backend_root_cert" "permesi_root" {
  backend     = vault_mount.pki_root.path
  type        = "internal"
  common_name = var.pki_root_common_name
  ttl         = var.pki_root_ttl
  key_type    = "ec"
  key_bits    = 256
  issuer_name = "permesi-root"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "permesi_int" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = var.pki_intermediate_common_name
  key_type    = "ec"
  key_bits    = 256
}

resource "vault_pki_secret_backend_root_sign_intermediate" "permesi_int" {
  backend     = vault_mount.pki_root.path
  csr         = vault_pki_secret_backend_intermediate_cert_request.permesi_int.csr
  common_name = var.pki_intermediate_common_name
  ttl         = var.pki_intermediate_ttl
  format      = "pem_bundle"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "permesi_int" {
  backend     = vault_mount.pki_int.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.permesi_int.certificate
}

resource "vault_pki_secret_backend_config_urls" "pki_root" {
  backend                 = vault_mount.pki_root.path
  issuing_certificates    = [var.pki_root_issuing_certificates_url]
  crl_distribution_points = [var.pki_root_crl_distribution_points_url]
  depends_on              = [vault_pki_secret_backend_root_cert.permesi_root]
}

resource "vault_pki_secret_backend_config_urls" "pki_int" {
  backend                 = vault_mount.pki_int.path
  issuing_certificates    = [var.pki_int_issuing_certificates_url]
  crl_distribution_points = [var.pki_int_crl_distribution_points_url]
  depends_on              = [vault_pki_secret_backend_intermediate_set_signed.permesi_int]
}

# ----------------------------------------------------------------------------
# Runtime PKI roles (short-lived TLS)
#
# Server-only: a runtime leaf shares its DNS SAN and issuer with the bootstrap
# certificate, so without ClientAuth (client_flag adds it
# unless disabled) it cannot be replayed against cert auth to
# obtain the service's OpenBao token.
# ----------------------------------------------------------------------------
resource "vault_pki_secret_backend_role" "permesi_runtime" {
  backend                     = vault_mount.pki_int.path
  name                        = "permesi-runtime"
  allowed_domains             = local.permesi_dns_sans
  allow_bare_domains          = true
  allow_subdomains            = false
  allow_glob_domains          = false
  allow_wildcard_certificates = false
  allow_any_name              = false
  enforce_hostnames           = true
  allow_ip_sans               = false
  key_type                    = "ec"
  key_bits                    = 256
  key_usage                   = ["DigitalSignature", "KeyAgreement"]
  ext_key_usage               = ["ServerAuth"]
  server_flag                 = true
  client_flag                 = false
  ttl                         = "86400"  # 24h
  max_ttl                     = "259200" # 72h
}

resource "vault_pki_secret_backend_role" "genesis_runtime" {
  backend                     = vault_mount.pki_int.path
  name                        = "genesis-runtime"
  allowed_domains             = local.genesis_dns_sans
  allow_bare_domains          = true
  allow_subdomains            = false
  allow_glob_domains          = false
  allow_wildcard_certificates = false
  allow_any_name              = false
  enforce_hostnames           = true
  allow_ip_sans               = false
  key_type                    = "ec"
  key_bits                    = 256
  key_usage                   = ["DigitalSignature", "KeyAgreement"]
  ext_key_usage               = ["ServerAuth"]
  server_flag                 = true
  client_flag                 = false
  ttl                         = "86400"  # 24h
  max_ttl                     = "259200" # 72h
}

# ----------------------------------------------------------------------------
# Bootstrap PKI roles (longer-lived certificates for OpenBao cert auth)
# ----------------------------------------------------------------------------
resource "vault_pki_secret_backend_role" "permesi_bootstrap" {
  backend                     = vault_mount.pki_int.path
  name                        = "permesi-bootstrap"
  allowed_domains             = local.permesi_dns_sans
  allow_bare_domains          = true
  allow_subdomains            = false
  allow_glob_domains          = false
  allow_wildcard_certificates = false
  allow_any_name              = false
  enforce_hostnames           = true
  allow_ip_sans               = false
  key_type                    = "ec"
  key_bits                    = 256
  key_usage                   = ["DigitalSignature", "KeyAgreement"]
  ext_key_usage               = ["ClientAuth", "ServerAuth"]
  ttl                         = "604800"  # 7 days
  max_ttl                     = "2592000" # 30 days
}

resource "vault_pki_secret_backend_role" "genesis_bootstrap" {
  backend                     = vault_mount.pki_int.path
  name                        = "genesis-bootstrap"
  allowed_domains             = local.genesis_dns_sans
  allow_bare_domains          = true
  allow_subdomains            = false
  allow_glob_domains          = false
  allow_wildcard_certificates = false
  allow_any_name              = false
  enforce_hostnames           = true
  allow_ip_sans               = false
  key_type                    = "ec"
  key_bits                    = 256
  key_usage                   = ["DigitalSignature", "KeyAgreement"]
  ext_key_usage               = ["ClientAuth", "ServerAuth"]
  ttl                         = "604800"  # 7 days
  max_ttl                     = "2592000" # 30 days
}
