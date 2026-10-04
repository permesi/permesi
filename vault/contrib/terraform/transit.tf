# ----------------------------------------------------------------------------
# Transit - Permesi (TOTP protection and OIDC signing-key foundation)
# ----------------------------------------------------------------------------
resource "vault_mount" "transit_permesi" {
  path        = "transit/permesi"
  type        = "transit"
  description = "Permesi TOTP protection and OIDC signing keys"
}

removed {
  from = vault_transit_secret_backend_key.permesi_users

  lifecycle {
    # The legacy key is retired explicitly after operators have reviewed
    # backups and rollback requirements; see README.md. Terraform must not
    # turn an ordinary configuration apply into irreversible key deletion.
    destroy = false
  }
}

resource "vault_transit_secret_backend_key" "permesi_totp" {
  backend            = vault_mount.transit_permesi.path # "transit/permesi"
  name               = "totp"
  type               = "chacha20-poly1305"
  auto_rotate_period = 2592000 # 30 days
}

# ----------------------------------------------------------------------------
# Transit - Genesis (Admission token signing)
# ----------------------------------------------------------------------------
resource "vault_mount" "transit_genesis" {
  path        = "transit/genesis"
  type        = "transit"
  description = "Genesis admission token signing"
}

resource "vault_transit_secret_backend_key" "genesis_signing" {
  backend            = vault_mount.transit_genesis.path
  name               = "genesis-signing"
  type               = "ed25519"
  auto_rotate_period = 2592000 # 30 days
}

# OIDC signing is distinct from TOTP encryption and Genesis admission keys.
resource "vault_transit_secret_backend_key" "permesi_oidc" {
  backend                = vault_mount.transit_permesi.path
  name                   = "oidc-signing"
  type                   = "rsa-2048"
  exportable             = false
  allow_plaintext_backup = false
  deletion_allowed       = false
  auto_rotate_period     = 2592000 # Retain prior public versions for verification.
}
