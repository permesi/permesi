# ----------------------------------------------------------------------------
# Transit - Permesi (Users data encryption)
# ----------------------------------------------------------------------------
resource "vault_mount" "transit_permesi" {
  path        = "transit/permesi"
  type        = "transit"
  description = "Permesi user data encryption"
}

resource "vault_transit_secret_backend_key" "permesi_users" {
  backend            = vault_mount.transit_permesi.path
  name               = "users"
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