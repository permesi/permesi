resource "vault_mount" "permesi" {
  path        = "secret/permesi"
  type        = "kv"
  description = "KV-v2 storage for Permesi secrets"
  options = {
    version = "2"
  }
}

resource "random_id" "opaque_seed" {
  byte_length = 32
}

resource "random_id" "mfa_pepper" {
  byte_length = 32
}

resource "vault_kv_secret_v2" "config" {
  mount = vault_mount.permesi.path
  name  = "config"
  data_json = jsonencode({
    opaque_server_seed  = random_id.opaque_seed.b64_std
    mfa_recovery_pepper = random_id.mfa_pepper.b64_std
  })
}