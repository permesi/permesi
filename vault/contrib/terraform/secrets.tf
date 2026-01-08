resource "vault_mount" "kv" {
  path        = "kv"
  type        = "kv"
  description = "KV-v2 storage for Permesi secrets"
  options = {
    version = "2"
  }
}

resource "random_id" "opaque_seed" {
  byte_length = 32
}

resource "vault_kv_secret_v2" "opaque" {
  mount = vault_mount.kv.path
  name  = "permesi/opaque"
  data_json = jsonencode({
    opaque_seed_b64 = random_id.opaque_seed.b64_std
  })
}