resource "vault_mount" "permesi" {
  path        = "secret/permesi"
  type        = "kv"
  description = "KV-v2 storage for Permesi secrets"
  options = {
    version = "2"
  }

  # Vault audit backend enablement can race with secrets-engine enablement in dev mode.
  # Ordering this avoids transient "failed to audit response" / "path is already in use" failures.
  depends_on = [vault_audit.file]
}

resource "random_id" "opaque_seed" {
  byte_length = 32
}

resource "vault_kv_secret_v2" "opaque" {
  mount = vault_mount.permesi.path
  name  = "opaque"
  data_json = jsonencode({
    opaque_seed_b64 = random_id.opaque_seed.b64_std
  })
}
