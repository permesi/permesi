# Separate edge buckets leave core authority reads, credential issue and
# administrative revocation outside these paths. Auth roles share a mount.
resource "vault_quota_rate_limit" "genesis" {
  for_each = {
    signing     = { path = "${vault_mount.transit_genesis.path}/sign/genesis-signing", role = null }
    credentials = { path = "${vault_mount.db.path}/creds/genesis", role = null }
    pki         = { path = "pki-int/issue/genesis-runtime", role = null }
    approle     = { path = "auth/${vault_auth_backend.approle.path}", role = vault_approle_auth_backend_role.genesis.role_name }
  }
  name     = "genesis-${each.key}"
  path     = each.value.path
  role     = each.value.role
  interval = 1
  rate     = var.genesis_quota_rate
}
