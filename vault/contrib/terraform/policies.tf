resource "vault_policy" "permesi" {
  name   = "permesi"
  policy = file("${path.module}/policies/permesi-policy.hcl")
}

resource "vault_policy" "genesis" {
  name   = "genesis"
  policy = file("${path.module}/policies/genesis-policy.hcl")
}

resource "vault_policy" "operators" {
  name   = "permesi-operators"
  policy = file("${path.module}/policies/operator-policy.hcl")
}

resource "vault_policy" "vault_proxy" {
  name   = "vault-proxy"
  policy = file("${path.module}/policies/vault-proxy-policy.hcl")
}

resource "vault_policy" "vault_proxy_rotate" {
  name   = "vault-proxy-rotate"
  policy = file("${path.module}/policies/vault-proxy-rotate-policy.hcl")
}
