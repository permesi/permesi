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