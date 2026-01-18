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

resource "vault_policy" "permesi_pki_issue_only" {
  name   = "permesi-pki-issue-only"
  policy = file("${path.module}/policies/permesi-pki-issue-only.hcl")
}

resource "vault_policy" "genesis_pki_issue_only" {
  name   = "genesis-pki-issue-only"
  policy = file("${path.module}/policies/genesis-pki-issue-only.hcl")
}
