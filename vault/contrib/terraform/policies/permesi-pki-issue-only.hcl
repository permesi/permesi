path "pki-int/issue/permesi-runtime" {
  capabilities = ["create", "update"]
}

path "pki-int/ca" {
  capabilities = ["read"]
}

path "pki-int/ca_chain" {
  capabilities = ["read"]
}

path "auth/approle/role/permesi/secret-id" {
  capabilities = ["create", "update"]
}
