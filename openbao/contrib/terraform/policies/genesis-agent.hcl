path "pki-int/issue/genesis-runtime" {
  capabilities = ["create", "update"]
}

path "pki-int/ca" {
  capabilities = ["read"]
}

path "pki-int/ca_chain" {
  capabilities = ["read"]
}
