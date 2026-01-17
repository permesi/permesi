path "pki_int/issue/permesi-runtime" {
  capabilities = ["create", "update"]
}

path "pki_int/ca" {
  capabilities = ["read"]
}

path "pki_int/ca_chain" {
  capabilities = ["read"]
}
