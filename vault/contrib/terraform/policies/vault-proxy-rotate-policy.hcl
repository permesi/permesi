path "auth/approle/role/vault-proxy/secret-id" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
