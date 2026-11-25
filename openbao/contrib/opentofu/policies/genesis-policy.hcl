path "auth/token/lookup-self" { capabilities = ["read"] }

path "database/creds/genesis" { capabilities = ["read"] }
path "transit/genesis/sign/genesis-signing" {
  capabilities = ["update"]
  required_parameters = ["input", "key_version"]
  allowed_parameters = {
    "input"       = []
    "key_version" = []
  }
}
path "transit/genesis/keys/genesis-signing" { capabilities = ["read"] }

path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/leases/renew" {
  capabilities = ["update"]
  required_parameters = ["lease_id"]
  allowed_parameters = {
    "lease_id"  = ["database/creds/genesis/*"]
    "increment" = []
  }
}
