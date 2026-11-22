path "auth/token/lookup-self" { capabilities = ["read"] }

# totp
path "transit/permesi/decrypt/totp" { capabilities = ["update"] }

# Generate a new DEK (plaintext + wrapped). Needed for initial DEK and rotations.
path "transit/permesi/datakey/plaintext/totp" { capabilities = ["update"] }

path "secret/permesi/data/admission-authority" { capabilities = ["read"] }
path "secret/permesi/data/config" { capabilities = ["read"] }

path "database/creds/permesi" { capabilities = ["read"] }

path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/leases/renew" {
  capabilities = ["update"]
  required_parameters = ["lease_id"]
  allowed_parameters = {
    "lease_id"  = ["database/creds/permesi/*"]
    "increment" = []
  }
}

# Runtime reads verification material and signs; rotation, retirement and export remain operator-only.
path "transit/permesi/keys/oidc-signing" { capabilities = ["read"] }
path "transit/permesi/sign/oidc-signing" { capabilities = ["update"] }
