# users
path "transit/permesi/encrypt/users" { capabilities = ["update"] }
path "transit/permesi/decrypt/users" { capabilities = ["update"] }
path "transit/permesi/keys/users"    { capabilities = ["read"] }

# totp
path "transit/permesi/encrypt/totp" { capabilities = ["update"] }
path "transit/permesi/decrypt/totp" { capabilities = ["update"] }
path "transit/permesi/keys/totp"    { capabilities = ["read"] }

# Generate a new DEK (plaintext + wrapped). Needed for initial DEK and rotations.
path "transit/permesi/datakey/plaintext/totp" { capabilities = ["update"] }

path "secret/permesi/data/config" { capabilities = ["read"] }

path "database/creds/permesi" { capabilities = ["read"] }

path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/leases/renew"      { capabilities = ["update"] }
