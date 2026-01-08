path "transit/permesi/encrypt/users" { capabilities = ["update"] }
path "transit/permesi/decrypt/users" { capabilities = ["update"] }
path "transit/permesi/keys/users"    { capabilities = ["read"] }

path "kv/data/permesi/opaque" { capabilities = ["read"] }

path "database/creds/permesi" { capabilities = ["read"] }

path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/leases/renew"      { capabilities = ["update"] }