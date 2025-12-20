# permesi

Core IAM/OIDC authority.

## Vault requirement

Vault is required in production for AppRole auth, dynamic DB creds, and transit encryption. Running without Vault is not supported.
See the canonical checklist in `../../README.md#vault-dependency` and the Vault ops notes in `../../vault/README.md`.
TL;DR:
- Run Vault in HA with tested failover.
- Use auto-unseal or keep a documented unseal runbook.
- Alert on health, sealed state, and token/lease renew failures.

## CLI example

`--vault-url` must point to the AppRole login endpoint.
The DSN can omit username/password because Vault injects DB creds (e.g. `postgres://postgres@localhost:5432/permesi`).

AppRole CLI example (direct secret_id):

```sh
cargo run -p permesi --bin permesi -- \
  --port 8080 \
  --dsn "postgres://postgres@localhost:5432/permesi" \
  --admission-jwks-path "./jwks.json" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$PERMESI_ROLE_ID" \
  --vault-secret-id "$PERMESI_SECRET_ID"
```

AppRole CLI example (wrapped token):

```sh
cargo run -p permesi --bin permesi -- \
  --port 8080 \
  --dsn "postgres://postgres@localhost:5432/permesi" \
  --admission-jwks-path "./jwks.json" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$PERMESI_ROLE_ID" \
  --vault-wrapped-token "$PERMESI_WRAPPED_TOKEN"
```
