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
Admission PASERK keyset can be provided via a local file/string or fetched from a URL.
Admission tokens use RFC3339 `iat` / `exp` claims.

Local dev note: when running the workspace frontend (Trunk on `:8080`), use `--port 8001` and point the PASERK URL at `genesis` on `:8000` to avoid collisions.

AppRole CLI example (direct secret_id):

```sh
cargo run -p permesi --bin permesi -- \
  --port 8001 \
  --dsn "postgres://postgres@localhost:5432/permesi" \
  --admission-paserk-url "http://localhost:8000/paserk.json" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$PERMESI_ROLE_ID" \
  --vault-secret-id "$PERMESI_SECRET_ID"
```

AppRole CLI example (wrapped token):

```sh
cargo run -p permesi --bin permesi -- \
  --port 8001 \
  --dsn "postgres://postgres@localhost:5432/permesi" \
  --admission-paserk-url "http://localhost:8000/paserk.json" \
  --vault-url "http://vault:8200/v1/auth/approle/login" \
  --vault-role-id "$PERMESI_ROLE_ID" \
  --vault-wrapped-token "$PERMESI_WRAPPED_TOKEN"
```

## Admission Token Verification

- `permesi` verifies Admission Tokens offline using the PASERK keyset (file/string/URL).
- There is no online revocation check today; `jti` is not looked up in a database.

## Missing / Planned

- Optional revocation mode (DB lookup or cached revocation list) for stricter enforcement.
