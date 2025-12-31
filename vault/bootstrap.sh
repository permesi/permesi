#!/bin/sh
set -eu

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_DEV_ROOT_TOKEN_ID="${VAULT_DEV_ROOT_TOKEN_ID:-dev-root}"
VAULT_LISTEN_ADDRESS="${VAULT_LISTEN_ADDRESS:-0.0.0.0:8200}"
VAULT_APPROLE_MOUNT="${VAULT_APPROLE_MOUNT:-approle}"
VAULT_TRANSIT_MOUNT="${VAULT_TRANSIT_MOUNT:-transit/permesi}"
VAULT_TRANSIT_KEY="${VAULT_TRANSIT_KEY:-users}"
VAULT_GENESIS_TRANSIT_MOUNT="${VAULT_GENESIS_TRANSIT_MOUNT:-transit/genesis}"
VAULT_GENESIS_TRANSIT_KEY="${VAULT_GENESIS_TRANSIT_KEY:-genesis-signing}"
VAULT_TRANSIT_AUTO_ROTATE_PERIOD="${VAULT_TRANSIT_AUTO_ROTATE_PERIOD:-30d}"
VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-kv}"
VAULT_OPAQUE_SECRET_PATH="${VAULT_OPAQUE_SECRET_PATH:-permesi/opaque}"
VAULT_OPAQUE_SEED_B64="${VAULT_OPAQUE_SEED_B64:-}"
VAULT_DATABASE_MOUNT="${VAULT_DATABASE_MOUNT:-database}"
VAULT_POSTGRES_HOST="${VAULT_POSTGRES_HOST:-host.containers.internal}"
VAULT_POSTGRES_PORT="${VAULT_POSTGRES_PORT:-5432}"
VAULT_POSTGRES_USERNAME="${VAULT_POSTGRES_USERNAME:-postgres}"
VAULT_POSTGRES_PASSWORD="${VAULT_POSTGRES_PASSWORD:-postgres}"
VAULT_POSTGRES_DATABASE_GENESIS="${VAULT_POSTGRES_DATABASE_GENESIS:-genesis}"
VAULT_POSTGRES_DATABASE_PERMESI="${VAULT_POSTGRES_DATABASE_PERMESI:-permesi}"
VAULT_POSTGRES_SSLMODE="${VAULT_POSTGRES_SSLMODE:-disable}"
VAULT_POSTGRES_REASSIGN_OWNER="${VAULT_POSTGRES_REASSIGN_OWNER:-postgres}"

vault server -dev \
    -dev-root-token-id="$VAULT_DEV_ROOT_TOKEN_ID" \
    -dev-listen-address="$VAULT_LISTEN_ADDRESS" &
VAULT_PID=$!

echo "Waiting for Vault to start at ${VAULT_ADDR}..."
until vault status >/dev/null 2>&1; do
    sleep 0.2
done
echo "Vault is up."

vault login "$VAULT_DEV_ROOT_TOKEN_ID" >/dev/null

# Transit engine + key used by permesi (see `services/permesi/src/vault/transit.rs`).
vault secrets enable -path="$VAULT_TRANSIT_MOUNT" transit >/dev/null 2>&1 || true
vault write "${VAULT_TRANSIT_MOUNT}/keys/${VAULT_TRANSIT_KEY}" \
    type=chacha20-poly1305 >/dev/null
vault write "${VAULT_TRANSIT_MOUNT}/keys/${VAULT_TRANSIT_KEY}/config" \
    auto_rotate_period="$VAULT_TRANSIT_AUTO_ROTATE_PERIOD" >/dev/null

# Transit engine + key used by genesis admission signing (Ed25519).
vault secrets enable -path="$VAULT_GENESIS_TRANSIT_MOUNT" transit >/dev/null 2>&1 || true
vault write "${VAULT_GENESIS_TRANSIT_MOUNT}/keys/${VAULT_GENESIS_TRANSIT_KEY}" \
    type=ed25519 >/dev/null
vault write "${VAULT_GENESIS_TRANSIT_MOUNT}/keys/${VAULT_GENESIS_TRANSIT_KEY}/config" \
    auto_rotate_period="$VAULT_TRANSIT_AUTO_ROTATE_PERIOD" >/dev/null

# AppRole auth for both services (mounted at `auth/<mount>/`).
vault auth enable -path="$VAULT_APPROLE_MOUNT" approle >/dev/null 2>&1 || true

# KV v2 for OPAQUE server setup (seed-based).
vault secrets enable -path="$VAULT_KV_MOUNT" kv-v2 >/dev/null 2>&1 || true
if [ -z "$VAULT_OPAQUE_SEED_B64" ]; then
    VAULT_OPAQUE_SEED_B64=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
fi
vault kv put "${VAULT_KV_MOUNT}/${VAULT_OPAQUE_SECRET_PATH}" \
    opaque_seed_b64="$VAULT_OPAQUE_SEED_B64" >/dev/null

# Database secrets engine (Postgres) for local dev.
#
# Both services request dynamic credentials from:
# - permesi: `GET /v1/${VAULT_DATABASE_MOUNT}/creds/permesi`
# - genesis: `GET /v1/${VAULT_DATABASE_MOUNT}/creds/genesis`
#
# This expects a Postgres instance reachable from inside the Vault container (see `.justfile` `postgres` recipe).
vault secrets enable -path="$VAULT_DATABASE_MOUNT" database >/dev/null 2>&1 || true

DB_BOOTSTRAPPED=0
DB_CONFIG_NAME_GENESIS=genesis
DB_CONFIG_NAME_PERMESI=permesi
DB_CONNECTION_URL_GENESIS="postgresql://{{username}}:{{password}}@${VAULT_POSTGRES_HOST}:${VAULT_POSTGRES_PORT}/${VAULT_POSTGRES_DATABASE_GENESIS}?sslmode=${VAULT_POSTGRES_SSLMODE}"
DB_CONNECTION_URL_PERMESI="postgresql://{{username}}:{{password}}@${VAULT_POSTGRES_HOST}:${VAULT_POSTGRES_PORT}/${VAULT_POSTGRES_DATABASE_PERMESI}?sslmode=${VAULT_POSTGRES_SSLMODE}"

echo "Configuring database secrets engine (${VAULT_DATABASE_MOUNT}) for Postgres at ${VAULT_POSTGRES_HOST}:${VAULT_POSTGRES_PORT} (sslmode=${VAULT_POSTGRES_SSLMODE})..."
i=0
while :; do
    GENESIS_READY=0
    PERMESI_READY=0

    if vault write "${VAULT_DATABASE_MOUNT}/config/${DB_CONFIG_NAME_GENESIS}" \
        plugin_name=postgresql-database-plugin \
        allowed_roles=genesis \
        connection_url="$DB_CONNECTION_URL_GENESIS" \
        username="$VAULT_POSTGRES_USERNAME" \
        password="$VAULT_POSTGRES_PASSWORD" \
        max_connection_lifetime=120 >/dev/null 2>&1; then
        GENESIS_READY=1
    fi

    if vault write "${VAULT_DATABASE_MOUNT}/config/${DB_CONFIG_NAME_PERMESI}" \
        plugin_name=postgresql-database-plugin \
        allowed_roles=permesi \
        connection_url="$DB_CONNECTION_URL_PERMESI" \
        username="$VAULT_POSTGRES_USERNAME" \
        password="$VAULT_POSTGRES_PASSWORD" \
        max_connection_lifetime=120 >/dev/null 2>&1; then
        PERMESI_READY=1
    fi

    if [ "$GENESIS_READY" -eq 1 ] && [ "$PERMESI_READY" -eq 1 ]; then
        DB_BOOTSTRAPPED=1
        break
    fi

    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        echo "WARN: Could not configure database secrets engine; Postgres may not be ready/reachable yet (or databases are missing)."
        break
    fi
    sleep 1
done

if [ "$DB_BOOTSTRAPPED" -eq 1 ]; then
    if ! vault write "${VAULT_DATABASE_MOUNT}/roles/permesi" \
        db_name="$DB_CONFIG_NAME_PERMESI" \
        default_ttl=1h \
        max_ttl=4h \
        creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
        creation_statements="GRANT ALL PRIVILEGES ON DATABASE \"${VAULT_POSTGRES_DATABASE_PERMESI}\" TO \"{{name}}\";" \
        creation_statements="GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
        creation_statements="GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";" \
        renew_statements="ALTER ROLE \"{{name}}\" WITH VALID UNTIL '{{expiration}}';" \
        revocation_statements="SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';" \
        revocation_statements="REVOKE ALL PRIVILEGES ON DATABASE \"${VAULT_POSTGRES_DATABASE_PERMESI}\" FROM \"{{name}}\";" \
        revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";" \
        revocation_statements="REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\";" \
        revocation_statements="REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM \"{{name}}\";" \
        revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO \"${VAULT_POSTGRES_REASSIGN_OWNER}\";" \
        revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
        revocation_statements="DROP USER IF EXISTS \"{{name}}\";" >/dev/null; then
        echo "WARN: Could not create database role ${VAULT_DATABASE_MOUNT}/roles/permesi."
    fi

    if ! vault write "${VAULT_DATABASE_MOUNT}/roles/genesis" \
        db_name="$DB_CONFIG_NAME_GENESIS" \
        default_ttl=1h \
        max_ttl=4h \
        creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
        creation_statements="GRANT ALL PRIVILEGES ON DATABASE \"${VAULT_POSTGRES_DATABASE_GENESIS}\" TO \"{{name}}\";" \
        creation_statements="GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
        creation_statements="GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";" \
        renew_statements="ALTER ROLE \"{{name}}\" WITH VALID UNTIL '{{expiration}}';" \
        revocation_statements="SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';" \
        revocation_statements="REVOKE ALL PRIVILEGES ON DATABASE \"${VAULT_POSTGRES_DATABASE_GENESIS}\" FROM \"{{name}}\";" \
        revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";" \
        revocation_statements="REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\";" \
        revocation_statements="REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM \"{{name}}\";" \
        revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO \"${VAULT_POSTGRES_REASSIGN_OWNER}\";" \
        revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
        revocation_statements="DROP USER IF EXISTS \"{{name}}\";" >/dev/null; then
        echo "WARN: Could not create database role ${VAULT_DATABASE_MOUNT}/roles/genesis."
    fi
fi

# Minimal policies for dev that match how the services talk to Vault.
vault policy write permesi - <<EOF
path "${VAULT_TRANSIT_MOUNT}/encrypt/${VAULT_TRANSIT_KEY}" { capabilities = ["update"] }
path "${VAULT_TRANSIT_MOUNT}/decrypt/${VAULT_TRANSIT_KEY}" { capabilities = ["update"] }
path "${VAULT_TRANSIT_MOUNT}/keys/${VAULT_TRANSIT_KEY}"    { capabilities = ["read"] }

path "${VAULT_KV_MOUNT}/data/${VAULT_OPAQUE_SECRET_PATH}" { capabilities = ["read"] }

path "${VAULT_DATABASE_MOUNT}/creds/permesi" { capabilities = ["read"] }

path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/leases/renew"      { capabilities = ["update"] }
EOF

vault policy write genesis - <<EOF
path "${VAULT_DATABASE_MOUNT}/creds/genesis" { capabilities = ["read"] }
path "${VAULT_GENESIS_TRANSIT_MOUNT}/sign/${VAULT_GENESIS_TRANSIT_KEY}" { capabilities = ["update"] }
path "${VAULT_GENESIS_TRANSIT_MOUNT}/keys/${VAULT_GENESIS_TRANSIT_KEY}" { capabilities = ["read"] }

path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/leases/renew"      { capabilities = ["update"] }
EOF

vault write "auth/${VAULT_APPROLE_MOUNT}/role/permesi" token_policies=permesi token_ttl=1h token_max_ttl=4h >/dev/null
vault write "auth/${VAULT_APPROLE_MOUNT}/role/genesis" token_policies=genesis token_ttl=1h token_max_ttl=4h >/dev/null

PERMESI_ROLE_ID=$(vault read -field=role_id "auth/${VAULT_APPROLE_MOUNT}/role/permesi/role-id")
PERMESI_SECRET_ID=$(vault write -field=secret_id -f "auth/${VAULT_APPROLE_MOUNT}/role/permesi/secret-id")
GENESIS_ROLE_ID=$(vault read -field=role_id "auth/${VAULT_APPROLE_MOUNT}/role/genesis/role-id")
GENESIS_SECRET_ID=$(vault write -field=secret_id -f "auth/${VAULT_APPROLE_MOUNT}/role/genesis/secret-id")

cat <<EOF
Vault dev server ready on ${VAULT_LISTEN_ADDRESS}
Root token: ${VAULT_DEV_ROOT_TOKEN_ID}

AppRole mount: ${VAULT_APPROLE_MOUNT}
Login URL: ${VAULT_ADDR%/}/v1/auth/${VAULT_APPROLE_MOUNT}/login

Database mount: ${VAULT_DATABASE_MOUNT}
OPAQUE KV mount: ${VAULT_KV_MOUNT}
OPAQUE secret path: ${VAULT_OPAQUE_SECRET_PATH}

permesi RoleID:  ${PERMESI_ROLE_ID}
permesi SecretID: ${PERMESI_SECRET_ID}

genesis RoleID:  ${GENESIS_ROLE_ID}
genesis SecretID: ${GENESIS_SECRET_ID}

Example login:
  vault write auth/${VAULT_APPROLE_MOUNT}/login role_id=${PERMESI_ROLE_ID} secret_id=${PERMESI_SECRET_ID}
EOF

wait "$VAULT_PID"
