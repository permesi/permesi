set shell := ["zsh", "-uc"]

uid := `id -u`
gid := `id -g`
root := justfile_directory()

branch := if `git rev-parse --abbrev-ref HEAD` == "main" { "latest" } else { `git rev-parse --abbrev-ref HEAD` }

default: fmt clippy test
  @just --list

# ----------------------
# Rust workspace commands
# ----------------------

fmt:
  cargo fmt --all -- --check

clippy:
  cargo clippy --all-targets --all-features

test:
  cargo test --workspace

build:
  cargo build --workspace

build-permesi:
  cargo build -p permesi

build-genesis:
  cargo build -p genesis

# ----------------------
# OpenAPI spec generation
# ----------------------

openapi:
  just openapi-permesi
  just openapi-genesis

openapi-permesi:
  mkdir -p docs/openapi
  cargo run -p permesi --bin openapi > docs/openapi/permesi.json

openapi-genesis:
  mkdir -p docs/openapi
  cargo run -p genesis --bin openapi > docs/openapi/genesis.json

# ----------------------
# Container images (podman)
# ----------------------

image-permesi:
  podman build -f services/permesi/Dockerfile -t permesi:{{ branch }} .

image-genesis:
  podman build -f services/genesis/Dockerfile -t genesis:{{ branch }} .

images: image-permesi image-genesis

# ----------------------
# Local dependencies
# ----------------------

image-vault:
  podman build -f vault.Dockerfile -t permesi-vault:{{ branch }} .

vault: image-vault
  podman run --replace --rm --name vault \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
  -e VAULT_LISTEN_ADDRESS=0.0.0.0:8200 \
  permesi-vault:{{ branch }} &

vault-env:
  #!/usr/bin/env zsh
  set -e
  logs="$(podman logs vault)"
  login_url="$(printf '%s\n' "$logs" | rg "Login URL:" | tail -n 1 | sed -E 's/.*Login URL:[[:space:]]*//')"
  permesi_role_id="$(printf '%s\n' "$logs" | rg "permesi RoleID:" | tail -n 1 | sed -E 's/.*permesi RoleID:[[:space:]]*//')"
  permesi_secret_id="$(printf '%s\n' "$logs" | rg "permesi SecretID:" | tail -n 1 | sed -E 's/.*permesi SecretID:[[:space:]]*//')"
  genesis_role_id="$(printf '%s\n' "$logs" | rg "genesis RoleID:" | tail -n 1 | sed -E 's/.*genesis RoleID:[[:space:]]*//')"
  genesis_secret_id="$(printf '%s\n' "$logs" | rg "genesis SecretID:" | tail -n 1 | sed -E 's/.*genesis SecretID:[[:space:]]*//')"

  if [[ -z "$login_url" || -z "$permesi_role_id" || -z "$permesi_secret_id" || -z "$genesis_role_id" || -z "$genesis_secret_id" ]]; then
    echo "Missing values in vault logs. Run: just vault" >&2
    exit 1
  fi

  vault_addr="${login_url%/v1/auth/*}"

  printf '%s\n' \
    "export VAULT_ADDR=\"${vault_addr}\"" \
    "export VAULT_TOKEN=\"dev-root\"" \
    "" \
    "export GENESIS_DSN=\"postgres://postgres@localhost:5432/genesis\"" \
    "export GENESIS_VAULT_URL=\"${login_url}\"" \
    "export GENESIS_VAULT_ROLE_ID=\"${genesis_role_id}\"" \
    "export GENESIS_VAULT_SECRET_ID=\"${genesis_secret_id}\"" \
    "" \
    "export PERMESI_DSN=\"postgres://postgres@localhost:5432/permesi\"" \
    "export PERMESI_VAULT_URL=\"${login_url}\"" \
    "export PERMESI_VAULT_ROLE_ID=\"${permesi_role_id}\"" \
    "export PERMESI_VAULT_SECRET_ID=\"${permesi_secret_id}\""

vault-envrc:
  #!/usr/bin/env zsh
  set -e
  just --quiet vault-env > .envrc
  echo "Wrote .envrc from Vault logs."

vault_stop:
  podman stop vault || true

postgres version="latest":
  mkdir -p db/log/postgres
  podman run --replace --rm -d --name postgres-permesi \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e PGDATA=/db/data/{{ version }} \
    -p 5432:5432 \
    -v {{root}}/db:/db \
    -v {{root}}/db/config/postgres:/etc/postgresql/config \
    -v {{root}}/db/sql/00_init.sql:/docker-entrypoint-initdb.d/00_init.sql:ro \
    --userns keep-id:uid={{ uid }},gid={{ gid }} \
    --user {{ uid }}:{{ gid }} \
    postgres:{{ version }} \
    postgres -c config_file=/etc/postgresql/config/postgresql.conf
  until podman exec postgres-permesi pg_isready -U postgres > /dev/null 2>&1; do sleep 0.2; done
  podman exec -i postgres-permesi psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/00_init.sql

postgres_stop:
  podman stop postgres-permesi || true

jaeger:
  podman run --replace --rm --name jaeger \
  -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
  -p 6831:6831/udp \
  -p 6832:6832/udp \
  -p 5778:5778 \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  -p 14250:14250 \
  -p 14268:14268 \
  -p 14269:14269 \
  -p 9411:9411 \
  jaegertracing/all-in-one:latest &

jaeger_stop:
  podman stop jaeger || true

otel:
  podman run --replace --rm --name otel-collector \
  -p 4317:4317 \
  -p 4318:4318 \
  -p 8888:8888 \
  -v $PWD/.otel-collector-config.yml:/etc/otelcol-contrib/config.yaml \
  otel/opentelemetry-collector-contrib:latest &

otel_stop:
  podman stop otel-collector || true

dev-start: postgres vault jaeger otel

dev-stop: vault_stop postgres_stop jaeger_stop otel_stop
