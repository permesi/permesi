set shell := ["zsh", "-uc"]

uid := `id -u`
gid := `id -g`
root := justfile_directory()
net := "permesi-net"
subnet := "172.31.20.0/24"

branch := if `git rev-parse --abbrev-ref HEAD` == "main" { "latest" } else { `git rev-parse --abbrev-ref HEAD` }

default: fmt clippy test
  @just --list

setup-network:
  podman network inspect {{net}} >/dev/null 2>&1 || podman network create --subnet {{subnet}} {{net}}

fmt:
  cargo fmt --all -- --check

clippy:
  cargo clippy --all-targets --all-features

test:
  cargo test --workspace

coverage:
  cargo llvm-cov --all-features --workspace

build:
  cargo build --workspace

build-permesi:
  cargo build -p permesi

build-genesis:
  cargo build -p genesis

web:
  #!/usr/bin/env zsh
  set -euo pipefail
  just web-clean
  mkdir -p {{root}}/.tmp/xdg-cache
  cd {{root}}/apps/web
  npm run css:watch &
  css_pid=$!
  cleanup() {
    if kill -0 "$css_pid" >/dev/null 2>&1; then
      kill "$css_pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup EXIT INT TERM
  : "${PERMESI_API_HOST:=http://localhost:8001}"
  : "${PERMESI_TOKEN_HOST:=http://localhost:8000}"
  : "${PERMESI_API_TOKEN_HOST:=${PERMESI_TOKEN_HOST}}"
  : "${PERMESI_CLIENT_ID:=00000000-0000-0000-0000-000000000000}"
  XDG_CACHE_HOME="{{root}}/.tmp/xdg-cache" \
    PERMESI_API_HOST="${PERMESI_API_HOST}" \
    PERMESI_TOKEN_HOST="${PERMESI_TOKEN_HOST}" \
    PERMESI_API_TOKEN_HOST="${PERMESI_API_TOKEN_HOST}" \
    PERMESI_CLIENT_ID="${PERMESI_CLIENT_ID}" \
    trunk serve

web-build:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v trunk >/dev/null 2>&1; then
    just web-setup
  fi
  just web-node-setup
  mkdir -p {{root}}/.tmp/xdg-cache
  cd {{root}}/apps/web
  npm run css:build
  : "${PERMESI_API_HOST:=http://localhost:8001}"
  : "${PERMESI_TOKEN_HOST:=http://localhost:8000}"
  : "${PERMESI_API_TOKEN_HOST:=${PERMESI_TOKEN_HOST}}"
  : "${PERMESI_CLIENT_ID:=00000000-0000-0000-0000-000000000000}"
  XDG_CACHE_HOME="{{root}}/.tmp/xdg-cache" \
    PERMESI_API_HOST="${PERMESI_API_HOST}" \
    PERMESI_TOKEN_HOST="${PERMESI_TOKEN_HOST}" \
    PERMESI_API_TOKEN_HOST="${PERMESI_API_TOKEN_HOST}" \
    PERMESI_CLIENT_ID="${PERMESI_CLIENT_ID}" \
    trunk build --release

web-clean:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v trunk >/dev/null 2>&1; then
    just web-setup
  fi
  just web-node-setup
  mkdir -p {{root}}/.tmp/xdg-cache
  cd {{root}}/apps/web
  XDG_CACHE_HOME="{{root}}/.tmp/xdg-cache" trunk clean --dist dist
  npm run css:build
  if [[ ! -s assets/app.gen.css ]]; then
    echo "Missing generated CSS: apps/web/assets/app.gen.css" >&2
    exit 1
  fi

web-check:
  cargo check -p permesi_web

web-setup:
  #!/usr/bin/env zsh
  set -euo pipefail
  mkdir -p {{root}}/.tmp
  rustup target add wasm32-unknown-unknown
  if ! command -v trunk >/dev/null 2>&1; then
    cargo install --locked trunk
  fi

web-node-setup:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v node >/dev/null 2>&1; then
    echo "Install Node.js to build Tailwind assets." >&2
    exit 1
  fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "Install npm to build Tailwind assets." >&2
    exit 1
  fi
  cd {{root}}/apps/web
  if [[ -f package-lock.json ]]; then
    npm ci
  else
    npm install
  fi

web-css-watch:
  #!/usr/bin/env zsh
  set -euo pipefail
  just web-node-setup
  cd {{root}}/apps/web
  npm run css:build
  npm run css:watch

web-css-build:
  #!/usr/bin/env zsh
  set -euo pipefail
  just web-node-setup
  cd {{root}}/apps/web
  npm run css:build

genesis:
  cargo watch -x 'run -p genesis --bin genesis -- --port 8000 -vvv'

permesi:
  cargo watch -x 'run -p permesi --bin permesi -- --port 8001 -vvv'

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
# API helpers
# ----------------------

genesis-token:
  #!/usr/bin/env zsh
  set -euo pipefail
  token="$(
    xh '0:8000/token?client_id=00000000-0000-0000-0000-000000000000' \
      | jq -er '.token'
  )"
  python3 - "$token" <<'PY'
  import base64
  import json
  import sys

  token = sys.argv[1] if len(sys.argv) > 1 else ""
  if not token:
      raise SystemExit("missing token")

  parts = token.split(".")
  if len(parts) < 3 or parts[0] != "v4" or parts[1] != "public":
      raise SystemExit("unexpected token format")

  def b64url_decode(value: str) -> bytes:
      padding = "=" * (-len(value) % 4)
      return base64.urlsafe_b64decode(value + padding)

  body = b64url_decode(parts[2])
  if len(body) < 64:
      raise SystemExit("token body too short")

  payload = body[:-64]
  claims = json.loads(payload)

  output = {"claims": claims, "token": token}

  if len(parts) > 3:
      footer = json.loads(b64url_decode(parts[3]))
      output["footer"] = footer

  print(json.dumps(output, indent=2, sort_keys=True))
  PY

genesis-it: dev-start-infra
  #!/usr/bin/env zsh
  set -euo pipefail
  needs_env() {
    [[ -z "${GENESIS_TEST_DSN:-}" && -z "${GENESIS_DSN:-}" ]] \
      || [[ -z "${GENESIS_TEST_VAULT_URL:-}" && -z "${GENESIS_VAULT_URL:-}" ]] \
      || [[ -z "${GENESIS_TEST_VAULT_ROLE_ID:-}" && -z "${GENESIS_VAULT_ROLE_ID:-}" ]] \
      || [[ -z "${GENESIS_TEST_VAULT_SECRET_ID:-}" && -z "${GENESIS_VAULT_SECRET_ID:-}" ]]
  }
  # Wait for Vault to emit env vars, then source the .envrc for this shell.
  for _ in {1..20}; do
    if ! needs_env; then
      break
    fi
    just --quiet vault-envrc || true
    if [[ -f .envrc ]]; then
      source .envrc
    fi
    sleep 0.5
  done
  if [[ -z "${GENESIS_TEST_DSN:-}" && -z "${GENESIS_DSN:-}" ]]; then
    echo "Set GENESIS_TEST_DSN or GENESIS_DSN to run integration tests." >&2
    exit 1
  fi
  if [[ -z "${GENESIS_TEST_VAULT_URL:-}" && -z "${GENESIS_VAULT_URL:-}" ]]; then
    echo "Set GENESIS_TEST_VAULT_URL or GENESIS_VAULT_URL to run integration tests." >&2
    exit 1
  fi
  if [[ -z "${GENESIS_TEST_VAULT_ROLE_ID:-}" && -z "${GENESIS_VAULT_ROLE_ID:-}" ]]; then
    echo "Set GENESIS_TEST_VAULT_ROLE_ID or GENESIS_VAULT_ROLE_ID to run integration tests." >&2
    exit 1
  fi
  if [[ -z "${GENESIS_TEST_VAULT_SECRET_ID:-}" && -z "${GENESIS_VAULT_SECRET_ID:-}" ]]; then
    echo "Set GENESIS_TEST_VAULT_SECRET_ID or GENESIS_VAULT_SECRET_ID to run integration tests." >&2
    exit 1
  fi
  cargo test -p genesis --test integration_token -- --ignored

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
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^vault$')" ]]; then
    echo "vault already running"
    exit 0
  fi
  podman run --replace --rm --name vault \
    --network {{net}} \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
    -e VAULT_LISTEN_ADDRESS=0.0.0.0:8200 \
    permesi-vault:{{ branch }} &

vault-env:
  #!/usr/bin/env zsh
  set -e
  login_url=""
  permesi_role_id=""
  permesi_secret_id=""
  genesis_role_id=""
  genesis_secret_id=""
  for _ in {1..20}; do
    logs="$(podman logs vault 2>/dev/null || true)"
    login_url="$(printf '%s\n' "$logs" | rg "Login URL:" | tail -n 1 | sed -E 's/.*Login URL:[[:space:]]*//')"
    permesi_role_id="$(printf '%s\n' "$logs" | rg "permesi RoleID:" | tail -n 1 | sed -E 's/.*permesi RoleID:[[:space:]]*//')"
    permesi_secret_id="$(printf '%s\n' "$logs" | rg "permesi SecretID:" | tail -n 1 | sed -E 's/.*permesi SecretID:[[:space:]]*//')"
    genesis_role_id="$(printf '%s\n' "$logs" | rg "genesis RoleID:" | tail -n 1 | sed -E 's/.*genesis RoleID:[[:space:]]*//')"
    genesis_secret_id="$(printf '%s\n' "$logs" | rg "genesis SecretID:" | tail -n 1 | sed -E 's/.*genesis SecretID:[[:space:]]*//')"
    if [[ -n "$login_url" && -n "$permesi_role_id" && -n "$permesi_secret_id" && -n "$genesis_role_id" && -n "$genesis_secret_id" ]]; then
      break
    fi
    sleep 0.5
  done

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
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet vault-env > "$tmp"
  mv "$tmp" .envrc
  echo "Wrote .envrc from Vault logs."

vault_stop:
  podman stop vault || true

postgres version="18":
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^postgres-permesi$')" ]]; then
    echo "postgres-permesi already running"
    exit 0
  fi
  mkdir -p db/log/postgres
  podman run --replace --rm -d --name postgres-permesi \
      --network {{net}} \
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
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^jaeger$')" ]]; then
    echo "jaeger already running"
    exit 0
  fi
  podman run --replace --rm --name jaeger \
    --network {{net}} \
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
  jaegertracing/jaeger:latest &

jaeger_stop:
  podman stop jaeger || true

dev-start: dev-start-infra web

dev-start-infra: setup-network postgres vault jaeger

dev-stop: vault_stop postgres_stop jaeger_stop

podman-check:
  #!/usr/bin/env zsh
  set -euo pipefail
  socket="/run/user/$(id -u)/podman/podman.sock"
  socket_url="unix://${socket}"
  echo "Checking podman socket at: ${socket}"
  if [[ ! -S "$socket" ]]; then
    echo "Socket not found. Start it with: systemctl --user start podman.socket" >&2
    exit 1
  fi
  if ! podman --url "$socket_url" info >/dev/null 2>&1 \
    && ! podman --remote info >/dev/null 2>&1; then
    echo "podman remote API is not reachable. Common fix:" >&2
    echo "  sudo chown -R $USER:$USER /run/user/$(id -u)/libpod" >&2
    echo "  sudo rm -f /run/user/$(id -u)/libpod/tmp/alive.lck" >&2
    echo "  systemctl --user restart podman.socket" >&2
    exit 1
  fi
  echo "podman remote API is reachable."
