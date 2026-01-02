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

# ----------------------
# Version bumping
# ----------------------

check-clean:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "Working directory is not clean. Commit or stash your changes first." >&2
    git status --short
    exit 1
  fi

check-develop:
  #!/usr/bin/env zsh
  set -euo pipefail
  current_branch="$(git branch --show-current)"
  if [[ "$current_branch" != "develop" ]]; then
    echo "Not on develop branch (currently on: ${current_branch})." >&2
    echo "Switch to develop before bumping." >&2
    exit 1
  fi

_bump-workspace bump_kind: check-develop check-clean
  #!/usr/bin/env zsh
  set -euo pipefail
  bump_kind="{{bump_kind}}"
  base_ref_default="origin/main"
  if ! git rev-parse --verify "$base_ref_default" >/dev/null 2>&1; then
    base_ref_default="main"
  fi
  base_ref="${BUMP_BASE_REF:-$base_ref_default}"
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for version bumping." >&2
    exit 1
  fi
  if ! cargo set-version -h >/dev/null 2>&1; then
    echo "cargo set-version not found; install cargo-edit (cargo install cargo-edit)." >&2
    exit 1
  fi
  base_commit="$(git merge-base "$base_ref" HEAD)"
  changed="$(git diff --name-only "$base_commit"..HEAD | sort -u)"
  if [[ -z "$changed" ]]; then
    echo "No changes detected."
    exit 0
  fi
  current_version="$(
    cargo metadata --no-deps --format-version 1 \
      | jq -r '.packages[] | select(.name == "permesi") | .version' \
      | head -n 1
  )"
  if [[ -z "$current_version" || "$current_version" == "null" ]]; then
    echo "Failed to resolve current workspace version." >&2
    exit 1
  fi
  echo "Current version: ${current_version}"
  cargo update
  just test
  cargo set-version --workspace --bump "$bump_kind"
  new_version="$(
    cargo metadata --no-deps --format-version 1 \
      | jq -r '.packages[] | select(.name == "permesi") | .version' \
      | head -n 1
  )"
  if [[ -z "$new_version" || "$new_version" == "null" ]]; then
    echo "Failed to resolve new workspace version." >&2
    exit 1
  fi
  echo "New version: ${new_version}"
  git fetch --tags --quiet
  if git rev-parse -q --verify "refs/tags/${new_version}" >/dev/null 2>&1; then
    echo "Tag ${new_version} already exists." >&2
    exit 1
  fi
  git add -A
  git commit -m "chore(release): bump version to ${new_version}"
  git push origin develop

_deploy-merge-and-tag:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for tagging." >&2
    exit 1
  fi
  new_version="$(
    cargo metadata --no-deps --format-version 1 \
      | jq -r '.packages[] | select(.name == "permesi") | .version' \
      | head -n 1
  )"
  if [[ -z "$new_version" || "$new_version" == "null" ]]; then
    echo "Failed to resolve workspace version." >&2
    exit 1
  fi
  git fetch --tags --quiet
  if git rev-parse -q --verify "refs/tags/${new_version}" >/dev/null 2>&1; then
    echo "Tag ${new_version} already exists." >&2
    exit 1
  fi
  git pull origin develop
  git checkout main
  git pull origin main
  if ! git merge develop --no-edit; then
    echo "Merge failed; resolve conflicts manually." >&2
    git checkout develop
    exit 1
  fi
  git tag "$new_version"
  git push origin main "$new_version"
  git checkout develop

deploy:
  @just _bump-workspace patch
  @just _deploy-merge-and-tag

deploy-minor:
  @just _bump-workspace minor
  @just _deploy-merge-and-tag

deploy-major:
  @just _bump-workspace major
  @just _deploy-merge-and-tag

deploy-current: check-develop check-clean
  #!/usr/bin/env zsh
  set -euo pipefail
  just test
  just _deploy-merge-and-tag

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
  if [[ ! -s assets/app.gen.css ]]; then
    echo "Missing generated CSS: apps/web/assets/app.gen.css" >&2
    exit 1
  fi

web-clean:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v trunk >/dev/null 2>&1; then
    just web-setup
  fi
  just web-node-setup
  rm -rf {{root}}/.tmp/xdg-cache
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

firefox-dev:
  #!/usr/bin/env zsh
  set -euo pipefail
  script="{{root}}/firefox-dev.sh"
  if [[ ! -x "$script" ]]; then
    echo "Missing executable: ${script}" >&2
    exit 1
  fi
  nohup "$script" >/tmp/firefox-dev.log 2>&1 &
  disown
  echo "Firefox dev launched (log: /tmp/firefox-dev.log)"

firefox:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v hyprctl >/dev/null 2>&1; then
    echo "hyprctl not found; run: just firefox-dev" >&2
    exit 1
  fi
  hyprctl dispatch exec "[workspace 2] bash -lc 'cd {{root}} && just firefox-dev'"

genesis:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  cargo watch -x 'run -p genesis --bin genesis -- --port 8000 -vvv'

permesi:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  if [[ -n "${PERMESI_ADMISSION_PASERK_URL:-}" ]]; then
  echo "Waiting for genesis PASERK at ${PERMESI_ADMISSION_PASERK_URL}..."
  python3 - "$PERMESI_ADMISSION_PASERK_URL" <<'PY'
  import json
  import sys
  import time
  import urllib.request

  url = sys.argv[1]
  deadline = time.time() + 30

  while time.time() < deadline:
      try:
          with urllib.request.urlopen(url, timeout=1) as resp:
              if resp.status != 200:
                  raise RuntimeError(f"status {resp.status}")
              json.loads(resp.read())
          raise SystemExit(0)
      except Exception:
          time.sleep(0.5)

  print(f"Timed out waiting for {url}", file=sys.stderr)
  raise SystemExit(1)
  PY
  fi
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

signup-verify-url:
  #!/usr/bin/env zsh
  set -euo pipefail
  podman exec -i postgres-permesi psql -U postgres -d permesi -Atc \
    "select payload_json->>'verify_url' from email_outbox order by created_at desc limit 1;"

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

vault-persist: image-vault
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^vault$')" ]]; then
    echo "vault already running"
    exit 0
  fi
  podman volume inspect permesi-vault-data >/dev/null 2>&1 || podman volume create permesi-vault-data >/dev/null
  podman run --replace --rm --name vault \
    --network {{net}} \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -v {{root}}/vault/config.hcl:/vault/config/vault.hcl:ro \
    -v {{root}}/vault:/workspace/vault:ro \
    -v permesi-vault-data:/vault/data \
    --entrypoint vault \
    permesi-vault:{{ branch }} \
    server -config=/vault/config/vault.hcl &

vault-wait:
  #!/usr/bin/env zsh
  set -euo pipefail
  for _ in {1..40}; do
    vault_status="$(
      podman exec vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json 2>/dev/null || true'
    )"
    if [[ -n "$vault_status" ]] && rg -q '"initialized":' <<<"$vault_status"; then
      exit 0
    fi
    sleep 0.5
  done
  echo "Vault did not respond on http://127.0.0.1:8200" >&2
  exit 1

vault-init:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/vault/keys.json"
  mkdir -p {{root}}/vault
  if [[ -f "$keys" ]]; then
    echo "Vault already initialized (keys file exists)."
    exit 0
  fi
  just vault-wait
  vault_status="$(
    podman exec vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json 2>/dev/null || true'
  )"
  if [[ -z "$vault_status" ]]; then
    echo "Vault status unavailable; is the server running?" >&2
    exit 1
  fi
  initialized="$(printf '%s' "$vault_status" | jq -r '.initialized')"
  if [[ "$initialized" == "true" ]]; then
    echo "Vault is already initialized but ${keys} is missing." >&2
    echo "Restore the keys file or reset the vault data volume." >&2
    exit 1
  fi
  podman exec vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault operator init -key-shares=1 -key-threshold=1 -format=json' > "$keys"
  chmod 600 "$keys"
  echo "Wrote ${keys}"

vault-unseal:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just vault-init" >&2
    exit 1
  fi
  just vault-wait
  vault_status="$(
    podman exec vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json 2>/dev/null || true'
  )"
  sealed="$(printf '%s' "$vault_status" | jq -r '.sealed')"
  if [[ "$sealed" != "true" ]]; then
    echo "Vault already unsealed."
    exit 0
  fi
  unseal_key="$(jq -r '.unseal_keys_b64[0]' "$keys")"
  podman exec vault sh -c "VAULT_ADDR=http://127.0.0.1:8200 vault operator unseal '${unseal_key}'" >/dev/null
  echo "Vault unsealed."

vault-bootstrap:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just vault-init" >&2
    exit 1
  fi
  token="$(jq -r '.root_token' "$keys")"
  podman exec \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e VAULT_TOKEN="$token" \
    vault \
    sh /workspace/vault/bootstrap-persist.sh

vault-persist-ready: vault-persist vault-init vault-unseal vault-bootstrap

vault-env:
  #!/usr/bin/env zsh
  set -e
  keys="{{root}}/vault/keys.json"
  if [[ -f "$keys" ]]; then
    vault_addr="${VAULT_ADDR:-http://127.0.0.1:8200}"
    approle_mount="${VAULT_APPROLE_MOUNT:-approle}"
    token="$(jq -r '.root_token' "$keys")"
    permesi_role_id="$(
      podman exec \
        -e VAULT_ADDR="$vault_addr" \
        -e VAULT_TOKEN="$token" \
        vault \
        vault read -field=role_id "auth/${approle_mount}/role/permesi/role-id"
    )"
    permesi_secret_id="$(
      podman exec \
        -e VAULT_ADDR="$vault_addr" \
        -e VAULT_TOKEN="$token" \
        vault \
        vault write -field=secret_id -f "auth/${approle_mount}/role/permesi/secret-id"
    )"
    genesis_role_id="$(
      podman exec \
        -e VAULT_ADDR="$vault_addr" \
        -e VAULT_TOKEN="$token" \
        vault \
        vault read -field=role_id "auth/${approle_mount}/role/genesis/role-id"
    )"
    genesis_secret_id="$(
      podman exec \
        -e VAULT_ADDR="$vault_addr" \
        -e VAULT_TOKEN="$token" \
        vault \
        vault write -field=secret_id -f "auth/${approle_mount}/role/genesis/secret-id"
    )"
    printf '%s\n' \
      "export VAULT_ADDR=\"${vault_addr}\"" \
      "export VAULT_TOKEN=\"${token}\"" \
      "" \
      "export GENESIS_DSN=\"postgres://postgres@localhost:5432/genesis\"" \
      "export GENESIS_VAULT_URL=\"${vault_addr%/}/v1/auth/${approle_mount}/login\"" \
      "export GENESIS_VAULT_ROLE_ID=\"${genesis_role_id}\"" \
      "export GENESIS_VAULT_SECRET_ID=\"${genesis_secret_id}\"" \
      "" \
      "export PERMESI_DSN=\"postgres://postgres@localhost:5432/permesi\"" \
      "export PERMESI_VAULT_URL=\"${vault_addr%/}/v1/auth/${approle_mount}/login\"" \
      "export PERMESI_VAULT_ROLE_ID=\"${permesi_role_id}\"" \
      "export PERMESI_VAULT_SECRET_ID=\"${permesi_secret_id}\""
    exit 0
  fi
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

dev-env:
  #!/usr/bin/env zsh
  set -euo pipefail
  just --quiet vault-env
  printf '\n'
  printf '%s\n' \
    "export PERMESI_ADMISSION_PASERK_URL=\"http://localhost:8000/paserk.json\"" \
    "export PERMESI_FRONTEND_BASE_URL=\"http://localhost:8080\"" \
    "export PERMESI_EMAIL_OUTBOX_POLL_SECONDS=\"10\""

vault-envrc:
  #!/usr/bin/env zsh
  set -e
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet vault-env > "$tmp"
  mv "$tmp" .envrc
  echo "Wrote .envrc from Vault logs."

vault-info:
  #!/usr/bin/env zsh
  set -euo pipefail
  echo "Vault container mounts:"
  if podman container inspect vault >/dev/null 2>&1; then
    podman container inspect vault \
      | jq -r '.[0].Mounts[]? | "\(.Name)\t\(.Destination)\t\(.Source)"'
  else
    echo "vault container not running."
  fi
  echo ""
  echo "Vault data volume:"
  if podman volume inspect permesi-vault-data >/dev/null 2>&1; then
    podman volume inspect permesi-vault-data \
      | jq -r '.[0] | "\(.Name)\t\(.Mountpoint)"'
  else
    echo "permesi-vault-data volume not found."
  fi

dev-envrc:
  #!/usr/bin/env zsh
  set -e
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet dev-env > "$tmp"
  mv "$tmp" .envrc
  if command -v direnv >/dev/null 2>&1; then
    direnv allow >/dev/null 2>&1 || true
  fi
  echo "Wrote .envrc from Vault logs + dev endpoints."

vault-stop:
  podman stop vault || true

vault-reset:
  #!/usr/bin/env zsh
  set -euo pipefail
  echo "This will delete the persistent Vault volume and keys file."
  printf "Type 'delete' to continue: "
  read -r confirm
  if [[ "$confirm" != "delete" ]]; then
    echo "Aborted."
    exit 1
  fi
  just vault-stop
  podman volume rm permesi-vault-data >/dev/null 2>&1 || true
  rm -f {{root}}/vault/keys.json
  echo "Vault data and keys removed."

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

postgres-stop:
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

jaeger-stop:
  podman stop jaeger || true

dev-start:
  #!/usr/bin/env zsh
  set -euo pipefail
  just dev-start-infra
  just dev-envrc
  just web

dev-start-all:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux not found. Install tmux or run: just dev-start" >&2
    exit 1
  fi
  session="permesi"
  start_session() {
    local left_pane
    local right_pane
    left_pane="$(
      tmux new-session -d -s "$session" -c "{{root}}" -P -F "#{pane_id}" "just genesis"
    )"
    right_pane="$(
      tmux split-window -t "$left_pane" -h -c "{{root}}" -P -F "#{pane_id}" "just permesi"
    )"
    tmux split-window -t "$left_pane" -v -c "{{root}}" "just web"
    tmux split-window -t "$right_pane" -v -c "{{root}}"
  }
  if [[ -n "${TMUX-}" ]]; then
    just dev-start-infra
    just dev-envrc
    if tmux has-session -t "$session" 2>/dev/null; then
      echo "tmux session '${session}' already exists."
      echo "Attach with: tmux attach -t ${session}"
      exit 0
    fi
    start_session
    echo "Created tmux session '${session}'."
    echo "Attach with: tmux attach -t ${session}"
    exit 0
  fi
  if tmux has-session -t "$session" 2>/dev/null; then
    tmux attach -t "$session"
    exit 0
  fi
  just dev-start-infra
  just dev-envrc
  start_session
  tmux attach -t "$session"

dev-start-infra: setup-network postgres vault-persist-ready jaeger

dev-stop: vault-stop postgres-stop jaeger-stop

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
