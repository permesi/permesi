genesis:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  if ! command -v vault >/dev/null 2>&1; then
    echo "vault CLI not found; install it or set GENESIS_VAULT_SECRET_ID manually before running." >&2
    exit 1
  fi
  cargo watch --use-shell=zsh -- zsh -c 'set -euo pipefail; export GENESIS_VAULT_SECRET_ID="$(vault write -force -field=secret_id auth/approle/role/genesis/secret-id)"; exec cargo run -p genesis --bin genesis -- --port 8000 -vvv'

permesi:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  if [[ -n "${PERMESI_SOCKET_MODE:-}" ]]; then
    export PERMESI_ADMISSION_PASERK_URL="https://genesis.permesi.localhost/paserk.json"
  fi
  paserk_url="${PERMESI_ADMISSION_PASERK_URL:-}"
  ca_path="{{root}}/certs/permesi/ca.pem"
  paserk_ca_path="${PERMESI_ADMISSION_PASERK_CA_PATH:-$ca_path}"
  if [[ -n "${PERMESI_ADMISSION_PASERK_CA_PATH:-}" && ! -f "$paserk_ca_path" ]]; then
    echo "Missing ${paserk_ca_path}; falling back to ${ca_path}" >&2
    paserk_ca_path="${ca_path}"
  fi
  if [[ "$paserk_url" == *"permesi.localhost"* && "$paserk_url" != *":8000"* ]]; then
    mkcert_ca="{{root}}/certs/mkcert-root.pem"
    if [[ -f "$mkcert_ca" ]]; then
      paserk_ca_path="$mkcert_ca"
    fi
  fi
  if [[ -n "$paserk_url" ]]; then
  if [[ ! -f "$paserk_ca_path" ]]; then
    echo "Missing ${paserk_ca_path}; run: just dev-tls-certs" >&2
    exit 1
  fi
  echo "Waiting for genesis PASERK at ${paserk_url}..."
  deadline=$((SECONDS + 30))
  success=0
  while (( SECONDS < deadline )); do
    code="$(curl -sS --cacert "$paserk_ca_path" -o /dev/null -w "%{http_code}" "$paserk_url" || true)"
    if [[ "$code" == "200" ]]; then
      success=1
      break
    fi
    sleep 0.5
  done
  if [[ "$success" -ne 1 ]]; then
    echo "Timed out waiting for ${paserk_url}" >&2
    exit 1
  fi
  fi
  if ! command -v vault >/dev/null 2>&1; then
    echo "vault CLI not found; install it or set PERMESI_VAULT_SECRET_ID manually before running." >&2
    exit 1
  fi
  cargo watch --use-shell=zsh -- zsh -c 'set -euo pipefail; export PERMESI_VAULT_SECRET_ID="$(vault write -force -field=secret_id auth/approle/role/permesi/secret-id)"; exec cargo run -p permesi --bin permesi -- --port 8001 -vvv'

genesis-socket:
  #!/usr/bin/env zsh
  set -euo pipefail
  mkdir -p {{root}}/.tmp
  rm -f {{root}}/.tmp/genesis.sock
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  # Unset TLS bundle to avoid conflict with --socket-path
  unset GENESIS_TLS_PEM_BUNDLE
  if ! command -v vault >/dev/null 2>&1; then
    echo "vault CLI not found; install it or set GENESIS_VAULT_SECRET_ID manually before running." >&2
    exit 1
  fi
  echo "Starting genesis on socket: {{root}}/.tmp/genesis.sock"
  cargo watch --use-shell=zsh -- zsh -c 'set -euo pipefail; export GENESIS_VAULT_SECRET_ID="$(vault write -force -field=secret_id auth/approle/role/genesis/secret-id)"; exec cargo run -p genesis --bin genesis -- --socket-path {{root}}/.tmp/genesis.sock -vvv'

permesi-socket:
  #!/usr/bin/env zsh
  set -euo pipefail
  mkdir -p {{root}}/.tmp
  rm -f {{root}}/.tmp/permesi.sock
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  export PERMESI_SOCKET_MODE=1
  # Unset TLS bundle to avoid conflict with --socket-path
  unset PERMESI_TLS_PEM_BUNDLE
  # Override PASERK URL to go through HAProxy (HTTPS on port 443)
  export PERMESI_ADMISSION_PASERK_URL="https://genesis.permesi.localhost/paserk.json"
  # Override CA path to trust mkcert (HAProxy) instead of internal Vault CA
  if [[ -f "{{root}}/certs/mkcert-root.pem" ]]; then
    export PERMESI_ADMISSION_PASERK_CA_PATH="{{root}}/certs/mkcert-root.pem"
  fi

  if ! command -v vault >/dev/null 2>&1; then
    echo "vault CLI not found; install it or set PERMESI_VAULT_SECRET_ID manually before running." >&2
    exit 1
  fi
  echo "Starting permesi on socket: {{root}}/.tmp/permesi.sock"
  cargo watch --use-shell=zsh -- zsh -c 'set -euo pipefail; export PERMESI_VAULT_SECRET_ID="$(vault write -force -field=secret_id auth/approle/role/permesi/secret-id)"; exec cargo run -p permesi --bin permesi -- --socket-path {{root}}/.tmp/permesi.sock -vvv'
