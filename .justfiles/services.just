genesis:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  if ! command -v bao >/dev/null 2>&1; then
    echo "bao CLI not found; install it or set GENESIS_OPENBAO_SECRET_ID manually before running." >&2
    exit 1
  fi
  cargo watch -w {{root}}/services/genesis -w {{root}}/crates/admission_token --use-shell=zsh -- zsh -c 'set -euo pipefail; export GENESIS_OPENBAO_SECRET_ID="$(bao write -force -field=secret_id auth/approle/role/genesis/secret-id)"; exec cargo run -p genesis --bin genesis --features telemetry -- --port 8000 -vvv'

permesi:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  # The local HAProxy overwrites forwarding headers; explicit trust is limited to loopback.
  export PERMESI_AUTH_TRUSTED_PROXIES="${PERMESI_AUTH_TRUSTED_PROXIES:-127.0.0.1/32,::1/128}"
  if ! command -v bao >/dev/null 2>&1; then
    echo "bao CLI not found; install it or set PERMESI_OPENBAO_SECRET_ID manually before running." >&2
    exit 1
  fi
  cargo watch -w {{root}}/services/permesi -w {{root}}/crates/admission_token --use-shell=zsh -- zsh -c 'set -euo pipefail; export PERMESI_OPENBAO_SECRET_ID="$(bao write -force -field=secret_id auth/approle/role/permesi/secret-id)"; exec cargo run -p permesi --bin permesi --features telemetry -- --port 8001 -vvv'

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
  if ! command -v bao >/dev/null 2>&1; then
    echo "bao CLI not found; install it or set GENESIS_OPENBAO_SECRET_ID manually before running." >&2
    exit 1
  fi
  echo "Starting genesis on socket: {{root}}/.tmp/genesis.sock"
  cargo watch -w {{root}}/services/genesis -w {{root}}/crates/admission_token --use-shell=zsh -- zsh -c 'set -euo pipefail; export GENESIS_OPENBAO_SECRET_ID="$(bao write -force -field=secret_id auth/approle/role/genesis/secret-id)"; exec cargo run -p genesis --bin genesis --features telemetry -- --socket-path {{root}}/.tmp/genesis.sock -vvv'

permesi-socket:
  #!/usr/bin/env zsh
  set -euo pipefail
  mkdir -p {{root}}/.tmp
  rm -f {{root}}/.tmp/permesi.sock
  if [[ -f {{root}}/.envrc ]]; then
    source {{root}}/.envrc
  fi
  export PERMESI_SOCKET_MODE=1
  # This opt-in local socket recipe uses the same trusted HAProxy boundary.
  export PERMESI_AUTH_TRUST_UNIX_PROXY="${PERMESI_AUTH_TRUST_UNIX_PROXY:-true}"
  # Unset TLS bundle to avoid conflict with --socket-path
  unset PERMESI_TLS_PEM_BUNDLE
  if ! command -v bao >/dev/null 2>&1; then
    echo "bao CLI not found; install it or set PERMESI_OPENBAO_SECRET_ID manually before running." >&2
    exit 1
  fi
  echo "Starting permesi on socket: {{root}}/.tmp/permesi.sock"
  cargo watch -w {{root}}/services/permesi -w {{root}}/crates/admission_token --use-shell=zsh -- zsh -c 'set -euo pipefail; export PERMESI_OPENBAO_SECRET_ID="$(bao write -force -field=secret_id auth/approle/role/permesi/secret-id)"; exec cargo run -p permesi --bin permesi --features telemetry -- --socket-path {{root}}/.tmp/permesi.sock -vvv'
