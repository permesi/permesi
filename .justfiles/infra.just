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
      -v {{root}}/db/sql/container-entrypoint.sql:/docker-entrypoint-initdb.d/00_init.sql:ro \
      --userns keep-id:uid={{ uid }},gid={{ gid }} \
      --user {{ uid }}:{{ gid }} \
      postgres:{{ version }} \
      postgres -c config_file=/etc/postgresql/config/postgresql.conf
  until podman exec postgres-permesi pg_isready -U postgres > /dev/null 2>&1; do sleep 0.2; done

postgres-stop:
  podman stop postgres-permesi || true

db-verify:
  #!/usr/bin/env zsh
  set -euo pipefail
  podman exec -i postgres-permesi psql -U postgres -d permesi -v ON_ERROR_STOP=1 -f /db/sql/verify_permesi.sql

db-bootstrap:
  #!/usr/bin/env zsh
  set -euo pipefail
  podman exec -i postgres-permesi psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f /db/sql/00_init.sql
  podman exec -i postgres-permesi psql -U postgres -d permesi -v ON_ERROR_STOP=1 -f /db/sql/verify_permesi.sql

jaeger:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^jaeger$')" ]]; then
    echo "jaeger already running"
    exit 0
  fi
  podman run --replace --rm -d --name jaeger \
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
  jaegertracing/jaeger:latest

jaeger-stop:
  podman stop jaeger || true

mkcert-local:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v mkcert >/dev/null 2>&1; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      echo "mkcert not found. Install it first (macOS): brew install mkcert nss" >&2
    else
      echo "mkcert not found. Install it first: https://github.com/FiloSottile/mkcert" >&2
    fi
    exit 1
  fi
  mkdir -p {{root}}/config/haproxy/certs
  cert="{{root}}/config/haproxy/certs/permesi.localhost.pem"
  if [[ -f "$cert" ]]; then
    echo "TLS cert already exists: $cert"
    exit 0
  fi
  mkcert -install
  mkdir -p {{root}}/certs
  caroot="$(mkcert -CAROOT)"
  root_ca="${caroot}/rootCA.pem"
  if [[ -f "$root_ca" ]]; then
    cp "$root_ca" "{{root}}/certs/mkcert-root.pem"
    chmod 0644 "{{root}}/certs/mkcert-root.pem"
  else
    echo "mkcert root CA not found at: $root_ca" >&2
  fi
  mkcert -key-file {{root}}/config/haproxy/certs/permesi.localhost-key.pem \
    -cert-file {{root}}/config/haproxy/certs/permesi.localhost-cert.pem \
    "localhost" "127.0.0.1" "::1" "*.localhost" \
    "permesi.localhost" "api.permesi.localhost" "genesis.permesi.localhost" "*.permesi.localhost"
  cat {{root}}/config/haproxy/certs/permesi.localhost-cert.pem \
    {{root}}/config/haproxy/certs/permesi.localhost-key.pem \
    > {{root}}/config/haproxy/certs/permesi.localhost.pem
  echo "Wrote {{root}}/config/haproxy/certs/permesi.localhost.pem"
  if [[ "$(uname -s)" == "Linux" ]]; then
    echo "If HTTPS still fails for server-side fetches, run: just mkcert-trust"
  fi

mkcert-trust:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "mkcert-trust is Linux-only; macOS/Windows use mkcert -install."
    exit 0
  fi
  if ! command -v mkcert >/dev/null 2>&1; then
    echo "mkcert not found. Install it first: https://github.com/FiloSottile/mkcert" >&2
    exit 1
  fi
  caroot="$(mkcert -CAROOT)"
  root_ca="${caroot}/rootCA.pem"
  if [[ ! -f "$root_ca" ]]; then
    echo "mkcert root CA not found at: $root_ca" >&2
    echo "Run: mkcert -install" >&2
    exit 1
  fi
  if command -v update-ca-certificates >/dev/null 2>&1; then
    sudo install -m 0644 "$root_ca" /usr/local/share/ca-certificates/mkcert-permesi.crt
    sudo update-ca-certificates
    echo "Installed mkcert root CA via update-ca-certificates."
    exit 0
  fi
  if [[ -d /etc/ca-certificates/trust-source/anchors ]]; then
    sudo install -m 0644 "$root_ca" /etc/ca-certificates/trust-source/anchors/mkcert-permesi.crt
    if command -v trust >/dev/null 2>&1; then
      sudo trust extract-compat
    fi
    echo "Installed mkcert root CA via p11-kit trust-source anchors."
    exit 0
  fi
  if command -v trust >/dev/null 2>&1; then
    sudo trust anchor "$root_ca"
    echo "Installed mkcert root CA via trust anchor."
    exit 0
  fi
  if command -v update-ca-trust >/dev/null 2>&1; then
    sudo install -m 0644 "$root_ca" /etc/pki/ca-trust/source/anchors/mkcert-permesi.crt
    sudo update-ca-trust
    echo "Installed mkcert root CA via update-ca-trust."
    exit 0
  fi
  echo "No known system trust tool found. Install p11-kit (trust) or ca-certificates tools." >&2
  exit 1

dev-tls-certs:
  #!/usr/bin/env zsh
  set -euo pipefail
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
  if ! command -v podman >/dev/null 2>&1; then
    echo "podman not found; install it first." >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found; install it first." >&2
    exit 1
  fi
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just vault-init" >&2
    exit 1
  fi
  if [[ -z "$(podman ps -q --filter 'name=^vault$')" ]]; then
    echo "Vault container not running. Run: just vault-persist-ready" >&2
    exit 1
  fi
  certs_dir="{{root}}/certs"
  if [[ -x /bin/chmod ]]; then
    chmod_bin="/bin/chmod"
  elif [[ -x /usr/bin/chmod ]]; then
    chmod_bin="/usr/bin/chmod"
  else
    chmod_bin="chmod"
  fi
  root_token="$(jq -r '.root_token' "$keys")"
  vault_addr="http://127.0.0.1:8200"

  ensure_dir() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
      return 0
    fi
    mkdir -p "$dir"
    "$chmod_bin" 0700 "$dir"
  }

  write_file() {
    local path="$1"
    local mode="$2"
    local content="$3"
    local dir="${path:h}"
    ensure_dir "$dir"
    printf '%s\n' "$content" > "$path"
    "$chmod_bin" "$mode" "$path"
  }

  issue_cert() {
    local service="$1"
    local common_name="$2"
    local alt_names="$3"
    local out_dir="${certs_dir}/${service}"

    ensure_dir "$out_dir"

    cert_json="$(
      podman exec -e VAULT_ADDR="$vault_addr" -e VAULT_TOKEN="$root_token" \
        vault vault write -format=json "pki-int/issue/${service}-runtime" \
        "common_name=${common_name}" \
        "alt_names=${alt_names}" \
        "ttl=24h"
    )"

    tls_cert="$(jq -er '.data.certificate' <<<"$cert_json")"
    tls_key="$(jq -er '.data.private_key' <<<"$cert_json")"
    issuing_ca="$(jq -er '.data.issuing_ca' <<<"$cert_json")"
    ca_chain="$(jq -er '.data.ca_chain | join("\n")' <<<"$cert_json")"

    write_file "${out_dir}/tls.crt" 0644 "$tls_cert"
    write_file "${out_dir}/tls.key" 0600 "$tls_key"
    if [[ -n "$ca_chain" ]]; then
      full_ca="${ca_chain}"
    else
      full_ca="${issuing_ca}"
    fi
    write_file "${out_dir}/ca.pem" 0644 "$full_ca"

    # Create PEM bundle: Key + Cert + CA
    bundle_content="$(printf '%s\n%s\n%s' "${tls_key}" "${tls_cert}" "${full_ca}")"
    write_file "${out_dir}/tls.bundle.pem" 0600 "${bundle_content}"
  }

  issue_cert permesi "api.permesi.localhost" "api.permesi.localhost"
  issue_cert genesis "genesis.permesi.localhost" "genesis.permesi.localhost"
  echo "Wrote TLS certs and bundles to ${certs_dir}/permesi and ${certs_dir}/genesis."

haproxy-start:
  #!/usr/bin/env zsh
  set -euo pipefail
  cfg="{{root}}/config/haproxy/haproxy.cfg"
  cert="{{root}}/config/haproxy/certs/permesi.localhost.pem"
  backend_ca="{{root}}/certs/permesi/ca.pem"
  if [[ ! -f "$cfg" ]]; then
    echo "Missing HAProxy config: $cfg" >&2
    exit 1
  fi
  if [[ ! -f "$cert" ]]; then
    if command -v mkcert >/dev/null 2>&1; then
      echo "Missing TLS cert; generating with mkcert..."
      just --quiet mkcert-local
    else
      echo "Missing TLS cert: $cert" >&2
      echo "Run: just mkcert-local" >&2
      exit 1
    fi
  fi
  if [[ ! -f "$backend_ca" ]]; then
    echo "Missing backend CA: ${backend_ca}. Run: just dev-tls-certs" >&2
    exit 1
  fi
  if [[ -n "$(podman ps -q --filter 'name=^permesi-haproxy$')" ]]; then
    echo "permesi-haproxy already running."
    exit 0
  fi
  port_args=(-p 443:8080)
  if [[ "$(uname -s)" == "Linux" ]] && sysctl -n net.ipv6.conf.all.disable_ipv6 >/dev/null 2>&1; then
    if [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" == "0" ]]; then
      port_args=(-p "[::]:443:8080")
    fi
  fi
  add_host_arg=()
  if [[ "$(uname -s)" == "Linux" ]]; then
    add_host_arg=(--add-host=host.containers.internal:host-gateway)
  fi
  if ! podman run --replace -d --name permesi-haproxy \
    "${add_host_arg[@]}" \
    "${port_args[@]}" \
    -v "{{root}}/config/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "{{root}}/config/haproxy/certs:/usr/local/etc/haproxy/certs:ro" \
    -v "${backend_ca}:/usr/local/etc/haproxy/ca.pem:ro" \
    docker.io/haproxy:latest; then
    if [[ "${port_args[*]}" == *"[::]:443:8080"* ]]; then
      echo "IPv6 publish failed; retrying IPv4-only."
      podman rm -f permesi-haproxy >/dev/null 2>&1 || true
      port_args=(-p 443:8080)
      podman run --replace -d --name permesi-haproxy \
        "${add_host_arg[@]}" \
        "${port_args[@]}" \
        -v "{{root}}/config/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        -v "{{root}}/config/haproxy/certs:/usr/local/etc/haproxy/certs:ro" \
        -v "${backend_ca}:/usr/local/etc/haproxy/ca.pem:ro" \
        docker.io/haproxy:latest
    else
      exit 1
    fi
  fi

haproxy-socket-start:
  #!/usr/bin/env zsh
  set -euo pipefail
  cfg="{{root}}/config/haproxy/haproxy-socket.cfg"
  cert="{{root}}/config/haproxy/certs/permesi.localhost.pem"
  backend_ca="{{root}}/certs/permesi/ca.pem"
  socket_dir="{{root}}/.tmp"

  if [[ ! -f "$cfg" ]]; then
    echo "Missing HAProxy socket config: $cfg" >&2
    exit 1
  fi
  # Ensure socket dir exists
  mkdir -p "$socket_dir"
  chmod 755 "$socket_dir" 2>/dev/null || true

  if [[ ! -f "$cert" ]]; then
    if command -v mkcert >/dev/null 2>&1; then
      echo "Missing TLS cert; generating with mkcert..."
      just --quiet mkcert-local
    else
      echo "Missing TLS cert: $cert" >&2
      echo "Run: just mkcert-local" >&2
      exit 1
    fi
  fi

  if [[ -n "$(podman ps -q --filter 'name=^permesi-haproxy$')" ]]; then
    echo "permesi-haproxy already running. Restarting with socket config..."
    podman stop permesi-haproxy >/dev/null
  fi

  port_args=(-p 443:8080)
  if [[ "$(uname -s)" == "Linux" ]] && sysctl -n net.ipv6.conf.all.disable_ipv6 >/dev/null 2>&1; then
    if [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" == "0" ]]; then
      port_args=(-p "[::]:443:8080")
    fi
  fi

  add_host_arg=()
  if [[ "$(uname -s)" == "Linux" ]]; then
    add_host_arg=(--add-host=host.containers.internal:host-gateway)
  fi

  echo "Starting HAProxy (socket mode)..."
  if ! podman run --replace -d --name permesi-haproxy \
    "${add_host_arg[@]}" \
    "${port_args[@]}" \
    -v "$cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "{{root}}/config/haproxy/certs:/usr/local/etc/haproxy/certs:ro" \
    -v "${backend_ca}:/usr/local/etc/haproxy/ca.pem:ro" \
    -v "${socket_dir}:/var/run/permesi:z" \
    docker.io/haproxy:latest; then
      echo "Failed to start HAProxy."
      exit 1
  fi

haproxy-stop:
  podman stop permesi-haproxy || true

haproxy-sysctl:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "haproxy-sysctl is Linux-only."
    exit 0
  fi
  echo "Allowing unprivileged binds to port 443..."
  sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443


# Restart everything: stop infra and tmux, then start again
restart: stop start

start:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v tmux >/dev/null 2>&1; then
    just dev-start-infra
    just haproxy-socket-start
    just dev-envrc
  export PERMESI_SOCKET_MODE=1
    echo "tmux not found; starting web here. Run: just genesis-socket / just permesi-socket in other shells."
    just web
    exit 0
  fi
  session="permesi"
  start_session() {
    local left_pane
    local right_pane
    left_pane="$(
      tmux new-session -d -s "$session" -c "{{root}}" -P -F "#{pane_id}" "just genesis-socket"
    )"
    right_pane="$(
      tmux split-window -t "$left_pane" -h -c "{{root}}" -P -F "#{pane_id}" "just permesi-socket"
    )"
    tmux split-window -t "$left_pane" -v -c "{{root}}" "just web"
    tmux split-window -t "$right_pane" -v -c "{{root}}"
  }
  if [[ -n "${TMUX-}" ]]; then
    just dev-start-infra
    just haproxy-socket-start
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
  just haproxy-socket-start
  just dev-envrc
  start_session
  tmux attach -t "$session"

start-http:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v tmux >/dev/null 2>&1; then
    just dev-start-infra
    just dev-envrc
    echo "tmux not found; starting web here. Run: just genesis / just permesi in other shells."
    just web
    exit 0
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

dev-start-infra: setup-network postgres vault-persist-ready dev-tls-certs jaeger haproxy-start

# Stop all services and the tmux session
stop: tmux-stop dev-stop

# Kill lingering dev processes, containers, and free ports
dev-stop: vault-stop postgres-stop jaeger-stop haproxy-stop
  #!/usr/bin/env zsh
  echo "Cleaning up lingering dev processes and test containers..."
  # Kill processes by port to ensure ports are freed (Linux specific)
  fuser -k 8000/tcp 8001/tcp 8080/tcp 8081/tcp 443/tcp 2>/dev/null || true
  # Specific process names cleanup
  pkill -f "cargo-watch" || true
  pkill -f "trunk serve" || true
  pkill -f "npm run css:watch" || true
  pkill -f "tailwindcss" || true
  # Cleanup any leaked testcontainers (permesi-test-*)
  podman ps -a --format "{{{{.Names}}}}" | grep -E "^permesi-test-" | xargs -r podman rm -f

# Kill the tmux session if it exists
tmux-stop:
  #!/usr/bin/env zsh
  tmux kill-session -t permesi 2>/dev/null || true

reset: stop
  #!/usr/bin/env zsh
  set -euo pipefail
  just vault-reset
  rm -rf {{root}}/db/data {{root}}/db/logs
  rm -rf {{root}}/config/haproxy/certs

# Generate a fresh platform operator token for admin claim/elevation.
operator-token:
    #!/usr/bin/env zsh
    set -euo pipefail
    keys="{{root}}/vault/keys.json"
    if [[ ! -f "$keys" ]]; then
        echo "❌ Vault keys not found. Is Vault initialized? Run: just vault-init" >&2
        exit 1
    fi
    root_token=$(jq -r '.root_token' "$keys")
    podman exec -e VAULT_TOKEN="$root_token" -e VAULT_ADDR="http://127.0.0.1:8200" \
        vault vault token create -policy=permesi-operators -period=24h -field=token

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
