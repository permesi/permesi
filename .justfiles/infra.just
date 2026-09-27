postgres version="18": setup-network
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^postgres-permesi$')" ]]; then
    echo "postgres-permesi already running"
    exit 0
  fi
  mkdir -p db/log/postgres
  podman run --replace --rm -d --name postgres-permesi \
      --network {{net}} \
      --label {{stack_label}} \
      -e POSTGRES_USER=postgres \
      -e POSTGRES_HOST_AUTH_METHOD=trust \
      -e PGDATA=/db/data/{{ version }} \
      -p {{publish_ip}}5432:5432 \
      -v {{root}}/db:/db \
      -v {{root}}/db/config/postgres:/etc/postgresql/config \
      -v {{root}}/db/sql/container-entrypoint.sql:/docker-entrypoint-initdb.d/00_init.sql:ro \
      --userns keep-id:uid={{ uid }},gid={{ gid }} \
      --user {{ uid }}:{{ gid }} \
      docker.io/library/postgres:{{ version }} \
      postgres -c config_file=/etc/postgresql/config/postgresql.conf
  until podman exec postgres-permesi pg_isready -U postgres > /dev/null 2>&1; do sleep 0.2; done

k8s-logs target="permesi" since="10m":
  #!/usr/bin/env zsh
  set -euo pipefail

  case "{{ target }}" in
    permesi|genesis|web)
      namespace="permesi-test"
      selector="app.kubernetes.io/name={{ target }}"
      container="{{ target }}"
      ;;
    gateway|envoy)
      namespace="envoy-gateway-system"
      selector="gateway.envoyproxy.io/owning-gateway-name=shared"
      container="envoy"
      ;;
    *)
      echo "Unknown target: {{ target }}" >&2
      echo "Use one of: permesi, genesis, web, gateway" >&2
      exit 1
      ;;
  esac

  kubectl logs \
    -n "$namespace" \
    -l "$selector" \
    -c "$container" \
    --since "{{ since }}" \
    --prefix \
    --max-log-requests=10 \
    -f

k8s-logs-permesi since="10m":
  just k8s-logs permesi "{{ since }}"

k8s-logs-genesis since="10m":
  just k8s-logs genesis "{{ since }}"

k8s-logs-web since="10m":
  just k8s-logs web "{{ since }}"

k8s-logs-gateway since="10m":
  just k8s-logs gateway "{{ since }}"

postgres-stop:
  podman stop postgres-permesi || true

db-verify:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -z "$(podman ps -q --filter 'name=^postgres-permesi$')" ]]; then
    echo "postgres-permesi is not running. Run: just postgres" >&2
    exit 1
  fi
  podman exec -i postgres-permesi psql -U postgres -d permesi -v ON_ERROR_STOP=1 -f /db/sql/verify_permesi.sql

db-bootstrap:
  #!/usr/bin/env zsh
  set -euo pipefail
  podman exec -i postgres-permesi psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f /db/sql/00_init.sql
  podman exec -i postgres-permesi psql -U postgres -d permesi -v ON_ERROR_STOP=1 -f /db/sql/verify_permesi.sql

jaeger: setup-network
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^{{jaeger_ctr}}$')" ]]; then
    echo "jaeger already running"
    exit 0
  fi
  podman run --replace --rm -d --name {{jaeger_ctr}} \
    --network {{net}} \
    --label {{stack_label}} \
    -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
    -p {{publish_ip}}6831:6831/udp \
    -p {{publish_ip}}6832:6832/udp \
    -p {{publish_ip}}5778:5778 \
    -p {{publish_ip}}16686:16686 \
    -p {{publish_ip}}4317:4317 \
    -p {{publish_ip}}4318:4318 \
    -p {{publish_ip}}14250:14250 \
    -p {{publish_ip}}14268:14268 \
    -p {{publish_ip}}14269:14269 \
    -p {{publish_ip}}9411:9411 \
  {{jaeger_image}}

jaeger-stop:
  podman stop {{jaeger_ctr}} || true

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
  if [[ -z "$(podman ps -q --filter 'name=^{{vault_ctr}}$')" ]]; then
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
        {{vault_ctr}} vault write -format=json "pki-int/issue/${service}-runtime" \
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

haproxy-start: setup-network
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
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
      # Over SSH the browser runs on another machine, which would not trust a CA
      # generated here; the laptop pushes a cert from its own CA instead.
      echo "Missing TLS cert: ${cert}" >&2
      echo "On a remote VM, run on your laptop: scripts/dev-remote <this-host> [repo-path]" >&2
      echo "(or, to trust a CA created on this host instead: just mkcert-local)" >&2
      exit 1
    elif command -v mkcert >/dev/null 2>&1; then
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
  # Publish on PERMESI_HTTPS_PORT: loopback (v4, plus v6 when enabled) by default,
  # every interface only when PERMESI_BIND_ADDR=0.0.0.0.
  port="{{https_port}}"
  if [[ "{{bind_addr}}" == "0.0.0.0" ]]; then
    v4_args=(-p "${port}:8080")
    v6_args=(-p "[::]:${port}:8080")
  else
    v4_args=(-p "127.0.0.1:${port}:8080")
    v6_args=("${v4_args[@]}" -p "[::1]:${port}:8080")
  fi
  port_args=("${v4_args[@]}")
  if [[ "$(uname -s)" == "Linux" && "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == "0" ]]; then
    port_args=("${v6_args[@]}")
  fi
  add_host_arg=()
  if [[ "$(uname -s)" == "Linux" ]]; then
    add_host_arg=(--add-host=host.containers.internal:host-gateway)
  fi
  if ! podman run --replace -d --name permesi-haproxy \
    --network {{net}} \
    --label {{stack_label}} \
    "${add_host_arg[@]}" \
    "${port_args[@]}" \
    -v "{{root}}/config/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "{{root}}/config/haproxy/certs:/usr/local/etc/haproxy/certs:ro" \
    -v "${backend_ca}:/usr/local/etc/haproxy/ca.pem:ro" \
    {{haproxy_image}}; then
    if [[ "${port_args[*]}" != "${v4_args[*]}" ]]; then
      echo "IPv6 publish failed; retrying IPv4-only."
      podman rm -f permesi-haproxy >/dev/null 2>&1 || true
      port_args=("${v4_args[@]}")
      podman run --replace -d --name permesi-haproxy \
        --network {{net}} \
        --label {{stack_label}} \
        "${add_host_arg[@]}" \
        "${port_args[@]}" \
        -v "{{root}}/config/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        -v "{{root}}/config/haproxy/certs:/usr/local/etc/haproxy/certs:ro" \
        -v "${backend_ca}:/usr/local/etc/haproxy/ca.pem:ro" \
        {{haproxy_image}}
    else
      exit 1
    fi
  fi

haproxy-socket-start: setup-network
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
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
      # Over SSH the browser runs on another machine, which would not trust a CA
      # generated here; the laptop pushes a cert from its own CA instead.
      echo "Missing TLS cert: ${cert}" >&2
      echo "On a remote VM, run on your laptop: scripts/dev-remote <this-host> [repo-path]" >&2
      echo "(or, to trust a CA created on this host instead: just mkcert-local)" >&2
      exit 1
    elif command -v mkcert >/dev/null 2>&1; then
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

  # Publish on PERMESI_HTTPS_PORT: loopback (v4, plus v6 when enabled) by default,
  # every interface only when PERMESI_BIND_ADDR=0.0.0.0.
  port="{{https_port}}"
  if [[ "{{bind_addr}}" == "0.0.0.0" ]]; then
    v4_args=(-p "${port}:8080")
    v6_args=(-p "[::]:${port}:8080")
  else
    v4_args=(-p "127.0.0.1:${port}:8080")
    v6_args=("${v4_args[@]}" -p "[::1]:${port}:8080")
  fi
  port_args=("${v4_args[@]}")
  if [[ "$(uname -s)" == "Linux" && "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == "0" ]]; then
    port_args=("${v6_args[@]}")
  fi

  add_host_arg=()
  if [[ "$(uname -s)" == "Linux" ]]; then
    add_host_arg=(--add-host=host.containers.internal:host-gateway)
  fi
  socket_user_args=(--userns keep-id --user "$(id -u):$(id -g)")

  echo "Starting HAProxy (socket mode)..."
  if ! podman run --replace -d --name permesi-haproxy \
    --network {{net}} \
    --label {{stack_label}} \
    "${add_host_arg[@]}" \
    "${socket_user_args[@]}" \
    "${port_args[@]}" \
    -v "$cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "{{root}}/config/haproxy/certs:/usr/local/etc/haproxy/certs:ro" \
    -v "${backend_ca}:/usr/local/etc/haproxy/ca.pem:ro" \
    -v "${socket_dir}:/var/run/permesi:z" \
    {{haproxy_image}}; then
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
  port="{{https_port}}"
  if (( port >= 1024 )); then
    echo "Not needed: PERMESI_HTTPS_PORT=${port} is not a privileged port."
    exit 0
  fi
  echo "Allowing unprivileged binds to port ${port}..."
  sudo sysctl -w net.ipv4.ip_unprivileged_port_start=${port}


# Restart everything: stop infra and the dev session, then start again
restart: stop start

# Backward-compatible aliases for the renamed start recipes
alias start-http := start

# Full dev stack over TLS: infra, then genesis, permesi, web and a spare shell in a
# dev session (Herdr workspace, tmux fallback; see _dev-session).
[doc("Start infra and genesis, permesi and web in a Herdr workspace (tmux fallback)")]
start: (_dev-session "tcp")

# Like `start`, but genesis and permesi serve Unix sockets behind HAProxy. Same host
# only, so HTTPS stays the default.
[doc("Like start, but the backends serve Unix sockets behind HAProxy")]
start-socket: (_dev-session "socket")

# Infra only (containers plus .envrc), for running the services in terminals of your
# choice: IDE terminals, zellij, or plain shells.
[doc("Start the infra containers and write .envrc, without the services")]
infra: dev-start-infra dev-envrc
  @echo "Infra ready. Start the services in separate terminals: just genesis | just permesi | just web"

# Build and attach the dev session. PERMESI_MUX=auto|herdr|tmux|none picks where
# genesis, permesi, web and a spare shell run: auto prefers Herdr (starting a headless
# server when none is running), then tmux, and otherwise prints the commands for
# plain terminals. Inside Herdr it only focuses the new workspace, because Herdr
# refuses to nest. PERMESI_NO_ATTACH=1, or a non-interactive caller, builds the
# session without attaching; scripts/dev-remote relies on that over SSH. Re-running
# while the session is alive only attaches. The Herdr ids go to
# .tmp/herdr-session.json so attach, logs and stop act on this workspace alone.
_dev-session mode:
  #!/usr/bin/env zsh
  set -euo pipefail
  root="{{root}}"
  state="${root}/.tmp/herdr-session.json"
  session="permesi"
  ws_label="{{herdr_label}}"
  if [[ "{{mode}}" == "socket" ]]; then
    cmd_genesis="just genesis-socket"
    cmd_permesi="just permesi-socket"
  else
    cmd_genesis="just genesis"
    cmd_permesi="just permesi"
  fi
  cmd_web="just web"
  attach=1
  if [[ -n "${PERMESI_NO_ATTACH:-}" || ! -t 0 || ! -t 1 ]]; then
    attach=0
  fi

  herdr_up() {
    herdr status server 2>/dev/null | grep -q 'status: running'
  }
  attach_herdr() {
    # Only an interactive caller gets its Herdr view switched or attached.
    if (( ! attach )); then
      echo "herdr workspace '${ws_label}' is ready. Attach with: just attach"
      return
    fi
    herdr workspace focus "$1" >/dev/null
    if [[ -n "${HERDR_ENV:-}" ]]; then
      echo "Focused herdr workspace '${ws_label}'."
    else
      exec herdr
    fi
  }
  attach_tmux() {
    if [[ -n "${TMUX:-}" ]] || (( ! attach )); then
      echo "tmux session '${session}' is ready. Attach with: tmux attach -t ${session}"
    else
      exec tmux attach -t "$session"
    fi
  }

  want="${PERMESI_MUX:-auto}"
  case "$want" in
    auto|herdr|tmux|none) ;;
    *) echo "PERMESI_MUX must be auto, herdr, tmux or none (got: ${want})" >&2; exit 1 ;;
  esac
  mux=none
  if [[ "$want" == "auto" || "$want" == "herdr" ]] && command -v herdr >/dev/null 2>&1; then
    if [[ -n "${HERDR_ENV:-}" ]] || herdr_up; then
      mux=herdr
    else
      echo "Starting a headless herdr server..."
      if command -v setsid >/dev/null 2>&1; then
        setsid nohup herdr server </dev/null >/dev/null 2>&1 &!
      else
        nohup herdr server </dev/null >/dev/null 2>&1 &!
      fi
      for _ in {1..20}; do
        herdr_up && break
        sleep 0.5
      done
      if herdr_up; then
        mux=herdr
      else
        echo "herdr server did not start; falling back." >&2
      fi
    fi
  fi
  if [[ "$want" == "herdr" && "$mux" != "herdr" ]]; then
    echo "PERMESI_MUX=herdr, but herdr is not installed or its server is not reachable." >&2
    exit 1
  fi
  if [[ "$mux" == "none" && "$want" != "none" ]] && command -v tmux >/dev/null 2>&1; then
    mux=tmux
  fi
  if [[ "$want" == "tmux" && "$mux" != "tmux" ]]; then
    echo "PERMESI_MUX=tmux, but tmux is not installed." >&2
    exit 1
  fi

  if [[ "$mux" == "herdr" ]] && ws="$(just --quiet _herdr-ws 2>/dev/null)"; then
    echo "herdr workspace '${ws_label}' is already running."
    attach_herdr "$ws"
    exit 0
  fi
  if [[ "$mux" == "tmux" ]] && tmux has-session -t "$session" 2>/dev/null; then
    echo "tmux session '${session}' is already running."
    attach_tmux
    exit 0
  fi

  just dev-start-infra
  if [[ "{{mode}}" == "socket" ]]; then
    just haproxy-socket-start
  fi
  just dev-envrc

  if [[ "$mux" == "none" ]]; then
    echo "Neither herdr nor tmux is available; run the services in separate terminals:"
    printf '  %s\n' "$cmd_genesis" "$cmd_permesi" "$cmd_web"
    exit 0
  fi

  just _prebuild

  if [[ "$mux" == "herdr" ]]; then
    envs=(--env "PERMESI_BIND_ADDR={{bind_addr}}" --env "PERMESI_HTTPS_PORT={{https_port}}")
    ws_json="$(herdr workspace create --cwd "$root" --label "$ws_label" "${envs[@]}" --no-focus)"
    ws="$(jq -r '.result.workspace.workspace_id' <<<"$ws_json")"
    p_genesis="$(jq -r '.result.root_pane.pane_id' <<<"$ws_json")"
    mkdir -p "${state:h}"
    jq -n --arg ws "$ws" --arg session "$ws_label" '{workspace: $ws, label: $session, panes: {}}' > "$state"
    split_pane() {
      herdr pane split "$1" --direction "$2" --cwd "$root" "${envs[@]}" --no-focus | jq -r '.result.pane.pane_id'
    }
    p_permesi="$(split_pane "$p_genesis" right)"
    p_web="$(split_pane "$p_genesis" down)"
    p_shell="$(split_pane "$p_permesi" down)"
    jq -n --arg ws "$ws" --arg session "$ws_label" \
      --arg g "$p_genesis" --arg p "$p_permesi" --arg w "$p_web" --arg s "$p_shell" \
      '{workspace: $ws, label: $session, panes: {genesis: $g, permesi: $p, web: $w, shell: $s}}' > "$state"
    herdr pane rename "$p_genesis" genesis >/dev/null
    herdr pane rename "$p_permesi" permesi >/dev/null
    herdr pane rename "$p_web" web >/dev/null
    herdr pane rename "$p_shell" shell >/dev/null
    herdr pane run "$p_genesis" "$cmd_genesis" >/dev/null
    herdr pane run "$p_permesi" "$cmd_permesi" >/dev/null
    herdr pane run "$p_web" "$cmd_web" >/dev/null
    echo "Created herdr workspace '${ws_label}' (genesis, permesi, web, shell)."
    echo "Logs without attaching: just logs [genesis|permesi|web]"
    attach_herdr "$ws"
    exit 0
  fi

  left="$(tmux new-session -d -s "$session" -c "$root" \
    -e "PERMESI_BIND_ADDR={{bind_addr}}" -e "PERMESI_HTTPS_PORT={{https_port}}" \
    -P -F "#{pane_id}" "$cmd_genesis")"
  # Keep a crashed service visible as "[dead]" instead of letting its pane vanish.
  tmux set-option -t "$session" remain-on-exit on
  tmux set-option -t "$session" pane-border-status top
  right="$(tmux split-window -t "$left" -h -c "$root" -P -F "#{pane_id}" "$cmd_permesi")"
  web="$(tmux split-window -t "$left" -v -c "$root" -P -F "#{pane_id}" "$cmd_web")"
  shell="$(tmux split-window -t "$right" -v -c "$root" -P -F "#{pane_id}")"
  tmux select-pane -t "$left" -T genesis
  tmux select-pane -t "$right" -T permesi
  tmux select-pane -t "$web" -T web
  tmux select-pane -t "$shell" -T shell
  tmux select-pane -t "$left"
  echo "Created tmux session '${session}' (genesis, permesi, web, shell)."
  attach_tmux

# Build genesis and permesi once before their panes start, so the cargo-watch runs
# find fresh artifacts instead of queueing on the shared target-dir lock. The builds
# mirror the pane commands exactly: a combined `-p genesis -p permesi` build unifies
# features differently, and the panes would rebuild anyway. Skip with
# PERMESI_NO_PREBUILD=1; a failure only warns, since the pane shows the error.
_prebuild:
  #!/usr/bin/env zsh
  set -uo pipefail
  if [[ "${PERMESI_NO_PREBUILD:-}" == "1" ]]; then
    exit 0
  fi
  cd "{{root}}"
  for svc in genesis permesi; do
    echo "Pre-building ${svc}..."
    if ! cargo build -p "$svc" --bin "$svc" --features telemetry; then
      echo "Pre-build of ${svc} failed; continuing (its pane shows the error)." >&2
    fi
  done

# Print the recorded Herdr workspace id if that workspace is still alive and labelled
# {{herdr_label}}, and fail otherwise. The label check keeps a stale id from ever targeting
# a workspace this checkout did not create.
_herdr-ws:
  #!/usr/bin/env zsh
  set -euo pipefail
  state="{{root}}/.tmp/herdr-session.json"
  command -v herdr >/dev/null 2>&1 || exit 1
  [[ -f "$state" ]] || exit 1
  ws="$(jq -r '.workspace // empty' "$state")"
  [[ -n "$ws" ]] || exit 1
  label="$(herdr workspace get "$ws" 2>/dev/null | jq -r '.result.workspace.label // empty')"
  [[ "$label" == "{{herdr_label}}" ]] || exit 1
  print -r -- "$ws"

# Attach to the running dev session: the recorded Herdr workspace, else the tmux
# session 'permesi'.
[doc("Attach to the running dev session (Herdr workspace, else tmux)")]
attach:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ws="$(just --quiet _herdr-ws 2>/dev/null)"; then
    herdr workspace focus "$ws" >/dev/null
    if [[ -n "${HERDR_ENV:-}" ]]; then
      echo "Focused herdr workspace '{{herdr_label}}'."
      exit 0
    fi
    exec herdr
  fi
  if command -v tmux >/dev/null 2>&1 && tmux has-session -t permesi 2>/dev/null; then
    if [[ -n "${TMUX:-}" ]]; then
      exec tmux switch-client -t permesi
    fi
    exec tmux attach -t permesi
  fi
  echo "No running dev session. Start one with: just start" >&2
  exit 1

# Print recent output of a service pane without attaching: `just logs permesi`, or
# a short tail of genesis, permesi and web with no argument. PERMESI_LOG_LINES sets
# the length (default 200 for one pane, 40 each for all three).
[doc("Print recent output of genesis, permesi or web without attaching")]
logs service="":
  #!/usr/bin/env zsh
  set -euo pipefail
  svc="{{service}}"
  case "$svc" in
    ""|genesis|permesi|web) ;;
    *) echo "usage: just logs [genesis|permesi|web]" >&2; exit 1 ;;
  esac
  if [[ -n "$svc" ]]; then
    names=("$svc")
    lines="${PERMESI_LOG_LINES:-200}"
  else
    names=(genesis permesi web)
    lines="${PERMESI_LOG_LINES:-40}"
  fi
  if just --quiet _herdr-ws >/dev/null 2>&1; then
    state="{{root}}/.tmp/herdr-session.json"
    for name in "${names[@]}"; do
      id="$(jq -r --arg n "$name" '.panes[$n] // empty' "$state")"
      [[ -n "$id" ]] || continue
      (( ${#names} > 1 )) && echo "===== ${name} ====="
      herdr pane read "$id" --source recent-unwrapped --lines "$lines"
      echo
    done
    exit 0
  fi
  if command -v tmux >/dev/null 2>&1 && tmux has-session -t permesi 2>/dev/null; then
    for name in "${names[@]}"; do
      id="$(tmux list-panes -t permesi -F '#{pane_title} #{pane_id}' | awk -v s="$name" '$1==s{print $2; exit}')"
      [[ -n "$id" ]] || continue
      (( ${#names} > 1 )) && echo "===== ${name} ====="
      # capture-pane pads to the pane height; drop the trailing blank lines.
      tmux capture-pane -pt "$id" -S "-${lines}" | awk '{l[NR]=$0} NF{last=NR} END{for(i=1;i<=last;i++) print l[i]}'
    done
    exit 0
  fi
  echo "No running dev session. Start one with: just start" >&2
  exit 1

# Warn loudly when the infra is published on every interface (PERMESI_BIND_ADDR=0.0.0.0).
_warn-exposed:
  #!/usr/bin/env zsh
  if [[ "{{bind_addr}}" == "0.0.0.0" ]]; then
    echo "⚠️  PERMESI_BIND_ADDR=0.0.0.0: Postgres (trust auth, no password) and Vault" >&2
    echo "   (root token in vault/keys.json) are reachable from the network." >&2
  fi

dev-start-infra: _warn-exposed setup-network postgres vault-persist-ready dev-tls-certs jaeger haproxy-start

# Stop the containers and service processes, then close the dev session. The session
# closes last so `just stop` typed in its spare shell still finishes the cleanup.
[doc("Stop the dev containers and processes, then close the dev session")]
stop: dev-stop mux-stop

# Stop the dev containers, then any dev process of this checkout that outlived its
# terminal. Other projects share the host, so a process is only signalled when its
# working directory is inside this repository; matching by name or port alone would
# kill another project's cargo-watch or port-8000 server.
[doc("Stop the dev containers and this checkout's leftover dev processes")]
dev-stop: vault-stop postgres-stop jaeger-stop haproxy-stop test-clean
  #!/usr/bin/env zsh
  set -uo pipefail
  root="{{root}}"
  root="${root:A}"
  pid_cwd() {
    if [[ -r "/proc/$1/cwd" ]]; then
      readlink "/proc/$1/cwd" 2>/dev/null
    elif command -v lsof >/dev/null 2>&1; then
      lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p'
    fi
  }
  port_pids() {
    if command -v lsof >/dev/null 2>&1; then
      lsof -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null
    elif command -v fuser >/dev/null 2>&1; then
      fuser -n tcp "$1" 2>/dev/null
    fi
  }
  typeset -U pids
  pids=()
  for port in 8000 8001 8081; do
    pids+=(${=$(port_pids "$port")})
  done
  pids+=(${=$(pgrep -f 'cargo-watch|trunk serve|npm run css:watch|tailwindcss|target/debug/(genesis|permesi)' 2>/dev/null)})
  for pid in "${pids[@]}"; do
    [[ "$pid" == "$$" ]] && continue
    cwd="$(pid_cwd "$pid")"
    if [[ -n "$cwd" && ( "$cwd" == "$root" || "$cwd" == "$root"/* ) ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  echo "Stopped permesi dev containers and processes."

# Remove integration-test leftovers: containers, then networks, named permesi-test-*.
# Tests create uniquely named ones and clean up after themselves; an interrupted run
# leaves them behind. Nothing outside that prefix is touched, so do not run this
# while `cargo test` is running.
[doc("Remove leaked permesi-test-* containers and networks")]
test-clean:
  #!/usr/bin/env zsh
  set -euo pipefail
  containers=(${(f)"$(podman ps -a --format '{{{{.Names}}' | grep -E '^permesi-test-' || true)"})
  if (( ${#containers} )); then
    podman rm -f "${containers[@]}" >/dev/null
    echo "Removed ${#containers} leaked test container(s)."
  fi
  networks=(${(f)"$(podman network ls --format '{{{{.Name}}' | grep -E '^permesi-test-' || true)"})
  if (( ${#networks} )); then
    podman network rm "${networks[@]}" >/dev/null
    echo "Removed ${#networks} leaked test network(s)."
  fi

# Close the dev session this checkout started: only the recorded Herdr workspace and
# the tmux session 'permesi'. Run from inside that session, it closes the other panes
# and keeps the calling one, so the command that asked for it can finish.
[doc("Close the Herdr workspace or tmux session this checkout started")]
mux-stop:
  #!/usr/bin/env zsh
  set -uo pipefail
  state="{{root}}/.tmp/herdr-session.json"
  if ws="$(just --quiet _herdr-ws 2>/dev/null)"; then
    if [[ "${HERDR_WORKSPACE_ID:-}" == "$ws" ]]; then
      for id in $(jq -r '.panes[]?' "$state"); do
        [[ "$id" == "${HERDR_PANE_ID:-}" ]] && continue
        herdr pane close "$id" >/dev/null 2>&1 || true
      done
      echo "Closed the service panes of herdr workspace '{{herdr_label}}' (kept this one)."
    else
      herdr workspace close "$ws" >/dev/null && echo "Closed herdr workspace '{{herdr_label}}'."
    fi
  fi
  rm -f "$state"
  if command -v tmux >/dev/null 2>&1 && tmux has-session -t permesi 2>/dev/null; then
    if [[ -n "${TMUX:-}" && "$(tmux display-message -p '#S')" == "permesi" ]]; then
      tmux kill-pane -a -t "${TMUX_PANE}"
      echo "Closed the other panes of tmux session 'permesi' (kept this one)."
    else
      tmux kill-session -t permesi && echo "Killed tmux session 'permesi'."
    fi
  fi

alias tmux-stop := mux-stop

reset: stop
  #!/usr/bin/env zsh
  set -euo pipefail
  just vault-reset
  rm -rf {{root}}/db/data {{root}}/db/log
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
        {{vault_ctr}} vault token create -policy=permesi-operators -period=24h -field=token

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

# Check the host before `just start`. Read-only: it installs and changes nothing,
# prints one line per check (✓ ok, ! warning, ✗ problem, each with a hint) and exits
# 1 when a required check fails. It is not a dependency of `start`, so startup stays
# fast; run it on a new laptop or VM and whenever `just start` misbehaves.
[doc("Check tools, multiplexer, ports, network and Vault state before just start")]
doctor:
  #!/usr/bin/env zsh
  set -uo pipefail
  autoload -Uz is-at-least
  root="{{root}}"
  root="${root:A}"
  fails=0
  warns=0
  ok() { print -r -- "  ✓ $*"; }
  warn() { print -r -- "  ! $*"; (( warns++ )); }
  fail() { print -r -- "  ✗ $*"; (( fails++ )); }
  section() { print -r -- ""; print -r -- "$*"; }
  have() { command -v "$1" >/dev/null 2>&1; }
  os="$(uname -s)"
  hint_install="install it with \`mise trust && mise install\` or your package manager"

  section "Required tools"
  for tool in zsh jq rg curl vault cargo node npm; do
    if have "$tool"; then ok "$tool"; else fail "$tool missing: ${hint_install}"; fi
  done
  if have podman; then
    pv="$(podman version --format '{{{{.Client.Version}}' 2>/dev/null)"
    if [[ "$(podman info --format '{{{{.Host.Security.Rootless}}' 2>/dev/null)" == "true" ]]; then
      ok "podman ${pv} (rootless)"
    else
      fail "podman ${pv} is not running rootless; the dev stack expects rootless podman"
    fi
    if [[ -n "$pv" ]] && ! is-at-least 5.3 "$pv"; then
      warn "podman ${pv} is older than 5.3; HAProxy's host.containers.internal:host-gateway mapping may not work"
    fi
  else
    fail "podman missing: install it with your package manager (rootless)"
  fi
  if have terraform; then
    tv="$(terraform version -json 2>/dev/null | jq -r '.terraform_version // empty')"
    if [[ -n "$tv" ]] && is-at-least 1.7 "$tv"; then ok "terraform ${tv}"; else fail "terraform ${tv:-unknown} is older than 1.7 (vault/contrib/terraform requires >= 1.7)"; fi
  else
    fail "terraform missing: ${hint_install}"
  fi
  if have cargo && cargo watch --version >/dev/null 2>&1; then
    ok "cargo-watch"
  else
    fail "cargo-watch missing: without it the service panes exit at once; ${hint_install}"
  fi
  if have rustup; then
    if rustup target list --installed 2>/dev/null | grep -qx 'wasm32-unknown-unknown'; then
      ok "rust target wasm32-unknown-unknown"
    else
      fail "rust target wasm32-unknown-unknown missing: rustup target add wasm32-unknown-unknown"
    fi
  else
    warn "rustup not found; cannot check the wasm32-unknown-unknown target the web console needs"
  fi

  section "Multiplexer (just start: Herdr first, tmux fallback)"
  want="${PERMESI_MUX:-auto}"
  pick=none
  if have herdr; then
    if herdr status server 2>/dev/null | grep -q 'status: running'; then
      if herdr status 2>/dev/null | grep -q 'endpoint_compatible: yes'; then
        ok "herdr $(herdr --version 2>/dev/null | awk '{print $2}') (server running)"
      else
        warn "herdr server is running but reports an incompatible endpoint; see \`herdr status\`"
      fi
    else
      ok "herdr $(herdr --version 2>/dev/null | awk '{print $2}') (just start will launch a headless server)"
    fi
    [[ "$want" == "auto" || "$want" == "herdr" ]] && pick=herdr
  else
    warn "herdr not installed (preferred): ${hint_install}"
  fi
  if have tmux; then
    tv="$(tmux -V 2>/dev/null | awk '{print $2}' | tr -cd '0-9.')"
    if [[ -n "$tv" ]] && is-at-least 3.2 "$tv"; then ok "tmux ${tv} (fallback)"; else warn "tmux ${tv:-unknown} is older than 3.2; the tmux fallback needs new-session -e"; fi
    [[ "$pick" == "none" && "$want" != "none" && "$want" != "herdr" ]] && pick=tmux
  fi
  [[ "$want" == "none" ]] && pick=none
  if [[ "$pick" == "none" && "$want" != "none" ]]; then
    warn "neither herdr nor tmux is usable; just start will only start the infra and print the service commands"
  else
    ok "just start will use: ${pick} (PERMESI_MUX=${want})"
  fi

  section "Optional tools"
  for pair in "trunk:just web installs a pinned release" "direnv:loads .envrc automatically" \
      "mkcert:laptop-local TLS (a remote VM gets its cert from scripts/dev-remote)" \
      "xh:just genesis-token" "python3:just genesis-token" "uv:schemathesis recipes" \
      "openssl:schemathesis auth recipes" "lsof:just stop process cleanup"; do
    tool="${pair%%:*}"
    if have "$tool"; then ok "$tool"; else warn "$tool missing (${pair#*:})"; fi
  done

  section "Settings"
  ok "PERMESI_BIND_ADDR={{bind_addr}} PERMESI_HTTPS_PORT={{https_port}} PERMESI_NET={{net}} PERMESI_SUBNET={{subnet}}"
  if [[ "{{bind_addr}}" == "0.0.0.0" ]]; then
    warn "PERMESI_BIND_ADDR=0.0.0.0 exposes Postgres (trust auth) and Vault (root token on disk) to the network"
  fi
  if [[ -f "${root}/.envrc" ]]; then
    baked="$(sed -n 's/^export PERMESI_HTTPS_PORT="\${PERMESI_HTTPS_PORT:-\([0-9]*\)}"$/\1/p' "${root}/.envrc")"
    if [[ -n "$baked" && "$baked" != "{{https_port}}" ]]; then
      warn ".envrc was generated for port ${baked}, not {{https_port}}: run \`just dev-envrc\` (or \`just restart\`)"
    fi
  fi

  section "Host"
  port="{{https_port}}"
  if [[ "$os" == "Linux" ]] && (( port < 1024 )); then
    start="$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)"
    if (( port < start )); then
      fail "port ${port} is privileged (ip_unprivileged_port_start=${start}): run \`just haproxy-sysctl\` or export PERMESI_HTTPS_PORT=8443"
    else
      ok "unprivileged binds allowed from port ${start}"
    fi
  fi
  resolved=""
  if [[ "$os" == "Darwin" ]]; then
    resolved="$(dscacheutil -q host -a name genesis.permesi.localhost 2>/dev/null | awk '/address:/{print $2}')"
  elif have getent; then
    resolved="$(getent hosts genesis.permesi.localhost 2>/dev/null | awk '{print $1}')"
  fi
  if print -r -- "$resolved" | grep -Eq '^(127\.|::1$)'; then
    ok "*.permesi.localhost resolves to loopback for the services"
  else
    fail "genesis.permesi.localhost does not resolve to loopback (permesi fetches PASERK by that name); add '127.0.0.1 permesi.localhost api.permesi.localhost genesis.permesi.localhost' to /etc/hosts"
  fi
  if [[ -n "${SSH_CONNECTION:-}" ]] && have loginctl; then
    if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" == "yes" ]]; then
      ok "systemd linger enabled (containers and sessions survive logout)"
    else
      warn "systemd linger is off: containers and the dev session may stop when you log out; run \`loginctl enable-linger $USER\`"
    fi
  fi
  owner_cwd() {
    local pid cwd
    for pid in ${=$(lsof -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null)}; do
      if [[ -r "/proc/${pid}/cwd" ]]; then
        cwd="$(readlink "/proc/${pid}/cwd" 2>/dev/null)"
      else
        cwd="$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')"
      fi
      print -r -- "$cwd"
    done
  }
  listening() {
    if have lsof; then
      lsof -t -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    elif have ss; then
      [[ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]]
    else
      return 1
    fi
  }
  running() { [[ -n "$(podman ps -q --filter "name=^$1\$" 2>/dev/null)" ]]; }
  for spec in "5432:postgres-permesi" "8200:{{vault_ctr}}" "16686:{{jaeger_ctr}}" "4317:{{jaeger_ctr}}" "${port}:permesi-haproxy"; do
    p="${spec%%:*}"
    ctr="${spec#*:}"
    if listening "$p" && ! running "$ctr"; then
      warn "port ${p} is taken by something other than ${ctr}; ${ctr} will fail to start"
    fi
  done
  if have lsof; then
    for p in 8000 8001 8081; do
      for cwd in ${(f)"$(owner_cwd "$p")"}; do
        if [[ -n "$cwd" && "$cwd" != "$root" && "$cwd" != "$root"/* ]]; then
          warn "port ${p} is held by a process outside this checkout (${cwd}); the matching service cannot bind"
        fi
      done
    done
  fi

  section "Isolation"
  if have podman; then
    if podman network exists {{net}} 2>/dev/null; then
      current="$(podman network inspect {{net}} --format '{{{{range .Subnets}}{{{{.Subnet}} {{{{end}}' 2>/dev/null)"
      current="${current% }"
      if [[ " ${current} " == *" {{subnet}} "* ]]; then
        ok "podman network {{net}} uses {{subnet}}"
      else
        fail "podman network {{net}} uses ${current:-no subnet}, expected {{subnet}}: remove it or set PERMESI_SUBNET"
      fi
    else
      ok "podman network {{net}} will be created with {{subnet}}"
    fi
    if [[ "$os" == "Linux" ]] && have ip; then
      ip2int() { local a b c d; IFS=. read -r a b c d <<<"$1"; print -r -- $(( (a << 24) + (b << 16) + (c << 8) + d )); }
      net_ip="{{subnet}}"; net_ip="${net_ip%/*}"; net_len="{{subnet}}"; net_len="${net_len#*/}"
      n1=$(ip2int "$net_ip"); m1=$(( (0xFFFFFFFF << (32 - net_len)) & 0xFFFFFFFF ))
      for route in ${(f)"$(ip -o -4 route show 2>/dev/null | awk '$1 ~ /\// {print $1" "$3}')"}; do
        dst="${route%% *}"; dev="${route#* }"
        r_ip="${dst%/*}"; r_len="${dst#*/}"
        n2=$(ip2int "$r_ip"); m2=$(( (0xFFFFFFFF << (32 - r_len)) & 0xFFFFFFFF ))
        m=$(( m1 < m2 ? m1 : m2 ))
        if (( (n1 & m) == (n2 & m) )); then
          fail "{{subnet}} overlaps host route ${dst} (dev ${dev}); containers could not reach that range: set PERMESI_SUBNET to a free range"
        fi
      done
    fi
    leaked="$(podman ps -a --format '{{{{.Names}}' 2>/dev/null | grep -c '^permesi-test-' || true)"
    leaked_nets="$(podman network ls --format '{{{{.Name}}' 2>/dev/null | grep -c '^permesi-test-' || true)"
    if (( leaked + leaked_nets > 0 )); then
      warn "${leaked} leaked test container(s) and ${leaked_nets} test network(s): run \`just test-clean\`"
    fi
    for legacy in vault jaeger; do
      if podman container exists "$legacy" 2>/dev/null; then
        nets="$(podman container inspect "$legacy" --format '{{{{range $k, $v := .NetworkSettings.Networks}}{{{{$k}} {{{{end}}' 2>/dev/null)"
        if [[ " ${nets} " == *" {{net}} "* ]]; then
          warn "legacy container '${legacy}' from the old permesi flow is still around: podman rm -f ${legacy}"
        fi
      fi
    done
    for ctr in ${(f)"$(podman ps --filter label={{stack_label}} --format '{{{{.Names}}' 2>/dev/null)"}; do
      nets="$(podman container inspect "$ctr" --format '{{{{range $k, $v := .NetworkSettings.Networks}}{{{{$k}} {{{{end}}' 2>/dev/null)"
      if [[ " ${nets} " != *" {{net}} "* ]]; then
        warn "${ctr} runs outside {{net}}: restart it with \`just stop && just start\`"
      fi
    done
  fi

  section "Vault state"
  keys="${root}/vault/keys.json"
  volume=0
  have podman && podman volume exists permesi-vault-data 2>/dev/null && volume=1
  if [[ -f "$keys" ]]; then
    if jq -e '.unseal_keys_b64' "$keys" >/dev/null 2>&1; then
      ok "vault/keys.json holds the persistent Vault's unseal key"
    elif (( volume )); then
      fail "vault/keys.json has no unseal key but the persistent Vault volume exists (overwritten by \`just vault\`?): run \`just vault-reset\`"
    else
      ok "vault/keys.json is from the ephemeral dev Vault"
    fi
  elif (( volume )); then
    fail "the Vault volume permesi-vault-data exists but vault/keys.json is missing, so Vault cannot be unsealed: restore the keys file or run \`just vault-reset\`"
  else
    ok "no Vault state yet; just start initializes it"
  fi

  print -r -- ""
  if (( fails )); then
    print -r -- "✗ ${fails} problem(s), ${warns} warning(s)."
    exit 1
  fi
  print -r -- "✓ Ready (${warns} warning(s))."
