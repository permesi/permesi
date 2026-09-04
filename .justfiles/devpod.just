# ----------------------------------------------------------------------------
# DevPod / compose dev path
# ----------------------------------------------------------------------------
# These recipes run *inside* the workspace (`app`) container and target the
# compose sibling services by name (postgres, vault, jaeger) instead of the
# host-podman containers used by the legacy `infra.just` / `vault.just` recipes.
# There is no podman available inside the container, so Vault/Postgres/PKI are
# driven with the `vault`, `psql`, and `terraform` CLIs directly.
#
# Typical flow (after `scripts/dev-up` brings the workspace up):
#   just devpod-bootstrap   # one-time: verify DB, init/unseal Vault, terraform, TLS
#   just devpod-dev         # run genesis/permesi/web in a tmux session
#
# The frontend HAProxy certificate is issued with mkcert (covering
# permesi.localhost + subdomains, which the Vault PKI roles intentionally do
# not allow); backend service certs come from the dev Vault PKI.

vault_addr_devpod := "http://vault:8200"
db_host_devpod := "postgres"

# One-time bootstrap of the compose dev stack.
devpod-bootstrap: devpod-wait-infra devpod-db-verify devpod-vault-init devpod-vault-unseal devpod-vault-tf devpod-tls-certs devpod-envrc
  @echo "✅ DevPod bootstrap complete. Run: just devpod-dev"

# Block until the postgres and vault siblings are reachable.
devpod-wait-infra:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Waiting for postgres ({{db_host_devpod}}:5432)..."
  for _ in $(seq 1 60); do
    if pg_isready -h "{{db_host_devpod}}" -p 5432 -U postgres >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  pg_isready -h "{{db_host_devpod}}" -p 5432 -U postgres >/dev/null
  echo "Waiting for vault ({{vault_addr_devpod}})..."
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "{{vault_addr_devpod}}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200"; then
      break
    fi
    sleep 0.5
  done
  curl -fsS -o /dev/null "{{vault_addr_devpod}}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200"
  echo "✓ Infra reachable."

# Verify the Postgres schema (auto-loaded by the postgres initdb mount).
devpod-db-verify:
  #!/usr/bin/env bash
  set -euo pipefail
  dsn="postgres://postgres@{{db_host_devpod}}:5432/permesi"
  if ! psql "$dsn" -tAc "select 1" >/dev/null 2>&1; then
    echo "❌ Cannot reach database 'permesi' at {{db_host_devpod}}:5432." >&2
    echo "   The postgres sibling loads db/sql/00_init.sql on first start; if the" >&2
    echo "   volume predates a schema change, recreate it: 'devpod stop permesi' or" >&2
    echo "   remove the 'pgdata' volume and re-run 'scripts/dev-up'." >&2
    exit 1
  fi
  tables="$(psql "$dsn" -tAc "select count(*) from information_schema.tables where table_schema='public'")"
  echo "✓ Database 'permesi' reachable (${tables} public tables)."

# Initialize Vault (file storage) and persist unseal keys to vault/keys.json.
devpod-vault-init:
  #!/usr/bin/env bash
  set -euo pipefail
  export VAULT_ADDR="{{vault_addr_devpod}}"
  keys="{{root}}/vault/keys.json"
  mkdir -p "{{root}}/vault"
  if [[ -f "$keys" ]]; then
    echo "Vault already initialized (keys file exists)."
    exit 0
  fi
  initialized="$(vault status -format=json 2>/dev/null || true)"
  initialized="$(printf '%s' "$initialized" | jq -r '.initialized // "unknown"' 2>/dev/null || echo unknown)"
  if [[ "$initialized" == "true" ]]; then
    echo "Vault is already initialized but ${keys} is missing." >&2
    echo "Restore the keys file or recreate the 'vault-data' volume." >&2
    exit 1
  fi
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "$keys"
  chmod 600 "$keys"
  echo "Wrote ${keys}"

# Unseal Vault using the persisted key.
devpod-vault-unseal:
  #!/usr/bin/env bash
  set -euo pipefail
  export VAULT_ADDR="{{vault_addr_devpod}}"
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just devpod-vault-init" >&2
    exit 1
  fi
  # `vault status` exits non-zero when sealed; capture output first so pipefail
  # does not corrupt the parse (otherwise a sealed vault is misread as unsealed).
  sealed="$(vault status -format=json 2>/dev/null || true)"
  sealed="$(printf '%s' "$sealed" | jq -r '.sealed // "unknown"' 2>/dev/null || echo unknown)"
  if [[ "$sealed" == "false" ]]; then
    echo "Vault already unsealed."
    exit 0
  fi
  unseal_key="$(jq -r '.unseal_keys_b64[0]' "$keys")"
  vault operator unseal "$unseal_key" >/dev/null
  echo "Vault unsealed."

# Apply the Vault Terraform configuration (DB engine, AppRole, PKI, transit).
devpod-vault-tf:
  #!/usr/bin/env bash
  set -euo pipefail
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just devpod-vault-init" >&2
    exit 1
  fi
  if ! command -v terraform >/dev/null 2>&1; then
    echo "❌ terraform not found (expected via mise)." >&2
    exit 1
  fi
  export VAULT_ADDR="{{vault_addr_devpod}}"
  export VAULT_TOKEN="$(jq -r '.root_token' "$keys")"
  export TF_VAR_database_host="${TF_VAR_database_host:-{{db_host_devpod}}}"
  export TF_VAR_permesi_database_password="${TF_VAR_permesi_database_password:-vault_permesi}"
  export TF_VAR_genesis_database_password="${TF_VAR_genesis_database_password:-vault_genesis}"
  cd "{{root}}/vault/contrib/terraform"
  echo "Resource initialization (terraform init)..."
  terraform init >/dev/null
  echo "Applying Terraform configuration..."
  terraform apply -auto-approve
  echo "✅ Vault configured via Terraform."

# Issue TLS material: mkcert frontend cert + Vault PKI backend certs.
devpod-tls-certs:
  #!/usr/bin/env bash
  set -euo pipefail
  export VAULT_ADDR="{{vault_addr_devpod}}"
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just devpod-vault-init" >&2
    exit 1
  fi
  export VAULT_TOKEN="$(jq -r '.root_token' "$keys")"
  certs_dir="{{root}}/certs"
  haproxy_certs="{{root}}/config/haproxy/certs"
  mkdir -p "$certs_dir" "$haproxy_certs"

  # --- Frontend cert (mkcert) ---
  if ! command -v mkcert >/dev/null 2>&1; then
    echo "❌ mkcert not found (expected from postcreate)." >&2
    exit 1
  fi
  # If the host shared its mkcert CA (scripts/trust-ca, gated by PERMESI_TRUST_CA=1),
  # issue the frontend cert from that host-owned, host-trusted CA so browsers accept
  # https://permesi.localhost with no per-recreate re-trust. Otherwise mkcert falls
  # back to its container CAROOT (cert is valid but the host must import the CA once).
  shared_caroot="${certs_dir}/mkcert-caroot"
  if [[ -f "${shared_caroot}/rootCA.pem" && -f "${shared_caroot}/rootCA-key.pem" ]]; then
    export CAROOT="${shared_caroot}"
    echo "Using host-shared mkcert CA: ${shared_caroot}"
    # Force reissue so the cert always chains to the (possibly changed) host CA.
    rm -f "${haproxy_certs}/permesi.localhost.pem" \
      "${haproxy_certs}/permesi.localhost-cert.pem" \
      "${haproxy_certs}/permesi.localhost-key.pem"
  fi
  front_cert="${haproxy_certs}/permesi.localhost.pem"
  if [[ ! -f "$front_cert" ]]; then
    mkcert -key-file "${haproxy_certs}/permesi.localhost-key.pem" \
      -cert-file "${haproxy_certs}/permesi.localhost-cert.pem" \
      "localhost" "127.0.0.1" "::1" "*.localhost" \
      "permesi.localhost" "api.permesi.localhost" "genesis.permesi.localhost" \
      "*.permesi.localhost"
    cat "${haproxy_certs}/permesi.localhost-cert.pem" \
        "${haproxy_certs}/permesi.localhost-key.pem" > "$front_cert"
    echo "Wrote ${front_cert}"
  else
    echo "Frontend cert already present: ${front_cert}"
  fi
  caroot="$(mkcert -CAROOT)"
  if [[ -f "${caroot}/rootCA.pem" ]]; then
    cp "${caroot}/rootCA.pem" "${certs_dir}/mkcert-root.pem"
    chmod 0644 "${certs_dir}/mkcert-root.pem"
    echo "Host trust CA exported: ${certs_dir}/mkcert-root.pem"
  fi

  # --- Backend service certs (Vault PKI) ---
  issue_cert() {
    local service="$1" common_name="$2" alt_names="$3"
    local out_dir="${certs_dir}/${service}"
    mkdir -p "$out_dir"; chmod 0755 "$out_dir"
    local cert_json
    cert_json="$(vault write -format=json "pki-int/issue/${service}-runtime" \
      "common_name=${common_name}" "alt_names=${alt_names}" "ttl=24h")"
    local tls_cert tls_key issuing_ca ca_chain full_ca
    tls_cert="$(jq -er '.data.certificate' <<<"$cert_json")"
    tls_key="$(jq -er '.data.private_key' <<<"$cert_json")"
    issuing_ca="$(jq -er '.data.issuing_ca' <<<"$cert_json")"
    ca_chain="$(jq -er '.data.ca_chain | join("\n")' <<<"$cert_json")"
    full_ca="${ca_chain:-$issuing_ca}"
    printf '%s\n' "$tls_cert" > "${out_dir}/tls.crt"; chmod 0644 "${out_dir}/tls.crt"
    printf '%s\n' "$tls_key" > "${out_dir}/tls.key"; chmod 0600 "${out_dir}/tls.key"
    printf '%s\n' "$full_ca" > "${out_dir}/ca.pem"; chmod 0644 "${out_dir}/ca.pem"
    printf '%s\n%s\n%s' "$tls_key" "$tls_cert" "$full_ca" > "${out_dir}/tls.bundle.pem"
    chmod 0600 "${out_dir}/tls.bundle.pem"
  }
  issue_cert permesi "api.permesi.localhost" "api.permesi.localhost"
  issue_cert genesis "genesis.permesi.localhost" "genesis.permesi.localhost"
  echo "Wrote backend TLS certs to ${certs_dir}/permesi and ${certs_dir}/genesis."

# Print the dev .envrc (sibling endpoints + Vault AppRole creds + dev URLs).
devpod-env:
  #!/usr/bin/env bash
  set -euo pipefail
  export VAULT_ADDR="{{vault_addr_devpod}}"
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just devpod-vault-init" >&2
    exit 1
  fi
  export VAULT_TOKEN="$(jq -r '.root_token' "$keys")"
  approle_mount="${VAULT_APPROLE_MOUNT:-approle}"
  login_url="{{vault_addr_devpod}}/v1/auth/${approle_mount}/login"
  permesi_role_id="$(vault read -field=role_id "auth/${approle_mount}/role/permesi/role-id")"
  permesi_secret_id="$(vault write -field=secret_id -f "auth/${approle_mount}/role/permesi/secret-id")"
  genesis_role_id="$(vault read -field=role_id "auth/${approle_mount}/role/genesis/role-id")"
  genesis_secret_id="$(vault write -field=secret_id -f "auth/${approle_mount}/role/genesis/secret-id")"
  operator_token="$(vault token create -policy=permesi-operators -period=24h -field=token)"
  printf '%s\n' \
    "export VAULT_ADDR=\"{{vault_addr_devpod}}\"" \
    "export VAULT_TOKEN=\"${VAULT_TOKEN}\"" \
    "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
    "" \
    "export GENESIS_DSN=\"postgres://postgres@{{db_host_devpod}}:5432/genesis\"" \
    "export GENESIS_VAULT_URL=\"${login_url}\"" \
    "export GENESIS_VAULT_ROLE_ID=\"${genesis_role_id}\"" \
    "export GENESIS_VAULT_SECRET_ID=\"${genesis_secret_id}\"" \
    "export GENESIS_TLS_PEM_BUNDLE=\"{{root}}/certs/genesis/tls.bundle.pem\"" \
    "# In-container API helpers (e.g. 'just genesis-token', schemathesis) hit genesis" \
    "# directly: inside the app container the *.permesi.localhost names resolve to" \
    "# loopback, where only :8000/:8001 listen (HAProxy runs in a separate deps" \
    "# container), so verify against the Vault PKI CA rather than the mkcert frontend." \
    "export GENESIS_API_BASE_URL=\"https://genesis.permesi.localhost:8000\"" \
    "export GENESIS_CA_PATH=\"{{root}}/certs/genesis/ca.pem\"" \
    "" \
    "export PERMESI_DSN=\"postgres://postgres@{{db_host_devpod}}:5432/permesi\"" \
    "export PERMESI_VAULT_URL=\"${login_url}\"" \
    "export PERMESI_VAULT_ROLE_ID=\"${permesi_role_id}\"" \
    "export PERMESI_VAULT_SECRET_ID=\"${permesi_secret_id}\"" \
    "export PERMESI_TLS_PEM_BUNDLE=\"{{root}}/certs/permesi/tls.bundle.pem\"" \
    "export PERMESI_ADMISSION_PASERK_CA_PATH=\"{{root}}/certs/genesis/ca.pem\"" \
    "export PERMESI_ADMISSION_PASERK_URL=\"https://genesis.permesi.localhost:8000/paserk.json\"" \
    "export PERMESI_FRONTEND_BASE_URL=\"https://permesi.localhost\"" \
    "export PERMESI_API_BASE_URL=\"https://api.permesi.localhost\"" \
    "export PERMESI_TOKEN_BASE_URL=\"https://genesis.permesi.localhost\"" \
    "export PERMESI_PASSKEYS_ALLOWED_ORIGINS=\"https://permesi.localhost\"" \
    "export PERMESI_EMAIL_OUTBOX_POLL_SECONDS=\"10\"" \
    "" \
    "# Tracing to the jaeger sibling (UI: http://localhost:16686). Unset to disable." \
    "export OTEL_EXPORTER_OTLP_ENDPOINT=\"http://jaeger:4317\""

# Write .envrc from devpod-env and allow direnv.
devpod-envrc:
  #!/usr/bin/env bash
  set -euo pipefail
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet devpod-env > "$tmp"
  mv "$tmp" "{{root}}/.envrc"
  if command -v direnv >/dev/null 2>&1; then
    direnv allow "{{root}}" >/dev/null 2>&1 || true
  fi
  echo "Wrote {{root}}/.envrc for the compose dev stack."

# Apply host git identity and SSH commit signing from the environment forwarded by
# scripts/dev-up. With no explicit signing program, Git uses ssh-keygen and the
# forwarded SSH agent instead of a host-only signing helper.
devpod-git-config:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ -n "${GIT_USER_NAME:-}" ]]; then
    git config --global user.name "$GIT_USER_NAME"
  fi
  if [[ -n "${GIT_USER_EMAIL:-}" ]]; then
    git config --global user.email "$GIT_USER_EMAIL"
  fi
  if [[ -n "${GIT_SIGNING_KEY:-}" ]]; then
    git config --global gpg.format ssh
    git config --global user.signingkey "$GIT_SIGNING_KEY"
    git config --global commit.gpgsign true
    if [[ -n "${GIT_SSH_SIGNING_PROGRAM:-}" ]]; then
      git config --global gpg.ssh.program "$GIT_SSH_SIGNING_PROGRAM"
    else
      git config --global --unset-all gpg.ssh.program 2>/dev/null || true
    fi
    echo "Configured git identity + SSH commit signing (${GIT_USER_EMAIL:-no email})."
  elif [[ -n "${GIT_USER_NAME:-}${GIT_USER_EMAIL:-}" ]]; then
    echo "Configured git identity (${GIT_USER_EMAIL:-no email}); signing off (GIT_SIGNING_KEY unset)."
  else
    echo "No GIT_* env forwarded; set GIT_USER_NAME/GIT_USER_EMAIL/GIT_SIGNING_KEY in .devpod.env."
  fi

# Make the stack ready on every container start: wait for the siblings, unseal
# Vault (it re-seals across restarts), refresh .envrc, and start the services in
# tmux. Set PERMESI_DEVPOD_NO_AUTOSTART=1 to skip starting the services.
devpod-start: devpod-wait-infra devpod-vault-unseal devpod-envrc
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ "${PERMESI_DEVPOD_NO_AUTOSTART:-}" == "1" ]]; then
    echo "Service auto-start disabled (PERMESI_DEVPOD_NO_AUTOSTART=1). Run: just devpod-dev"
    exit 0
  fi
  just devpod-dev

# Run genesis/permesi/web in a tmux session named 'permesi' (uses your default prefix).
# Attach to watch the 3 panes, detach to go back to coding; services keep running.
devpod-dev:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ ! -f "{{root}}/.envrc" ]]; then
    echo "Missing {{root}}/.envrc. Run: just devpod-bootstrap" >&2
    exit 1
  fi
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux not found; run services manually: just genesis / just permesi / just web" >&2
    exit 1
  fi
  session="permesi"
  if tmux has-session -t "$session" 2>/dev/null; then
    echo "tmux session '${session}' already running. Attach: tmux attach -t ${session}"
    exit 0
  fi
  # Pre-build the native service binaries once, in parallel, so genesis and permesi
  # don't serialize on the shared CARGO_TARGET_DIR build lock when they start under
  # cargo-watch (the lock is per target dir, so otherwise only one compiles at a time
  # while the others wait — leaving CPU cores idle). Skip with
  # PERMESI_DEVPOD_NO_PREBUILD=1.
  if [[ "${PERMESI_DEVPOD_NO_PREBUILD:-}" != "1" ]] && command -v cargo >/dev/null 2>&1; then
    echo "Pre-building genesis + permesi (parallel; avoids cargo-watch lock contention)..."
    ( cd "{{root}}" && cargo build -p genesis -p permesi ) \
      || echo "Pre-build failed (continuing; services will build on start)." >&2
  fi
  left="$(tmux new-session -d -s "$session" -c "{{root}}" -P -F "#{pane_id}" "just genesis")"
  right="$(tmux split-window -t "$left" -h -c "{{root}}" -P -F "#{pane_id}" "just permesi")"
  web="$(tmux split-window -t "$left" -v -c "{{root}}" -P -F "#{pane_id}" "just web")"
  tmux split-window -t "$right" -v -c "{{root}}"
  # Stable titles so `just devpod-logs` can find panes regardless of index renumbering.
  tmux select-pane -t "$left" -T genesis
  tmux select-pane -t "$right" -T permesi
  tmux select-pane -t "$web" -T web
  tmux set-option -t "$session" pane-border-status top
  # Keep a service pane visible (as "[dead]") if its command exits unexpectedly,
  # so a crash/timeout leaves diagnosable output instead of silently vanishing.
  tmux set-option -t "$session" remain-on-exit on
  tmux select-pane -t "$left"
  echo "Started services in tmux session '${session}'."
  echo "  Watch:  tmux attach -t ${session}    (detach with your tmux prefix + d)"
  echo "  Logs:   just devpod-logs [genesis|permesi|web]   (no attach; avoids nesting)"

# Tail a service's output without attaching tmux (handy when nested in a host tmux).
devpod-logs service="":
  #!/usr/bin/env bash
  set -euo pipefail
  if ! tmux has-session -t permesi 2>/dev/null; then
    echo "No 'permesi' session. Start it: just devpod-dev" >&2
    exit 1
  fi
  pane_for() {
    tmux list-panes -t permesi -F '#{pane_title} #{pane_id}' | awk -v s="$1" '$1==s{print $2; exit}'
  }
  svc="{{service}}"
  if [[ -n "$svc" ]]; then
    case "$svc" in genesis|permesi|web) ;; *) echo "usage: just devpod-logs [genesis|permesi|web]" >&2; exit 1 ;; esac
    id="$(pane_for "$svc")"
    [[ -n "$id" ]] || { echo "pane '$svc' not found" >&2; exit 1; }
    exec tmux capture-pane -pt "$id" -S -200
  fi
  for name in genesis permesi web; do
    id="$(pane_for "$name")"
    [[ -n "$id" ]] || continue
    echo "===== ${name} ====="
    tmux capture-pane -pt "$id" -S -40
    echo
  done

# Stop the dev tmux session (deps run in the same compose project; this only stops
# the in-app services).
# Killing the tmux panes is not enough: `cargo watch` re-execs the service binaries,
# which get reparented to PID 1 and keep holding :8000/:8001, and `trunk serve`
# survives too on :8081. Left running, they make the next `just devpod-dev` fail with
# "Address already in use". Reap the watchers, the genesis/permesi binaries, and the
# web toolchain by command pattern so restarts are reliable.
devpod-dev-stop:
  #!/usr/bin/env bash
  tmux kill-session -t permesi 2>/dev/null || true
  for pat in 'trunk serve' 'cargo-watch' 'debug/genesis' 'debug/permesi' 'css:watch'; do
    pkill -f "$pat" 2>/dev/null || true
  done
  echo "Stopped tmux session 'permesi' and reaped dev service processes (if any)."

# Print guidance for trusting the dev CA on the host browser.
devpod-trust-ca:
  #!/usr/bin/env bash
  set -euo pipefail
  ca="{{root}}/certs/mkcert-root.pem"
  if [[ ! -f "$ca" ]]; then
    echo "Missing ${ca}. Run: just devpod-tls-certs" >&2
    exit 1
  fi
  echo "Recommended (automatic): let the HOST own the mkcert CA so certs are valid"
  echo "in your browser with no manual import and no re-trust after recreates:"
  echo "  PERMESI_TRUST_CA=1 scripts/dev-up      # or run: scripts/trust-ca"
  echo
  echo "Manual alternative — trust this CA on your HOST:"
  echo "  ${ca}"
  echo
  echo "Firefox: Settings → Privacy & Security → Certificates → View Certificates"
  echo "         → Authorities → Import → select the file → trust for websites."
  echo "Chromium: Settings → Privacy → Security → Manage certificates → Authorities → Import."
  echo "Also add to /etc/hosts on the host if needed:"
  echo "  127.0.0.1 permesi.localhost api.permesi.localhost genesis.permesi.localhost"
