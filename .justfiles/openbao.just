# ----------------------
# Local dependencies
# ----------------------

# Refuse to run the ephemeral dev-mode OpenBao over a persistent OpenBao's keys file:
# `openbao` overwrites openbao/keys.json with the dev root token, which would destroy
# the only copy of the persistent OpenBao's unseal key.
_openbao-keys-guard:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/openbao/keys.json"
  if [[ -f "$keys" ]] && jq -e '.unseal_keys_b64' "$keys" >/dev/null 2>&1; then
    echo "❌ ${keys} belongs to the persistent OpenBao (it holds the unseal key)." >&2
    echo "   Running the ephemeral dev OpenBao would overwrite it. Run: just openbao-reset" >&2
    exit 1
  fi

openbao: _openbao-keys-guard openbao-stop setup-network
  #!/usr/bin/env zsh
  set -euo pipefail

  # Ensure clean slate for ephemeral dev
  rm -rf {{root}}/openbao/contrib/terraform/.terraform \
         {{root}}/openbao/contrib/terraform/terraform.tfstate \
         {{root}}/openbao/contrib/terraform/terraform.tfstate.backup

  if [[ -n "$(podman ps -q --filter 'name=^{{openbao_ctr}}$')" ]]; then
    echo "openbao already running"
    exit 0
  fi

  # Start ephemeral openbao (memory backend)
  podman run --replace --rm -d --name {{openbao_ctr}} \
    --network {{net}} \
    --label {{stack_label}} \
    -p {{publish_ip}}8200:8200 \
    -v {{root}}/openbao/audit.hcl:/openbao/config/audit.hcl:ro \
    -e BAO_DEV_ROOT_TOKEN_ID=dev-root \
    -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    {{openbao_image}}

  # Create a temporary keys file for openbao-tf-apply to consume
  mkdir -p {{root}}/openbao
  echo '{"root_token": "dev-root"}' > {{root}}/openbao/keys.json

  echo "Waiting for OpenBao..."
  just openbao-wait

  # Dev mode pre-mounts a KV engine at secret/, which shadows the secret/permesi
  # mount Terraform creates.
  podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=dev-root \
    {{openbao_ctr}} bao secrets disable secret >/dev/null

  echo "Applying Terraform configuration..."
  just openbao-tf-apply

openbao-persist: setup-network
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^{{openbao_ctr}}$')" ]]; then
    if podman inspect {{openbao_ctr}} | jq -r '.[0].Mounts[]?.Destination' | rg -q '^/workspace/openbao$'; then
      echo "openbao already running"
      exit 0
    fi
    echo "openbao running without /workspace/openbao mount; restarting with persisted config."
    podman stop {{openbao_ctr}} >/dev/null 2>&1 || true
  fi
  podman volume inspect permesi-openbao-data >/dev/null 2>&1 || podman volume create --label {{stack_label}} permesi-openbao-data >/dev/null
  # The image runs as the unprivileged `openbao` user, which owns /openbao/file and
  # /openbao/logs; a fresh named volume inherits that ownership.
  podman run --replace --rm -d --name {{openbao_ctr}} \
    --network {{net}} \
    --label {{stack_label}} \
    -p {{publish_ip}}8200:8200 \
    -v {{root}}/openbao/config.hcl:/openbao/config/openbao.hcl:ro \
    -v {{root}}/openbao/audit.hcl:/openbao/config/audit.hcl:ro \
    -v {{root}}/openbao:/workspace/openbao:ro \
    -v permesi-openbao-data:/openbao/file \
    --entrypoint bao \
    {{openbao_image}} \
    server -config=/openbao/config

openbao-wait:
  #!/usr/bin/env zsh
  set -euo pipefail
  for _ in {1..40}; do
    openbao_status="$(
      podman exec {{openbao_ctr}} sh -c 'BAO_ADDR=http://127.0.0.1:8200 bao status -format=json 2>/dev/null || true' 2>/dev/null || true
    )"
    if [[ -n "$openbao_status" ]] && rg -q '"initialized":' <<<"$openbao_status"; then
      exit 0
    fi
    sleep 0.5
  done
  echo "OpenBao did not respond on http://127.0.0.1:8200" >&2
  exit 1

openbao-init:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/openbao/keys.json"
  mkdir -p {{root}}/openbao
  if [[ -f "$keys" ]]; then
    echo "OpenBao already initialized (keys file exists)."
    exit 0
  fi
  just openbao-wait
  openbao_status="$(
    podman exec {{openbao_ctr}} sh -c 'BAO_ADDR=http://127.0.0.1:8200 bao status -format=json 2>/dev/null || true'
  )"
  if [[ -z "$openbao_status" ]]; then
    echo "OpenBao status unavailable; is the server running?" >&2
    exit 1
  fi
  initialized="$(printf '%s' "$openbao_status" | jq -r '.initialized')"
  if [[ "$initialized" == "true" ]]; then
    echo "OpenBao is already initialized but ${keys} is missing." >&2
    echo "Restore the keys file or reset the openbao data volume." >&2
    exit 1
  fi
  podman exec {{openbao_ctr}} sh -c 'BAO_ADDR=http://127.0.0.1:8200 bao operator init -key-shares=1 -key-threshold=1 -format=json' > "$keys"
  chmod 600 "$keys"
  echo "Wrote ${keys}"

openbao-unseal:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/openbao/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just openbao-init" >&2
    exit 1
  fi
  just openbao-wait
  openbao_status="$(
    podman exec {{openbao_ctr}} sh -c 'BAO_ADDR=http://127.0.0.1:8200 bao status -format=json 2>/dev/null || true'
  )"
  sealed="$(printf '%s' "$openbao_status" | jq -r '.sealed')"
  if [[ "$sealed" != "true" ]]; then
    echo "OpenBao already unsealed."
    exit 0
  fi
  unseal_key="$(jq -r '.unseal_keys_b64[0]' "$keys")"
  podman exec {{openbao_ctr}} sh -c "BAO_ADDR=http://127.0.0.1:8200 bao operator unseal '${unseal_key}'" >/dev/null
  echo "OpenBao unsealed."


openbao-tf-apply:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/openbao/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just openbao-init" >&2
    exit 1
  fi
  if ! command -v terraform >/dev/null 2>&1; then
      echo "❌ Terraform not found. Install terraform to use this recipe." >&2
      exit 1
  fi

  token="$(jq -r '.root_token' "$keys")"
  cd {{root}}/openbao/contrib/terraform

    # The hashicorp/vault provider speaks OpenBao's API but only reads VAULT_* variables.
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="$token"
    export TF_VAR_database_host="${TF_VAR_database_host:-postgres-permesi}"
    export TF_VAR_permesi_database_password="${TF_VAR_permesi_database_password:-openbao_permesi}"
    export TF_VAR_genesis_database_password="${TF_VAR_genesis_database_password:-openbao_genesis}"

    echo "Resource initialization (terraform init)..."
    terraform init >/dev/null

    echo "Applying Terraform configuration..."
    terraform apply -auto-approve

    echo "✅ OpenBao configured via Terraform."
    echo "🔑 Operator token: in .envrc as PERMESI_OPERATOR_TOKEN, or mint one with: just operator-token"

openbao-tf-env:
  #!/usr/bin/env zsh
  set -euo pipefail
  cd {{root}}/openbao/contrib/terraform

  if [[ ! -f "terraform.tfstate" ]]; then
      echo "❌ No Terraform state found. Run: just openbao-tf-apply" >&2
      exit 1
  fi

  # Extract values from Terraform output
  vals=$(terraform output -json)
  permesi_role_id=$(echo "$vals" | jq -r '.permesi_role_id.value')
  genesis_role_id=$(echo "$vals" | jq -r '.genesis_role_id.value')

  openbao_addr="http://127.0.0.1:8200"
  approle_mount="${OPENBAO_APPROLE_MOUNT:-approle}"

  token=""
  if [[ -f "{{root}}/openbao/keys.json" ]]; then
      token=$(jq -r '.root_token' "{{root}}/openbao/keys.json")
  elif [[ -n "${BAO_TOKEN:-}" ]]; then
      token="${BAO_TOKEN}"
  fi
  if [[ -z "$token" ]]; then
      echo "❌ Missing BAO_TOKEN (or {{root}}/openbao/keys.json) to generate AppRole SecretIDs." >&2
      exit 1
  fi

  permesi_secret_id="$(
    podman exec \
      -e BAO_ADDR="$openbao_addr" \
      -e BAO_TOKEN="$token" \
      {{openbao_ctr}} \
      bao write -field=secret_id -f "auth/${approle_mount}/role/permesi/secret-id"
  )"
  genesis_secret_id="$(
    podman exec \
      -e BAO_ADDR="$openbao_addr" \
      -e BAO_TOKEN="$token" \
      {{openbao_ctr}} \
      bao write -field=secret_id -f "auth/${approle_mount}/role/genesis/secret-id"
  )"
  operator_token="$(
    podman exec \
      -e BAO_ADDR="$openbao_addr" \
      -e BAO_TOKEN="$token" \
      {{openbao_ctr}} \
      bao token create -policy=permesi-operators -period=24h -field=token
  )"

  root_token=""
  if [[ -f "{{root}}/openbao/keys.json" ]]; then
      root_token=$(jq -r '.root_token' "{{root}}/openbao/keys.json")
  fi

  printf '%s\n' \
    "export BAO_ADDR=\"${openbao_addr}\"" \
    "$([[ -n "${root_token}" ]] && printf 'export BAO_TOKEN="%s"' "${root_token}")" \
    "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
    "" \
    "export GENESIS_DSN=\"postgres://postgres@localhost:5432/genesis\"" \
    "export GENESIS_OPENBAO_URL=\"${openbao_addr%/}/v1/auth/${approle_mount}/login\"" \
    "export GENESIS_OPENBAO_ROLE_ID=\"${genesis_role_id}\"" \
    "export GENESIS_OPENBAO_SECRET_ID=\"${genesis_secret_id}\"" \
    "" \
    "export PERMESI_DSN=\"postgres://postgres@localhost:5432/permesi\"" \
    "export PERMESI_OPENBAO_URL=\"${openbao_addr%/}/v1/auth/${approle_mount}/login\"" \
    "export PERMESI_OPENBAO_ROLE_ID=\"${permesi_role_id}\"" \
    "export PERMESI_OPENBAO_SECRET_ID=\"${permesi_secret_id}\""

openbao-persist-ready: openbao-persist openbao-init openbao-unseal openbao-tf-apply

openbao-env:
  #!/usr/bin/env zsh
  set -e
  # If we have Terraform state, prefer the Terraform env generator
  if [[ -f "{{root}}/openbao/contrib/terraform/terraform.tfstate" ]]; then
      just openbao-tf-env
      exit 0
  fi

  keys="{{root}}/openbao/keys.json"
  if [[ -f "$keys" ]]; then
    openbao_addr="${BAO_ADDR:-http://127.0.0.1:8200}"
    approle_mount="${OPENBAO_APPROLE_MOUNT:-approle}"
    token="$(jq -r '.root_token' "$keys")"
    permesi_role_id="$(
      podman exec \
        -e BAO_ADDR="$openbao_addr" \
        -e BAO_TOKEN="$token" \
        {{openbao_ctr}} \
        bao read -field=role_id "auth/${approle_mount}/role/permesi/role-id"
    )"
    permesi_secret_id="$(
      podman exec \
        -e BAO_ADDR="$openbao_addr" \
        -e BAO_TOKEN="$token" \
        {{openbao_ctr}} \
        bao write -field=secret_id -f "auth/${approle_mount}/role/permesi/secret-id"
    )"
    genesis_role_id="$(
      podman exec \
        -e BAO_ADDR="$openbao_addr" \
        -e BAO_TOKEN="$token" \
        {{openbao_ctr}} \
        bao read -field=role_id "auth/${approle_mount}/role/genesis/role-id"
    )"
    genesis_secret_id="$(
      podman exec \
        -e BAO_ADDR="$openbao_addr" \
        -e BAO_TOKEN="$token" \
        {{openbao_ctr}} \
        bao write -field=secret_id -f "auth/${approle_mount}/role/genesis/secret-id"
    )"
    operator_token="$(
      podman exec \
        -e BAO_ADDR="$openbao_addr" \
        -e BAO_TOKEN="$token" \
        {{openbao_ctr}} \
        bao token create -policy=permesi-operators -period=24h -field=token
    )"
    printf '%s\n' \
      "export BAO_ADDR=\"${openbao_addr}\"" \
      "export BAO_TOKEN=\"${token}\"" \
      "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
      "" \
      "export GENESIS_DSN=\"postgres://postgres@localhost:5432/genesis\"" \
      "export GENESIS_OPENBAO_URL=\"${openbao_addr%/}/v1/auth/${approle_mount}/login\"" \
      "export GENESIS_OPENBAO_ROLE_ID=\"${genesis_role_id}\"" \
      "export GENESIS_OPENBAO_SECRET_ID=\"${genesis_secret_id}\"" \
      "" \
      "export PERMESI_DSN=\"postgres://postgres@localhost:5432/permesi\"" \
      "export PERMESI_OPENBAO_URL=\"${openbao_addr%/}/v1/auth/${approle_mount}/login\"" \
      "export PERMESI_OPENBAO_ROLE_ID=\"${permesi_role_id}\"" \
      "export PERMESI_OPENBAO_SECRET_ID=\"${permesi_secret_id}\""
    exit 0
  fi
  login_url=""
  permesi_role_id=""
  permesi_secret_id=""
  genesis_role_id=""
  genesis_secret_id=""
  for _ in {1..20}; do
    logs="$(podman logs {{openbao_ctr}} 2>/dev/null || true)"
    login_url="$(printf '%s\n' "$logs" | rg "Login URL:" | tail -n 1 | sed -E 's/.*Login URL:[[:space:]]*//')"
    permesi_role_id="$(printf '%s\n' "$logs" | rg "permesi RoleID:" | tail -n 1 | sed -E 's/.*permesi RoleID:[[:space:]]*//')"
    permesi_secret_id="$(printf '%s\n' "$logs" | rg "permesi SecretID:" | tail -n 1 | sed -E 's/.*permesi SecretID:[[:space:]]*//')"
    genesis_role_id="$(printf '%s\n' "$logs" | rg "genesis RoleID:" | tail -n 1 | sed -E 's/.*genesis RoleID:[[:space:]]*//')"
    genesis_secret_id="$(printf '%s\n' "$logs" | rg "genesis SecretID:" | tail -n 1 | sed -E 's/.*genesis SecretID:[[:space:]]*//')"
    operator_token="$(printf '%s\n' "$logs" | rg "Operator Token:" | tail -n 1 | sed -E 's/.*Operator Token:[[:space:]]*//')"
    if [[ -n "$login_url" && -n "$permesi_role_id" && -n "$permesi_secret_id" && -n "$genesis_role_id" && -n "$genesis_secret_id" && -n "$operator_token" ]]; then
      break
    fi
    sleep 0.5
  done

  if [[ -z "$login_url" || -z "$permesi_role_id" || -z "$permesi_secret_id" || -z "$genesis_role_id" || -z "$genesis_secret_id" || -z "$operator_token" ]]; then
    echo "Missing values in openbao logs. Run: just openbao" >&2
    exit 1
  fi

  openbao_addr="${login_url%/v1/auth/*}"

  printf '%s\n' \
    "export BAO_ADDR=\"${openbao_addr}\"" \
    "export BAO_TOKEN=\"dev-root\"" \
    "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
    "" \
    "export GENESIS_DSN=\"postgres://postgres@localhost:5432/genesis\"" \
    "export GENESIS_OPENBAO_URL=\"${login_url}\"" \
    "export GENESIS_OPENBAO_ROLE_ID=\"${genesis_role_id}\"" \
    "export GENESIS_OPENBAO_SECRET_ID=\"${genesis_secret_id}\"" \
    "" \
    "export PERMESI_DSN=\"postgres://postgres@localhost:5432/permesi\"" \
    "export PERMESI_OPENBAO_URL=\"${login_url}\"" \
    "export PERMESI_OPENBAO_ROLE_ID=\"${permesi_role_id}\"" \
    "export PERMESI_OPENBAO_SECRET_ID=\"${permesi_secret_id}\""

dev-env:
  #!/usr/bin/env zsh
  set -euo pipefail
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet openbao-env > "$tmp"
  openbao_block="$(
    rg -N '^export BAO_' "$tmp"
  )"
  operator_block="$(
    rg -N '^export PERMESI_OPERATOR_TOKEN=' "$tmp"
  )"
  genesis_block="$(
    rg -N '^export GENESIS_' "$tmp"
  )"
  permesi_block="$(
    rg -N '^export PERMESI_' "$tmp" | rg -v '^export PERMESI_OPERATOR_TOKEN='
  )"
  printf '%s\n' \
    "export PERMESI_BIND_ADDR=\"\${PERMESI_BIND_ADDR:-{{bind_addr}}}\"" \
    "export PERMESI_HTTPS_PORT=\"\${PERMESI_HTTPS_PORT:-{{https_port}}}\"" \
    "export OTEL_EXPORTER_OTLP_ENDPOINT=\"\${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}\"" \
    "" \
    "$openbao_block" \
    "$operator_block" \
    "" \
    "$genesis_block" \
    "export GENESIS_TLS_PEM_BUNDLE=\"{{root}}/certs/genesis/tls.bundle.pem\"" \
    "" \
    "$permesi_block" \
    "export PERMESI_TLS_PEM_BUNDLE=\"{{root}}/certs/permesi/tls.bundle.pem\"" \
    "export PERMESI_ADMISSION_PASERK_CA_PATH=\"{{root}}/certs/genesis/ca.pem\"" \
    "export PERMESI_ADMISSION_PASERK_URL=\"https://genesis.permesi.localhost:8000/paserk.json\"" \
    "export PERMESI_FRONTEND_BASE_URL=\"https://permesi.localhost{{https_suffix}}\"" \
    "export PERMESI_API_BASE_URL=\"https://api.permesi.localhost{{https_suffix}}\"" \
    "export PERMESI_TOKEN_BASE_URL=\"https://genesis.permesi.localhost{{https_suffix}}\"" \
    "export PERMESI_PASSKEYS_ALLOWED_ORIGINS=\"https://permesi.localhost{{https_suffix}}\"" \
    "export PERMESI_EMAIL_OUTBOX_POLL_SECONDS=\"10\""

openbao-envrc:
  #!/usr/bin/env zsh
  set -e
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet openbao-env > "$tmp"
  mv "$tmp" .envrc
  echo "Wrote .envrc from OpenBao logs."

openbao-info:
  #!/usr/bin/env zsh
  set -euo pipefail
  echo "OpenBao container mounts:"
  if podman container inspect {{openbao_ctr}} >/dev/null 2>&1; then
    podman container inspect {{openbao_ctr}} \
      | jq -r '.[0].Mounts[]? | "\(.Name)\t\(.Destination)\t\(.Source)"'
  else
    echo "openbao container not running."
  fi
  echo ""
  echo "OpenBao data volume:"
  if podman volume inspect permesi-openbao-data >/dev/null 2>&1; then
    podman volume inspect permesi-openbao-data \
      | jq -r '.[0] | "\(.Name)\t\(.Mountpoint)"'
  else
    echo "permesi-openbao-data volume not found."
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
  echo "Wrote .envrc from OpenBao logs + dev endpoints."

openbao-stop:
  podman stop {{openbao_ctr}} || true

openbao-reset: openbao-stop
  #!/usr/bin/env zsh
  set -euo pipefail
  echo "This will delete the persistent OpenBao volume, keys file, and Terraform state."
  printf "Type 'delete' to continue: "
  read -r confirm
  if [[ "$confirm" != "delete" ]]; then
    echo "Aborted."
    exit 1
  fi
  # Robust volume removal
  if podman volume inspect permesi-openbao-data >/dev/null 2>&1; then
    echo "Removing OpenBao data volume..."
    if ! podman volume rm permesi-openbao-data; then
      echo "❌ Failed to remove volume 'permesi-openbao-data'. It may be in use by another container." >&2
      exit 1
    fi
  else
    echo "OpenBao data volume not found (already deleted)."
  fi

  rm -f {{root}}/openbao/keys.json
  rm -rf {{root}}/openbao/contrib/terraform/.terraform \
         {{root}}/openbao/contrib/terraform/.terraform.lock.hcl \
         {{root}}/openbao/contrib/terraform/terraform.tfstate \
         {{root}}/openbao/contrib/terraform/terraform.tfstate.backup
  echo "OpenBao keys and Terraform state removed."
