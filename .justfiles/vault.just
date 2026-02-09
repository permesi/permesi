# ----------------------
# Local dependencies
# ----------------------

vault: vault-stop
  #!/usr/bin/env zsh
  set -euo pipefail

  # Ensure clean slate for ephemeral dev
  rm -rf {{root}}/vault/contrib/terraform/.terraform \
         {{root}}/vault/contrib/terraform/terraform.tfstate \
         {{root}}/vault/contrib/terraform/terraform.tfstate.backup

  if [[ -n "$(podman ps -q --filter 'name=^vault$')" ]]; then
    echo "vault already running"
    exit 0
  fi

  # Start ephemeral vault (memory backend)
  podman run --replace --rm -d --name vault \
    --network {{net}} \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
    -e VAULT_LISTEN_ADDRESS=0.0.0.0:8200 \
    hashicorp/vault:latest

  # Create a temporary keys file for vault-tf-apply to consume
  mkdir -p {{root}}/vault
  echo '{"root_token": "dev-root"}' > {{root}}/vault/keys.json

  echo "Waiting for Vault..."
  just vault-wait

  echo "Applying Terraform configuration..."
  just vault-tf-apply

vault-persist:
  #!/usr/bin/env zsh
  set -euo pipefail
  if [[ -n "$(podman ps -q --filter 'name=^vault$')" ]]; then
    if podman inspect vault | jq -r '.[0].Mounts[]?.Destination' | rg -q '^/workspace/vault$'; then
      echo "vault already running"
      exit 0
    fi
    echo "vault running without /workspace/vault mount; restarting with persisted config."
    podman stop vault >/dev/null 2>&1 || true
  fi
  podman volume inspect permesi-vault-data >/dev/null 2>&1 || podman volume create permesi-vault-data >/dev/null
  podman run --replace --rm -d --name vault \
    --network {{net}} \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -v {{root}}/vault/config.hcl:/vault/config/vault.hcl:ro \
    -v {{root}}/vault:/workspace/vault:ro \
    -v permesi-vault-data:/vault/data \
    --entrypoint vault \
    hashicorp/vault:latest \
    server -config=/vault/config/vault.hcl

vault-wait:
  #!/usr/bin/env zsh
  set -euo pipefail
  for _ in {1..40}; do
    vault_status="$(
      podman exec vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json 2>/dev/null || true' 2>/dev/null || true
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


vault-tf-apply:
  #!/usr/bin/env zsh
  set -euo pipefail
  keys="{{root}}/vault/keys.json"
  if [[ ! -f "$keys" ]]; then
    echo "Missing ${keys}. Run: just vault-init" >&2
    exit 1
  fi
  if ! command -v terraform >/dev/null 2>&1; then
      echo "❌ Terraform not found. Install terraform to use this recipe." >&2
      exit 1
  fi

  token="$(jq -r '.root_token' "$keys")"
  cd {{root}}/vault/contrib/terraform

    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="$token"
    export TF_VAR_database_host="${TF_VAR_database_host:-postgres-permesi}"
    export TF_VAR_permesi_database_password="${TF_VAR_permesi_database_password:-vault_permesi}"
    export TF_VAR_genesis_database_password="${TF_VAR_genesis_database_password:-vault_genesis}"

    echo "Resource initialization (terraform init)..."
    terraform init >/dev/null

    echo "Applying Terraform configuration..."
    terraform apply -auto-approve

    echo "✅ Vault configured via Terraform."  echo "🔑 Operator Token: $(just --quiet operator-token)"

vault-tf-env:
  #!/usr/bin/env zsh
  set -euo pipefail
  cd {{root}}/vault/contrib/terraform

  if [[ ! -f "terraform.tfstate" ]]; then
      echo "❌ No Terraform state found. Run: just vault-tf-apply" >&2
      exit 1
  fi

  # Extract values from Terraform output
  vals=$(terraform output -json)
  permesi_role_id=$(echo "$vals" | jq -r '.permesi_role_id.value')
  genesis_role_id=$(echo "$vals" | jq -r '.genesis_role_id.value')

  vault_addr="http://127.0.0.1:8200"
  approle_mount="${VAULT_APPROLE_MOUNT:-approle}"

  token=""
  if [[ -f "{{root}}/vault/keys.json" ]]; then
      token=$(jq -r '.root_token' "{{root}}/vault/keys.json")
  elif [[ -n "${VAULT_TOKEN:-}" ]]; then
      token="${VAULT_TOKEN}"
  fi
  if [[ -z "$token" ]]; then
      echo "❌ Missing VAULT_TOKEN (or {{root}}/vault/keys.json) to generate AppRole SecretIDs." >&2
      exit 1
  fi

  permesi_secret_id="$(
    podman exec \
      -e VAULT_ADDR="$vault_addr" \
      -e VAULT_TOKEN="$token" \
      vault \
      vault write -field=secret_id -f "auth/${approle_mount}/role/permesi/secret-id"
  )"
  genesis_secret_id="$(
    podman exec \
      -e VAULT_ADDR="$vault_addr" \
      -e VAULT_TOKEN="$token" \
      vault \
      vault write -field=secret_id -f "auth/${approle_mount}/role/genesis/secret-id"
  )"
  operator_token="$(
    podman exec \
      -e VAULT_ADDR="$vault_addr" \
      -e VAULT_TOKEN="$token" \
      vault \
      vault token create -policy=permesi-operators -period=24h -field=token
  )"

  root_token=""
  if [[ -f "{{root}}/vault/keys.json" ]]; then
      root_token=$(jq -r '.root_token' "{{root}}/vault/keys.json")
  fi

  printf '%s\n' \
    "export VAULT_ADDR=\"${vault_addr}\"" \
    "$([[ -n "${root_token}" ]] && printf 'export VAULT_TOKEN="%s"' "${root_token}")" \
    "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
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

vault-persist-ready: vault-persist vault-init vault-unseal vault-tf-apply

vault-env:
  #!/usr/bin/env zsh
  set -e
  # If we have Terraform state, prefer the Terraform env generator
  if [[ -f "{{root}}/vault/contrib/terraform/terraform.tfstate" ]]; then
      just vault-tf-env
      exit 0
  fi

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
    operator_token="$(
      podman exec \
        -e VAULT_ADDR="$vault_addr" \
        -e VAULT_TOKEN="$token" \
        vault \
        vault token create -policy=permesi-operators -period=24h -field=token
    )"
    printf '%s\n' \
      "export VAULT_ADDR=\"${vault_addr}\"" \
      "export VAULT_TOKEN=\"${token}\"" \
      "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
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
    operator_token="$(printf '%s\n' "$logs" | rg "Operator Token:" | tail -n 1 | sed -E 's/.*Operator Token:[[:space:]]*//')"
    if [[ -n "$login_url" && -n "$permesi_role_id" && -n "$permesi_secret_id" && -n "$genesis_role_id" && -n "$genesis_secret_id" && -n "$operator_token" ]]; then
      break
    fi
    sleep 0.5
  done

  if [[ -z "$login_url" || -z "$permesi_role_id" || -z "$permesi_secret_id" || -z "$genesis_role_id" || -z "$genesis_secret_id" || -z "$operator_token" ]]; then
    echo "Missing values in vault logs. Run: just vault" >&2
    exit 1
  fi

  vault_addr="${login_url%/v1/auth/*}"

  printf '%s\n' \
    "export VAULT_ADDR=\"${vault_addr}\"" \
    "export VAULT_TOKEN=\"dev-root\"" \
    "export PERMESI_OPERATOR_TOKEN=\"${operator_token}\"" \
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
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet vault-env > "$tmp"
  vault_block="$(
    rg -N '^export VAULT_' "$tmp"
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
    "$vault_block" \
    "$operator_block" \
    "" \
    "$genesis_block" \
    "export GENESIS_TLS_PEM_BUNDLE=\"{{root}}/certs/genesis/tls.bundle.pem\"" \
    "" \
    "$permesi_block" \
    "export PERMESI_TLS_PEM_BUNDLE=\"{{root}}/certs/permesi/tls.bundle.pem\"" \
    "export PERMESI_ADMISSION_PASERK_CA_PATH=\"{{root}}/certs/genesis/ca.pem\"" \
    "export PERMESI_ADMISSION_PASERK_URL=\"https://genesis.permesi.localhost:8000/paserk.json\"" \
    "export PERMESI_FRONTEND_BASE_URL=\"https://permesi.localhost\"" \
    "export PERMESI_API_BASE_URL=\"https://api.permesi.localhost\"" \
    "export PERMESI_TOKEN_BASE_URL=\"https://genesis.permesi.localhost\"" \
    "export PERMESI_PASSKEYS_ALLOWED_ORIGINS=\"https://permesi.localhost\"" \
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

vault-reset: vault-stop
  #!/usr/bin/env zsh
  set -euo pipefail
  echo "This will delete the persistent Vault volume, keys file, and Terraform state."
  printf "Type 'delete' to continue: "
  read -r confirm
  if [[ "$confirm" != "delete" ]]; then
    echo "Aborted."
    exit 1
  fi
  # Robust volume removal
  if podman volume inspect permesi-vault-data >/dev/null 2>&1; then
    echo "Removing Vault data volume..."
    if ! podman volume rm permesi-vault-data; then
      echo "❌ Failed to remove volume 'permesi-vault-data'. It may be in use by another container." >&2
      exit 1
    fi
  else
    echo "Vault data volume not found (already deleted)."
  fi

  rm -f {{root}}/vault/keys.json
  rm -rf {{root}}/vault/contrib/terraform/.terraform \
         {{root}}/vault/contrib/terraform/.terraform.lock.hcl \
         {{root}}/vault/contrib/terraform/terraform.tfstate \
         {{root}}/vault/contrib/terraform/terraform.tfstate.backup
  echo "Vault keys and Terraform state removed."
