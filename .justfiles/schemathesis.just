# --------------------------------------
# API contract testing (Schemathesis)
# --------------------------------------

schemathesis-permesi:
  #!/usr/bin/env zsh
  set -euo pipefail

  runner=()
  if command -v schemathesis >/dev/null 2>&1; then
    runner=(schemathesis)
  elif command -v uv >/dev/null 2>&1; then
    echo "schemathesis not found; installing with uv tool install schemathesis..."
    uv tool install schemathesis
    if command -v schemathesis >/dev/null 2>&1; then
      runner=(schemathesis)
    elif command -v uvx >/dev/null 2>&1; then
      runner=(uvx --from schemathesis schemathesis)
    else
      echo "schemathesis installed but not on PATH. Add uv tool bin to PATH and retry." >&2
      exit 1
    fi
  elif command -v uvx >/dev/null 2>&1; then
    runner=(uvx --from schemathesis schemathesis)
  else
    echo "schemathesis not found and uv/uvx are unavailable. Install uv, then rerun." >&2
    exit 1
  fi

  : "${PERMESI_API_BASE_URL:=https://api.permesi.localhost}"
  : "${PERMESI_API_TLS_VERIFY:=false}"
  : "${PERMESI_SCHEMATHESIS_PHASES:=examples,coverage}"
  : "${PERMESI_SCHEMATHESIS_MAX_EXAMPLES:=25}"
  : "${PERMESI_SCHEMATHESIS_MODE:=positive}"
  : "${PERMESI_SCHEMATHESIS_HYPOTHESIS_DIR:=/tmp/permesi-schemathesis-hypothesis}"
  : "${PERMESI_SCHEMATHESIS_EXCLUDE_LOGOUT:=true}"
  : "${PERMESI_SCHEMATHESIS_LOGOUT_COVERAGE:=true}"

  mkdir -p "${PERMESI_SCHEMATHESIS_HYPOTHESIS_DIR}"

  if ! curl -fsS -k "${PERMESI_API_BASE_URL%/}/health" >/dev/null; then
    echo "permesi API is not reachable at ${PERMESI_API_BASE_URL}. Run just start and retry." >&2
    exit 1
  fi

  headers=()
  if [[ -n "${PERMESI_SESSION_COOKIE:-}" ]]; then
    headers+=(--header "Cookie: permesi_session=${PERMESI_SESSION_COOKIE}")
  fi
  if [[ -n "${PERMESI_ADMIN_TOKEN:-}" ]]; then
    headers+=(--header "Authorization: Bearer ${PERMESI_ADMIN_TOKEN}")
  fi

  help_text="$("${runner[@]}" run -h 2>/dev/null || true)"
  base_args=(run docs/openapi/permesi.json)

  if echo "$help_text" | rg -q -- '--config-file'; then
    base_args+=(--config-file services/permesi/openapi/schemathesis/schemathesis.toml)
  else
    base_args+=(--phases "${PERMESI_SCHEMATHESIS_PHASES}")
    base_args+=(--max-examples "${PERMESI_SCHEMATHESIS_MAX_EXAMPLES}")
    base_args+=(
      --checks
      not_a_server_error,status_code_conformance,content_type_conformance,response_headers_conformance,response_schema_conformance
    )
  fi

  base_args+=(-m "${PERMESI_SCHEMATHESIS_MODE}")
  base_args+=(--url "${PERMESI_API_BASE_URL}")
  base_args+=(--tls-verify "${PERMESI_API_TLS_VERIFY}")
  base_args+=("${headers[@]}")

  main_args=("${base_args[@]}")
  if [[ "${PERMESI_SCHEMATHESIS_EXCLUDE_LOGOUT}" == "true" ]]; then
    main_args+=(--exclude-path "/v1/auth/logout")
  fi

  echo "Running permesi Schemathesis baseline..."
  HYPOTHESIS_STORAGE_DIRECTORY="${PERMESI_SCHEMATHESIS_HYPOTHESIS_DIR}" \
    "${runner[@]}" "${main_args[@]}"

  if [[ "${PERMESI_SCHEMATHESIS_LOGOUT_COVERAGE}" == "true" ]]; then
    echo "Running permesi Schemathesis logout-only coverage..."
    logout_args=("${base_args[@]}")
    logout_args+=(--include-path "/v1/auth/logout")
    HYPOTHESIS_STORAGE_DIRECTORY="${PERMESI_SCHEMATHESIS_HYPOTHESIS_DIR}" \
      "${runner[@]}" "${logout_args[@]}"
  fi

schemathesis-genesis:
  #!/usr/bin/env zsh
  set -euo pipefail

  runner=()
  if command -v schemathesis >/dev/null 2>&1; then
    runner=(schemathesis)
  elif command -v uv >/dev/null 2>&1; then
    echo "schemathesis not found; installing with uv tool install schemathesis..."
    uv tool install schemathesis
    if command -v schemathesis >/dev/null 2>&1; then
      runner=(schemathesis)
    elif command -v uvx >/dev/null 2>&1; then
      runner=(uvx --from schemathesis schemathesis)
    else
      echo "schemathesis installed but not on PATH. Add uv tool bin to PATH and retry." >&2
      exit 1
    fi
  elif command -v uvx >/dev/null 2>&1; then
    runner=(uvx --from schemathesis schemathesis)
  else
    echo "schemathesis not found and uv/uvx are unavailable. Install uv, then rerun." >&2
    exit 1
  fi

  : "${GENESIS_API_BASE_URL:=https://genesis.permesi.localhost}"
  : "${GENESIS_API_TLS_VERIFY:=false}"
  : "${GENESIS_SCHEMATHESIS_PHASES:=examples,coverage}"
  : "${GENESIS_SCHEMATHESIS_MAX_EXAMPLES:=25}"
  : "${GENESIS_SCHEMATHESIS_MODE:=positive}"
  : "${GENESIS_SCHEMATHESIS_HYPOTHESIS_DIR:=/tmp/genesis-schemathesis-hypothesis}"

  mkdir -p "${GENESIS_SCHEMATHESIS_HYPOTHESIS_DIR}"

  help_text="$("${runner[@]}" run -h 2>/dev/null || true)"
  args=(run docs/openapi/genesis.json)

  if echo "$help_text" | rg -q -- '--config-file'; then
    args+=(--config-file services/genesis/openapi/schemathesis/schemathesis.toml)
  else
    args+=(--phases "${GENESIS_SCHEMATHESIS_PHASES}")
    args+=(--max-examples "${GENESIS_SCHEMATHESIS_MAX_EXAMPLES}")
    args+=(
      --checks
      not_a_server_error,status_code_conformance,content_type_conformance,response_headers_conformance,response_schema_conformance
    )
  fi

  args+=(-m "${GENESIS_SCHEMATHESIS_MODE}")
  args+=(--url "${GENESIS_API_BASE_URL}")
  args+=(--tls-verify "${GENESIS_API_TLS_VERIFY}")

  HYPOTHESIS_STORAGE_DIRECTORY="${GENESIS_SCHEMATHESIS_HYPOTHESIS_DIR}" \
    "${runner[@]}" "${args[@]}"

schemathesis-permesi-auth-env email="schemathesis.local@example.com" role="owner" with_admin="false":
  #!/usr/bin/env zsh
  set -euo pipefail

  if ! command -v podman >/dev/null 2>&1; then
    echo "podman is required" >&2
    exit 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required" >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
  fi
  if [[ -z "$(podman ps -q --filter 'name=^postgres-permesi$')" ]]; then
    echo "postgres-permesi is not running. Start the local stack first (e.g. just start)." >&2
    exit 1
  fi

  email="{{email}}"
  role="{{role}}"
  with_admin="{{with_admin}}"
  case "$role" in
    owner|admin|editor|member) ;;
    *)
      echo "Invalid role '$role'. Allowed: owner|admin|editor|member" >&2
      exit 1
      ;;
  esac
  if [[ ! "$email" =~ '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$' ]]; then
    echo "Invalid email '$email'" >&2
    exit 1
  fi
  email_sql="${email//\'/\'\'}"

  session_token="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | tr -d '\n')"
  if command -v sha256sum >/dev/null 2>&1; then
    session_hash_hex="$(printf '%s' "$session_token" | sha256sum | awk '{print $1}')"
  else
    session_hash_hex="$(printf '%s' "$session_token" | shasum -a 256 | awk '{print $1}')"
  fi

  podman exec -i postgres-permesi psql -q -U postgres -d permesi -v ON_ERROR_STOP=1 \
    -c "WITH upsert_user AS (
          INSERT INTO users (email, opaque_registration_record, status)
          VALUES ('${email_sql}', E'\\\\x00', 'active')
          ON CONFLICT (email) DO UPDATE SET status = 'active'
          RETURNING id
        ),
        target_user AS (
          SELECT id FROM upsert_user
          UNION
          SELECT id FROM users WHERE email = '${email_sql}'
        ),
        upsert_role AS (
          INSERT INTO user_roles (user_id, role)
          SELECT id, '${role}' FROM target_user
          ON CONFLICT (user_id) DO UPDATE SET role = '${role}'
          RETURNING user_id
        )
        INSERT INTO user_sessions (user_id, session_hash, expires_at)
        SELECT id, decode('${session_hash_hex}', 'hex'), NOW() + INTERVAL '2 hours'
        FROM target_user
        ON CONFLICT (session_hash) DO UPDATE
          SET expires_at = NOW() + INTERVAL '2 hours';" >/dev/null

  printf 'export PERMESI_SESSION_COOKIE="%s"\n' "$session_token"

  if [[ "$with_admin" == "true" ]]; then
    podman exec -i postgres-permesi psql -q -U postgres -d permesi -v ON_ERROR_STOP=1 \
      -c "WITH target_user AS (
            SELECT id FROM users WHERE email = '${email_sql}'
          )
          INSERT INTO platform_operators (user_id, enabled, created_by, note)
          SELECT id, TRUE, id, 'schemathesis fixture'
          FROM target_user
          ON CONFLICT (user_id) DO UPDATE SET enabled = TRUE;" >/dev/null

    vault_token="$(just --quiet operator-token)"
    api_base="${PERMESI_API_BASE_URL:-https://api.permesi.localhost}"
    admin_response="$(
      curl -fsS -k \
        -H "Content-Type: application/json" \
        -H "Cookie: permesi_session=${session_token}" \
        -X POST \
        "${api_base%/}/v1/auth/admin/elevate" \
        -d "{\"vault_token\":\"${vault_token}\"}"
    )"
    admin_token="$(printf '%s' "$admin_response" | jq -er '.admin_token')"
    printf 'export PERMESI_ADMIN_TOKEN="%s"\n' "$admin_token"
  fi

schemathesis-permesi-auth email="schemathesis.local@example.com" role="owner" with_admin="false":
  #!/usr/bin/env zsh
  set -euo pipefail

  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  just --quiet schemathesis-permesi-auth-env "{{email}}" "{{role}}" "{{with_admin}}" > "$tmp"
  source "$tmp"
  just schemathesis-permesi

schemathesis-permesi-auth-admin email="" role="owner":
  #!/usr/bin/env zsh
  set -euo pipefail

  email="{{email}}"
  if [[ -z "$email" ]]; then
    email="schemathesis.admin.$(date +%s).$RANDOM@example.com"
  fi

  just schemathesis-permesi-auth "$email" "{{role}}" "true"
