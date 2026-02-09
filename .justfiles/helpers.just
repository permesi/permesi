# ----------------------
# API helpers
# ----------------------

genesis-token:
  #!/usr/bin/env zsh
  set -euo pipefail
  token="$(
    xh 'https://genesis.permesi.localhost/token?client_id=00000000-0000-0000-0000-000000000000' \
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
  base="${PERMESI_FRONTEND_BASE_URL:-}"
  if [[ -n "$base" ]]; then
    base_escaped="${base//\'/\'\'}"
    url="$(
      podman exec -i postgres-permesi psql -U postgres -d permesi -Atc \
        "select payload_json->>'verify_url' from email_outbox where payload_json->>'verify_url' like '${base_escaped}%' order by created_at desc limit 1;"
    )"
    if [[ -n "$url" ]]; then
      printf '%s\n' "$url"
      exit 0
    fi
  fi
  podman exec -i postgres-permesi psql -U postgres -d permesi -Atc \
    "select payload_json->>'verify_url' from email_outbox where payload_json ? 'verify_url' and payload_json->>'verify_url' <> '' order by created_at desc limit 1;"

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
