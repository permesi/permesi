#!/usr/bin/env bash
set -euo pipefail

: "${VAULT_ADDR:=http://127.0.0.1:8200}"
: "${VAULT_TOKEN:=dev-root}"
: "${VAULT_TRANSIT_MOUNT:=transit/genesis}"
: "${VAULT_TRANSIT_KEY:=genesis-signing}"
: "${VAULT_TRANSIT_KEEP_VERSIONS:=2}"

export VAULT_ADDR VAULT_TOKEN

if ! command -v vault >/dev/null 2>&1; then
    echo "vault CLI not found in PATH" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to parse vault JSON output" >&2
    exit 1
fi

case "$VAULT_TRANSIT_KEEP_VERSIONS" in
'' | *[!0-9]*)
    keep=2
    ;;
*)
    keep="$VAULT_TRANSIT_KEEP_VERSIONS"
    ;;
esac

if [ "$keep" -lt 1 ]; then
    keep=1
fi

key_path="${VAULT_TRANSIT_MOUNT}/keys/${VAULT_TRANSIT_KEY}"
latest="$(
    vault read -format=json "$key_path" |
        jq -r '.data.latest_version'
)"

case "$latest" in
'' | *[!0-9]*)
    echo "Failed to read latest_version for ${key_path}." >&2
    exit 1
    ;;
esac

floor=$((latest - keep + 1))

if [ "$floor" -gt 1 ]; then
    echo "Trimming to version ${floor} and above for ${key_path}..."
    vault write "${key_path}/config" \
        deletion_allowed=true \
        min_encryption_version="$floor" \
        min_decryption_version="$floor" >/dev/null
    vault write "${key_path}/trim" min_available_version="$floor" >/dev/null
else
    echo "Nothing to trim yet for ${key_path}."
fi
