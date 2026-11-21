#!/usr/bin/env bash
set -euo pipefail

: "${BAO_ADDR:=http://127.0.0.1:8200}"
: "${BAO_TOKEN:=dev-root}"
: "${OPENBAO_TRANSIT_MOUNT:=transit/genesis}"
: "${OPENBAO_TRANSIT_KEY:=genesis-signing}"
: "${OPENBAO_TRANSIT_KEEP_VERSIONS:=2}"

export BAO_ADDR BAO_TOKEN

if ! command -v bao >/dev/null 2>&1; then
    echo "bao CLI not found in PATH" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to parse openbao JSON output" >&2
    exit 1
fi

case "$OPENBAO_TRANSIT_KEEP_VERSIONS" in
'' | *[!0-9]*)
    keep=2
    ;;
*)
    keep="$OPENBAO_TRANSIT_KEEP_VERSIONS"
    ;;
esac

if [ "$keep" -lt 1 ]; then
    keep=1
fi

key_path="${OPENBAO_TRANSIT_MOUNT}/keys/${OPENBAO_TRANSIT_KEY}"
latest="$(
    bao read -format=json "$key_path" |
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
    bao write "${key_path}/config" \
        deletion_allowed=true \
        min_encryption_version="$floor" \
        min_decryption_version="$floor" >/dev/null
    bao write "${key_path}/trim" min_available_version="$floor" >/dev/null
else
    echo "Nothing to trim yet for ${key_path}."
fi
