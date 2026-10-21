#!/usr/bin/env bash
# Reuse preprovisioned runners without sudo. Install only missing tooling, never
# prompt for credentials, and verify libc headers/static linking before Cargo.
set -euo pipefail

missing_toolchain() {
    echo "::error::MUSL tooling is unavailable. Provision musl-dev and musl-tools on this runner, or permit its existing noninteractive package installation policy."
}

if ! command -v musl-gcc >/dev/null 2>&1; then
    if ! command -v apt-get >/dev/null 2>&1; then
        missing_toolchain
        exit 1
    fi
    if [[ "$(id -u)" == "0" ]]; then
        apt-get install -y musl-dev musl-tools
    elif command -v sudo >/dev/null 2>&1; then
        if ! sudo -n -- apt-get install -y musl-dev musl-tools; then
            missing_toolchain
            exit 1
        fi
    else
        missing_toolchain
        exit 1
    fi
fi

if ! command -v musl-gcc >/dev/null 2>&1; then
    missing_toolchain
    exit 1
fi

probe_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/permesi-musl.XXXXXX")
trap 'rm -rf "$probe_dir"' EXIT
if ! printf '%s\n' '#include <stdlib.h>' 'int main(void) { return EXIT_SUCCESS; }' \
    | musl-gcc -static -x c - -o "$probe_dir/probe"; then
    echo "::error::musl-gcc cannot compile and statically link a C program. Repair the runner's MUSL headers, libraries and compiler before retrying."
    exit 1
fi
echo "MUSL headers and static linking verified."
