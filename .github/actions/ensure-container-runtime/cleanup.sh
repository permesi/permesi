#!/usr/bin/env bash
# Remove only the engine directories saved by this action. Never reset the host
# engine or Podman machines; subordinate-UID files need the job's user namespace.
set -euo pipefail

service_dir="${STATE_service_dir:-}"
runtime_dir="${STATE_runtime_dir:-}"
if [[ -z "${service_dir}" && -z "${runtime_dir}" ]]; then
    exit 0
fi
if [[ ! "${service_dir}" =~ ^/.*\/pci\.[[:alnum:]]{6}$ || ! "${runtime_dir}" =~ ^/.*\/pci\.[[:alnum:]]{6}$ || "${service_dir}" == "${runtime_dir}" || -L "${service_dir}" || -L "${runtime_dir}" ]]; then
    echo "::error::Invalid job container cleanup state."
    exit 1
fi
if [[ ! -d "${service_dir}" && ! -d "${runtime_dir}" ]]; then
    exit 0
fi

export XDG_RUNTIME_DIR="${runtime_dir}"
engine=(podman --remote=false --root "${service_dir}/storage"
    --runroot "${runtime_dir}/runroot" --tmpdir "${runtime_dir}/libpod"
    --network-config-dir "${service_dir}/networks")
cleanup_status=0
for resource in container volume image; do
    if ! timeout 60s "${engine[@]}" "${resource}" rm --all --force; then
        cleanup_status=1
    fi
done
if ! timeout 60s "${engine[@]}" network prune --force; then
    cleanup_status=1
fi

# Validate the recorded PID's current command line without signalling a process.
service_matches() {
    local pid="$1"
    local -a args
    [[ "${pid}" =~ ^[1-9][0-9]*$ && -r "/proc/${pid}/cmdline" ]] || return 1
    mapfile -d '' -t args < "/proc/${pid}/cmdline" || return 1
    [[ " ${args[*]} " == *" system service "* && " ${args[*]} " == *" unix://${runtime_dir}/podman.sock "* ]]
}

# Check the recorded PID still belongs to this exact service before signalling it.
service_pid="${STATE_service_pid:-}"
if service_matches "${service_pid}"; then
    kill "${service_pid}" 2>/dev/null || true
    for _ in {1..50}; do
        if ! service_matches "${service_pid}"; then
            break
        fi
        sleep 0.1
    done
    if service_matches "${service_pid}"; then
        kill -KILL "${service_pid}" 2>/dev/null || true
        for _ in {1..50}; do
            if ! service_matches "${service_pid}"; then
                break
            fi
            sleep 0.1
        done
    fi
    if service_matches "${service_pid}"; then
        cleanup_status=1
    fi
fi
# The storage namespace can bind-mount the overlay driver and netns directories.
# Detach only these job-owned mounts before deleting subordinate-UID layer files.
if ! timeout 60s "${engine[@]}" unshare bash -s -- "${service_dir}" "${runtime_dir}" <<'REMOVE_STORAGE'
set -euo pipefail
umount -l "$1/storage/overlay" 2>/dev/null || true
umount -l "$2/netns" 2>/dev/null || true
rm -rf --one-file-system -- "$1" "$2"
REMOVE_STORAGE
then
    cleanup_status=1
fi
# Podman's shutdown can recreate ordinary lock files after the child exits.
if ! rm -rf --one-file-system -- "${service_dir}" "${runtime_dir}"; then
    cleanup_status=1
fi
exit "${cleanup_status}"
