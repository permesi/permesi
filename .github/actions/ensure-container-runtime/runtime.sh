#!/usr/bin/env bash
# Export only a verified container API. Each self-hosted job owns its socket and
# engine, so another job's cleanup cannot interrupt testcontainers. Shared Podman
# migrations and process/socket removal belong to runner maintenance, not CI jobs.
set -euo pipefail

if [[ "${PERMESI_TEST_REQUIRE_PODMAN:-0}" != 1 && "${RUNNER_ENVIRONMENT:-}" == github-hosted && -S /var/run/docker.sock ]]; then
    echo "GitHub-hosted runner detected. Using system Docker daemon."
    docker --host unix:///var/run/docker.sock info >/dev/null
    {
        echo "DOCKER_HOST=unix:///var/run/docker.sock"
        echo "CONTAINER_TOOL=docker"
    } >> "${GITHUB_ENV}"
    docker --host unix:///var/run/docker.sock pull docker.io/library/postgres:18 || true
    docker --host unix:///var/run/docker.sock pull docker.io/hashicorp/vault:1.17.3 || true
    exit 0
fi

if ! command -v podman >/dev/null 2>&1; then
    echo "Installing Podman and dependencies..."
    sudo apt-get update
    sudo apt-get install -y podman dbus-user-session slirp4netns
fi

runtime_uid=$(id -u)
if [[ -d "/run/user/${runtime_uid}" ]]; then
    runtime_base="/run/user/${runtime_uid}"
else
    runtime_base="/tmp/podman-run-${runtime_uid}"
    mkdir -p "${runtime_base}"
    chmod 700 "${runtime_base}"
fi
if [[ -S "${runtime_base}/bus" ]]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${runtime_base}/bus"
else
    export DBUS_SESSION_BUS_ADDRESS=""
fi

# A private socket alone still inherits the shared engine's rootless pause
# process. Job cleanup can kill that process and poison the next job's setup.
service_dir=$(mktemp -d "${RUNNER_TEMP:-${runtime_base}}/pci.XXXXXX")
runtime_dir=$(mktemp -d "${runtime_base}/pci.XXXXXX")
export XDG_RUNTIME_DIR="${runtime_dir}"
engine=(podman --remote=false --root "${service_dir}/storage"
    --runroot "${runtime_dir}/runroot" --tmpdir "${runtime_dir}/libpod"
    --network-config-dir "${service_dir}/networks")
endpoint="unix://${runtime_dir}/podman.sock"
ready=0
service_pid=""
# Record ownership for the action's post hook before starting any job processes.
if [[ -n "${GITHUB_STATE:-}" ]]; then
    {
        echo "service_dir=${service_dir}"
        echo "runtime_dir=${runtime_dir}"
    } >> "${GITHUB_STATE}"
fi
trap 'if [[ "${ready}" -eq 0 ]]; then if [[ -n "${service_pid}" ]]; then kill "${service_pid}" 2>/dev/null || true; wait "${service_pid}" 2>/dev/null || true; fi; rm -rf "${service_dir}" "${runtime_dir}"; fi' EXIT

"${engine[@]}" info >/dev/null
"${engine[@]}" system service --time=0 "${endpoint}" \
    >"${service_dir}/service.log" 2>&1 </dev/null &
service_pid=$!
if [[ -n "${GITHUB_STATE:-}" ]]; then
    echo "service_pid=${service_pid}" >> "${GITHUB_STATE}"
fi
# Netavark remounts /run inside its DNS namespace. Same-user socket hard links
# remain reachable through the private runtime directory carried into that mount.
if [[ -S "${runtime_base}/bus" ]]; then
    ln "${runtime_base}/bus" "${runtime_dir}/bus"
fi
if [[ -S "${runtime_base}/systemd/private" ]]; then
    mkdir -m 700 "${runtime_dir}/systemd"
    ln "${runtime_base}/systemd/private" "${runtime_dir}/systemd/private"
fi

for attempt in {1..60}; do
    if timeout 2s podman --url "${endpoint}" info >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "${service_pid}" 2>/dev/null; then
        break
    fi
    echo "Waiting for job Podman API... (${attempt})"
    sleep 0.5
done
if [[ "${ready}" -ne 1 ]]; then
    echo "::error::Job Podman API did not become ready."
    cat "${service_dir}/service.log"
    exit 1
fi

# A fresh store needs these images; retry transient registry failures and fail
# setup if they remain unavailable instead of exporting an unusable test runtime.
for image in docker.io/library/postgres:18 docker.io/hashicorp/vault:1.17.3; do
    pulled=0
    for attempt in {1..3}; do
        if podman --url "${endpoint}" pull "${image}"; then
            pulled=1
            break
        fi
        sleep 2
    done
    if [[ "${pulled}" -ne 1 ]]; then
        echo "::error::Required CI image could not be pulled: ${image}"
        exit 1
    fi
done
{
    echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}"
    echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS}"
    echo "DOCKER_HOST=${endpoint}"
    # Podman CLI steps must also use the job's engine, rather than host defaults.
    echo "CONTAINER_HOST=${endpoint}"
    echo "CONTAINER_TOOL=podman"
} >> "${GITHUB_ENV}"
