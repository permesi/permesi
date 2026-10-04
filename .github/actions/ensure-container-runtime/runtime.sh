#!/usr/bin/env bash
# Export only a verified container API. Each self-hosted job owns its socket and
# service, so another job's cleanup cannot interrupt testcontainers. Shared Podman
# migrations and process/socket removal belong to runner maintenance, not CI jobs.
set -euo pipefail

if [[ "${RUNNER_ENVIRONMENT:-}" == github-hosted && -S /var/run/docker.sock ]]; then
    echo "GitHub-hosted runner detected. Using system Docker daemon."
    docker --host unix:///var/run/docker.sock info >/dev/null
    {
        echo "DOCKER_HOST=unix:///var/run/docker.sock"
        echo "CONTAINER_TOOL=docker"
    } >> "${GITHUB_ENV}"
    docker --host unix:///var/run/docker.sock pull postgres:18 || true
    docker --host unix:///var/run/docker.sock pull hashicorp/vault:1.17.3 || true
    exit 0
fi

if ! command -v podman >/dev/null 2>&1; then
    echo "Installing Podman and dependencies..."
    sudo apt-get update
    sudo apt-get install -y podman dbus-user-session slirp4netns
fi

runtime_uid=$(id -u)
if [[ -d "/run/user/${runtime_uid}" ]]; then
    export XDG_RUNTIME_DIR="/run/user/${runtime_uid}"
else
    export XDG_RUNTIME_DIR="/tmp/podman-run-${runtime_uid}"
    mkdir -p "${XDG_RUNTIME_DIR}"
    chmod 700 "${XDG_RUNTIME_DIR}"
fi
if [[ -S "${XDG_RUNTIME_DIR}/bus" ]]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
else
    export DBUS_SESSION_BUS_ADDRESS=""
fi

# Local engine health does not establish that a remote API socket is listening.
podman --remote=false info >/dev/null
service_dir=$(mktemp -d "${RUNNER_TEMP:-${XDG_RUNTIME_DIR}}/pci.XXXXXX")
endpoint="unix://${service_dir}/podman.sock"
ready=0
podman --remote=false system service --time=0 "${endpoint}" \
    >"${service_dir}/service.log" 2>&1 </dev/null &
service_pid=$!
# Failed setup cleans up only the process/directory created here. On success the
# Actions runner's job cleanup owns the child process and its temporary directory.
trap 'if [[ "${ready}" -eq 0 ]]; then kill "${service_pid}" 2>/dev/null || true; wait "${service_pid}" 2>/dev/null || true; rm -rf "${service_dir}"; fi' EXIT

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

{
    echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}"
    echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS}"
    echo "DOCKER_HOST=${endpoint}"
    echo "CONTAINER_TOOL=podman"
} >> "${GITHUB_ENV}"
podman --url "${endpoint}" pull postgres:18 || true
podman --url "${endpoint}" pull hashicorp/vault:1.17.3 || true
