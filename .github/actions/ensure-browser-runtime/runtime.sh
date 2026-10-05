#!/usr/bin/env bash
# Probe empty, private profiles before publishing the browser alias. A --version
# result alone does not prove that headless tests can read the browser's DevTools
# port file. The first hosted run had no port file and suppressed startup output;
# failed probes now print that output so the actual launch failure can be diagnosed.
# Prefer native Chrome, then try Chromium. Probes carry no session or credentials;
# every process and profile created here is stopped/removed before returning.
set -euo pipefail

alias_dir="${RUNNER_TEMP:?}/browser-test-bin"
: "${GITHUB_PATH:?}"
probe_dir=""
probe_pid=""

# Retire only this probe's timeout process/group and freshly allocated directory.
cleanup_probe() {
    if [[ -n "${probe_pid}" ]]; then
        kill "${probe_pid}" 2>/dev/null || true
        wait "${probe_pid}" 2>/dev/null || true
        probe_pid=""
    fi
    if [[ -n "${probe_dir}" ]]; then
        rm -rf -- "${probe_dir}"
        probe_dir=""
    fi
}
trap cleanup_probe EXIT

mkdir -m 700 "${alias_dir}"
for candidate in google-chrome google-chrome-stable chromium; do
    browser="$(command -v "${candidate}" || true)"
    if [[ -z "${browser}" ]]; then
        continue
    fi
    echo "Checking headless browser: ${candidate}"
    probe_dir=$(mktemp -d /tmp/permesi-ci-browser.XXXXXX)
    timeout --kill-after=2s 15s "${browser}" \
        --headless --no-sandbox --disable-dev-shm-usage \
        --disable-background-networking \
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE ::1, EXCLUDE [::1]' \
        --remote-debugging-port=0 "--user-data-dir=${probe_dir}" about:blank \
        >"${probe_dir}/startup.log" 2>&1 </dev/null &
    probe_pid=$!
    ready=0
    for _probe_attempt in {1..100}; do
        if ! kill -0 "${probe_pid}" 2>/dev/null; then
            break
        fi
        if [[ -s "${probe_dir}/DevToolsActivePort" ]] &&
            IFS= read -r port <"${probe_dir}/DevToolsActivePort"; then
            if [[ "${port}" =~ ^[0-9]{1,5}$ ]] && (( port > 0 && port <= 65535 )) &&
                curl --fail --silent --noproxy '*' --max-time 1 "http://127.0.0.1:${port}/json/version" >/dev/null; then
                ready=1
                break
            fi
        fi
        sleep 0.1
    done
    if [[ "${ready}" -eq 1 ]]; then
        "${browser}" --version
        ln -s -- "${browser}" "${alias_dir}/chromium"
        echo "${alias_dir}" >> "${GITHUB_PATH}"
        cleanup_probe
        exit 0
    fi
    echo "::warning::${candidate} did not expose a usable host-visible DevTools endpoint."
    cat "${probe_dir}/startup.log"
    cleanup_probe
done
echo "::error::No installed Chromium-compatible browser passed headless startup."
exit 1
