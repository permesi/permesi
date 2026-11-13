default: fmt clippy test
  @just --list

# Create the dedicated dev network (PERMESI_NET / PERMESI_SUBNET). An existing network
# must already carry the expected subnet, and a range that another podman network or
# a host route uses is reported instead of silently landing on a different subnet.
[doc("Create the dedicated permesi-net podman network (PERMESI_NET / PERMESI_SUBNET)")]
setup-network:
  #!/usr/bin/env zsh
  set -euo pipefail
  if podman network exists {{net}}; then
    current="$(podman network inspect {{net}} --format '{{{{range .Subnets}}{{{{.Subnet}} {{{{end}}')"
    current="${current% }"
    if [[ " ${current} " != *" {{subnet}} "* ]]; then
      echo "❌ podman network {{net}} uses ${current:-no subnet}, expected {{subnet}}." >&2
      echo "   Remove it (podman network rm {{net}}) or set PERMESI_SUBNET to match." >&2
      exit 1
    fi
    # Networks created before the stack label existed are accepted, with a hint.
    if [[ "$(podman network inspect {{net}} --format '{{{{index .Labels "io.permesi.stack"}}')" != "dev" ]]; then
      echo "⚠️  podman network {{net}} lacks the {{stack_label}} label (created by an older setup)." >&2
      echo "   Recreate it while the stack is stopped: just stop && podman network rm {{net}}" >&2
    fi
    exit 0
  fi
  if ! err="$(podman network create --subnet {{subnet}} --label {{stack_label}} {{net}} 2>&1 >/dev/null)"; then
    echo "❌ Could not create podman network {{net}} with subnet {{subnet}}:" >&2
    echo "   ${err}" >&2
    echo "   Pick a free range, for example: export PERMESI_SUBNET=172.31.21.0/24" >&2
    exit 1
  fi

fmt:
  cargo fmt --all -- --check

[doc("Check online that installed stable is current and matches the active compiler; install nothing")]
rust-check:
  #!/usr/bin/env bash
  set -euo pipefail
  status=0
  report="$(rustup check --no-self-update)" || status=$?
  if [[ "${status}" != 0 && "${status}" != 100 ]]; then
    echo "Could not check Rust updates; check your connection and run just rust-check again." >&2
    exit 1
  fi
  stable_status="$(printf '%s\n' "${report}" | awk '$1 ~ /^stable-/ { print; exit }')"
  printf '%s\n' "${stable_status}"
  case "$(printf '%s' "${stable_status}" | tr '[:upper:]' '[:lower:]')" in
    *" - up to date"*) ;;
    *)
      echo "Stable Rust is missing or outdated. Run: rustup update stable" >&2
      exit 1
      ;;
  esac
  stable="$(rustup run stable rustc --version)"
  active="$(rustc --version)"
  if [[ "${active}" != "${stable}" ]]; then
    echo "Active compiler: ${active}; expected stable: ${stable}." >&2
    echo "Check PATH, RUSTUP_TOOLCHAIN and rustup overrides; select the updated stable toolchain." >&2
    exit 1
  fi
  echo "Rust toolchain matches current stable: ${active}"

clippy: rust-check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo clippy --locked -p permesi_web --target wasm32-unknown-unknown --all-targets --all-features -- -D warnings

# Local test suite: formatting, clippy, the release web build and every workspace test
test: fmt clippy web-build
  cargo test --workspace

verify-release: fmt clippy test web-build

coverage:
  cargo llvm-cov --all-features --workspace

[doc("Measure fresh PostgreSQL/Vault fixture phases with four concurrent workers (1..10 rounds)")]
test-fixture-profile rounds="3":
  cargo run --locked -p test_support --example fixture_profile -- {{quote(rounds)}}

[doc("Verify cached service build identity in Git-less crates, Git checkouts and worktrees")]
test-build-identity:
  python3 "{{root}}/scripts/test-build-identity.py"

[doc("Report job/step timings and runner assignments for every attempt of a GitHub run")]
ci-timings run_id:
  python3 "{{root}}/scripts/ci-timings.py" {{quote(run_id)}}

build: rust-check
  cargo build --workspace

build-permesi: rust-check
  cargo build -p permesi

build-genesis: rust-check
  cargo build -p genesis

update:
  cargo update

clean:
  cargo clean --target-dir "{{root}}/target"

# Resolve workspace version (expects a single shared version).
_workspace-version:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v jq >/dev/null 2>&1; then
        echo "❌ jq is required to resolve workspace versions." >&2
        exit 1
    fi
    versions="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].version' | sort -u)"
    if [[ -z "${versions}" ]]; then
        echo "❌ Failed to resolve workspace versions." >&2
        exit 1
    fi
    if [[ "$(printf '%s\n' "${versions}" | wc -l | tr -d ' ')" -ne 1 ]]; then
        echo "❌ Expected a single workspace version, found:" >&2
        printf '%s\n' "${versions}" >&2
        exit 1
    fi
    printf '%s\n' "${versions}"

# Get current version
version:
    @just --quiet _workspace-version

# Check if working directory is clean
check-clean:
    #!/usr/bin/env bash
    if [[ -n $(git status --porcelain) ]]; then
        echo "❌ Working directory is not clean. Commit or stash your changes first."
        git status --short
        exit 1
    fi
    echo "✅ Working directory is clean"

# Check if tag already exists for a given version
check-tag-not-exists version:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{version}}"

    git fetch --tags --quiet

    if git rev-parse -q --verify "refs/tags/${version}" >/dev/null 2>&1; then
        echo "❌ Tag ${version} already exists!"
        exit 1
    fi

    echo "✅ No tag exists for version ${version}"

# Releases run .github/workflows/release.yml on develop: it checks that the commit passed
# Test & Build and that the version (Cargo.toml, Cargo.lock and both OpenAPI specs'
# info.version) is new, then builds and publishes everything. `main` only allows the
# operator to push, and a protected branch refuses an update while a `CI OK` check of the
# same commit is still pending (develop's own Test & Build), so once the run has succeeded
# this recipe waits for that run and then fast-forwards `main` to the released commit. The
# operator bumps the version beforehand, as the last commit of the work.

# Release develop: start the Release workflow, follow it, then fast-forward main
release:
    #!/usr/bin/env bash
    set -euo pipefail
    git fetch --quiet origin develop
    sha="$(git rev-parse origin/develop)"
    last="$(gh run list --workflow release.yml --branch develop --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"
    gh workflow run release.yml --ref develop
    # The dispatched run is the first new one for this commit; never just "the latest".
    run=""
    for _ in $(seq 30); do
        run="$(gh run list --workflow release.yml --branch develop --event workflow_dispatch --limit 10 --json databaseId,headSha --jq "[.[] | select(.databaseId > ${last} and .headSha == \"${sha}\")][0].databaseId // empty")"
        [[ -z "${run}" ]] || break
        sleep 2
    done
    [[ -n "${run}" ]] || { echo "The dispatched release run did not appear." >&2; exit 1; }
    gh run watch "${run}" --exit-status
    # develop's own Test & Build must have finished, and passed, before main can move.
    ci=""
    for _ in $(seq 30); do
        ci="$(gh run list --workflow build.yml --branch develop --commit "${sha}" --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
        [[ -z "${ci}" ]] || break
        sleep 2
    done
    [[ -n "${ci}" ]] || { echo "No Test & Build run of develop for ${sha}; push it to main yourself when CI OK passed." >&2; exit 1; }
    echo "Waiting for develop's Test & Build (run ${ci}) before moving main..."
    gh run watch "${ci}" --exit-status > /dev/null || { echo "Test & Build failed on ${sha}; re-run its failed jobs, then: git push origin ${sha}:refs/heads/main" >&2; exit 1; }
    git push origin "${sha}:refs/heads/main"

# ----------------------
# Sandbox branch helpers
# ----------------------

# Squash all sandbox commits onto origin/develop and force-push the sandbox branch.
# Requires a clean working tree.
# Usage:
#   just sandbox-squash
#   just sandbox-squash "commit message"
sandbox-squash message="" base="origin/develop": check-clean
    #!/usr/bin/env bash
    set -euo pipefail

    message="{{message}}"
    base="{{base}}"
    current_branch="$(git branch --show-current)"

    if [[ "${current_branch}" == "develop" || "${current_branch}" == "main" ]]; then
        echo "❌ Refusing to rewrite ${current_branch}. Run from a disposable branch." >&2
        exit 1
    fi

    git fetch origin --quiet
    if ! git rev-parse --verify "${base}" >/dev/null 2>&1; then
        echo "❌ Base ref '${base}' not found. Use e.g. base=origin/develop." >&2
        exit 1
    fi

    git reset --soft "${base}"
    git add -A

    if git diff --cached --quiet; then
        echo "❌ No changes to commit after soft reset." >&2
        exit 1
    fi

    change_stats="$(
      git diff --cached --name-status | awk '
      BEGIN {added=0; modified=0; deleted=0;}
      {
        code = substr($1, 1, 1);
        if (code == "A") {
          added++;
        } else if (code == "D") {
          deleted++;
        } else {
          modified++;
        }
      }
      END {
        printf "added: %d, modified: %d, deleted: %d", added, modified, deleted
      }'
    )"
    file_list="$(git diff --cached --name-only | sed 's/^/- /')"
    detail_body="$(printf '%s\n\n%s' "${change_stats}" "${file_list}")"

    if [[ -n "${message}" ]]; then
        git commit -m "${message}" -m "${detail_body}"
    else
        git commit -m "squash $(date +%Y-%m-%d)" -m "${detail_body}"
    fi
    git push --force-with-lease origin HEAD
