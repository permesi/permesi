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

clippy:
  cargo clippy --all-targets --all-features

# Local test suite: formatting, clippy, the release web build and every workspace test
test: fmt clippy web-build
  cargo test --workspace

verify-release: fmt clippy test web-build

coverage:
  cargo llvm-cov --all-features --workspace

build:
  cargo build --workspace

build-permesi:
  cargo build -p permesi

build-genesis:
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

# Releases run scripts/release (see its header for the whole flow): the version bump
# is staged on the scratch `release` branch, Test & Build and a candidate run of the
# Deploy workflow (every build, package and image, published nowhere) test that exact
# commit, and only then do develop, main and the signed tag move together in one atomic
# push; the tag's run then publishes exactly what the candidate run built. The bump
# changes only the version (Cargo.toml, the workspace entries of Cargo.lock and the
# OpenAPI specs' info.version) and is verified locally in a temporary worktree first.
# Every deploy recipe is idempotent: rerunning it resumes the staged candidate, or
# says there is nothing left to release.

# Deploy: stage a patch bump, wait for CI on it, then release it
deploy:
    @scripts/release deploy patch

# Deploy with minor version bump
deploy-minor:
    @scripts/release deploy minor

# Deploy with major version bump
deploy-major:
    @scripts/release deploy major

# Release develop's version as is when it has no tag yet (no new bump)
deploy-current:
    @scripts/release deploy current

# Show where a release stands: develop, main, sandbox, the staged candidate and its runs
release-status:
    @scripts/release status

# Check everything a release needs; changes nothing that lasts
release-preflight:
    @scripts/release preflight

# Publish an existing release tag again if its own run cannot (recovery run on main)
release-republish version:
    @scripts/release republish {{version}}

# Apply branch protection (main requires "CI OK") and the rule that release tags never move
protect-branches:
    @scripts/release protect

# Build and package the current branch like a release candidate; releases nothing, no tag
release-dry-run:
    @scripts/release dry-run

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
