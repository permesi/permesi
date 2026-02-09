default: fmt clippy test
  @just --list

setup-network:
  podman network inspect {{net}} >/dev/null 2>&1 || podman network create --subnet {{subnet}} {{net}}

fmt:
  cargo fmt --all -- --check

clippy:
  cargo clippy --all-targets --all-features

test:
  cargo test --workspace

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
  cargo clean

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

# Check if on develop branch
check-develop:
    #!/usr/bin/env bash
    current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "develop" ]]; then
        echo "❌ Not on develop branch (currently on: $current_branch)"
        echo "Switch to develop branch first: git checkout develop"
        exit 1
    fi
    echo "✅ On develop branch"

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

_require-bump-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! cargo set-version -h >/dev/null 2>&1; then
        echo "❌ cargo set-version not found; install cargo-edit (cargo install cargo-edit)." >&2
        exit 1
    fi

_require-tag-signing:
    #!/usr/bin/env bash
    set -euo pipefail
    gpg_cmd="$(git config --get gpg.program || true)"
    if [[ -n "$gpg_cmd" ]]; then
        if ! command -v "$gpg_cmd" >/dev/null 2>&1; then
            echo "❌ Configured gpg.program '${gpg_cmd}' not found." >&2
            exit 1
        fi
    elif command -v gpg >/dev/null 2>&1; then
        gpg_cmd="gpg"
    elif command -v gpg2 >/dev/null 2>&1; then
        gpg_cmd="gpg2"
    else
        echo "❌ gpg not found; required for signed tags (git tag -s)." >&2
        exit 1
    fi
    if ! "$gpg_cmd" --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'; then
        echo "❌ No GPG secret keys found for signing." >&2
        echo "Configure a signing key and retry (git config user.signingkey <KEYID>)." >&2
        exit 1
    fi

_bump bump_kind: check-develop check-clean _require-bump-tools
    #!/usr/bin/env bash
    set -euo pipefail

    bump_kind="{{bump_kind}}"

    cleanup() {
        status=$?
        if [ $status -ne 0 ]; then
            echo "↩️  Restoring version files after failure..."
            git checkout -- Cargo.toml Cargo.lock >/dev/null 2>&1 || true
        fi
        exit $status
    }
    trap cleanup EXIT

    previous_version="$(just --quiet _workspace-version)"
    echo "ℹ️  Current version: ${previous_version}"

    echo "🔧 Bumping ${bump_kind} version..."
    cargo set-version --workspace --bump "${bump_kind}"
    new_version="$(just --quiet _workspace-version)"
    echo "📝 New version: ${new_version}"

    validate_bump() {
        local previous=$1 bump=$2 current=$3
        IFS=. read -r prev_major prev_minor prev_patch <<<"${previous}"
        IFS=. read -r new_major new_minor new_patch <<<"${current}"

        case "${bump}" in
            patch)
                (( new_major == prev_major && new_minor == prev_minor && new_patch == prev_patch + 1 )) || { echo "❌ Expected patch bump from ${previous}, got ${current}"; exit 1; }
                ;;
            minor)
                (( new_major == prev_major && new_minor == prev_minor + 1 && new_patch == 0 )) || { echo "❌ Expected minor bump from ${previous}, got ${current}"; exit 1; }
                ;;
            major)
                (( new_major == prev_major + 1 && new_minor == 0 && new_patch == 0 )) || { echo "❌ Expected major bump from ${previous}, got ${current}"; exit 1; }
                ;;
        esac
    }

    validate_bump "${previous_version}" "${bump_kind}" "${new_version}"

    echo "🔍 Verifying tag does not exist for ${new_version}..."
    git fetch --tags --quiet
    if git rev-parse -q --verify "refs/tags/${new_version}" >/dev/null 2>&1; then
        echo "❌ Tag ${new_version} already exists!"
        exit 1
    fi

    echo "🔄 Updating dependencies..."
    cargo update

    echo "🧹 Running clean build..."
    cargo clean

    echo "🧪 Running tests with new version (via just test)..."
    just test

    git add Cargo.toml Cargo.lock
    git commit -m "bump version to ${new_version}"
    git push origin develop
    echo "✅ Version bumped and pushed to develop"

# Bump version and commit (patch level)
bump:
    @just _bump patch

# Bump minor version
bump-minor:
    @just _bump minor

# Bump major version
bump-major:
    @just _bump major

# Internal function to handle the merge and tag process
_deploy-merge-and-tag: _require-tag-signing
    #!/usr/bin/env bash
    set -euo pipefail

    start_branch="$(git branch --show-current)"
    created_tag=""

    cleanup() {
        status=$?
        if [ $status -ne 0 ]; then
            if [[ -n "$created_tag" ]] && git rev-parse -q --verify "refs/tags/${created_tag}" >/dev/null 2>&1; then
                git tag -d "$created_tag" >/dev/null 2>&1 || true
            fi
            if [[ -n "$start_branch" ]]; then
                git checkout "$start_branch" >/dev/null 2>&1 || true
            fi
        fi
        trap - EXIT
        exit $status
    }
    trap cleanup EXIT

    new_version="$(just --quiet _workspace-version)"
    echo "🚀 Starting deployment for version $new_version..."

    # Double-check tag doesn't exist (safety check)
    echo "🔍 Verifying tag doesn't exist..."
    git fetch --tags --quiet
    if git rev-parse -q --verify "refs/tags/${new_version}" >/dev/null 2>&1; then
        echo "❌ Tag ${new_version} already exists on remote!"
        echo "This should not happen. The tag may have been created in a previous run."
        exit 1
    fi

    # Ensure develop is up to date
    echo "🔄 Ensuring develop is up to date..."
    git pull --ff-only origin develop

    # Switch to main and merge develop
    echo "🔄 Switching to main branch..."
    git checkout main
    git pull --ff-only origin main

    echo "🔀 Merging develop into main..."
    if ! git merge develop --no-edit; then
        echo "❌ Merge failed! Please resolve conflicts manually."
        exit 1
    fi

    # Create signed tag
    echo "🏷️  Creating signed tag $new_version..."
    git tag -s "$new_version" -m "Release version $new_version"
    created_tag="$new_version"

    # Push main and tag atomically
    echo "⬆️  Pushing main branch and tag..."
    if ! git push origin main "$new_version"; then
        echo "❌ Push failed! Rolling back..."
        exit 1
    fi

    # Switch back to develop
    echo "🔄 Switching back to develop..."
    git checkout develop

    echo "✅ Deployment complete!"
    echo "🎉 Version $new_version has been released"
    echo "📋 Summary:"
    echo "   - develop branch: bumped and pushed"
    echo "   - main branch: merged and pushed"
    echo "   - tag $new_version: created and pushed"
    echo "🔗 Monitor release: https://github.com/nbari/permesi/actions"

    if git rev-parse --verify sandbox >/dev/null 2>&1; then
        echo "🔄 Resetting sandbox branch to origin/develop..."
        git fetch origin
        git branch -f sandbox origin/develop
        # Track origin/sandbox so "git push" works without arguments
        git branch --set-upstream-to=origin/sandbox sandbox
        git push --force origin sandbox:sandbox
        echo "✅ Sandbox reset to origin/develop (pushed to origin/sandbox for CI)"
    fi

# Deploy: merge to main, tag, and push everything
deploy: bump _deploy-merge-and-tag

# Deploy with minor version bump
deploy-minor: bump-minor _deploy-merge-and-tag

# Deploy with major version bump
deploy-major: bump-major _deploy-merge-and-tag

# Deploy current version without bumping
deploy-current: check-develop check-clean test _deploy-merge-and-tag

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

# Create & push a test tag like t-YYYYMMDD-HHMMSS (skips publish/release in CI)
# Usage:
#   just t-deploy
#   just t-deploy "optional tag message"
t-deploy message="CI test": check-develop check-clean _require-tag-signing test
    #!/usr/bin/env bash
    set -euo pipefail

    message="{{message}}"
    ts="$(date -u +%Y%m%d-%H%M%S)"
    tag="t-${ts}"

    echo "🏷️  Creating signed test tag: ${tag}"
    git fetch --tags --quiet

    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
        echo "❌ Tag ${tag} already exists. Aborting." >&2
        exit 1
    fi

    git tag -s "${tag}" -m "${message}"
    git push origin "${tag}"

    echo "✅ Pushed ${tag}"
    echo "🧹 To remove it:"
    echo "   git push origin :refs/tags/${tag} && git tag -d ${tag}"

