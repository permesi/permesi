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

test:
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
    signing_format="$(git config --get gpg.format || true)"
    signing_format="${signing_format:-openpgp}"

    case "${signing_format}" in
        ssh)
            if ! command -v ssh-keygen >/dev/null 2>&1; then
                echo "❌ ssh-keygen not found; required for SSH-signed tags." >&2
                exit 1
            fi
            if [[ -z "$(git config --get user.signingkey || true)" ]]; then
                echo "❌ user.signingkey is required for SSH-signed tags." >&2
                echo "Configure it with: git config user.signingkey '<SSH public key or key path>'" >&2
                exit 1
            fi
            ;;
        openpgp)
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
                echo "❌ gpg not found; required for OpenPGP-signed tags." >&2
                exit 1
            fi
            if ! "$gpg_cmd" --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'; then
                echo "❌ No OpenPGP secret keys found for signing." >&2
                echo "Configure a signing key and retry (git config user.signingkey <KEYID>)." >&2
                exit 1
            fi
            ;;
        *)
            echo "❌ Unsupported Git signing format '${signing_format}' for release tags." >&2
            echo "Use SSH or OpenPGP signing." >&2
            exit 1
            ;;
    esac

# Bump the workspace version on develop and push the bump commit. The commit changes
# nothing but the version: Cargo.toml, the workspace entries of Cargo.lock
# (`cargo update --workspace` leaves third-party crates alone; dependency updates go
# through sandbox like any other change) and the OpenAPI specs regenerated from the
# already-tested code so the published API docs carry the release version. A clean
# local build and `verify-release` run before the push as a fast fail; CI on develop
# is the gate that decides whether the commit is released.
_bump bump_kind: check-develop check-clean _require-bump-tools
    #!/usr/bin/env bash
    set -euo pipefail

    bump_kind="{{bump_kind}}"
    release_files=(Cargo.toml Cargo.lock docs/openapi/permesi.json docs/openapi/genesis.json)

    cleanup() {
        status=$?
        if [ $status -ne 0 ]; then
            echo "↩️  Restoring version files after failure..."
            git checkout -- "${release_files[@]}" >/dev/null 2>&1 || true
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

    echo "🔒 Updating the workspace entries in Cargo.lock..."
    cargo update --workspace

    echo "📄 Regenerating the OpenAPI specs..."
    just openapi

    echo "🧹 Running clean build..."
    just clean

    echo "🧪 Running release verification (including frontend build)..."
    CARGO_TARGET_DIR="{{root}}/target" just verify-release

    git add "${release_files[@]}"
    git commit -m "bump version to ${new_version}"
    git push origin develop
    echo "✅ Version bumped and pushed to develop"
    just _sync-sandbox

# Bump version and commit (patch level)
bump:
    @just _bump patch

# Bump minor version
bump-minor:
    @just _bump minor

# Bump major version
bump-major:
    @just _bump major

# Everything a release needs, checked before anything is changed or pushed. `kind`
# is patch, minor, major or current (release the current version as is). It requires
# a clean develop equal to origin/develop that main can fast-forward to, an
# authenticated gh (to follow CI), a free tag for the version being released, and a
# working signing setup: a throwaway local tag exercises the key or agent for real.
_release-preflight kind: check-develop check-clean _require-tag-signing
    #!/usr/bin/env bash
    set -euo pipefail
    kind="{{kind}}"

    current="$(just --quiet _workspace-version)"
    IFS=. read -r major minor patch <<<"${current}"
    case "${kind}" in
        patch) version="${major}.${minor}.$((patch + 1))" ;;
        minor) version="${major}.$((minor + 1)).0" ;;
        major) version="$((major + 1)).0.0" ;;
        current) version="${current}" ;;
        *) echo "❌ Unknown release kind '${kind}' (patch, minor, major or current)." >&2; exit 1 ;;
    esac
    if [[ "${kind}" != "current" ]]; then
        just --quiet _require-bump-tools
    fi

    git fetch --quiet --tags origin
    if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/develop)" ]]; then
        echo "❌ develop differs from origin/develop; pull or push it first." >&2
        exit 1
    fi
    if ! git merge-base --is-ancestor origin/main HEAD; then
        echo "❌ origin/main has commits develop lacks, so main cannot fast-forward." >&2
        echo "   Merge main into develop first." >&2
        exit 1
    fi
    if ! command -v gh >/dev/null 2>&1 || ! gh auth status >/dev/null 2>&1; then
        echo "❌ gh must be installed and authenticated to follow CI (gh auth login)." >&2
        exit 1
    fi
    if git rev-parse -q --verify "refs/tags/${version}" >/dev/null 2>&1; then
        echo "❌ Tag ${version} already exists." >&2
        exit 1
    fi
    probe="release-signing-probe-$$"
    if ! git tag -s "${probe}" -m "signing probe" HEAD >/dev/null 2>&1; then
        echo "❌ git could not sign a tag; check the signing key or agent." >&2
        exit 1
    fi
    git tag -d "${probe}" >/dev/null
    echo "✅ Release preflight passed for ${version}"

# Wait for the push-triggered "Test & Build" run of exactly this commit and fail
# unless it succeeds, so only a commit CI has passed is ever tagged or put on main.
# A run of the same commit on sandbox counts too: it is the same code. When the run
# fails, the gate keeps waiting for PERMESI_RELEASE_RERUN_WAIT seconds (default 900):
# "Re-run failed jobs" in GitHub starts a new attempt of the same run, the gate
# follows it, and the release continues on its own if that attempt passes.
# PERMESI_RELEASE_CI_TIMEOUT caps each attempt's wait in seconds (default 3600).
_release-gate sha:
    #!/usr/bin/env bash
    set -euo pipefail
    sha="{{sha}}"
    timeout="${PERMESI_RELEASE_CI_TIMEOUT:-3600}"
    deadline=$((SECONDS + timeout))
    appear_deadline=$((SECONDS + 300))

    echo "⏳ Waiting for the Test & Build run of ${sha:0:12}..."
    run_id=""
    while [[ -z "${run_id}" ]]; do
        run_id="$(gh run list --workflow build.yml --commit "${sha}" --event push --limit 1 \
            --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
        if [[ -z "${run_id}" ]]; then
            if (( SECONDS >= appear_deadline )); then
                echo "❌ No Test & Build run appeared for ${sha} within 5 minutes." >&2
                exit 1
            fi
            sleep 10
        fi
    done
    url="$(gh run view "${run_id}" --json url --jq .url)"
    echo "🔗 ${url}"

    rerun_wait="${PERMESI_RELEASE_RERUN_WAIT:-900}"
    if (( rerun_wait >= 60 )); then window="$((rerun_wait / 60)) minutes"; else window="${rerun_wait} seconds"; fi
    failed_at=""
    last=""
    while true; do
        state="$(gh run view "${run_id}" --json status,conclusion,attempt \
            --jq '"\(.status) \(.conclusion // "-") \(.attempt)"' 2>/dev/null || echo "unknown - ?")"
        read -r status conclusion attempt <<<"${state}"
        if [[ "${status} ${attempt}" != "${last}" ]]; then
            echo "   CI: ${status} (attempt ${attempt})"
            last="${status} ${attempt}"
        fi
        if [[ "${status}" == "completed" ]]; then
            if [[ "${conclusion}" == "success" ]]; then
                echo "✅ CI passed for ${sha:0:12}"
                exit 0
            fi
            if [[ -z "${failed_at}" ]]; then
                failed_at="${SECONDS}"
                echo "❌ CI finished with '${conclusion}': ${url}" >&2
                echo "   Re-run the failed jobs in GitHub within ${window} and this release" >&2
                echo "   continues by itself; Ctrl-C to stop waiting." >&2
            elif (( SECONDS - failed_at >= rerun_wait )); then
                echo "❌ No re-run started within ${window}; nothing was released." >&2
                echo "   Re-run the jobs or fix forward (sandbox, then develop), then: just deploy-current" >&2
                exit 1
            fi
        elif [[ -n "${failed_at}" ]]; then
            echo "🔁 Re-run started; following attempt ${attempt}"
            failed_at=""
            deadline=$((SECONDS + timeout))
        fi
        if [[ -z "${failed_at}" ]] && (( SECONDS >= deadline )); then
            echo "❌ CI did not finish within ${timeout}s: ${url}" >&2
            echo "   When it passes, finish with: just deploy-current" >&2
            exit 1
        fi
        sleep 20
    done

# Tag the CI-verified commit and move main to it in one atomic push. Either both refs
# land or neither does, and GitHub rejects a push that is not a fast-forward of main,
# so main and the tag always point at the exact commit CI tested; no merge happens.
_release-promote version sha:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{version}}"
    sha="{{sha}}"

    echo "🏷️  Creating signed tag ${version} on ${sha:0:12}..."
    git tag -s "${version}" "${sha}" -m "Release version ${version}"
    echo "⬆️  Pushing ${sha:0:12} to main together with tag ${version} (atomic)..."
    if ! git push --atomic origin "${sha}:refs/heads/main" "refs/tags/${version}"; then
        git tag -d "${version}" >/dev/null 2>&1 || true
        echo "❌ Push rejected; nothing was released and the local tag was removed." >&2
        exit 1
    fi

    git fetch --quiet origin
    if git show-ref --verify --quiet refs/heads/main && [[ "$(git branch --show-current)" != "main" ]]; then
        if git merge-base --is-ancestor main origin/main; then
            git branch -f main origin/main >/dev/null
        else
            echo "⚠️  Local main has commits origin/main lacks; left it untouched." >&2
        fi
    fi
    echo "✅ Released ${version}: main and the tag point at ${sha:0:12}"

# Keep sandbox equal to develop; runs after the version bump and again after a
# release, with develop checked out. sandbox (local and on origin) moves to develop's
# HEAD when it is an ancestor of it (a fast-forward), or when its content equals HEAD
# or the commit before it (work that was squash-merged and then bumped). A forced move
# uses --force-with-lease and keeps the old tip as refs/backup/sandbox/<tip>. A
# sandbox that holds work develop lacks, or is already ahead of it, is left alone, and
# no outcome here fails the release.
_sync-sandbox:
    #!/usr/bin/env bash
    set -euo pipefail
    target="$(git rev-parse HEAD)"
    if ! git fetch --quiet origin sandbox 2>/dev/null; then
        echo "ℹ️  origin has no sandbox branch; nothing to sync."
        exit 0
    fi
    old="$(git rev-parse refs/remotes/origin/sandbox)"

    if [[ "${old}" == "${target}" ]]; then
        echo "✅ sandbox matches develop (${target:0:12})"
    elif git merge-base --is-ancestor "${target}" "${old}"; then
        echo "ℹ️  sandbox is ahead of develop; left as is."
        exit 0
    elif git merge-base --is-ancestor "${old}" "${target}"; then
        if ! git push --quiet origin "${target}:refs/heads/sandbox"; then
            echo "⚠️  Could not fast-forward sandbox; sync it yourself." >&2
            exit 0
        fi
        echo "✅ sandbox fast-forwarded to develop (${target:0:12})"
    elif git diff --quiet "${old}" "${target}" ||
        { git rev-parse -q --verify "${target}^" >/dev/null && git diff --quiet "${old}" "${target}^"; }; then
        git update-ref "refs/backup/sandbox/${old:0:12}" "${old}"
        if ! git push --quiet --force-with-lease="sandbox:${old}" origin "${target}:refs/heads/sandbox"; then
            echo "⚠️  sandbox changed on origin meanwhile; left it alone." >&2
            exit 0
        fi
        echo "✅ sandbox moved to develop (${target:0:12}); its squash-merged history is kept as refs/backup/sandbox/${old:0:12}"
    else
        echo "⚠️  sandbox has changes develop does not contain; left it alone." >&2
        exit 0
    fi

    if git show-ref --verify --quiet refs/heads/sandbox && [[ "$(git branch --show-current)" != "sandbox" ]]; then
        local_tip="$(git rev-parse refs/heads/sandbox)"
        if [[ "${local_tip}" == "${old}" ]] || git merge-base --is-ancestor "${local_tip}" "${target}"; then
            git branch -f sandbox "${target}" >/dev/null
            git branch --set-upstream-to=origin/sandbox sandbox >/dev/null 2>&1 || true
        else
            echo "⚠️  Local sandbox has commits of its own; left the local branch alone." >&2
        fi
    fi

# Release flow behind the deploy recipes (kind: patch, minor, major or current).
# Flow: preflight, version bump pushed to develop with sandbox kept in step (skipped
# for current), wait for CI on that exact commit, then tag it and fast-forward main
# to it in one atomic push, and sync sandbox once more. Nothing reaches main or gets
# tagged unless CI passed on that very commit. If CI fails or the wait is
# interrupted, develop and sandbox hold the bump commit: fix forward on sandbox,
# merge into develop, and run `just deploy-current`, which releases without bumping.
_release kind:
    #!/usr/bin/env bash
    set -euo pipefail
    kind="{{kind}}"

    just _release-preflight "${kind}"
    if [[ "${kind}" != "current" ]]; then
        just _bump "${kind}"
    fi
    version="$(just --quiet _workspace-version)"
    sha="$(git rev-parse HEAD)"

    just _release-gate "${sha}"
    just _release-promote "${version}" "${sha}"
    just _sync-sandbox

    echo "🎉 Version ${version} released"
    echo "🔗 Monitor the release: https://github.com/permesi/permesi/actions"

# Deploy: bump the patch version, wait for CI on develop, then tag and fast-forward main
deploy: (_release "patch")

# Deploy with minor version bump
deploy-minor: (_release "minor")

# Deploy with major version bump
deploy-major: (_release "major")

# Release the current develop commit without bumping (also resumes an interrupted deploy)
deploy-current: (_release "current")

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
