# Contributing to Permesi

Thank you for helping. Permesi is an identity and access management system, so
the bar for a change is correctness and security first, then clarity. We prefer
small, well-documented diffs over large refactors, and a change that is easy to
review over one that is clever.

Three documents define what is expected, and they are short enough to read in
full before a first contribution:

- [AGENTS.md](AGENTS.md) is the contributor contract: code style, security
  invariants, module organization, documentation and testing rules. Its rules
  are mandatory.
- [AI_POLICY.md](AI_POLICY.md) says how AI-assisted work is treated. In short,
  a human owns every contribution and is accountable for it.
- [README.md](README.md) explains the architecture and how to run the stack, and
  [docs/README.md](docs/README.md) indexes the engineering and operations guides.

## Getting started

1. Install the prerequisites and start the local stack as described in the
   [Quick Start](README.md#quick-start-full-local-stack): `just doctor` checks
   the host, `just start` brings up PostgreSQL 19, OpenBao, Genesis, Permesi and
   the web console, and `just status` shows whether everything is healthy.
2. Pick something to work on from [TODO.md](TODO.md) or the open issues. For a
   larger change, open an issue first so the approach can be agreed before the
   work is done.
3. Work on a branch of your own. Maintainers integrate through `sandbox`; see
   [Releasing](#releasing).

## Making a change

- **Keep it focused.** Do not refactor, rename or reorder unrelated code.
- **Do not weaken security.** Authentication, authorization, token semantics,
  validation, rate and risk controls, TLS verification and logging hygiene stay
  as they are unless the change is explicitly about them. Never log secrets,
  tokens, passwords or verification links.
- **Configuration is declared once.** Runtime settings for `permesi` and
  `genesis` are defined in the service's `cli/commands/mod.rs`, validated by
  clap, and validated again in `cli/dispatch/mod.rs`. Do not hard-code values.
- **Test it.** Add a regression test with every bug fix. For anything
  security-sensitive, cover the malformed, missing, expired, replayed,
  mismatched, unauthorized and cross-tenant cases and assert that the protected
  state did not change. A skipped dependency or an empty test filter is not
  coverage.
- **Document it.** A change to behavior, flow or an endpoint is incomplete
  without its documentation: module docs for flows and trust boundaries, item
  docs for non-obvious invariants, and the relevant guide under `docs/`.
- **Regenerate the contract.** After changing an endpoint, run `just openapi`
  and commit the updated `docs/openapi/*.json`. Schema changes go in `db/sql/`.
- **Record what users need to know.** Add an entry to [CHANGELOG.md](CHANGELOG.md)
  for anything an operator, integrator or contributor has to know about.

## Checks before you submit

`just test` runs formatting, Clippy, the release web build and every workspace
test, which is the same suite a release runs. The individual gates are:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked -p permesi_web --target wasm32-unknown-unknown --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

`just clippy` runs both Clippy commands. Run `just web-setup` once to install
the WebAssembly target. Clippy is strict (`all` and `pedantic` are denied), and
production code does not use `unwrap`, `expect`, panics or `#[allow(...)]`.

The telemetry feature is off by default, and container images and releases
build with it on. Keep both the default and the `--all-features` builds
compiling and tested.

The integration tests start disposable PostgreSQL and OpenBao containers with
Podman, so they need a working Podman and nothing else. They use random ports
and unique container names, and they never touch the development stack.
`just test-clean` removes containers a crashed run left behind.

### Keeping Rust aligned with CI

`stable` selects a release channel; it does not automatically update an already
installed compiler. Run `rustup update stable` periodically. `just rust-check`
checks online without installing anything and refuses an outdated or missing
stable toolchain, an active compiler that differs from installed stable, or a
failed update check. It runs before `just build`, `build-permesi`,
`build-genesis` and `clippy`, including the `test`, `verify-release` and default
validation flows. Formatting remains offline. Check `PATH`, `RUSTUP_TOOLCHAIN`
and rustup overrides if an updated stable toolchain is installed but another
compiler is active. This checks today's stable, not the compiler recorded by a
past CI run.

## Commits and pull requests

- Write a short, plain, imperative subject that says what changed and why it
  matters, for example `Close the PostgreSQL pool on shutdown`. Do not use
  Conventional Commits prefixes such as `feat:` or `fix:`, and avoid vague
  subjects like `Update code`.
- A pull request states the problem, the approach and the impact, links the
  issue if there is one, and shows how it was validated: the commands run and,
  where it helps, output or screenshots. Mention OpenAPI and SQL changes.
- You are responsible for everything you submit. See [AI_POLICY.md](AI_POLICY.md).

## Continuous integration

See [CI, module boundaries, and build provenance](docs/ci-and-testing.md) for
module organization conventions, CI test/cache structure, `just test-fixture-profile`,
`just test-build-identity`, scenario commit checks, and `just ci-timings`.

Container jobs verify the API endpoint used by tests before proceeding. Each
self-hosted job starts a Podman service with its own runtime and Unix socket
under the user runtime directory, plus private image storage under
`RUNNER_TEMP`. `DOCKER_HOST` and `CONTAINER_HOST` route tests and CLI commands
to that job's engine, including when shared host Podman state is stale.
Same-user systemd socket hard links keep container DNS available, and an action
post hook removes the job's resources and subordinate-UID files through its own
namespace. Job setup does not migrate shared container state or remove another
job's socket or service. Runner maintenance handles Podman migrations while jobs
are stopped, plus orphaned resources after runner crashes when post hooks cannot
execute. GitHub-hosted jobs use the existing system Docker API. The runtime
action runs its isolation and readiness regressions before setup; run those
locally with `python3 .github/actions/ensure-container-runtime/test_runtime.py`.

## Releasing

This section is for maintainers. Work lands on `sandbox`; when its CI run is
green it is fast-forwarded into `develop`, and `just release` releases from
`develop`. The release rule is that the commit released is exactly the commit CI
tested, and the workflow changes nothing in the repository:

1. As the last commit of the work, the operator bumps the version with a tool of
   their choice (`cargo set-version --workspace --bump patch`, or `gbump`) in
   `Cargo.toml` and `Cargo.lock`, and sets `info.version` in
   `docs/openapi/permesi.json` and `docs/openapi/genesis.json` to the same value
   (`just openapi` regenerates them). The same commit gives the release its
   section in `CHANGELOG.md`: the version heading with the release date and the
   link at the foot of the file. The reviewer checks that the bump is present and
   complete.
2. Verify that `cargo audit --deny unsound --deny yanked` passes.
3. Merge `sandbox` into `develop` as a fast-forward and push. `CI OK` is a check
   on the commit, so the CI run that passed on `sandbox` already counts for the
   release guard once `develop` points at the same commit, and you can run
   `just release` at once.
4. Run `just release`. It starts `.github/workflows/release.yml` on `develop`,
   follows the run and, once it has succeeded and `develop`'s own Test & Build
   has finished, fast-forwards `main` to the released commit. `main` only allows
   the operator to push (the workflow's token cannot), and a protected branch
   refuses an update while a `CI OK` check of that commit is still pending, so
   this push waits for `develop`'s run and runs from the operator's machine.

   **Helm qualification before chart publication:** `release.yml` builds fresh
   images and dispatches their final digests to `permesi/permesi-helm`, where
   `release-bump-pr.yml` opens a bump PR with auto-merge enabled (so passing
   Charts CI can merge to Helm `main` and publish the chart automatically).
   Whenever a release carries Helm-affecting configuration, auth-mode, or SQL
   changes that require manual packaged-stack qualification, establish a merge
   hold on `permesi/permesi-helm` (for example, pause auto-merge or require
   manual review on Helm `main`) **before** running `just release` so the
   dispatched PR cannot auto-merge before qualification completes. Then qualify
   those exact dispatched image digests with matching SQL (packaged umbrella
   stack, Agent / native-Kubernetes / AppRole auth-mode transitions, and browser
   upgrade preserving existing OPAQUE and discoverable passkey credentials)
   before releasing the hold and merging to Helm `main`.

```
Release workflow (workflow_dispatch on develop)
 guard         develop only; the version is X.Y.Z, above the latest tag and untagged; both
               OpenAPI specs carry it; main is an ancestor; `CI OK` passed on this commit
 build         musl archives, Debian and RPM packages for x86_64 (amd64) and aarch64 (arm64),
               each on a native hosted runner, nothing from a cache
 frontend      the production web build, signed (checksums, cosign, build provenance)
 images        permesi, genesis and web, pushed only as `:sha-<commit>`, keylessly signed
               and OCI-attested
 release       exact file set checked, SHA256SUMS, build-provenance attestation, the GitHub
               release (this creates the tag at the tested commit) and a final check that
               the tag and the assets are right
 then          image digests get the version (and `latest`) tags, the web build goes to
               Cloudflare Pages, Helm is dispatched with the digests, and the API docs go
               to GitHub Pages
```

The Rust toolchain is `stable`, resolved once by the guard: every Rust job of the
run installs exactly that version, a re-run of failed jobs keeps it (the guard's
output is kept), and the release notes end with "Built with Rust X.Y.Z". Nothing
has to be bumped when Rust releases a new stable.

Nothing is published before every build job has succeeded. If a job fails, fix
the cause and use "Re-run failed jobs" on the run: a draft release left by a
failed run is replaced, an already published release is kept, and images are
retagged to the same digests. A failure after the tag exists (the release is
public) cannot be repaired by changing code under the same version: bump to the
next version and release that. The production steps (the `latest` image tag,
Cloudflare Pages, Helm and the docs) run only while the version is the highest
release tag, checked right before each acts, so a re-run of an older release
never rolls production back. The tag is created by GitHub and is not signed.
Releases need `just` and `gh` (logged in). Dependency updates (`cargo update`)
are ordinary changes made on `sandbox`, so CI tests them before a release.

The workflows reference actions by full commit SHA (checked by
`scripts/check-action-pins.py`), Dependabot proposes updates, the Rust toolchain
comes from `rustup` through `.github/actions/rust-toolchain`, no checkout keeps
the token, and every Cargo command uses `--locked`. To check a downloaded release
file:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify <file> --repo permesi/permesi --signer-workflow permesi/permesi/.github/workflows/release.yml
```

Every image digest is also keylessly signed by the Release workflow and carries
an OCI build-provenance attestation. Verify a published image against its digest
(constraining the OIDC issuer and the exact workflow identity, never a
permissive certificate-identity regex):

```sh
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/permesi/permesi/.github/workflows/release.yml@refs/heads/develop" \
  "ghcr.io/permesi/permesi@sha256:<digest>"
```

Real OIDC signing and publication require an authorized workflow run; they
cannot be produced locally.

## Security issues

Do not open a public issue, discussion or pull request for a suspected
vulnerability. Follow the [security policy](.github/SECURITY.md) and report it
privately.

## License

By contributing you agree that your work is licensed under the project's
[BSD-3-Clause license](LICENSE).
