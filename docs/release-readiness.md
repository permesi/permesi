# Release readiness as of 2026-11-06

Application changes remain on `sandbox`; Helm preparation remains on
`sandbox/release-readiness`. The application `main`/`develop` and Helm `main`
branches were unchanged by this qualification. No release tag, image or chart was
published. [TODO](../TODO.md#current-release-qualification) tracks the remaining work.

## Completed qualification

Permesi commit `ef3f9e2e13a8aaf24be04462c4a5099d139d65ea` requires discoverable
passkey enrollment while preserving required user verification and the existing
origin, RP, session-binding and cryptographic proof checks. The regression failed
against the previous policy and passed with the fix. All 38 targeted WebAuthn tests
ran without skips. Local default/all-feature library and binary suites passed
786/816 tests; their two ignored browser tests ran explicitly in hosted CI.
Native/WASM Clippy, formatting and OpenAPI checks also passed.

The [application Test & Build run](https://github.com/permesi/permesi/actions/runs/40477038756)
passed on that exact commit, including browser/PostgreSQL checks, coverage,
service/frontend builds, schema/integration/unit tests and three/five-replica
OAuth scenarios. The sandbox frontend preview deployed; production was not promoted.

Helm implementation commit `f031e2424553b6e5ea2dfde8dd152feb1613bb8b` passed
[Charts CI](https://github.com/permesi/permesi-helm/actions/runs/40477040602),
including release contracts, lint, 319 chart tests, chart installation, Kind smoke,
real dependency lifecycle and the new packaged embedded umbrella gate. Later
Helm commit `92d18e6414d33a75d3e36564308ec9081ea503e0` records local qualification
results and changes documentation only. Source chart versions are aligned at
0.4.6; committed application images and SQL still target published application
0.4.3, not the sandbox build.

Local candidate qualification used freshly built telemetry-enabled backends and
web from the application commit above, exact imported image manifests and matching
SQL. The packaged stack and Agent/native-Kubernetes/AppRole transitions passed.
The full browser upgrade preserved baseline OPAQUE and credential records, allowed
password/MFA sign-in, enrolled a discoverable passkey, reinstalled the package and
replaced every application pod before authenticating with that persisted passkey.
The temporary test cluster was removed. The reproducible procedures and limits are
in the [Helm installation guide](https://github.com/permesi/permesi-helm/blob/sandbox/release-readiness/docs/install-guide.md#qualifying-candidate-application-images).

An old nonresident credential cannot become discoverable through a server update.
Its row is retained; the user signs in with password/MFA and enrolls a new passkey.
See [WebAuthn policy](webauthn-exchanges.md#flow-and-bindings). These tests do not
establish Firefox/Safari compatibility, multi-host production HA or disaster recovery.

## Remaining work and release conditions

The separate [Rust Security Audit](https://github.com/permesi/permesi/actions/runs/40477038659)
previously failed on `crypto-bigint 0.5.5` / `RUSTSEC-2026-0387`. The 2026-11-06
refresh removes that version entirely through OpenID Connect 4.1.0 and an exact
upstream OPAQUE Git pin containing its unpublished RustCrypto migration. Only patched
`crypto-bigint 0.7.10` remains. The local audit now passes under the existing policy;
the older reviewed RSA exception and maintenance-warning policy remain unchanged.

The manual upstream recheck on **2026-11-06** is recorded below. The dependency
blocker is cleared locally; final release qualification remains required. The weekly Cargo
Dependabot group is prepared on `sandbox`, but GitHub reads that configuration from
the default branch. It is inactive until configuration promotion; do not promote
application code merely to activate it. The existing weekly audit detects
advisories and does not resolve dependency updates. See [workflow policy](../.github/workflows/README.md).

Keep the shared upstream OPAQUE revision fixed until a compatible published release
contains the migration, inspect all `crypto-bigint` paths and require
`cargo audit --deny unsound --deny yanked` to pass under the existing policy.
Rerun full application CI and qualify the final images
with matching SQL through the Helm packaged-stack, auth-mode and browser upgrade
procedures. Earlier green runs qualify only the commits identified above.

Keep publication held until that evidence is current and promotion is authorized.
Successful Helm `main` CI can start Auto Release and chart publication, so merging
the prepared branch is itself a publication decision. Other product and production
milestones remain open in TODO; this record does not mark them complete.

## Dependency recheck on 2026-10-29

`cargo upgrade --pinned` and an incompatible-upgrade dry run found no additional
direct upgrades except the four intentionally older `opaque_*` aliases. Those must
remain on Argon2 0.5, rand_chacha 0.3, rand_core 0.6 and SHA-2 0.10 to match
`opaque-ke 4.0.1`; upgrading them independently prevents dependency resolution or
breaks its protocol traits. The current prerelease, `opaque-ke 4.1.0-pre.2`, still
requires `elliptic-curve ^0.13` and `voprf ^0.5`, so it does not resolve the advisory.
To preserve these aliases during routine updates, exclude their package names:
`cargo upgrade --pinned --exclude argon2 --exclude rand_chacha --exclude rand_core --exclude sha2`.

`cargo update` found no further compatible lockfile updates. All three affected
paths remain: OPAQUE/voprf, WebAuthn/crypto-glue and OpenID Connect/P-256/P-384.
WebAuthn's latest published `0.6.1-dev` requires `crypto-glue ^0.1.15`; the newer
0.2 series uses the updated elliptic-curve stack but is outside that requirement.
Forcing `crypto-glue 0.1.18` fails because its exact digest prerelease conflicts
with the workspace's stable digest requirements, and it still requires the old
elliptic-curve stack. `openidconnect 4.0.1` remains the latest published release
and requires the old P-256/P-384 versions.

The fixed `crypto-bigint 0.7.10` cannot satisfy `elliptic-curve 0.13.8`'s `^0.5`
requirement. A fresh `cargo audit --deny unsound --deny yanked` against RustSec
revision `ee1a49a2769a24a596afc1c20cb33748d2769586` still fails solely on
[`RUSTSEC-2026-0387`](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
which requires `crypto-bigint >=0.7.6`; it also reports one allowed maintenance
warning for `paste`. No audit exception or dependency override was added. The
release remains blocked pending compatible parent-library releases.

Formatting, native all-target/all-feature Clippy and strict WASM Clippy pass with
this graph. Locked default and all-feature workspace tests pass 815 and 845 tests
respectively, with three browser tests ignored in each standard run. Those browser
workflows and the full isolated OAuth scenarios were not rerun for this recheck;
these results do not replace the final release qualification described above.

## Dependency refresh on 2026-10-31

`cargo upgrade --incompatible allow --pinned allow --exclude argon2 --exclude rand_chacha --exclude rand_core --exclude sha2`
upgrades `webauthn-rs` and its exactly matched protocol crate from `0.6.1-dev` to
stable `0.6.2`, and `web-sys` to `0.3.107`. The shared `opaque-ke`
dependency also moves to `4.1.0-pre.2` for the backend, browser client and scenario
runner. Its optional KEM feature stays disabled and the existing suite is unchanged.
The OPAQUE compatibility aliases remain unchanged. `cargo update` refreshes the
remaining compatible lockfile dependencies, including the matching wasm-bindgen
family, encoding_rs, log and orion. Existing
lockfile updates from the earlier recheck are retained.

WebAuthn now uses `crypto-glue 0.2.2`, `elliptic-curve 0.14.3` and the patched
`crypto-bigint 0.7.10`. Discoverable login uses the new single-credential verification
API with the current locked passkey; credential ID, proof, RP, origin and required
user-verification checks remain enforced. Persisted credential serialization is
unchanged. A regression verifies that a substituted credential ID is rejected,
consumes the challenge and cannot produce a session or change the credential.

Public, deterministic fixtures generated with `opaque-ke 4.0.1` verify that the
prerelease preserves the Vault-seed setup derivation, stored registration bytes,
pending client/server login states, handshake bytes and session keys. An altered
legacy finalization MAC is rejected. Isolated compile probes confirm that replacing
the aliases with Argon2 0.6, rand_chacha/rand_core 0.10 and SHA-2 0.11 fails on the
library's older KSF, RNG and digest traits; rand_core 0.10 also lacks the older
`getrandom`/`std` features. Those modern crate versions are already used elsewhere
in the workspace. Updating the aliases alone cannot migrate OPAQUE's dependencies.

`cargo tree --locked -i crypto-bigint@0.5.5` still shows OPAQUE/voprf and the isolated
scenario runner's OpenID Connect client. `opaque-ke 4.0.1` and `openidconnect 4.0.1`
remain their latest stable releases; even `opaque-ke 4.1.0-pre.2` still uses the older
elliptic-curve/voprf stack. Forcing `crypto-bigint 0.7.10` fails dependency resolution
because `elliptic-curve 0.13.8` requires `^0.5`. No fork, override or audit exception
was introduced.

`cargo audit --deny unsound --deny yanked` against RustSec revision
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81` still fails on
[`RUSTSEC-2026-0387`](https://rustsec.org/advisories/RUSTSEC-2026-0387.html), with the
existing allowed `paste` maintenance warning. The release remains blocked until
the remaining dependency paths are fixed and final qualification is repeated.

On this graph, locked default and all-feature workspace tests pass 819 and 849 tests
respectively, with three browser tests ignored in each standard run. Formatting,
native all-target/all-feature Clippy, strict WASM Clippy and `just openapi-check`
pass; generated API artifacts are unchanged. The browser workflows and full isolated
OAuth scenarios were not rerun, so these checks do not replace final release
qualification.

## Dependency refresh on 2026-11-06

`cargo upgrade` raises the scenario runner's `openidconnect` requirement from
`4.0.1` to `4.1.0`, removing its old P-256/P-384 dependency path. The backend,
browser and scenario runner now share upstream OPAQUE revision
[`027abbc91115baa38b70ad3af7f5a22f072f978b`](https://github.com/meta/opaque-ke/commit/027abbc91115baa38b70ad3af7f5a22f072f978b),
pinned once in the workspace manifest. Although it still declares version
`4.1.0-pre.2`, this Git revision includes the November 5 RustCrypto migration that
the published crate lacks. A future published release containing the migration can
replace that single dependency entry after compatibility and audit checks pass.

OPAQUE now uses Argon2 0.6, rand_chacha/rand_core 0.10 and SHA-2 0.11 without the
four older OPAQUE aliases. RSA 0.9 verification separately retains SHA-2 0.10 under
`rsa_sha2`; older transitive crypto versions still required by WebAuthn/RSA are not
forced outside their upstream constraints. Ephemeral ceremony CSPRNGs are seeded
from OS/browser entropy and reject entropy failure. The existing deterministic
Vault-seed setup derivation, cipher suite, identifiers and KSF parameters remain
unchanged; the optional KEM feature stays disabled.

`cargo update` removes `crypto-bigint 0.5.5`, `elliptic-curve 0.13.8` and the old
OPAQUE/voprf stack. `cargo tree --locked -i crypto-bigint` shows only patched
`0.7.10`. Other compatible updates include Leptos `0.8.23`, `aes 0.9.4`,
`ctutils 0.4.8`, `cc 1.11.1` and stable `pkcs1 0.8.0`.

`cargo audit --deny unsound --deny yanked` passes against RustSec revision
`26fd2d43f7280a1fb925a3743ec463017afe7119`, without a new exception. The existing
reviewed RSA exception remains. Two maintenance warnings are still allowed by the
existing policy: Leptos' `paste` and `astral-tokio-tar 0.6.4` through
`testcontainers 0.28.0`
([`RUSTSEC-2026-0440`](https://rustsec.org/advisories/RUSTSEC-2026-0440.html)).

Four public fixture regressions preserve the production Vault-seed setup bytes,
legacy registration records, pending client/server states, replayed handshake bytes
and session keys, reject a tampered legacy finalization, and complete a fresh
current-client login against the legacy record. voprf changed its random scalar
sampling, so a fixed RNG seed generates a different fresh client request. Replaying
the actual legacy encoded request retains the protocol compatibility assertion.

The browser release build uses wasm-bindgen CLI `0.2.130`, matching the locked Rust
crate; the older Trunk CLI pin failed the schema-version check and was corrected.
Formatting, native all-target/all-feature Clippy, strict WASM Clippy and OpenAPI
drift checks pass. Locked default and all-feature workspace suites pass 820 and 850
tests respectively, with three browser tests ignored in each standard run. Those
three tests run explicitly and pass alongside the Chromium console smoke suite.
Generated API artifacts are unchanged. These full-suite counts precede the final
compatible `flate2 1.1.11` lockfile refresh; that final graph passes `cargo check`,
formatting, both Clippy gates and the existing security audit policy. Hosted CI
must qualify the exact committed lockfile. The full isolated OAuth scenarios, hosted
application CI and final exact-image/SQL Helm qualification were not rerun for this
refresh; publication remains subject to those release conditions.

## Dependency refresh on 2026-11-07

Before splitting the unit-test CI job, `cargo upgrade` and `cargo update` refresh
`serde_spanned` to `1.1.3`, `smallvec` to `1.16.5`, `toml` to
`1.2.1+spec-1.1.0`, `toml_datetime` to `1.1.3+spec-1.1.0` and `uuid` to `1.29.1`.
The workspace also moves `axum-server` from `0.8.0` to
[`0.9.0`](https://github.com/programatik29/axum-server/releases/tag/v0.9.0). Its breaking
custom TLS acceptor change does not require application changes: both services
continue to supply their existing Rustls configuration to `from_tcp_rustls`.
Rustls already enables TLS 1.2 in this dependency graph; the upgrade does not
change the configured certificate verification or protocol policy.

The reviewed OPAQUE Git revision and RSA-specific SHA-2 compatibility alias remain
pinned. `cargo audit` passes with the existing RSA exception and the existing
`paste` and `astral-tokio-tar` maintenance warnings; no exception is added.

Formatting, native all-target/all-feature Clippy, strict WASM Clippy and Actionlint
pass. All four component/default-or-all-feature command selections compile and
list the expected targets, including all-feature integration targets and doctests.
The scenario runner's 45 unit tests pass, including its local HTTPS server and
client checks against the updated server library. These checks do not execute the
full database/Vault test suites; exact-commit CI qualification remains required
before the updated lockfile is release-ready.
