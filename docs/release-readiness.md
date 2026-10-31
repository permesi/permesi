# Release readiness as of 2026-10-31

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
failed on `crypto-bigint 0.5.5` / `RUSTSEC-2026-0387`. The locked graph still reaches
it through `elliptic-curve 0.13.8`, including OPAQUE/voprf and the scenario runner's
OpenID Connect client. WebAuthn 0.6.2 removes its affected path, but updating one
path is insufficient.
Compatible published parent-library upgrades must remove every affected path;
the remaining parents have no such stable release yet. No new audit exception,
fork or backport was added. The older RSA exception and maintenance-warning policy
remain unchanged.

Recheck upstream around **2026-11-03**. This is a manual review target, not a
scheduled reminder or a promise to release after a week. The weekly Cargo
Dependabot group is prepared on `sandbox`, but GitHub reads that configuration from
the default branch. It is inactive until configuration promotion; do not promote
application code merely to activate it. The existing weekly audit detects
advisories and does not resolve dependency updates. See [workflow policy](../.github/workflows/README.md).

When compatible releases exist, update dependencies on `sandbox`, inspect all
`crypto-bigint` paths and require `cargo audit --deny unsound --deny yanked` to pass
under the existing policy. Rerun full application CI and qualify the final images
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
