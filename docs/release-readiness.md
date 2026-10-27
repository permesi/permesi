# Release readiness as of 2026-10-27

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
it through `elliptic-curve 0.13.8`, including OPAQUE/voprf, WebAuthn/crypto-glue and
the scenario runner's OpenID Connect client. Updating one path is insufficient.
Compatible published parent-library upgrades must remove every affected path;
normal dependency updates in this batch did not do so. No new audit exception,
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
