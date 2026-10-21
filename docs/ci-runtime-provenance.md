# Fixture runtime and native build identity

This follow-up to [the maintainability batch](maintainability-ci.md) measures test
fixtures before tuning them and makes the existing same-run binary transport
check its expected commit explicitly. `CI_RUNNER`, fresh per-test databases,
default/all-feature suites and both three/five-replica gates remain unchanged.

## Fixture measurement

Run `just test-fixture-profile` for three rounds of four independent PostgreSQL 18
and Vault 1.17.3 pairs, matching CI's four concurrent-test limit. An optional round
count from one to ten changes the sample count: `just test-fixture-profile 5`.
Each pair measures container start/port discovery, PostgreSQL TCP readiness,
canonical SQL bootstrap, Vault auth/transit setup and explicit removal separately.
The JSON on stdout records milliseconds and fixed phase names; build output goes
to stderr. Initialization failure, setup failure or unsuccessful removal returns
nonzero. An incomplete run never produces a successful profile. Images should be
present before timing; engine initialization is outside the measured interval.
This representative workload does not measure every test's Vault configuration,
OPAQUE work, deliberate lock waits or service startup.

On the local Linux/Podman host, 12 fresh pairs took 12,715 ms before the change and
9,907 ms afterward, about 22% less wall time. Median pair durations fell from
3,922 to 3,025 ms. Both helpers previously slept 500 ms unconditionally after their
container readiness condition, before even querying published ports. They now
query immediately and retain all 60 bounded mapping attempts, backoff, PostgreSQL
TCP readiness/startup permits and Vault HTTP-health checks. The database often
still needs a short TCP wait after its log readiness. A subsequent run under
concurrent test load took 10,927 ms. These are local fixture observations, not a
claim of a 22% reduction in the entire hosted pipeline.

An older hosted release run also exposed the client-reader regression's 500 ms
whole-request deadline. The test now observes `pg_blocking_pids` while retaining
the held client `FOR SHARE` transaction until the request completes. A real wait
on that reader fails the test; a ten-second watchdog bounds unrelated hangs.
Concurrent consent and single-grant assertions remain. A mutation that holds a
conflicting `FOR UPDATE` lock fails with the explicit blocker diagnostic. Product
lock modes and authorization policy are unchanged.
This test covers the held row-reader boundary; it does not test advisory-lock
fairness or all possible serialization between users. The former 500 ms
single-request assertion did not establish those broader properties either.

## Cached build identity

Both service build scripts use `services/build_identity.rs`. It explicitly tracks
`BUILD_GIT_COMMIT_HASH` addition, change and removal, preserves package input
tracking and watches available Git HEAD, loose/packed references and linked-worktree
markers. The existing precedence remains explicit build hash, discovered Git
commit, then `unknown`; this change does not create a runtime configuration flag.
Git discovery uses the already-present libgit2 dependency without requiring a
Git executable inside service image builds.

`just test-build-identity` requires Python 3.11+, Git and a temporary directory
outside any Git checkout for the Git-less case (the ordinary system temp directory
works). It compiles tiny disposable crates using the actual service
build scripts and identity-selection constants. It exercises cached Git-less
builds through unset/A/B/empty/unknown/unset transitions without source changes or
cleaning the target, then loose refs, packed-ref movement, detached HEAD and linked
worktrees. Dependencies are reused offline in `target/build-identity-regression`;
the normal locked workspace build must have fetched them first. Removing the
environment invalidation directive makes the cached Git-less regression fail.
Build and Git subprocesses share a sanitized environment: caller Git redirection
and metadata overrides are discarded, and global/system Git configuration is
isolated. A regression first reproduced redirection into a separate disposable
repository, then verified that its HEAD, config, index, branch and sentinel remain
unchanged under the corrected helper. No development repository is used as the
adversarial target.
The reusable native-test workflow runs this check after both test configurations.

The scenario runner accepts `--expected-commit <full-lowercase-40-character-SHA>`,
also available as `PERMESI_SCENARIO_EXPECTED_COMMIT`. CI sets it to `github.sha`
for the entire scenario job, including harness subprocesses. Before creating any
dependency or service, the runner requires its linked identity and both service
`--version` identities to match the expected commit and workspace version exactly.
Mixed, unknown, shortened or wrong-version artifact identities fail closed. A
well-formed run with mismatched artifacts writes blocked results for every selected
repetition without starting infrastructure. Malformed expected-commit arguments are
clap usage errors before a run exists.
The flag is optional for local work. For example, after building the current tree:

```sh
target/debug/permesi-oauth-scenario --expected-commit "$(git rev-parse HEAD)" --replicas 5 --suite ha
```

The archive still comes only from the same workflow run, with an exact-SHA name
and executable permissions preserved through tar transport. The explicit check
detects accidental stale/mixed artifacts; self-reported commit labels are not
cryptographic attestation of a hostile executable, nor proof that a local tree is
clean. Same-run artifact trust remains necessary. Cross-run/cross-branch reuse is
not enabled. Optional signed manifests/checksums and a separate reuse policy are
future work.

## Validation boundary

Local default/all-feature suites pass 723/753 tests, with the two ignored browser
tests then explicitly passing through `just web-test-browser-built`. Strict native
and WASM Clippy, formatting, service/runner builds, OpenAPI byte comparison and
Actionlint with ShellCheck pass. The phase profiler exercises canonical schema
bootstrap/verification on fresh databases. Fifteen container-runtime tests, eight
runner Python regressions and all three build-identity/isolation regressions pass. The environment
invalidation and conflicting-client-lock mutations fail as intended; restored
code passes.

Stripped archive transport preserves staged bytes/executable modes,
and both full HA topologies pass 36/36 cases with zero cleanup errors while enforcing
the expected commit. All eight real cleanup/isolation/restart harness checks pass
on each topology with the same expected-commit environment, including the harness's
intentional startup-failure substitutes.

Independent Herdr/OMP `xai-oauth/grok-4.7` review found a medium-severity isolation
defect in the new regression script: Git subprocesses could inherit caller
repository redirection. The shared sanitized environment fixes both build/Git
paths, and the protected foreign-state regression was observed failing before the
fix and passing afterward. The reviewer independently reran all three tests and
verified hostile XDG Git hooks were not invoked. Its full review and corrected-file
re-review found no remaining confirmed defect. Malformed-CLI report boundaries,
row-lock coverage and self-reported artifact labels are documented limitations.
The reviewer inspected primary HA/harness evidence but did not rerun long suites.

Hosted comparisons must distinguish queue/dependency waits, compilation,
test execution, artifact transfer and retries. A single completed run is useful
evidence, but several comparable runs are needed before claiming a CI speedup.
