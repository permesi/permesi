# Fixture runtime measurement

This follow-up to [the maintainability batch](maintainability-ci.md) measures test
fixtures before tuning them. `CI_RUNNER`, fresh per-test databases,
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

## Validation and review

Workspace, real browser, canonical schema, strict native/WASM Clippy, formatting
and OpenAPI checks pass. The full three/five-replica suites and both eight-check
harnesses pass with zero cleanup failures. The conflicting-client-lock mutation
fails as intended. Independent Herdr/OMP `xai-oauth/grok-4.7` review found no
confirmed defect in the fixture changes and verified the row-lock coverage
boundary. Hosted runtime comparisons and broader advisory-lock fairness remain
separate follow-ups.
