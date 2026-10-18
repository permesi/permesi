# Configurable OAuth HA scenarios

The standalone runner accepts `--replicas 3` through `--replicas 5`, with three as
the default. Each replica is an actual Permesi process with its own private socket
and Vault-issued runtime database credentials. All use one issuer, audience, shared
PostgreSQL and shared Vault configuration. Replica selection is controlled only by
the harness; browser parameters or headers cannot choose a backend.

Build with `just oauth-scenario-build`, then run:

```sh
target/debug/permesi-oauth-scenario --replicas 3 --suite ha
target/debug/permesi-oauth-scenario --replicas 5 --suite full --access-token-ttl-seconds 10
just oauth-scenario-harness-test --replicas 5
```

The full registry contains 34 cases. The focused `ha` suite selects seven cases:
provisioning, shared OPAQUE exchanges, authorization-code and refresh races, rolling
restart, backend outage and persisted-consent failover. JSON reports record the
configured replica count even when setup fails. CI runs separate three/five matrix
members with the same checked-out binaries and compiled frontend. Both must pass;
neither an unavailable dependency nor a skipped selection is coverage.

Code and refresh races dispatch concurrently through all configured private sockets.
Exactly one HTTP response must succeed; every other response must be an actual
`invalid_grant`, rather than a network error or 503. Independent signature, exact
user/client/application/organization/scope and hash-receipt checks remain in force.
Losing refresh reuse revokes its family, including the winning successor, on every
replica. Refresh races also check issuer/audience/client, TTL, no fabricated ID token,
the successor's previous hash and the family's `reuse` revocation before any test
replays can cause it. No assertion retries an exchange or relaxes protocol validation.

Rolling replacement issues a code and starts login/reauthentication on the selected
process, sends SIGTERM and requires a clean bounded exit. A survivor verifies the
original full session and completes login. The selected slot then starts a new
process with identical configuration and a different PID/birth-tick identity. It
must redeem the old code and finish the pending reauthentication while rejecting
spent proofs and code replay. This repeats for every configured slot. Health checks
target each private socket and cannot be satisfied by a different backend.

The outage case kills the last process before redemption. The stable issuer must
return 503 for that selected backend, and direct exchange must fail while PostgreSQL
still shows an unconsumed, unexpired code. Surviving processes then race code and
refresh redemption. After recovery, every replica must reject replay of the code,
refresh predecessor and family-revoked successor. This tests explicit selection of
a survivor; it does not implement or certify automatic production load balancing.

Every child handle is retained before its PID/birth ticks are atomically published
to the existing secret-free ownership record. Stops remove reaped incarnations;
restarts publish the new identity before awaiting readiness. Recordings retain
container names, network, private directory and the public resource origin. No
credential, command line, callback, proof, code or token enters the journal.
The long-lived host Podman process controlling Chromium is journaled too: its handle
is retained and its identity published before waiting for the browser handshake.
Every service-generation update preserves it, and only successful browser reaping
clears it. Healthy startup therefore records the configured replicas plus Genesis
and this browser controller; the browser container is separately label-owned.
Only old socket files can be removed for replacement; a regular file or symlink
fails without being deleted. Explicitly stopped slots are restored after a case,
including assertion failure; unplanned child exits and failed recovery remain
failures, with later unexecuted cases reported blocked.
Failed graceful stops and unready replacements force retirement and update the
journal before restoration. Incomplete retirement or journal failure blocks later
cases. Every live slot must pass its own health check before the next case starts.
The five-second SIGTERM test budget covers idle replacement; it deliberately does
not claim the product's full thirty-second drain and worker-shutdown budget.

Eight harness checks cover remote-engine rejection, partial startup, repeated
interruption, total deadline, cleanup failure, fresh repetitions, parallel stacks
and runner SIGKILL after a replacement. Recovery checks actual replacement
PID/birth ticks and private command paths before terminating a process. An independent
child observation must be entirely covered by the journal; journal-only recovery is
tested before out-of-band discovery is permitted as a final cleanup safety net. Private
file removal additionally requires an owned mode-0700 temporary directory and a
matching run marker. Container/network removal still requires exact ownership
labels; shared-engine prune/reset is never used.
Recovery requires Python 3.9+ and Linux 5.3+. It opens a
[PID file descriptor](https://docs.python.org/3/library/os.html#os.pidfd_open) before
validating birth/path ownership and signals that descriptor, closing the race between
a successful identity check and numeric PID reuse. Missing capabilities fail closed.

Six dependency-free recovery tests exercise rejected owner markers, directory
permissions, symlinks, PID birth/path substitution, pinned signalling, missing journal
children and a child-observation failure that must still kill and reap the runner. Run them with
`python3 -m unittest discover -s tools/oauth_scenario/tests -p '*_test.py'`.

This is one-host process/state coverage. It does not establish multi-host network
partitions, throughput, database/Vault outage policy, crashes inside a token commit,
ambiguous response-loss recovery, zero-downtime draining of in-flight requests or
host-power-loss journal durability. There remains an unavoidable process-level
SIGKILL window between spawning a child and publishing its identity; the recovery
check deliberately kills only after a replacement is journaled and ready.

Before this follow-up, default workspace checks passed and the all-feature run passed 702
tests (the two browser-only tests use their separate gate). Strict
all-target/all-feature Clippy, workspace/native-WASM checks, formatting and unchanged
OpenAPI regeneration pass. The original HA implementation passed all 41 runner tests, and all six Python
recovery tests pass. One intermediate runner repeat reported 22 passes and ten setup
failures because Unix/localhost listener binds were denied in that invocation; the
normal final runner check subsequently passed. This does not replace live CI validation.
The pre-exited-child shutdown regression was observed failing before its fix.
Removing the owner-marker check, accepting a pre-exited replica for fault injection,
allowing a single-response race, or omitting journaled process identities makes the
respective negative test fail; restoring each guard passes. A separate attempted
supervisor mutation stopped at restricted socket setup and is not mutation evidence;
the unmodified supervisor test passes normally.
Additional corrected regression checks were observed red/green for failed-stop
retirement, refresh client binding and browser-controller journaling. Scratch Python
mutations also fail for an omitted journal child and numeric-PID signalling, then
pass with the guards restored. All source mutations were restored byte for byte.

Claude's independent Herdr review found no critical, high or medium issues and five
low findings in test recovery or coverage. All were independently verified and
addressed: failed-transition retirement/readiness, journal-only recovery, exact refresh
claims/lineage, revocation-before-replay assertions and pinned recovery signalling.
The PID-reuse finding was a race identified by inspection, not a reproduced unrelated
process kill. Missing `/proc` metadata now fails closed; stale labels/order comments
were corrected. A second review confirmed those fixes but reproduced one medium
coverage failure: the strict process oracle also observes the host browser controller.
It is now journaled before readiness and covered by two owned-child lifecycle tests.
A third focused review accepted the correction, with no remaining critical, high,
medium or low findings. All 41 runner tests and six Python tests were independently
rerun by Claude. The subsequent live matrix and oracle correction are recorded below. Expected refresh
scope is deliberately rebuilt from the fixture independently of the response; drift
fails closed and is a maintenance coupling rather than delegated authority widening.
Rootless Podman may manage helper descendants beyond the direct host controller;
container cleanup relies on verified labels, and this harness does not certify a
host-wide descendant-process audit. Shared engine helpers must never be pruned as
part of an individual run's recovery.

The first local validation session could not start Podman because
`/run/user/1000/libpod` was read-only; its five-replica HA attempt executed zero cases.
In the subsequent unrestricted local session, the corrected runner passes all 34 cases
with three replicas and again with five, each with zero cleanup errors. Both topologies
also pass all eight separate recovery harness checks. A fresh Web release build, console
browser smoke and both actual PostgreSQL browser tests pass. The earlier
[three-replica hardening record](database-hardening.md) validates the prior 32-case
implementation and cannot establish the new restart/five-replica coverage.

The first live three/five CI matrix on `d5548b2` passed 32/34 cases per member, including
rolling replacement, code races and shared OPAQUE state. Both failed the same new
refresh-lineage oracle: refresh families store the internal registration ID, while
the oracle compared it directly with the public protocol client ID. The correction
resolves that ID through `oauth_clients` and retains every tenant, lineage and reuse
predicate. A real PostgreSQL query regression deliberately uses distinct IDs and
rejects substituted bindings/revocation state. The corrected local and hosted three/five
full suites pass 34/34 cases and all eight harness checks per topology. Hosted run
`39103751747` passed on its fourth attempt: integration and unit jobs needed isolated
reruns after PostgreSQL container-startup timeouts, and the five-replica harness needed
an isolated rerun after its simultaneous-run check failed while the three-replica harness
was also active on the same host. Both hosted real suites passed on their first execution.
The follow-up workflow serializes database-heavy test jobs and topology matrix members
to reduce shared-host contention. Its fresh run `39110929583` passed both topologies,
their harnesses and the required `CI OK` gate on the first attempt. Independent review
of the correction is complete.

After the 0.4.1 release, simultaneous branch runs exposed more fixture contention:
PostgreSQL startup failed after a five-second TCP probe, while the scenario harness
reported only a generic failure. Unit and integration jobs now cap Rust test threads
at four, and the shared fixture limits concurrent PostgreSQL startups through actual
TCP readiness with a 30-second deadline. The harness still fails on any broken
ownership or cleanup invariant, but reports its source line and exception class
without disclosing captured process output.

The combined follow-up also bounds hierarchy mutation waits and corrects cancelled
transaction startup. AGY/Gemini 4 Argon completed static Herdr review; Claude's independent
review found additional transaction-cancellation and organization-update issues. Confirmed
findings now have fixes and PostgreSQL regression evidence. The corrected Claude review
reports no remaining actionable findings; 688 default/718 all-feature workspace tests
and both PostgreSQL browser tests pass. The signed correction was published as `2be597f`.
Hosted builds, browser checks, both workspace suites and both three/five scenario suites
passed in run `39103751747` after the isolated retries described above. Details are recorded in
[the mutation validation record](tenant-mutation-validation.md).
The validated topology remains single-host with a shared PostgreSQL/Vault stack; multi-host
load, network partitions and in-flight response-loss ambiguity remain separate work.
