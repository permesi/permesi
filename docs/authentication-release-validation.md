# Authentication release validation

This record covers the five-part shared-authentication and OAuth refresh batch on
`sandbox`. The implementation includes durable OPAQUE and WebAuthn exchanges,
password/MFA authority transitions, shared authentication admission and rotating refresh
families. It prepares the workspace for release; it does not create a release tag,
promote a deployment or claim OIDC certification. [TODO.md](../TODO.md) remains the
authoritative roadmap.

## Implemented boundaries

OPAQUE and all four WebAuthn ceremonies use bounded, AEAD-sealed PostgreSQL state,
hashed external references and atomic single-attempt consumption. Replicas share the
database, Vault seed and protocol configuration; no sticky session or local challenge
map is needed. WebAuthn binds purpose, relying party/origin, user and original session.
The current user, session and credential state is locked through authority issuance.
See [OPAQUE](opaque-exchanges.md) and [WebAuthn](webauthn-exchanges.md) for migration,
expiry, encrypted-state retention and format-upgrade requirements.

Password rotation and MFA recovery atomically revoke old authority and advance the
user authorization revision. MFA enrollment/elevation/recovery checks current session
kind and expiry under identity/session locks, consumes its original limited authority
on success and cannot reenroll an already confirmed TOTP credential to bypass elevation.
[MFA lifecycle](mfa-lifecycle.md) describes the intentionally preserved factor/session
policy and remaining recent-authentication and attempt-counter work.

[Authentication admission](authentication-operations.md) separates flow and subject
budgets, verifies transport/proxy identity, bounds database waits and returns generic
429/503 responses with sanitized outcome events. Transient exchange encryption uses
192-bit XChaCha nonces with a documented cumulative-start policy. The isolated scenario
runner explicitly configures and reports a 1,000-attempt fixture IP budget because its
32 cases share one loopback address. The service default remains 100; dedicated low-limit
regressions still exercise enforcement. Running the same current suite with a budget
of 100 reproduces 429 failures in the final rotation/failover cases without retries.

[Refresh families](oauth-refresh-tokens.md) persist only token hashes and immutable
user/client/application/organization/grant/scope bindings. Rotation, access signing,
issuance receipts and successor insertion commit together. Reuse commits whole-family
revocation, including a concurrently issued successor. Current ancestry, membership,
consent and user revision are revalidated. Explicit OIDC offline consent is required.
The default absolute lifetime is 30 days and idle lifetime is seven days. Already
signed JWTs retain their finite lifetime; refresh revocation does not retract them.

## Checks and execution evidence

Default and all-feature workspace runs pass 642 and 672 tests respectively. Their two
ignored PostgreSQL browser tests were exercised explicitly through the browser workflow.
The real dependency runs include PostgreSQL cryptographic/concurrency tests and initial
and replacement Vault database credentials; unavailable-dependency skips and zero-test
filters are not counted as evidence.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --all-features` | Pass |
| `cargo test --locked --workspace` and `--all-features` | 642 / 672 passing tests |
| Native scenario runner and Web tests | 24 / 23 passing tests, included above |
| Full isolated runtime-role A/B scenario suite | 32 cases pass; zero infrastructure or cleanup errors |
| Scenario process/harness checks | Seven pass |
| Browser workflow | Console and both actual PostgreSQL/OPAQUE/authorization stages pass |
| Fresh canonical database bootstrap, verification and reapplication | Pass |
| Actual Vault initial/replacement runtime-role checks | Pass |
| OpenAPI regeneration, native/WASM builds and Web checks | Pass |
| `cargo audit --deny unsound --deny yanked`, existing repository policy | Pass; three allowed maintenance warnings |

The dependency audit used RustSec revision `ef6173cbc5c50ec8166f9a5b28f07834144373ee`,
verified against the upstream HEAD through GitHub's API. The restricted primary environment
used that matching cached advisory database and a writable copy of the local registry index;
the successful scan had no missing-index/yanked-check errors. Registry metadata was cached.
The existing RSA advisory exception and maintenance-warning policy were unchanged.

The pushed OAuth candidate `994adfb` passed every required job in
[CI run 37449927709](https://github.com/permesi/permesi/actions/runs/37449927709), including
coverage, format/check/Clippy, schema, integration/unit tests, musl and frontend builds,
browser tests, isolated scenarios, integrity checks and `CI OK`. Package publication
is skipped on `sandbox`. The final Genesis search-path correction has additional local
Vault and mutation evidence below. Any subsequent push or release promotion must check
its own exact commit's hosted results; an earlier green run is not evidence for a later
head. There are no configured local pre-commit or pre-push hooks to run.

## Independent review and corrections

Claude reviewed the earlier milestones independently through Herdr. Confirmed issues
were fixed in Podman 4.x/5.x fixture publication, nested connection acquisition under an
identity guard, MFA transition/audit ordering, proof versus dependency error handling,
IPv4-mapped proxy trust and bootstrap grants that reopened refresh-history privileges.
Regression checks use real HTTP/database/cryptographic paths. Strict scratch reversions
must run a nonzero matching test and fail at its intended assertion; compilation errors
and unmatched filters do not count as security regression evidence.

After Claude's quota prevented completion of the final review, the authorized fallback
used Herdr/OMP with `xai-oauth/grok-4.7`. Grok independently reviewed the full corrected
batch, database constraints/permissions, code and refresh replay, tenant/scope boundaries,
proxy trust, error handling, OpenAPI and documentation. Optional helper starts selected
the wrong provider and failed with 403 before returning review content; no helper review
was used. The final review is Grok's own review with the requested provider/model.

The review confirmed a high-severity temporary-object resolution defect in privileged
Permesi cleanup. A sibling Genesis catalog-lookup path had the same defect. Both now
explicitly search trusted `public` objects before `pg_temp`, preserving PostgreSQL's
trusted implicit catalog lookup. Harmless temporary-object probes run using actual
initial and replacement Vault credentials. Each passes with the fix and fails after a
scratch-only restoration of the old search path. Fresh bootstrap and schema reapplication
also pass. No retention predicate, token policy or unrelated database privilege was
relaxed. The corrected review has no unresolved confirmed critical/high finding.

A proposed refresh-cleanup bypass was rejected after inspecting its fixed predicates:
owner-authorized cleanup removes a family's lineage only after absolute expiry plus
seven days and retains all spent lineage while the family can remain live. It cannot
erase arbitrary live replay state after the search-path fix. A proposed reachable missing
WebAuthn credential-binding mutation was also rejected: intact sealed state derives both
offered IDs and library state from the same stored credential list, and unknown IDs are
rejected before that defensive branch. This does not claim every dependency-failure
branch has an individual mutation test.

After Grok finished, a fresh native Claude review through a separate Herdr pane examined
the batch before reading earlier conclusions. It agreed that the corrected protocol,
tenant, replay, exchange-encryption and SQL search-path boundaries hold, and found four
additional low-severity issues. Password rotation now rechecks its exact session and
recent authentication on the guarded transaction; recovery regeneration/TOTP disabling
also recheck their already-required recency. Password, recovery-storage and passkey
MFA-state failures now return the documented generic 503. README/CLI help now describe
the actual per-purpose pending limits.

One finding corrected a broader database-privilege claim. Refresh-table direct
deletion is denied, but existing parent-table DELETE rights can indirectly erase lineage
through cascades. OAuth/tenant handlers revoke or soft-delete; existing internal user
management physically deletes users and their authority. The documentation now states
this limit and tracks broader privilege/FK hardening separately. This correction does
not claim to harden arbitrary database-runtime compromise or change user-deletion policy.

All five new actual HTTP/database/cryptographic tests and 87 related tests pass without
dependency skips. Nine scratch-only reversions each run one matching test and fail its
intended status assertion: snapshot-only password authorization, omitted locked recency
on password/recovery/TOTP mutations, and the password/recovery-read/recovery-insert/
recovery-state/passkey-MFA 500 paths. The first returns 204 instead of 401; stale recovery
returns 200 instead of 401; stale TOTP disabling returns 204 instead of 401; restored
dependency errors return 500 instead of 503. The
main tree retains strict warnings and unchanged checks; only scratch dead-code warnings
were relaxed to keep mutations executable. Compilation failures and unmatched filters
were excluded from the evidence.

Claude's corrected review found no new confirmed defects. It reran both complete workspace
configurations (642/672 passing), all 32 isolated scenarios, seven harness checks and all
three Chromium browser stages with real dependencies and zero scenario cleanup errors.
Password rotation now shares the configured authentication lock deadline (one second by
default), so contention can return a generic 503 rather than wait indefinitely. The
missing-pepper configuration branch was inspected but has no separate regression test.

An additional Codex/Daybreak Blue review was attempted after Claude completed. The local
model catalog lists Blue eligibility for GPT-6 Sol, but the documented API Blue alias was
rejected as unsupported on the ChatGPT-authenticated Codex surface. That attempt returned
no review content and is not counted as a Blue review or verified active Blue treatment.
The independent review evidence above is from Grok and Claude.

## Remaining release and policy work

Bootstrap ownership can remain with the bootstrap user when broad ownership reassignment
fails. Verified non-superuser ownership and narrower existing identity-table grants remain
an explicit database hardening task, including indirect parent-delete cascades, rather
than a guarantee of this batch. HAProxy scripts
and real transport/proxy tests were reviewed; an end-to-end HAProxy stack, multi-host
load/fault benchmarks and Firefox/Safari were not exercised by this validation.

UserInfo, introspection/public revocation and immediate resource-server revocation policy,
broader grants UI, device authorization, M2M, formal OIDC conformance, ancestor mutation
coordination/deadlines, consistent recent authentication, terminal MFA attempt counters,
independent exchange-key rotation and the existing WASM Clippy backlog remain tracked
in TODO. The current Chromium, real-dependency and A/B tests establish the exercised
boundaries, not certification or production throughput. Release promotion should use an
exact green commit and the documented schema/configuration rollout requirements.
