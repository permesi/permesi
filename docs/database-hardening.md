# Database ownership and runtime authority

Each service uses a dedicated PostgreSQL database. The trusted Vault database login
owns its service's application objects and can mint short-lived login roles. Those
logins inherit `permesi_runtime` or `genesis_runtime`; runtime roles never own schema
objects and have no login, role-creation, database-creation, replication or RLS-bypass
authority. A runtime role with additional memberships or privileged attributes makes
bootstrap fail rather than accepting an expanded trust boundary.

`00_init.sql` validates role attributes and memberships before granting authority.
Administrator passes pin `search_path` to trusted catalogs, qualify helper calls and
transfer ownership without executing application DDL/DML. Schemas, seeds and the
transactional verifier run through fresh connections authenticated as the service
owner. `SET ROLE` or `SET SESSION AUTHORIZATION` from an administrator session would
leave a restorable administrator identity and are not substitutes for this boundary.
`bootstrap_ownership.sql` transfers legacy application relations, routines and
enum/domain types in the dedicated database's `public` schema and verifies the owner.
An unexpected object owner aborts the transaction. Extension members retain their
extension-managed ownership; PostgreSQL catalogs and shared objects are excluded.
There is no database-wide `REASSIGN OWNED BY postgres` or swallowed ownership error.
Owner membership is limited to its runtime group and `pg_signal_backend`. The only
additional exception is PostgreSQL's ADMIN-only grant for safe login roles that belong
solely to that owner's runtime group; a live Vault lease must not prevent reapplication.
Unexpected inherited/settable or administrative memberships fail closed.

The canonical runtime policy lives at the end of each service schema. Reapplication
revokes legacy table and column privileges before granting actual service operations.
Runtime roles have no table TRUNCATE, REFERENCES, TRIGGER or MAINTAIN privileges and
cannot create persistent schemas or tables. Tenant parents and OAuth grants allow
revocation/soft deletion, not physical runtime deletion. Audit tables allow direct runtime
reads and inserts only; existing user-deletion cascades are not an audit-retention policy.
The fixed global role registry is read-only. Session/factor removal, authorization
configuration replacement and other existing child deletion operations retain their
required privileges. Refresh metadata and issuance receipts retain their existing
immutable and one-way transition rules. New tables and sequences require explicit
runtime grants instead of inheriting broad default authority.
Admin-attempt records permit only the existing `is_failure` success transition;
runtime credentials cannot rewrite their identity or timestamps.
Saved-consent checks retain PostgreSQL row-share locks. The runtime has UPDATE only on
`oauth_grant_scopes.scope_id` to acquire those locks; an immutable-binding trigger rejects
actual rewrites, including substitution with another registered, client-allowed scope.
It has no direct DELETE privilege on those rows. Explicit consent can still append
bindings, and existing client/scope retirement cascades still remove them.

These are service-role privileges, not tenant-specific database credentials or RLS.
Application handlers continue enforcing identity, tenant membership and delegated
authority. The trusted bootstrap/Vault owner credentials remain outside runtime
configuration and must be protected separately.

## Retained authorization history

The composite foreign keys from `oauth_refresh_families` and
`oauth_token_issuances` to `oauth_grants` use immediate `ON DELETE RESTRICT`.
Reapplying the schema upgrades existing cascading constraints without removing rows.
Even a user deletion that would otherwise cascade through membership and grants
cannot erase retained refresh lineage or receipts. Administrative user deletion
continues to work for unreferenced users; dependent records produce a generic HTTP
409 with no tenant, grant or token identifiers. This is not a new account-erasure
workflow. Privileged maintenance removes history under the existing expiry/retention
policy; live families and their spent predecessors remain protected.

`cleanup_expired_tokens()` is owned by the non-superuser service owner, explicitly
searches trusted tables before `pg_temp`, and is executable by the runtime role rather
than PUBLIC. The normal runtime cannot replace its implementation or bypass retention
by altering constraints or triggers. The trusted schema owner remains a privileged
maintenance identity and must not be used as the service runtime login.
Genesis partition rollover is executable only by its maintenance owner or an explicitly
authorized maintenance identity. Runtime credentials and PUBLIC cannot invoke its
parameterized retention/partition DDL. Scheduled jobs already run as `vault_genesis`.

## Rollout and HA

Quiesce writers during the schema/privilege migration and apply the canonical
bootstrap with an authorized bootstrap administrator and `ON_ERROR_STOP=1`.
Ownership preflight, owner schema/grants and administrator post-verification use
separate transactions. A failed owner phase can leave a committed safe ownership
repair; resolve the failure and reapply, keeping writers quiesced throughout.
Provide authentication for the administrator and both owner logins. Prefer the existing
`cronmap` peer mapping while running as OS user `postgres` over the local socket, or a
separately authorized PostgreSQL client-certificate mapping for remote maintenance.
Positional reconnects reuse the administrator's certificate/key, so the server's
`pg_ident` mapping must explicitly allow that certificate identity for both owner roles;
separate owner certificates are not selected automatically.
Vault rotates owner passwords, so a static password file becomes stale; do not reset
those passwords with `ALTER ROLE` and break Vault's connection. Use peer/certificate
authentication for the owner connections rather than maintaining stale owner-password
files. If the administrator uses a protected libpq password file, unset `PGPASSWORD`:
it overrides the password file for every reconnect. The local container
uses its existing Unix-socket authentication. Never substitute a privileged session
with `SET ROLE` to avoid an owner-login failure. See the existing maintenance mapping in
[`cron_jobs.sql`](../db/sql/cron_jobs.sql).
For the local development stack, `just db-bootstrap` reapplies bootstrap and the
transactional verifier. Existing installations need the ownership and grant changes,
not only a new service binary. Provision production Vault passwords beforehand as
described in the database bootstrap documentation; the local defaults are for local
development only. Stop rollout if ownership verification or the verifier fails.
Remove the test-only `seed_test_client.sql` include from a production bootstrap,
as described in the README; do not deploy the local development defaults unchanged.

All replicas inherit the same PostgreSQL runtime policy through their own Vault-issued
credentials. No instance owns the shared tables, no authorization state moves into
process memory, and code/refresh transitions still use PostgreSQL locks and transactions.
The isolated runner now starts actual A/B/C processes, requires three distinct runtime
database identities, exchanges codes concurrently on all three, rotates A/B-issued
refresh authority on C, and checks replay-family revocation on every process.
This exercises three same-host replicas; it does not establish multi-host throughput
or network-failure coverage.
Keep PostgreSQL's `createrole_self_grant` empty for these Vault owners. An additional
INHERIT/SET grant on created logins is intentionally rejected during reapplication.

## Verification status

The final HA and hosted gates remain pending. Seven real PostgreSQL privilege tests and
the actual Vault credential test now pass, including hostile-owner, failed-bootstrap,
legacy repair, three independent runtime identities, immutable consent and live-lease
reapplication. The local test fixtures can reach their configured container API, while
direct Podman CLI runtime writes and Node listener binding remain denied. The standalone
scenario preflight is still blocked at 0/32 and browser/harness gates remain open.
Setup failures are not coverage. Before the compatible dependency refresh described
below, both complete default and all-feature workspace suites passed, including real
PostgreSQL/Vault integration and runner routing tests. The two additional runtime-login
HTTP regressions also passed. Final checks against the refreshed lockfiles remain pending.
Five initial Claude/Herdr source-review rounds reported no remaining actionable
findings. Two later reviews checked the runtime correction and its regressions;
all implementation findings are resolved, and the final documentation correction
records their scope and the remaining hosted validation.
Source review does not establish live database or HA behavior.
The three hermetic bootstrap-diagnostic tests pass. Temporarily removing SQLSTATE validation
makes the negative test fail at its assertion; restoring it returns the tests to green.
That mutation establishes diagnostic classification only, not live database security.
Before the dependency refresh, compilation, strict workspace Clippy, OpenAPI
generation, Web native tests and the WASM build passed. These results do not
complete this milestone or establish compatibility with the refreshed lockfiles.

The current validation record is:

| Gate | Result |
| --- | --- |
| Formatting and diff checks | Pass |
| Strict all-target/all-feature Clippy and workspace test compilation | Pass before dependency refresh; refreshed graph awaits hosted validation |
| Admission-token, Web native and test-support tests | 51 pass before dependency refresh |
| Bootstrap diagnostic mutation | Assertion fails with SQLSTATE check removed; passes after restoration |
| OpenAPI generation, WASM/Web and native scenario builds | Pass before dependency refresh |
| Seven database privilege tests and actual Vault runtime test | Eight pass against real disposable dependencies before dependency refresh |
| Canonical schema verifier | Passes locally through bootstrap and on hosted CI |
| Default/all-feature workspace tests | Pre-refresh pass; Permesi library 425/440 pass, two later HTTP regressions pass separately; final lockfile rerun pending |
| Database safeguard mutations | Consent rewrites, administrator-session restoration and skipped global preflight each fail at their intended assertion; restored sources and all eight database/Vault tests pass |
| Browser, harness and full three-replica scenario suite | Blocked by local listener/Podman permissions; protocol suite 0/32 |

The first pushed commit, `259b53d`, passed hosted formatting, Clippy, compilation,
production Web audit and canonical PostgreSQL schema verification in
[run 39025398078](https://github.com/permesi/permesi/actions/runs/39025398078).
Coverage then caught missing UPDATE authority required by PostgreSQL's saved-consent
row locks: runtime refresh returned 503. The correction retains those locks, grants
only `scope_id` UPDATE and rejects actual binding rewrites with a database trigger.
A real-login regression substitutes another otherwise allowed scope through UPDATE,
UPSERT and MERGE. Each must return 23514 with the immutable guard's exact message
and leave consent unchanged; updates to the other binding columns and DELETE remain
denied. The verifier checks the enabled row-level BEFORE UPDATE trigger, its exact
function, all-column coverage and absence of a WHEN condition or arguments.
Two production-router regressions authenticate through a real non-superuser runtime
login, covering code exchange/replay and saved-consent skipping with exact requested
scopes. They passed separately after the full workspace runs; final aggregate counts
against the refreshed graph remain pending. Three temporary SQL mutations removed
the consent guard, restored an administrator session, or skipped global preflight.
Each failed at the intended security assertion. Sources were restored byte-for-byte,
and all seven database tests plus the Vault test returned to green.
Corrected hosted protocol validation remains pending. The integration job separately timed out starting
PostgreSQL containers for existing Genesis tests and stopped before the Permesi
database/Vault targets. Its new `--no-fail-fast` flag preserves later test-binary results
when an earlier dependency fails. The unit job also recorded three PostgreSQL startup
timeouts alongside the refresh assertion; its final result was 421 pass, four fail.
The complete local Genesis integration target subsequently passed both tests.
A hostile-owner fixture also found ambiguous resolution of an unqualified `format()`
call during schema reapplication. Canonical Genesis and Permesi grant/migration calls
now use `pg_catalog.format`, and protocol-scope seeding uses `pg_catalog.unnest`.
Bootstrap failures report only an allow-listed SQL filename,
numeric line and SQLSTATE; raw errors, SQL values and contexts remain private.

## Compatible dependency refresh

`cargo upgrade` raised the compatible UUID and libc manifest lower bounds, and
`cargo update` refreshed the compatible dependency graph. The explicit OPAQUE protocol
aliases retain their required older trait ecosystems; no protocol or serialized-state
migration is introduced by changing those aliases.
The Web lockfile includes exactly the `source-map-js` 1.2.2 version, URL and integrity
update from [PR 15](https://github.com/permesi/permesi/pull/15). It addresses the reported
indexed-source-map denial of service. The npm audit gate now includes build dependencies.

Local registry resolution/downloads fail for `registry.npmjs.org` and `static.crates.io`;
npm installation and refreshed Rust builds/audits therefore lack a local pass. The
existing CI unit job now runs the full all-feature workspace suite, alongside the
separate default unit/integration jobs, so hosted validation covers the refreshed graph.
No new audit exclusions or weakened checks are used.

## Independent review

Claude reviewed the surrounding SQL, bootstrap callers, runtime operations, tests,
three-replica runner and documentation in a separate Herdr pane. No CRITICAL or HIGH
finding was reported. The confirmed findings and corrections are:

| Severity | Finding | Correction |
| --- | --- | --- |
| MEDIUM | Administrator `SET ROLE` left a restorable privileged session; owner-controlled triggers, overloads or search paths could cross that boundary | Fresh owner-authenticated connections; catalog-only administrator passes and qualified helper calls |
| LOW | Owner memberships could carry unrelated or privileged authority | Fail-closed membership checks, with a narrow exception for safe ADMIN-only grants on live Vault logins |
| LOW | Owner-password guidance conflicted with Vault rotation and libpq reconnect behavior | Existing peer or explicitly mapped certificate authentication; password-file and certificate-reuse limitations documented |
| LOW | Negative bootstrap tests accepted unrelated setup errors | Typed exact policy diagnostics, private raw stderr and a mutation-tested SQLSTATE classifier |
| LOW | Historical A/B results and review status could overstate final validation | Separate historical evidence from pending PostgreSQL/A/B/C gates |
| LOW | A negative test used effective superuser membership rather than actual grants | Query direct `pg_auth_members` rows before restoring mutated attributes |
| MEDIUM (test coverage) | Runtime grant drift was covered through refresh but lacked direct code-exchange and saved-consent route regressions | Real non-superuser runtime-login HTTP tests assert committed exchange/replay and exact subset consent |
| LOW | Consent-trigger verifier accepted incomplete trigger metadata | Require row-level BEFORE UPDATE, every column, no WHEN condition and the expected function, with catalog-qualified checks |
| LOW | New consent-lock privilege lacked UPSERT/MERGE and other-column negatives | Assert exact immutable-guard rejection and unchanged consent for all rewrite forms; other binding columns and DELETE remain denied |
| LOW | Fail-fast integration execution hid later security results after a dependency failure | Continue all standalone integration binaries and document the missed hosted coverage |
| LOW | Owner-phase helper qualification was inconsistent | Qualify Genesis formatting and protocol-scope seeding helpers as well as Permesi migration/grant formatting |

All confirmed findings were accepted and corrected. The suggestion to expose raw psql
stderr was replaced with typed, allow-listed diagnostics to preserve logging hygiene.
Follow-up reviews also strengthened the global-preflight test: a rejected bootstrap
must not grant `pg_signal_backend` before the per-database check. Those direct-grant
assertions passed against PostgreSQL, including the mutation that deliberately skipped
preflight. The latest Claude review confirmed the two runtime-router tests, exact
trigger metadata, UPSERT/MERGE negatives, integration continuation and catalog helper
qualification. Its sole remaining finding was stale documentation, corrected here.
The reviewer reran formatting/diff checks but did not independently execute the live
database tests. No review finding was rejected as a false positive.

The schema owner is trusted to define its own schema and policy; the verifier cannot
prove safety after that owner is compromised. Genesis-specific hostile-owner and
live-lease reapplication cases remain additional coverage; the corresponding Permesi
cases passed against their disposable dependencies. The user-delete HTTP conflict test uses a
synthetic restrictive dependency, while real receipt/family cascade retention is tested
at the SQL boundary. The runner shares canonical SQL but has separate Rust bootstrap
orchestration that must stay aligned. Distinct runtime-login counts supplement actual
process/socket checks; they do not map each database identity to a particular process.
Broader multi-host/load/fault coverage remains separate. Keep parameterized Genesis
maintenance owner-only; validate its argument bounds before extending EXECUTE to a
less-trusted maintenance role.

Run `cargo test -p permesi --test database_privileges` for canonical bootstrap,
legacy ownership/grant repair, hostile role/object rejection, three independent
runtime-login privilege checks, Genesis partition/maintenance permissions and
receipt/family parent-deletion regressions.
`cargo test -p permesi --test vault_db_runtime` verifies real Vault credential
issuance/revocation and non-superuser maintenance after reapplication. The full live
protocol gate is `just oauth-scenario --suite full --access-token-ttl-seconds 10`,
followed by `just oauth-scenario-harness-test`. Database setup errors are failures,
not successful skipped security coverage.
