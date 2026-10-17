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

The final live PostgreSQL/HA gates remain pending. Five independent Claude/Herdr source
review rounds verified the corrected owner-session boundary, membership guard, diagnostic
classification, direct-grant assertions and documentation. The final focused review
reported no remaining actionable findings; source review does not establish live
database or HA behavior.
An earlier implementation passed four new PostgreSQL regressions, the actual Vault
runtime test, the user-delete handler regression and gateway routing tests. Subsequent
caller-audit and review fixes add the admin-success column grant, owner-only Genesis
rollover, authenticated-owner bootstrap and strict owner memberships. The hostile-owner,
failed-bootstrap and live-lease reapplication regressions have not executed against
PostgreSQL. The primary agent's current session denies Podman runtime
directory writes and loopback/Unix listener binding, so the latest dependency tests fail
at setup and the full scenario suite is blocked at 0/32. Setup failures are not coverage.
The user-delete handler, gateway-routing, browser and harness gates also lack a final
live pass. Database mutation red/green validation must be completed when dependencies
are available; a setup failure cannot establish a killed mutation.
The two hermetic bootstrap-diagnostic tests pass. Temporarily removing SQLSTATE validation
makes the negative test fail at its assertion; restoring it returns the tests to green.
That mutation establishes diagnostic classification only, not live database security.
Compilation, strict workspace Clippy, OpenAPI generation, Web native tests and the
WASM build pass, but do not complete this milestone.

The current validation record is:

| Gate | Result |
| --- | --- |
| Formatting, diff checks and strict all-target/all-feature Clippy | Pass |
| Workspace all-feature test compilation | Pass |
| Admission-token, Web native and test-support tests | 50 pass |
| Bootstrap diagnostic mutation | Assertion fails with SQLSTATE check removed; passes after restoration |
| OpenAPI generation, WASM/Web and native scenario builds | Pass |
| Six database privilege tests, actual Vault runtime test and schema verifier | Blocked at dependency setup |
| Default/all-feature workspace tests | Stop at Genesis Unix-listener permission failure |
| Browser, harness and full three-replica scenario suite | Blocked by local listener/Podman permissions; protocol suite 0/32 |

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

All confirmed findings were accepted and corrected. The suggestion to expose raw psql
stderr was replaced with typed, allow-listed diagnostics to preserve logging hygiene.
Follow-up reviews also strengthened the global-preflight test: a rejected bootstrap
must not grant `pg_signal_backend` before the per-database check. The final direct-grant
assertions compile but have not executed against PostgreSQL in this session. Claude's
final review confirmed those assertions and the historical-validation wording, reran
formatting, strict Clippy and integration-test compilation, and reported no remaining
actionable findings. No review finding was rejected as a false positive.

The schema owner is trusted to define its own schema and policy; the verifier cannot
prove safety after that owner is compromised. Genesis-specific hostile-owner and
live-lease reapplication cases remain additional coverage; the corresponding Permesi
cases are implemented but await execution. The user-delete HTTP conflict test uses a
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
