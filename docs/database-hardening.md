# Database ownership and runtime authority

Each service uses a dedicated PostgreSQL database. The trusted OpenBao database login
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
solely to that owner's runtime group; a live OpenBao lease must not prevent reapplication.
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
authority. The trusted bootstrap/OpenBao owner credentials remain outside runtime
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
parameterized retention/partition DDL. Scheduled jobs already run as `openbao_genesis`.

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
OpenBao rotates owner passwords, so a static password file becomes stale; do not reset
those passwords with `ALTER ROLE` and break OpenBao's connection. Use peer/certificate
authentication for the owner connections rather than maintaining stale owner-password
files. If the administrator uses a protected libpq password file, unset `PGPASSWORD`:
it overrides the password file for every reconnect. The local container
uses its existing Unix-socket authentication. Never substitute a privileged session
with `SET ROLE` to avoid an owner-login failure. See the existing maintenance mapping in
[`cron_jobs.sql`](../db/sql/cron_jobs.sql).
For the local development stack, `just db-bootstrap` reapplies bootstrap and the
transactional verifier. Existing installations need the ownership and grant changes,
not only a new service binary. Provision production OpenBao passwords beforehand as
described in the database bootstrap documentation; the local defaults are for local
development only. Stop rollout if ownership verification or the verifier fails.
Remove the test-only `seed_test_client.sql` include from a production bootstrap,
as described in the README; do not deploy the local development defaults unchanged.

All replicas inherit the same PostgreSQL runtime policy through their own OpenBao-issued
credentials. No instance owns the shared tables, no authorization state moves into
process memory, and code/refresh transitions still use PostgreSQL locks and transactions.
The isolated runner now starts actual A/B/C processes, requires three distinct runtime
database identities, exchanges codes concurrently on all three, rotates A/B-issued
refresh authority on C, and checks replay-family revocation on every process.
This exercises three same-host replicas; it does not establish multi-host throughput
or network-failure coverage.
Keep PostgreSQL's `createrole_self_grant` empty for these OpenBao owners. An additional
INHERIT/SET grant on created logins is intentionally rejected during reapplication.

## Scope Boundaries & Verification

The schema owner is trusted to define its own schema and policy; the verifier cannot prove safety after that owner is compromised. Keep parameterized Genesis maintenance owner-only; validate its argument bounds before extending `EXECUTE` to a less-trusted maintenance role. The isolated scenario runner shares canonical SQL with `db/sql/` and keeps its Rust bootstrap orchestration aligned.

Run the database and OpenBao runtime privilege regressions with:

```sh
# Canonical bootstrap, legacy ownership/grant repair, hostile role/object rejection,
# three independent runtime-login privilege checks, Genesis maintenance permissions,
# and receipt/family parent-deletion restrictions:
cargo test --locked -p permesi --test database_privileges

# Real OpenBao credential issuance/revocation and non-superuser maintenance after reapplication:
cargo test --locked -p permesi --test openbao_db_runtime

# Multi-replica end-to-end runtime-role protocol suite and harness
# (requires Node 24; install Better Auth fixture deps once on a clean checkout):
just oauth-scenario-better-auth-setup
just oauth-scenario --suite full --access-token-ttl-seconds 10
just oauth-scenario-harness-test
```

Database setup errors are failures and never count as skipped security coverage.

Genesis runtime can read the lookup columns `clients.id`, `uuid` and
`is_reserved`, insert four receipt columns through `tokens`, and read the
returned receipt ID. Maintenance owns the partitions. On the dedicated cluster
bootstrap, `genesis_connection_limit` (psql variable, default 32) bounds aggregate
connections to the Genesis database. New dynamic logins default to ten connections
each. Credential management connects to `postgres` so a full Genesis database
still permits revocation. Reserve cluster-wide connection capacity for the core
and management roles when sizing these limits. Restrict additional databases
through CONNECT ACLs or pg_hba rules. Shared storage, CPU and I/O remain shared.
