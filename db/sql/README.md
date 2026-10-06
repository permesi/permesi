# Database SQL helpers

`db/sql/` is the single source of truth for Permesi IAM database schemas and bootstrap helpers.

## Bootstrapping

- `00_init.sql` — creates databases, roles, grants, and loads service schemas.
- `01_genesis.sql` — Genesis schema (includes `partitioning.sql`).
- `02_permesi.sql` — Permesi schema (includes `cleanup_expired_tokens()`).
- `seed_test_client.sql` — optional test-only seed client for Genesis.
- `cron_jobs.sql` — **only place** where pg_cron jobs are registered (run against `postgres`).
- `check.sql` — post-bootstrap verification (run against `postgres`).
- `reset_all.sql` — destructive reset for dev/test (run against `postgres`).

The OAuth foundation is additive in `02_permesi.sql`. Reapply that script to the
existing Permesi database with the role that owns the existing Permesi tables and
`ON_ERROR_STOP=1` before starting
a binary that exposes OAuth management. It creates the OAuth tables, seeds fixed
protocol scope entries for existing applications, and adds a trigger to seed new
applications. Reapplying preserves client configuration and grants. Runtime table
grants are applied when `permesi_runtime` already exists; normal bootstrap also
grants all tables after creating that role. There is no RLS change. Authorization additionally creates
`oauth_authorization_requests` and `oauth_authorization_codes`, with hash-only code/
browser/CSRF storage, immutable snapshots, exact redirect/composite consent foreign
keys, bounded TTLs and one-way consumption. Reapply as the existing table owner
before enabling protocol routes. The existing cleanup function removes expired
OAuth state after seven days.

Confidential credential management adds nullable `oauth_client_secrets.expires_at`,
a unique index for the non-revoked current credential, and triggers that make identity/
hash fields immutable under updates, revocation irreversible under updates, initial
retirement bounded to 3600 seconds, existing deadlines nonextendable, and live retiring
overlap singular. Inserts require live initial state and assign creation time in PostgreSQL. Reapply as the existing schema owner before starting the
credential APIs. Existing client/grant data is preserved; older manual credential
imports must already satisfy the one-current invariant to create the new index.
Credential APIs neither automatically delete history nor issue tokens. The schema also adds
independent credential-management and revocation actions to the existing shared rate-limit table.
Both schema reapplication and bootstrap revoke DELETE/TRUNCATE on credential history
from the runtime role; schema-owner FK cleanup still cascades. This does not harden the
role's broader existing identity-table privileges against database compromise.
Integration tests reapply the canonical script with an issued credential present,
run `verify_permesi.sql`, and verify that authentication still works afterward.

Current token issuance adds immutable hash-only receipts; refresh tokens add
`oauth_refresh_families` and `oauth_refresh_tokens`, retaining spent lineage until
absolute family expiry plus seven days. Reapply the schema and canonical runtime grants
before rollout: runtime users can insert/read families and tokens, revoke families and
consume tokens, but cannot rewrite bindings or directly erase replay history. See
[refresh policy](../../docs/oauth-refresh-tokens.md) for rotation, consent and revision invalidation.
Broader existing parent-table DELETE grants can still erase family history indirectly
through foreign-key cascades. OAuth/tenant handlers use revocation/soft deletion; existing
internal user management still physically deletes users. Closing arbitrary runtime parent
deletion remains part of the least-privilege follow-up.

Both `cleanup_expired_tokens()` and `genesis_tokens_rollover()` explicitly search trusted
`public` objects before `pg_temp`, with PostgreSQL's implicit trusted catalog search.
Temporary tables/views must never execute caller-defined code under a function owner's
authority. Vault integration tests load the Genesis partition helper and exercise harmless
temporary-object rejection on initial and replacement runtime credentials for both services.
Local bootstrap ownership can remain with the bootstrap user when broad reassignment
fails; verified non-superuser ownership and broader least-privilege grants remain tracked
in [TODO.md](../../TODO.md).

## Runtime role & grant checks

Shared OPAQUE state adds `opaque_exchanges`: hashed external references, AEAD-sealed
server transcripts, purpose/user/password-revision/session bindings and bounded
database-clock expiration. Reapply `02_permesi.sql` before the new binary; bootstrap
and reapplication apply narrow SELECT/INSERT/DELETE runtime privileges, explicitly
revoking MAINTAIN as well as mutation/DDL-related privileges. Expired
exchanges are pruned during new starts and existing maintenance. See
[deployment and retention](../../docs/opaque-exchanges.md); encrypted WAL/backups
follow ordinary database retention and are not cryptographically erased by row removal.

WebAuthn adds `webauthn_exchanges` with separate ceremony purposes, sealed protocol state,
hashed references and current user/session/subject bindings. Its runtime permissions and
single-attempt consumption match the shared exchange boundary described in
[WebAuthn exchanges](../../docs/webauthn-exchanges.md). Transient encryption-format upgrades
require outstanding ceremonies to restart; permanent credentials remain usable.

Use these psql commands to verify runtime roles and grants after bootstrap:

```sql
-- roles + membership
\du+ vault_genesis
\du+ genesis_runtime
\du+ vault_permesi
\du+ permesi_runtime

-- database-level grants (run in postgres)
\l+ genesis
\l+ permesi

-- schema/table grants (genesis)
\c genesis
\dn+ public
\dp public.clients
\dp public.tokens
\dp public.tokens_default

-- schema/table grants (permesi)
\c permesi
\dn+ public
\dp public.users
\dp public.user_sessions
\dp public.email_outbox

-- default privileges (future tables)
\c genesis
SELECT * FROM pg_default_acl WHERE defaclnamespace = 'public'::regnamespace;
\c permesi
SELECT * FROM pg_default_acl WHERE defaclnamespace = 'public'::regnamespace;

-- programmatic checks (examples)
\c genesis
SELECT has_table_privilege('genesis_runtime', 'public.clients', 'SELECT') AS clients_select;
\c permesi
SELECT has_table_privilege('permesi_runtime', 'public.users', 'SELECT') AS users_select;
```
