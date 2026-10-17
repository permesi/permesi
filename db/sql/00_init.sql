-- Postgres init for local dev.
--
-- This file is executed via a shim in `/docker-entrypoint-initdb.d/` (so it runs on first init),
-- and also executed explicitly by the `just db-bootstrap` recipe (so it's safe to re-run).
--
-- `CREATE DATABASE` can't run inside a transaction block, so we use `psql`'s `\gexec` to
-- conditionally emit and execute the statement.

\set ON_ERROR_STOP on
\set bootstrap_admin :USER
SET search_path = pg_catalog, pg_temp;
DO $$ BEGIN
    IF pg_catalog.current_database()<>'postgres' THEN
        RAISE EXCEPTION 'Start canonical bootstrap in the postgres maintenance database';
    END IF;
END $$;

-- Guard against concurrent init runs (entrypoint + `just postgres`).
SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtext('permesi-initdb')::bigint);

-- -----------------------------------------------------------------------------
-- Vault database root users (dev defaults).
--
-- Vault's Postgres database secrets engine needs a non-superuser "root" user per
-- database connection to create/revoke short-lived roles.
--
-- Local/dev runs with `trust` auth (see `.justfile`), so these passwords are not
-- security-sensitive. In production, create equivalent roles with strong
-- passwords and do not rely on this dev bootstrap.
-- -----------------------------------------------------------------------------
SELECT pg_catalog.format(
    'CREATE ROLE %I WITH LOGIN PASSWORD %L CREATEROLE',
    'vault_permesi',
    'change-me'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_permesi')\gexec

SELECT pg_catalog.format(
    'CREATE ROLE %I WITH LOGIN PASSWORD %L CREATEROLE',
    'vault_genesis',
    'change-me'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_genesis')\gexec

-- Validate roles before any membership or database-ownership mutation.
SELECT pg_catalog.format('CREATE ROLE %I NOLOGIN', 'genesis_runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'genesis_runtime')\gexec
SELECT pg_catalog.format('CREATE ROLE %I NOLOGIN', 'permesi_runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'permesi_runtime')\gexec
\ir bootstrap_ownership.sql

-- Allow Vault to terminate sessions during lease revocation (non-superuser).
GRANT pg_signal_backend TO vault_permesi;
GRANT pg_signal_backend TO vault_genesis;

SELECT pg_catalog.format('CREATE DATABASE %I', 'genesis')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis')\gexec

SELECT pg_catalog.format('CREATE DATABASE %I', 'permesi')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi')\gexec

-- Ensure the databases are owned by the Vault root users.
ALTER DATABASE genesis OWNER TO vault_genesis;
ALTER DATABASE permesi OWNER TO vault_permesi;

-- Prevent cross-database access via the default PUBLIC grants.
REVOKE ALL ON DATABASE genesis FROM PUBLIC;
REVOKE ALL ON DATABASE permesi FROM PUBLIC;
GRANT CONNECT ON DATABASE genesis TO vault_genesis;
GRANT CONNECT ON DATABASE permesi TO vault_permesi;

SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtext('permesi-initdb')::bigint);

-- Administrator passes only inspect catalogs and transfer ownership under a pinned path.
-- Application DDL/DML runs in a fresh owner-authenticated connection: SET ROLE would
-- retain an administrator session identity that an owner-controlled trigger could restore.
\connect genesis :bootstrap_admin
SET search_path = pg_catalog, pg_temp;
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('genesis-schema-bootstrap')::bigint);
\ir bootstrap_ownership.sql
GRANT genesis_runtime TO vault_genesis WITH ADMIN OPTION;
COMMIT;

\connect genesis vault_genesis
SET search_path = public, pg_temp;
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('genesis-schema-bootstrap')::bigint);
\ir 01_genesis.sql
\ir seed_test_client.sql
COMMIT;

\connect genesis :bootstrap_admin
SET search_path = pg_catalog, pg_temp;
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('genesis-schema-bootstrap')::bigint);
\ir bootstrap_ownership.sql
COMMIT;

\connect permesi :bootstrap_admin
SET search_path = pg_catalog, pg_temp;
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('permesi-schema-bootstrap')::bigint);
\ir bootstrap_ownership.sql
GRANT permesi_runtime TO vault_permesi WITH ADMIN OPTION;
COMMIT;

\connect permesi vault_permesi
SET search_path = public, pg_temp;
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('permesi-schema-bootstrap')::bigint);
\ir 02_permesi.sql
COMMIT;
-- Verification exercises application code, so it also runs as the authenticated owner.
\ir verify_permesi.sql

\connect permesi :bootstrap_admin
SET search_path = pg_catalog, pg_temp;
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('permesi-schema-bootstrap')::bigint);
\ir bootstrap_ownership.sql
COMMIT;
