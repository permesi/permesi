-- Postgres init for local dev.
--
-- This file is mounted into `/docker-entrypoint-initdb.d/` (so it runs on first init),
-- and also executed explicitly by the `just postgres` recipe (so it's safe to re-run).
--
-- `CREATE DATABASE` can't run inside a transaction block, so we use `psql`'s `\gexec` to
-- conditionally emit and execute the statement.

-- Guard against concurrent init runs (entrypoint + `just postgres`).
SELECT pg_advisory_lock(hashtext('permesi-initdb'));

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
SELECT format(
    'CREATE ROLE %I WITH LOGIN PASSWORD %L CREATEROLE',
    'vault_permesi',
    'vault_permesi'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_permesi')\gexec

SELECT format(
    'CREATE ROLE %I WITH LOGIN PASSWORD %L CREATEROLE',
    'vault_genesis',
    'vault_genesis'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_genesis')\gexec

-- Allow Vault to terminate sessions during lease revocation (non-superuser).
GRANT pg_signal_backend TO vault_permesi;
GRANT pg_signal_backend TO vault_genesis;

SELECT format('CREATE DATABASE %I', 'genesis')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis')\gexec

SELECT format('CREATE DATABASE %I', 'permesi')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi')\gexec

-- Ensure the databases are owned by the Vault root users.
ALTER DATABASE genesis OWNER TO vault_genesis;
ALTER DATABASE permesi OWNER TO vault_permesi;

-- Prevent cross-database access via the default PUBLIC grants.
REVOKE ALL ON DATABASE genesis FROM PUBLIC;
REVOKE ALL ON DATABASE permesi FROM PUBLIC;
GRANT CONNECT ON DATABASE genesis TO vault_genesis;
GRANT CONNECT ON DATABASE permesi TO vault_permesi;

SELECT pg_advisory_unlock(hashtext('permesi-initdb'));

-- Bootstrap genesis schema (idempotent, safe to re-run).
\connect genesis
\ir /db/sql/01_genesis.sql

-- Lock down the default schema so dynamic Vault users can't create objects.
REVOKE USAGE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO vault_genesis;
REASSIGN OWNED BY postgres TO vault_genesis;

-- -----------------------------------------------------------------------------
-- Genesis runtime role
--
-- Vault-minted DB users only get membership in this role, so we can manage
-- least-privilege grants centrally (and avoid expired users owning objects).
-- -----------------------------------------------------------------------------
SELECT format('CREATE ROLE %I NOLOGIN', 'genesis_runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'genesis_runtime')\gexec

GRANT genesis_runtime TO vault_genesis WITH ADMIN OPTION;

GRANT CONNECT, TEMPORARY ON DATABASE genesis TO genesis_runtime;
GRANT USAGE ON SCHEMA public TO genesis_runtime;

GRANT SELECT ON TABLE clients TO genesis_runtime;
-- Genesis inserts with `RETURNING`, so SELECT is required alongside INSERT.
GRANT SELECT, INSERT ON TABLE tokens TO genesis_runtime;
GRANT SELECT, INSERT ON TABLE tokens_default TO genesis_runtime;

-- Partitions (tables) created by the schema owner should inherit runtime grants.
ALTER DEFAULT PRIVILEGES FOR ROLE vault_genesis IN SCHEMA public
    GRANT SELECT, INSERT ON TABLES TO genesis_runtime;

-- Bootstrap permesi schema.
\connect permesi
\ir /db/sql/02_permesi.sql

-- Lock down the default schema so dynamic Vault users can't create objects.
REVOKE USAGE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO vault_permesi;
REASSIGN OWNED BY postgres TO vault_permesi;

-- -----------------------------------------------------------------------------
-- Permesi runtime role
--
-- Vault-minted DB users only get membership in this role, so we can manage
-- grants centrally (and avoid expired users owning objects).
-- -----------------------------------------------------------------------------
SELECT format('CREATE ROLE %I NOLOGIN', 'permesi_runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'permesi_runtime')\gexec

GRANT permesi_runtime TO vault_permesi WITH ADMIN OPTION;

GRANT CONNECT, TEMPORARY ON DATABASE permesi TO permesi_runtime;
GRANT USAGE ON SCHEMA public TO permesi_runtime;
-- Postgres does not support `GRANT USAGE ON ALL TYPES`, so enumerate enum types.
GRANT USAGE ON TYPE user_status TO permesi_runtime;
GRANT USAGE ON TYPE email_outbox_status TO permesi_runtime;
GRANT USAGE ON TYPE environment_tier TO permesi_runtime;
GRANT USAGE ON TYPE org_membership_status TO permesi_runtime;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO permesi_runtime;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO permesi_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES TO permesi_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO permesi_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public
    GRANT USAGE ON TYPES TO permesi_runtime;
