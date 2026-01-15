-- Post-bootstrap verification for Permesi IAM.
--
-- Run as a superuser against the `postgres` database:
--   psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/check.sql
--
-- This script validates:
--   - Databases and roles exist
--   - pg_cron is installed and preloaded in postgres
--   - Scheduled jobs are registered
--   - Genesis/Permesi schemas and key functions exist

\set ON_ERROR_STOP 1

\echo 'Checking core databases and roles...'

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis') THEN
        RAISE EXCEPTION 'Missing database: genesis';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi') THEN
        RAISE EXCEPTION 'Missing database: permesi';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_genesis') THEN
        RAISE EXCEPTION 'Missing role: vault_genesis';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_permesi') THEN
        RAISE EXCEPTION 'Missing role: vault_permesi';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'genesis_runtime') THEN
        RAISE EXCEPTION 'Missing role: genesis_runtime';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'permesi_runtime') THEN
        RAISE EXCEPTION 'Missing role: permesi_runtime';
    END IF;
END;
$$;

\echo 'Checking pg_cron in postgres...'

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        RAISE EXCEPTION 'pg_cron extension is not installed';
    END IF;
    IF position(
        'pg_cron' IN coalesce(current_setting('shared_preload_libraries', true), '')
    ) = 0 THEN
        RAISE EXCEPTION 'pg_cron is not preloaded in shared_preload_libraries';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        RAISE EXCEPTION 'pg_cron extension is not created in postgres';
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'genesis_tokens_rollover') THEN
        RAISE EXCEPTION 'Missing cron job: genesis_tokens_rollover';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'permesi_cleanup_expired_tokens') THEN
        RAISE EXCEPTION 'Missing cron job: permesi_cleanup_expired_tokens';
    END IF;
END;
$$;

\echo 'Checking genesis schema...'
\connect genesis

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'clients') THEN
        RAISE EXCEPTION 'Missing genesis table: clients';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'tokens') THEN
        RAISE EXCEPTION 'Missing genesis table: tokens';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc WHERE proname = 'genesis_tokens_rollover'
    ) THEN
        RAISE EXCEPTION 'Missing function: genesis_tokens_rollover';
    END IF;
END;
$$;

\echo 'Checking permesi schema...'
\connect permesi

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'users') THEN
        RAISE EXCEPTION 'Missing permesi table: users';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'user_sessions') THEN
        RAISE EXCEPTION 'Missing permesi table: user_sessions';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc WHERE proname = 'cleanup_expired_tokens'
    ) THEN
        RAISE EXCEPTION 'Missing function: cleanup_expired_tokens';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'citext') THEN
        RAISE EXCEPTION 'Missing extension: citext';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'totp_deks') THEN
        RAISE EXCEPTION 'Missing permesi table: totp_deks';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'totp_credentials') THEN
        RAISE EXCEPTION 'Missing permesi table: totp_credentials';
    END IF;
END;
$$;

\echo 'Check complete.'
