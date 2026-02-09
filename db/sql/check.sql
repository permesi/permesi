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
    IF NOT pg_has_role('vault_genesis', 'genesis_runtime', 'MEMBER') THEN
        RAISE EXCEPTION 'Missing role membership: vault_genesis -> genesis_runtime';
    END IF;
    IF NOT pg_has_role('vault_permesi', 'permesi_runtime', 'MEMBER') THEN
        RAISE EXCEPTION 'Missing role membership: vault_permesi -> permesi_runtime';
    END IF;
    IF NOT has_database_privilege('genesis_runtime', 'genesis', 'CONNECT') THEN
        RAISE EXCEPTION 'Missing grant: genesis_runtime CONNECT on genesis';
    END IF;
    IF NOT has_database_privilege('permesi_runtime', 'permesi', 'CONNECT') THEN
        RAISE EXCEPTION 'Missing grant: permesi_runtime CONNECT on permesi';
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
    IF NOT EXISTS (
        SELECT 1
        FROM cron.job
        WHERE jobname = 'genesis_tokens_rollover'
          AND schedule = '5 0 * * *'
          AND command = 'SELECT genesis_tokens_rollover(7, 2);'
          AND "database" = 'genesis'
          AND username = 'vault_genesis'
    ) THEN
        RAISE EXCEPTION 'Missing/misconfigured cron job: genesis_tokens_rollover';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM cron.job
        WHERE jobname = 'permesi_cleanup_expired_tokens'
          AND schedule = '15 0 * * *'
          AND command = 'SELECT cleanup_expired_tokens();'
          AND "database" = 'permesi'
          AND username = 'vault_permesi'
    ) THEN
        RAISE EXCEPTION 'Missing/misconfigured cron job: permesi_cleanup_expired_tokens';
    END IF;
END;
$$;

\echo 'Checking genesis schema...'
\connect genesis

DO $$
BEGIN
    IF to_regclass('public.clients') IS NULL THEN
        RAISE EXCEPTION 'Missing genesis table: clients';
    END IF;
    IF to_regclass('public.tokens') IS NULL THEN
        RAISE EXCEPTION 'Missing genesis table: tokens';
    END IF;
    IF to_regprocedure('public.genesis_tokens_rollover(integer, integer)') IS NULL THEN
        RAISE EXCEPTION 'Missing function: public.genesis_tokens_rollover(integer, integer)';
    END IF;
END;
$$;

\echo 'Checking permesi schema...'
\connect permesi

DO $$
BEGIN
    IF to_regclass('public.users') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: users';
    END IF;
    IF to_regclass('public.user_sessions') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: user_sessions';
    END IF;
    IF to_regprocedure('public.cleanup_expired_tokens()') IS NULL THEN
        RAISE EXCEPTION 'Missing function: public.cleanup_expired_tokens()';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'citext') THEN
        RAISE EXCEPTION 'Missing extension: citext';
    END IF;
    IF to_regclass('public.totp_deks') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: totp_deks';
    END IF;
    IF to_regclass('public.totp_credentials') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: totp_credentials';
    END IF;
    IF to_regclass('public.totp_audit_log') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: totp_audit_log';
    END IF;
    IF to_regclass('public.passkeys') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: passkeys';
    END IF;
    IF to_regclass('public.passkey_audit_log') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: passkey_audit_log';
    END IF;
    IF to_regclass('public.user_mfa_state') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: user_mfa_state';
    END IF;
    IF to_regclass('public.security_keys') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: security_keys';
    END IF;
    IF to_regclass('public.security_key_audit_log') IS NULL THEN
        RAISE EXCEPTION 'Missing permesi table: security_key_audit_log';
    END IF;
END;
$$;

\echo 'Check complete.'
