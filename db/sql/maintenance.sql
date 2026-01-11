-- Optional pg_cron schedule for permesi maintenance.
-- Run this in the permesi database after the schema is created.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron')
        AND position(
            'pg_cron' IN coalesce(current_setting('shared_preload_libraries', true), '')
        ) > 0 THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        IF NOT EXISTS (
            SELECT 1
            FROM cron.job
            WHERE jobname = 'permesi_cleanup_expired_tokens'
        ) THEN
            PERFORM cron.schedule(
                'permesi_cleanup_expired_tokens',
                '15 0 * * *',
                $cron$SELECT cleanup_expired_tokens();$cron$
            );
        END IF;
    ELSE
        RAISE NOTICE 'pg_cron not available or not preloaded; skipping cron.schedule';
    END IF;
END;
$$;
