-- Partition maintenance for tokens using pg_cron.
-- Run this in the genesis database after creating the schema.

CREATE OR REPLACE FUNCTION genesis_tokens_rollover(retention_days int, premake_days int)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    d date;
    part_name text;
    part_date date;
    got_lock boolean;
BEGIN
    got_lock := pg_try_advisory_lock(hashtext('genesis_tokens_rollover'));
    IF NOT got_lock THEN
        RAISE NOTICE 'genesis_tokens_rollover: advisory lock busy, skipping run';
        RETURN;
    END IF;

    BEGIN
        FOR d IN
            SELECT generate_series(current_date, current_date + premake_days, interval '1 day')::date
        LOOP
            part_name := format('tokens_%s', to_char(d, 'YYYY_MM_DD'));
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF tokens FOR VALUES FROM (%L) TO (%L)',
                part_name, d::timestamptz, (d + 1)::timestamptz
            );
        END LOOP;

        FOR part_name IN
            SELECT c.relname
            FROM pg_class c
            JOIN pg_inherits i ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            WHERE p.relname = 'tokens'
        LOOP
            IF part_name ~ '^tokens_[0-9]{4}_[0-9]{2}_[0-9]{2}$' THEN
                part_date := to_date(
                    substring(part_name from '([0-9]{4}_[0-9]{2}_[0-9]{2})'),
                    'YYYY_MM_DD'
                );
                IF part_date < current_date - retention_days THEN
                    EXECUTE format('DROP TABLE IF EXISTS %I', part_name);
                END IF;
            END IF;
        END LOOP;
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_advisory_unlock(hashtext('genesis_tokens_rollover'));
            RAISE;
    END;

    PERFORM pg_advisory_unlock(hashtext('genesis_tokens_rollover'));
    RAISE NOTICE 'genesis_tokens_rollover: completed';
END;
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron')
        AND position(
            'pg_cron' IN coalesce(current_setting('shared_preload_libraries', true), '')
        ) > 0 THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'genesis_tokens_rollover') THEN
            PERFORM cron.schedule(
                'genesis_tokens_rollover',
                '5 0 * * *',
                $cron$SELECT genesis_tokens_rollover(7, 2);$cron$
            );
        END IF;
    ELSE
        RAISE NOTICE 'pg_cron not available or not preloaded; skipping cron.schedule';
    END IF;
END;
$$;
