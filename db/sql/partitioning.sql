-- Partition maintenance helpers for tokens.
-- Run this in the genesis database after creating the schema.
-- Scheduling is centralized in db/sql/cron_jobs.sql (run against postgres).

CREATE OR REPLACE FUNCTION genesis_tokens_rollover(retention_days int, premake_days int)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
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
