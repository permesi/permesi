-- Partition maintenance helpers for tokens.
-- Run this in the genesis database after creating the schema.
-- Scheduling is centralized in db/sql/cron_jobs.sql (run against postgres).

-- Receipts written before a day's partition exists land in tokens_default, and
-- PostgreSQL refuses to create a partition whose range the default partition
-- already holds rows for. Each missing day is therefore built as a standalone
-- table, given that day's rows from the default partition, and then attached;
-- inserts wait on the short table lock instead of racing the move. Rows the
-- default partition still holds past retention are deleted with the old days.
-- Operators may drop tokens_default once the job runs; partitions are then
-- created directly. Day bounds are UTC whatever the caller's session time zone.
CREATE OR REPLACE FUNCTION genesis_tokens_rollover(retention_days int, premake_days int)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
-- Never resolve a caller's temporary relations before trusted tables and catalogs.
SET search_path = public, pg_temp
SET timezone = 'UTC'
AS $$
DECLARE
    d date;
    part_name text;
    part_date date;
    got_lock boolean;
    has_default boolean := to_regclass('public.tokens_default') IS NOT NULL;
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
            IF to_regclass(format('public.%I', part_name)) IS NOT NULL THEN
                CONTINUE;
            END IF;
            IF NOT has_default THEN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF tokens FOR VALUES FROM (%L) TO (%L)',
                    part_name, d::timestamptz, (d + 1)::timestamptz
                );
            ELSE
                LOCK TABLE tokens IN SHARE ROW EXCLUSIVE MODE;
                EXECUTE format(
                    'CREATE TABLE %I (LIKE tokens INCLUDING DEFAULTS INCLUDING CONSTRAINTS)',
                    part_name
                );
                EXECUTE format(
                    'WITH moved AS (DELETE FROM tokens_default WHERE created_at >= %L AND created_at < %L RETURNING *) INSERT INTO %I SELECT * FROM moved',
                    d::timestamptz, (d + 1)::timestamptz, part_name
                );
                EXECUTE format(
                    'ALTER TABLE tokens ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)',
                    part_name, d::timestamptz, (d + 1)::timestamptz
                );
            END IF;
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

        IF has_default THEN
            DELETE FROM tokens_default
            WHERE created_at < (current_date - retention_days)::timestamptz;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_advisory_unlock(hashtext('genesis_tokens_rollover'));
            RAISE;
    END;

    PERFORM pg_advisory_unlock(hashtext('genesis_tokens_rollover'));
    RAISE NOTICE 'genesis_tokens_rollover: completed';
END;
$$;

-- Parameterized partition DDL and retention belong to the maintenance owner, never runtime.
REVOKE ALL ON FUNCTION genesis_tokens_rollover(integer,integer) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='genesis_runtime') THEN
        REVOKE ALL ON FUNCTION genesis_tokens_rollover(integer,integer) FROM genesis_runtime;
    END IF;
END $$;
