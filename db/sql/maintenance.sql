-- Manual cleanup helper for permesi maintenance.
-- Run this in the permesi database when you want to purge expired records.
-- Scheduling is centralized in db/sql/cron_jobs.sql (run against postgres).

SELECT cleanup_expired_tokens();
