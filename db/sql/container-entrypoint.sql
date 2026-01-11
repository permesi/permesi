-- Shim to run the real init script from its canonical location.
-- This ensures that relative includes (\ir) work correctly inside the container
-- even when this shim is mounted into /docker-entrypoint-initdb.d/
\i /db/sql/00_init.sql
