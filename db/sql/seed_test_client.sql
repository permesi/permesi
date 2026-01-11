-- Genesis test-only seed client.
-- Use only for local/dev setups.

INSERT INTO clients (id, name, uuid, is_reserved)
OVERRIDING SYSTEM VALUE
VALUES (0, '__test_only__', '00000000-0000-0000-0000-000000000000', false)
ON CONFLICT (id) DO NOTHING;
