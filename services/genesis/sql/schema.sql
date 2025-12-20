-- psql -U <user> -d genesis -f schema.sql

-- Ensure necessary extensions are enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- https://github.com/pksunkara/pgx_ulid
CREATE EXTENSION IF NOT EXISTS ulid;

-- Create the table for clients
DROP TABLE IF EXISTS clients CASCADE;
CREATE TABLE clients (
    id SMALLINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text NOT NULL,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE
);

INSERT INTO clients (id, name, uuid)
OVERRIDING SYSTEM VALUE
VALUES (0, 'unknown', '00000000-0000-0000-0000-000000000000');

-- Create the table for the tokens
DROP TABLE IF EXISTS tokens CASCADE;
CREATE TABLE tokens (
    id ulid NOT NULL DEFAULT gen_ulid() PRIMARY KEY,
    client_id SMALLINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE
);

-- Create the table for the metadata
DROP TABLE IF EXISTS metadata;
CREATE TABLE metadata (
    id ulid PRIMARY KEY REFERENCES tokens(id) ON DELETE CASCADE,
    ip_address INET,
    country CHAR(2),
    user_agent text
);

CREATE INDEX idx_metadata_country ON metadata(country);
CREATE INDEX idx_metadata_ip ON metadata(ip_address);
