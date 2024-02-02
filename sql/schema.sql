-- psql -U <user> -d genesis -f schema.sql

-- https://github.com/pksunkara/pgx_ulid
-- CREATE EXTENSION ulid;

-- Create the table for clients
DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
    id ulid NOT NULL DEFAULT gen_ulid() PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(64) NOT NULL
);

-- Create the table to prevent using same password
DROP TABLE IF EXISTS password_history;
CREATE TABLE password_history (
    id ulid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, password)
);

-- Create the table for the metadata
DROP TABLE IF EXISTS user_metadata;
CREATE TABLE user_metadata (
    id ulid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE
);
