#!/bin/bash
# Runs once on first initialization of the Postgres data volume. Creates the
# least-privilege role the gateway connects as, an application schema, and some
# real rows to query. The gateway connects as mcp_login and SET ROLEs to mcp_app,
# so it can never exceed these grants — even though its tool surface exposes DDL.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
-- Application schema (the gateway's world; it has no rights outside it).
CREATE SCHEMA IF NOT EXISTS app;

-- Bounded privilege-bearing role + the login user that assumes it.
DO \$do\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_app') THEN
    CREATE ROLE mcp_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_login') THEN
    CREATE ROLE mcp_login LOGIN PASSWORD '${MCP_APP_PASSWORD}' IN ROLE mcp_app;
  END IF;
END
\$do\$;

-- Scope: read/write within app, nothing else. No DDL on other schemas, no
-- superuser, no CREATEDB/CREATEROLE, cannot terminate other backends.
GRANT USAGE ON SCHEMA app TO mcp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO mcp_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO mcp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mcp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT USAGE, SELECT ON SEQUENCES TO mcp_app;

-- Something real to query through the gateway.
CREATE TABLE IF NOT EXISTS app.records (
  id       bigserial PRIMARY KEY,
  name     text NOT NULL,
  status   text NOT NULL DEFAULT 'open',
  owner    text,
  created  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO app.records (name, status, owner) VALUES
  ('Facility access request', 'open',   'sara'),
  ('Procurement ticket',      'open',   'khalid'),
  ('Onboarding checklist',    'closed', 'noura');

GRANT SELECT, INSERT, UPDATE, DELETE ON app.records TO mcp_app;
GRANT USAGE, SELECT ON SEQUENCE app.records_id_seq TO mcp_app;

-- Belt and braces: no rights on the public schema.
REVOKE ALL ON SCHEMA public FROM mcp_app;
EOSQL

echo "MCP least-privilege init complete (mcp_app bounded to schema app)."
