-- Least-privilege role for postgres-mcp (Tier-1 defense-in-depth).
--
-- Run this as a DBA once, then point the server at a login user whose role is
-- (or SET ROLEs to) mcp_app via POSTGRES_ROLE=mcp_app. The server then physically
-- cannot exceed these grants, even though its tool surface exposes DDL/admin —
-- those tools simply fail with "permission denied" for objects it wasn't granted.
--
-- Adjust the GRANTs to the exact schemas/tables the gateway's users should reach.
-- The point is that a gateway compromise is bounded by the database, not just by
-- the gateway's own ABAC.

-- 1. A NOLOGIN role that carries the privileges (SET ROLE target).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_app') THEN
    CREATE ROLE mcp_app NOLOGIN;
  END IF;
END$$;

-- 2. A LOGIN user the server actually connects as; it can assume mcp_app.
--    Give it a real password out-of-band; do NOT hardcode one here.
--    CREATE ROLE mcp_login LOGIN PASSWORD '<from-secret-store>' IN ROLE mcp_app;

-- 3. Scope of access. Replace `app` with your real schema(s).
GRANT USAGE ON SCHEMA app TO mcp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO mcp_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO mcp_app;
-- Future tables created in the schema inherit the grant:
ALTER DEFAULT PRIVILEGES IN SCHEMA app
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mcp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA app
  GRANT USAGE, SELECT ON SEQUENCES TO mcp_app;

-- 4. Explicitly WITHHOLD the dangerous surface. mcp_app is NOT a superuser, has
--    no CREATEDB/CREATEROLE, cannot terminate backends of other users, and cannot
--    touch schemas it wasn't granted. The server's POSTGRES_ALLOW_DANGEROUS gate is
--    a second lock; this is the first.
REVOKE ALL ON DATABASE postgres FROM mcp_app;

-- Verify:  SET ROLE mcp_app; SELECT current_user, session_user;
