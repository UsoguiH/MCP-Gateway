#!/bin/bash
# Runs once on first initialization of the Postgres data volume (after 01_init.sh).
# Creates the GATEWAY STATE database (Phase 3, decision D2): `gwstate`, owned by a
# dedicated least-privilege login role. The gateway's shared-state backend
# (app/statestore.py) connects as gwstate and owns only this database — it has no
# access to appdb, no superuser, no CREATEDB/CREATEROLE.
#
# Existing deployments (the pgdata volume already initialized) will not re-run
# this: use scripts/create_gwstate.ps1 instead — same statements via docker exec.
set -e

GWSTATE_PW="${GWSTATE_PASSWORD:-$(cat /run/secrets/gwstate_pw 2>/dev/null || true)}"
if [ -z "$GWSTATE_PW" ]; then
  echo "02_gwstate: no GWSTATE_PASSWORD or gwstate_pw secret — skipping gwstate creation"
  exit 0
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
DO \$do\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gwstate') THEN
    CREATE ROLE gwstate LOGIN PASSWORD '${GWSTATE_PW}';
  END IF;
END
\$do\$;
EOSQL

# CREATE DATABASE cannot run inside a DO block/transaction.
if ! psql -tA --username "$POSTGRES_USER" -c "SELECT 1 FROM pg_database WHERE datname = 'gwstate'" | grep -q 1; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
       -c "CREATE DATABASE gwstate OWNER gwstate"
fi

# The role owns its database (it creates/maintains the schema there) and nothing else.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname gwstate <<'EOSQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO gwstate;
EOSQL

echo "gwstate database ready (owner: gwstate, bounded to its own database)."
