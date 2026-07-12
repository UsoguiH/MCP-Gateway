"""postgres-mcp — full-featured PostgreSQL MCP server (read + write).

A production-grade MCP server exposing comprehensive database operations:

  * Query execution   — read-only queries, writes, atomic transactions, EXPLAIN
  * Schema inspection — databases, schemas, tables, columns, indexes,
                        constraints, views, matviews, functions, triggers,
                        sequences, enums, extensions
  * Row operations    — select/count/insert/bulk-insert/update/delete/upsert,
                        distinct values, per-column statistics, truncate
  * DDL               — create/drop/rename tables, columns, indexes,
                        constraints, views, schemas, sequences, enum types
  * Maintenance       — VACUUM, ANALYZE, REINDEX, matview refresh
  * Monitoring        — activity, long-running queries, locks, blockers,
                        cache hit ratios, index usage, table sizes/stats,
                        replication, settings; cancel/terminate backends
  * Roles & grants    — list/create/alter/drop roles, GRANT/REVOKE, ACL view
  * Data I/O          — CSV export (query or table) and CSV import via COPY

Connection is configured via environment (never via model-visible args):
  POSTGRES_URL / DATABASE_URL   e.g. postgresql://user:pass@host:5432/db
  or the standard PG* variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE)
  POSTGRES_STATEMENT_TIMEOUT_MS (default 30000)
  POSTGRES_MAX_ROWS             (default 500, hard cap on returned rows)
  POSTGRES_ALLOW_DANGEROUS      ("1" enables drop_database/terminate; default off)

Safety model:
  * Read tools run in READ ONLY transactions — writes are rejected by Postgres.
  * All identifiers are quoted via psycopg.sql.Identifier; all values are
    server-side bound parameters. No string-interpolated SQL from arguments.
  * Every statement runs under a statement timeout.
  * update_rows / delete_rows REQUIRE a WHERE clause (full-table changes must
    be explicit via truncate_table or execute_write).
  * Result sets are capped (row cap + byte cap) and report truncation.

Runs over stdio; the gateway spawns it.
"""
import base64
import datetime
import decimal
import ipaddress
import json
import os
import re
import uuid
from typing import Any, Optional

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("postgres")

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

CONNINFO = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL") or ""
STMT_TIMEOUT_MS = int(os.environ.get("POSTGRES_STATEMENT_TIMEOUT_MS", "30000"))
DEFAULT_MAX_ROWS = int(os.environ.get("POSTGRES_MAX_ROWS", "500"))
HARD_MAX_ROWS = 5000
MAX_RESULT_BYTES = 1_000_000          # cap serialized payloads (gateway also caps)
ALLOW_DANGEROUS = os.environ.get("POSTGRES_ALLOW_DANGEROUS", "0") == "1"
CONNECT_TIMEOUT = int(os.environ.get("POSTGRES_CONNECT_TIMEOUT", "10"))
# Least privilege: connect as a limited login role, then SET ROLE to it so the
# server can never exceed the grants of POSTGRES_ROLE even if the login user is
# more powerful. Leave unset to use the login role as-is. See
# deploy/postgres_least_privilege.sql for a ready-made role definition.
POSTGRES_ROLE = os.environ.get("POSTGRES_ROLE", "").strip()
# Identity marker surfaced in pg_stat_activity / server logs so DBA-side audit can
# attribute this connection to the gateway (and, per deployment, the tenant).
APP_NAME = os.environ.get("POSTGRES_APPNAME", "postgres-mcp")[:60]
_ROLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_VALID_PRIVILEGES = {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE",
                     "REFERENCES", "TRIGGER", "USAGE", "CREATE", "CONNECT",
                     "TEMPORARY", "EXECUTE", "ALL"}
_VALID_INDEX_METHODS = {"btree", "hash", "gist", "spgist", "gin", "brin"}


def _json_default(v: Any) -> Any:
    if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
        return v.isoformat()
    if isinstance(v, datetime.timedelta):
        return v.total_seconds()
    if isinstance(v, decimal.Decimal):
        return float(v) if v == v.to_integral_value() or abs(v) < 1e15 else str(v)
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, (bytes, memoryview)):
        b = bytes(v)
        return {"__bytes_base64__": base64.b64encode(b).decode(), "length": len(b)}
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address,
                      ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(v)
    if isinstance(v, range):
        return list(v)
    return str(v)


def _dumps(obj: Any) -> str:
    out = json.dumps(obj, ensure_ascii=False, default=_json_default)
    if len(out.encode("utf-8", "ignore")) > MAX_RESULT_BYTES:
        return json.dumps({"error": "result too large",
                           "hint": "narrow the query (fewer rows/columns) or lower limit",
                           "size_bytes": len(out)})
    return out


def _err(e: Exception) -> str:
    payload: dict[str, Any] = {"error": str(e).strip(), "type": type(e).__name__}
    sqlstate = getattr(e, "sqlstate", None)
    if sqlstate:
        payload["sqlstate"] = sqlstate
    diag = getattr(e, "diag", None)
    if diag is not None:
        for attr in ("message_detail", "message_hint", "constraint_name",
                     "table_name", "column_name"):
            val = getattr(diag, attr, None)
            if val:
                payload[attr] = val
    return json.dumps(payload, ensure_ascii=False)


def _connect(readonly: bool = False, autocommit: bool = False) -> psycopg.Connection:
    opts = f"-c statement_timeout={STMT_TIMEOUT_MS}"
    if POSTGRES_ROLE:
        if not _ROLE_RE.match(POSTGRES_ROLE):
            raise ValueError(f"invalid POSTGRES_ROLE: {POSTGRES_ROLE!r}")
        # -c role=... makes the session assume the least-privilege role at connect;
        # it cannot be escalated back without RESET ROLE privileges.
        opts += f" -c role={POSTGRES_ROLE}"
    conn = psycopg.connect(
        CONNINFO,
        row_factory=dict_row,
        connect_timeout=CONNECT_TIMEOUT,
        options=opts,
        application_name=APP_NAME,
    )
    conn.read_only = readonly
    conn.autocommit = autocommit
    return conn


def _clamp_limit(limit: Optional[int]) -> int:
    if limit is None or limit <= 0:
        return DEFAULT_MAX_ROWS
    return min(limit, HARD_MAX_ROWS)


def _fetch(cur: psycopg.Cursor, limit: int) -> dict[str, Any]:
    """Fetch up to limit rows plus one sentinel row to detect truncation."""
    if cur.description is None:
        return {"rows_affected": cur.rowcount}
    rows = cur.fetchmany(limit + 1)
    truncated = len(rows) > limit
    rows = rows[:limit]
    return {
        "columns": [d.name for d in cur.description],
        "rows": rows,
        "row_count": len(rows),
        "truncated": truncated,
    }


def _query(sql_obj: Any, params: Any = None, limit: Optional[int] = None,
           readonly: bool = True) -> str:
    lim = _clamp_limit(limit)
    try:
        with _connect(readonly=readonly) as conn, conn.cursor() as cur:
            cur.execute(sql_obj, params)
            return _dumps(_fetch(cur, lim))
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


def _write(sql_obj: Any, params: Any = None, limit: Optional[int] = None) -> str:
    lim = _clamp_limit(limit)
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(sql_obj, params)
            result = _fetch(cur, lim)
            if "rows_affected" not in result:
                result["rows_affected"] = cur.rowcount
            conn.commit()
            result["status"] = "committed"
            return _dumps(result)
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


def _admin(sql_obj: Any, params: Any = None) -> str:
    """Autocommit execution for statements that cannot run inside a transaction
    (VACUUM, REINDEX, CREATE/DROP DATABASE, ...)."""
    try:
        with _connect(autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(sql_obj, params)
            out: dict[str, Any] = {"status": "ok"}
            if cur.description is not None:
                out.update(_fetch(cur, DEFAULT_MAX_ROWS))
            return _dumps(out)
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


def _ident(*parts: str) -> sql.Identifier:
    for p in parts:
        if not p or len(p) > 128:
            raise ValueError(f"invalid identifier: {p!r}")
    return sql.Identifier(*parts)


def _table_ref(table: str, schema: str) -> sql.Identifier:
    return _ident(schema, table)


def _cols(names: list[str]) -> sql.Composed:
    return sql.SQL(", ").join(_ident(c) for c in names)


def _require(cond: bool, msg: str) -> Optional[str]:
    if not cond:
        return json.dumps({"error": msg})
    return None


# ==========================================================================
# 1. QUERY EXECUTION
# ==========================================================================

@mcp.tool()
def execute_query(query: str, params: Optional[list] = None,
                  limit: Optional[int] = None) -> str:
    """Run a read-only SQL query (SELECT/SHOW/WITH/EXPLAIN). Executes inside a READ ONLY
    transaction so any write is rejected. Use %s placeholders with the params list for
    values. Returns columns, rows, row_count and a truncated flag."""
    return _query(query, params, limit, readonly=True)


@mcp.tool()
def execute_write(statement: str, params: Optional[list] = None,
                  limit: Optional[int] = None) -> str:
    """Run a single write statement (INSERT/UPDATE/DELETE/DDL) and commit. Use %s
    placeholders with the params list. Returns rows_affected and any RETURNING rows.
    Prefer the dedicated typed tools (insert_row, update_rows, ...) when they fit."""
    return _write(statement, params, limit)


@mcp.tool()
def execute_transaction(statements: list[str]) -> str:
    """Run multiple SQL statements as ONE atomic transaction — all succeed or all roll
    back. Each list entry is a complete statement (no parameters). Returns per-statement
    rows_affected."""
    if err := _require(bool(statements), "statements list is empty"):
        return err
    try:
        results = []
        with _connect() as conn, conn.cursor() as cur:
            for i, stmt in enumerate(statements):
                cur.execute(stmt)
                results.append({"index": i, "rows_affected": cur.rowcount,
                                "statement": stmt[:120]})
            conn.commit()
        return _dumps({"status": "committed", "statements_run": len(results),
                       "results": results})
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


@mcp.tool()
def explain_query(query: str, analyze: bool = False, params: Optional[list] = None) -> str:
    """Show the execution plan for a query (EXPLAIN, JSON format). Set analyze=true to
    actually execute it and get real timings/row counts — the run is wrapped in a
    transaction that is ROLLED BACK, so writes do not persist."""
    try:
        with _connect() as conn, conn.cursor() as cur:
            prefix = "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " if analyze \
                else "EXPLAIN (FORMAT JSON) "
            cur.execute(prefix + query, params)
            plan = cur.fetchone()
            conn.rollback()   # never persist effects of EXPLAIN ANALYZE on writes
            key = list(plan.keys())[0]
            return _dumps({"plan": plan[key]})
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


# ==========================================================================
# 2. SERVER / DATABASE INFO
# ==========================================================================

@mcp.tool()
def server_info() -> str:
    """Server version, current database/user, uptime, connection counts, and data
    directory size summary."""
    q = """
    SELECT version()                                   AS version,
           current_database()                          AS database,
           current_user                                AS "user",
           inet_server_addr()::text                    AS server_addr,
           inet_server_port()                          AS server_port,
           pg_postmaster_start_time()                  AS started_at,
           now() - pg_postmaster_start_time()          AS uptime,
           (SELECT count(*) FROM pg_stat_activity)     AS connections,
           current_setting('max_connections')::int    AS max_connections,
           pg_size_pretty(pg_database_size(current_database())) AS database_size
    """
    return _query(q)


@mcp.tool()
def list_databases() -> str:
    """List all databases with owner, encoding, size and connection limit."""
    q = """
    SELECT d.datname AS name, pg_get_userbyid(d.datdba) AS owner,
           pg_encoding_to_char(d.encoding) AS encoding, d.datcollate AS collation,
           d.datconnlimit AS connection_limit, d.datistemplate AS is_template,
           CASE WHEN pg_catalog.has_database_privilege(d.datname, 'CONNECT')
                THEN pg_size_pretty(pg_database_size(d.datname)) END AS size
    FROM pg_database d ORDER BY d.datname
    """
    return _query(q)


@mcp.tool()
def create_database(name: str, owner: Optional[str] = None,
                    template: Optional[str] = None) -> str:
    """Create a new database (optionally with owner and template)."""
    stmt = sql.SQL("CREATE DATABASE {}").format(_ident(name))
    if owner:
        stmt += sql.SQL(" OWNER {}").format(_ident(owner))
    if template:
        stmt += sql.SQL(" TEMPLATE {}").format(_ident(template))
    return _admin(stmt)


@mcp.tool()
def drop_database(name: str, force: bool = False) -> str:
    """Drop a database. DESTRUCTIVE — requires POSTGRES_ALLOW_DANGEROUS=1 in the server
    environment. force=true also terminates existing connections to it."""
    if err := _require(ALLOW_DANGEROUS,
                       "drop_database disabled (set POSTGRES_ALLOW_DANGEROUS=1)"):
        return err
    stmt = sql.SQL("DROP DATABASE IF EXISTS {}").format(_ident(name))
    if force:
        stmt += sql.SQL(" WITH (FORCE)")
    return _admin(stmt)


@mcp.tool()
def database_size(database: Optional[str] = None) -> str:
    """Total on-disk size of a database (defaults to the current one)."""
    if database:
        return _query("SELECT %s AS database, pg_size_pretty(pg_database_size(%s)) AS size, "
                      "pg_database_size(%s) AS size_bytes", [database, database, database])
    return _query("SELECT current_database() AS database, "
                  "pg_size_pretty(pg_database_size(current_database())) AS size, "
                  "pg_database_size(current_database()) AS size_bytes")


@mcp.tool()
def list_extensions() -> str:
    """List installed extensions and the versions available on this server."""
    q = """
    SELECT a.name, a.default_version, i.extversion AS installed_version, a.comment
    FROM pg_available_extensions a
    LEFT JOIN pg_extension i ON i.extname = a.name
    ORDER BY (i.extversion IS NULL), a.name
    """
    return _query(q)


@mcp.tool()
def create_extension(name: str) -> str:
    """Install a PostgreSQL extension (CREATE EXTENSION IF NOT EXISTS)."""
    return _write(sql.SQL("CREATE EXTENSION IF NOT EXISTS {}").format(_ident(name)))


# ==========================================================================
# 3. SCHEMAS
# ==========================================================================

@mcp.tool()
def list_schemas(include_system: bool = False) -> str:
    """List schemas with owner and table count. include_system=true adds pg_catalog and
    information_schema."""
    q = """
    SELECT n.nspname AS name, pg_get_userbyid(n.nspowner) AS owner,
           (SELECT count(*) FROM pg_class c
            WHERE c.relnamespace = n.oid AND c.relkind = 'r') AS tables
    FROM pg_namespace n
    WHERE (%s OR (n.nspname NOT LIKE 'pg\\_%%' AND n.nspname <> 'information_schema'))
    ORDER BY n.nspname
    """
    return _query(q, [include_system])


@mcp.tool()
def create_schema(name: str, owner: Optional[str] = None) -> str:
    """Create a schema (optionally owned by a given role)."""
    stmt = sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(_ident(name))
    if owner:
        stmt += sql.SQL(" AUTHORIZATION {}").format(_ident(owner))
    return _write(stmt)


@mcp.tool()
def drop_schema(name: str, cascade: bool = False) -> str:
    """Drop a schema. cascade=true also drops all contained objects (DESTRUCTIVE)."""
    stmt = sql.SQL("DROP SCHEMA IF EXISTS {}").format(_ident(name))
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


# ==========================================================================
# 4. TABLE INSPECTION
# ==========================================================================

@mcp.tool()
def list_tables(schema: str = "public") -> str:
    """List tables in a schema with row estimates, total size, and comment."""
    q = """
    SELECT c.relname AS table, pg_get_userbyid(c.relowner) AS owner,
           c.reltuples::bigint AS estimated_rows,
           pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
           pg_total_relation_size(c.oid) AS total_size_bytes,
           obj_description(c.oid, 'pg_class') AS comment
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %s AND c.relkind IN ('r', 'p')
    ORDER BY c.relname
    """
    return _query(q, [schema])


@mcp.tool()
def describe_table(table: str, schema: str = "public") -> str:
    """Full structure of one table: columns (type, nullable, default, comment),
    primary key, indexes, foreign keys (both directions), check constraints,
    triggers, and size/row estimates."""
    try:
        with _connect(readonly=True) as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT a.attname AS column, format_type(a.atttypid, a.atttypmod) AS type,
                       NOT a.attnotnull AS nullable,
                       pg_get_expr(d.adbin, d.adrelid) AS default,
                       col_description(a.attrelid, a.attnum) AS comment,
                       a.attidentity <> '' AS is_identity
                FROM pg_attribute a
                JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0
                  AND NOT a.attisdropped
                ORDER BY a.attnum""", [schema, table])
            columns = cur.fetchall()
            if not columns:
                return json.dumps({"error": f"table {schema}.{table} not found"})

            cur.execute("""
                SELECT a.attname FROM pg_index i
                JOIN pg_class c ON c.oid = i.indrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
                WHERE n.nspname = %s AND c.relname = %s AND i.indisprimary""",
                        [schema, table])
            pk = [r["attname"] for r in cur.fetchall()]

            cur.execute("""
                SELECT i.relname AS name, pg_get_indexdef(x.indexrelid) AS definition,
                       x.indisunique AS unique, x.indisprimary AS primary
                FROM pg_index x
                JOIN pg_class c ON c.oid = x.indrelid
                JOIN pg_class i ON i.oid = x.indexrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s ORDER BY i.relname""",
                        [schema, table])
            indexes = cur.fetchall()

            cur.execute("""
                SELECT conname AS name, contype AS type,
                       pg_get_constraintdef(oid) AS definition
                FROM pg_constraint
                WHERE conrelid = format('%%I.%%I', %s::text, %s::text)::regclass
                ORDER BY conname""", [schema, table])
            constraints = [{**r, "type": {"c": "check", "f": "foreign_key",
                                          "p": "primary_key", "u": "unique",
                                          "x": "exclusion"}.get(r["type"], r["type"])}
                           for r in cur.fetchall()]

            cur.execute("""
                SELECT conname AS name, conrelid::regclass::text AS from_table,
                       pg_get_constraintdef(oid) AS definition
                FROM pg_constraint
                WHERE contype = 'f'
                  AND confrelid = format('%%I.%%I', %s::text, %s::text)::regclass""",
                        [schema, table])
            referenced_by = cur.fetchall()

            cur.execute("""
                SELECT t.tgname AS name, pg_get_triggerdef(t.oid) AS definition
                FROM pg_trigger t
                JOIN pg_class c ON c.oid = t.tgrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s AND NOT t.tgisinternal""",
                        [schema, table])
            triggers = cur.fetchall()

            cur.execute("""
                SELECT c.reltuples::bigint AS estimated_rows,
                       pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
                       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes_size,
                       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
                       obj_description(c.oid, 'pg_class') AS comment
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s""", [schema, table])
            meta = cur.fetchone()

        return _dumps({"schema": schema, "table": table, **(meta or {}),
                       "primary_key": pk, "columns": columns, "indexes": indexes,
                       "constraints": constraints, "referenced_by": referenced_by,
                       "triggers": triggers})
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


@mcp.tool()
def list_columns(table: str, schema: str = "public") -> str:
    """List the columns of a table with type, nullability, default and position."""
    q = """
    SELECT ordinal_position AS position, column_name AS column, data_type AS type,
           udt_name, is_nullable = 'YES' AS nullable, column_default AS default,
           character_maximum_length AS max_length
    FROM information_schema.columns
    WHERE table_schema = %s AND table_name = %s
    ORDER BY ordinal_position
    """
    return _query(q, [schema, table])


@mcp.tool()
def table_sizes(schema: Optional[str] = None, limit: int = 50) -> str:
    """Largest tables (table + index + toast size), optionally filtered by schema."""
    q = """
    SELECT n.nspname AS schema, c.relname AS table,
           pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
           pg_size_pretty(pg_indexes_size(c.oid)) AS indexes_size,
           pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
           pg_total_relation_size(c.oid) AS total_size_bytes,
           c.reltuples::bigint AS estimated_rows
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'm')
      AND n.nspname NOT LIKE 'pg\\_%%' AND n.nspname <> 'information_schema'
      AND (%s::text IS NULL OR n.nspname = %s)
    ORDER BY pg_total_relation_size(c.oid) DESC
    """
    return _query(q, [schema, schema], limit)


@mcp.tool()
def table_stats(table: str, schema: str = "public") -> str:
    """Planner/activity statistics for one table: live/dead tuples, seq vs index scans,
    inserts/updates/deletes, and last vacuum/analyze times."""
    q = """
    SELECT schemaname AS schema, relname AS table, seq_scan, seq_tup_read,
           idx_scan, idx_tup_fetch, n_tup_ins AS inserts, n_tup_upd AS updates,
           n_tup_del AS deletes, n_tup_hot_upd AS hot_updates,
           n_live_tup AS live_rows, n_dead_tup AS dead_rows,
           last_vacuum, last_autovacuum, last_analyze, last_autoanalyze,
           vacuum_count, autovacuum_count, analyze_count, autoanalyze_count
    FROM pg_stat_user_tables WHERE schemaname = %s AND relname = %s
    """
    return _query(q, [schema, table])


# ==========================================================================
# 5. INDEXES
# ==========================================================================

@mcp.tool()
def list_indexes(table: Optional[str] = None, schema: str = "public") -> str:
    """List indexes in a schema (optionally for one table) with definition, size,
    uniqueness and scan count."""
    q = """
    SELECT n.nspname AS schema, t.relname AS table, i.relname AS index,
           pg_get_indexdef(x.indexrelid) AS definition,
           x.indisunique AS unique, x.indisprimary AS primary, x.indisvalid AS valid,
           pg_size_pretty(pg_relation_size(x.indexrelid)) AS size,
           s.idx_scan AS scans
    FROM pg_index x
    JOIN pg_class t ON t.oid = x.indrelid
    JOIN pg_class i ON i.oid = x.indexrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = x.indexrelid
    WHERE n.nspname = %s AND (%s::text IS NULL OR t.relname = %s)
    ORDER BY t.relname, i.relname
    """
    return _query(q, [schema, table, table])


@mcp.tool()
def create_index(table: str, columns: list[str], schema: str = "public",
                 name: Optional[str] = None, unique: bool = False,
                 method: str = "btree", concurrently: bool = False) -> str:
    """Create an index on one or more columns. method: btree|hash|gist|spgist|gin|brin.
    concurrently=true avoids blocking writes (takes longer, cannot run in a transaction)."""
    if err := _require(method in _VALID_INDEX_METHODS,
                       f"invalid method {method!r}; use one of {sorted(_VALID_INDEX_METHODS)}"):
        return err
    if err := _require(bool(columns), "columns list is empty"):
        return err
    idx_name = name or f"idx_{table}_{'_'.join(columns)}"[:63]
    stmt = sql.SQL("CREATE {unique}INDEX {conc}IF NOT EXISTS {name} ON {tbl} USING {method} ({cols})").format(
        unique=sql.SQL("UNIQUE ") if unique else sql.SQL(""),
        conc=sql.SQL("CONCURRENTLY ") if concurrently else sql.SQL(""),
        name=_ident(idx_name), tbl=_table_ref(table, schema),
        method=sql.SQL(method), cols=_cols(columns))
    return _admin(stmt) if concurrently else _write(stmt)


@mcp.tool()
def drop_index(name: str, schema: str = "public", concurrently: bool = False) -> str:
    """Drop an index by name."""
    stmt = sql.SQL("DROP INDEX {conc}IF EXISTS {name}").format(
        conc=sql.SQL("CONCURRENTLY ") if concurrently else sql.SQL(""),
        name=_ident(schema, name))
    return _admin(stmt) if concurrently else _write(stmt)


@mcp.tool()
def reindex(target_type: str, name: str, schema: str = "public") -> str:
    """Rebuild indexes. target_type: 'index', 'table', or 'database' (name is the
    index/table/database name)."""
    kinds = {"index": "INDEX", "table": "TABLE", "database": "DATABASE"}
    if err := _require(target_type in kinds, "target_type must be index|table|database"):
        return err
    ref = _ident(name) if target_type == "database" else _ident(schema, name)
    return _admin(sql.SQL("REINDEX {} {}").format(sql.SQL(kinds[target_type]), ref))


@mcp.tool()
def index_usage(schema: Optional[str] = None, only_unused: bool = False,
                limit: int = 100) -> str:
    """Index scan statistics — spot unused or hot indexes. only_unused=true returns
    indexes never scanned (candidates for removal; excludes primary/unique)."""
    q = """
    SELECT s.schemaname AS schema, s.relname AS table, s.indexrelname AS index,
           s.idx_scan AS scans, s.idx_tup_read AS tuples_read,
           pg_size_pretty(pg_relation_size(s.indexrelid)) AS size,
           x.indisunique AS unique, x.indisprimary AS primary
    FROM pg_stat_user_indexes s JOIN pg_index x ON x.indexrelid = s.indexrelid
    WHERE (%s::text IS NULL OR s.schemaname = %s)
      AND (NOT %s OR (s.idx_scan = 0 AND NOT x.indisunique AND NOT x.indisprimary))
    ORDER BY s.idx_scan ASC, pg_relation_size(s.indexrelid) DESC
    """
    return _query(q, [schema, schema, only_unused], limit)


# ==========================================================================
# 6. CONSTRAINTS
# ==========================================================================

@mcp.tool()
def list_constraints(table: str, schema: str = "public") -> str:
    """List all constraints on a table (PK, FK, unique, check, exclusion) with their
    full definitions."""
    q = """
    SELECT con.conname AS name,
           CASE con.contype WHEN 'c' THEN 'check' WHEN 'f' THEN 'foreign_key'
                WHEN 'p' THEN 'primary_key' WHEN 'u' THEN 'unique'
                WHEN 'x' THEN 'exclusion' ELSE con.contype::text END AS type,
           pg_get_constraintdef(con.oid) AS definition
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %s AND c.relname = %s ORDER BY con.conname
    """
    return _query(q, [schema, table])


@mcp.tool()
def list_foreign_keys(table: Optional[str] = None, schema: str = "public") -> str:
    """List foreign keys in a schema (optionally for one table): local columns,
    referenced table/columns, and ON UPDATE/DELETE actions."""
    q = """
    SELECT con.conname AS name, c.relname AS table,
           (SELECT array_agg(a.attname ORDER BY u.ord)
            FROM unnest(con.conkey) WITH ORDINALITY u(attnum, ord)
            JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = u.attnum
           ) AS columns,
           rc.relname AS references_table,
           (SELECT array_agg(a.attname ORDER BY u.ord)
            FROM unnest(con.confkey) WITH ORDINALITY u(attnum, ord)
            JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = u.attnum
           ) AS references_columns,
           CASE con.confupdtype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
                WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL'
                WHEN 'd' THEN 'SET DEFAULT' END AS on_update,
           CASE con.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
                WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL'
                WHEN 'd' THEN 'SET DEFAULT' END AS on_delete
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_class rc ON rc.oid = con.confrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE con.contype = 'f' AND n.nspname = %s
      AND (%s::text IS NULL OR c.relname = %s)
    ORDER BY c.relname, con.conname
    """
    return _query(q, [schema, table, table])


@mcp.tool()
def add_constraint(table: str, constraint_name: str, definition: str,
                   schema: str = "public") -> str:
    """Add a constraint to a table. definition is the SQL after the constraint name,
    e.g. 'CHECK (price > 0)', 'UNIQUE (email)',
    'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE'."""
    stmt = sql.SQL("ALTER TABLE {} ADD CONSTRAINT {} ").format(
        _table_ref(table, schema), _ident(constraint_name)) + sql.SQL(definition)
    return _write(stmt)


@mcp.tool()
def drop_constraint(table: str, constraint_name: str, schema: str = "public",
                    cascade: bool = False) -> str:
    """Drop a named constraint from a table."""
    stmt = sql.SQL("ALTER TABLE {} DROP CONSTRAINT IF EXISTS {}").format(
        _table_ref(table, schema), _ident(constraint_name))
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


# ==========================================================================
# 7. VIEWS & MATERIALIZED VIEWS
# ==========================================================================

@mcp.tool()
def list_views(schema: str = "public") -> str:
    """List regular views in a schema."""
    q = """
    SELECT c.relname AS view, pg_get_userbyid(c.relowner) AS owner,
           obj_description(c.oid, 'pg_class') AS comment
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %s AND c.relkind = 'v' ORDER BY c.relname
    """
    return _query(q, [schema])


@mcp.tool()
def get_view_definition(view: str, schema: str = "public") -> str:
    """Return the SQL definition of a view or materialized view."""
    q = """
    SELECT n.nspname AS schema, c.relname AS view,
           CASE c.relkind WHEN 'm' THEN 'materialized' ELSE 'view' END AS kind,
           pg_get_viewdef(c.oid, true) AS definition
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('v', 'm')
    """
    return _query(q, [schema, view])


@mcp.tool()
def create_view(name: str, query: str, schema: str = "public",
                or_replace: bool = True, materialized: bool = False) -> str:
    """Create a view (or materialized view) from a SELECT query."""
    if materialized:
        stmt = sql.SQL("CREATE MATERIALIZED VIEW IF NOT EXISTS {} AS ").format(
            _ident(schema, name)) + sql.SQL(query)
    else:
        head = "CREATE OR REPLACE VIEW {} AS " if or_replace else "CREATE VIEW {} AS "
        stmt = sql.SQL(head).format(_ident(schema, name)) + sql.SQL(query)
    return _write(stmt)


@mcp.tool()
def drop_view(name: str, schema: str = "public", materialized: bool = False,
              cascade: bool = False) -> str:
    """Drop a view or materialized view."""
    kind = sql.SQL("MATERIALIZED VIEW") if materialized else sql.SQL("VIEW")
    stmt = sql.SQL("DROP {} IF EXISTS {}").format(kind, _ident(schema, name))
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


@mcp.tool()
def list_materialized_views(schema: str = "public") -> str:
    """List materialized views with size and populated state."""
    q = """
    SELECT c.relname AS view, pg_get_userbyid(c.relowner) AS owner,
           c.relispopulated AS populated,
           pg_size_pretty(pg_total_relation_size(c.oid)) AS size
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %s AND c.relkind = 'm' ORDER BY c.relname
    """
    return _query(q, [schema])


@mcp.tool()
def refresh_materialized_view(name: str, schema: str = "public",
                              concurrently: bool = False) -> str:
    """Refresh a materialized view. concurrently=true keeps it readable during refresh
    (requires a unique index on the matview)."""
    stmt = sql.SQL("REFRESH MATERIALIZED VIEW {conc}{name}").format(
        conc=sql.SQL("CONCURRENTLY ") if concurrently else sql.SQL(""),
        name=_ident(schema, name))
    return _write(stmt)


# ==========================================================================
# 8. FUNCTIONS, TRIGGERS, SEQUENCES, TYPES
# ==========================================================================

@mcp.tool()
def list_functions(schema: str = "public") -> str:
    """List user-defined functions and procedures with signature, return type,
    language and kind."""
    q = """
    SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS arguments,
           pg_get_function_result(p.oid) AS returns, l.lanname AS language,
           CASE p.prokind WHEN 'f' THEN 'function' WHEN 'p' THEN 'procedure'
                WHEN 'a' THEN 'aggregate' WHEN 'w' THEN 'window' END AS kind,
           pg_get_userbyid(p.proowner) AS owner
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_language l ON l.oid = p.prolang
    WHERE n.nspname = %s ORDER BY p.proname
    """
    return _query(q, [schema])


@mcp.tool()
def get_function_definition(name: str, schema: str = "public") -> str:
    """Return the full CREATE statement(s) for a function (all overloads)."""
    q = """
    SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS arguments,
           pg_get_functiondef(p.oid) AS definition
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = %s AND p.proname = %s AND p.prokind IN ('f', 'p')
    """
    return _query(q, [schema, name])


@mcp.tool()
def list_triggers(table: Optional[str] = None, schema: str = "public") -> str:
    """List triggers in a schema (optionally for one table) with timing, events and
    definition."""
    q = """
    SELECT t.tgname AS name, c.relname AS table, t.tgenabled <> 'D' AS enabled,
           pg_get_triggerdef(t.oid) AS definition
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE NOT t.tgisinternal AND n.nspname = %s
      AND (%s::text IS NULL OR c.relname = %s)
    ORDER BY c.relname, t.tgname
    """
    return _query(q, [schema, table, table])


@mcp.tool()
def list_sequences(schema: str = "public") -> str:
    """List sequences with current value, increment and owned-by column."""
    q = """
    SELECT s.schemaname AS schema, s.sequencename AS sequence, s.last_value,
           s.increment_by, s.min_value, s.max_value, s.cycle,
           (SELECT quote_ident(dc.relname) || '.' || quote_ident(a.attname)
            FROM pg_depend d
            JOIN pg_class sc ON sc.relname = s.sequencename
            JOIN pg_namespace sn ON sn.oid = sc.relnamespace AND sn.nspname = s.schemaname
            JOIN pg_class dc ON dc.oid = d.refobjid
            JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
            WHERE d.objid = sc.oid AND d.deptype IN ('a', 'i') LIMIT 1) AS owned_by
    FROM pg_sequences s WHERE s.schemaname = %s ORDER BY s.sequencename
    """
    return _query(q, [schema])


@mcp.tool()
def create_sequence(name: str, schema: str = "public", start: int = 1,
                    increment: int = 1) -> str:
    """Create a sequence with a given start value and increment."""
    stmt = sql.SQL("CREATE SEQUENCE IF NOT EXISTS {} INCREMENT BY {} START WITH {}").format(
        _ident(schema, name), sql.Literal(increment), sql.Literal(start))
    return _write(stmt)


@mcp.tool()
def set_sequence_value(name: str, value: int, schema: str = "public") -> str:
    """Set a sequence's current value (setval) — e.g. to resync after bulk import."""
    return _write("SELECT setval(%s, %s) AS new_value",
                  [f'"{schema}"."{name}"', value])


@mcp.tool()
def drop_sequence(name: str, schema: str = "public", cascade: bool = False) -> str:
    """Drop a sequence."""
    stmt = sql.SQL("DROP SEQUENCE IF EXISTS {}").format(_ident(schema, name))
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


@mcp.tool()
def list_enum_types(schema: str = "public") -> str:
    """List enum types and their allowed values."""
    q = """
    SELECT t.typname AS name,
           array_agg(e.enumlabel ORDER BY e.enumsortorder) AS values
    FROM pg_type t
    JOIN pg_enum e ON e.enumtypid = t.oid
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = %s GROUP BY t.typname ORDER BY t.typname
    """
    return _query(q, [schema])


@mcp.tool()
def create_enum_type(name: str, values: list[str], schema: str = "public") -> str:
    """Create an enum type with the given ordered values."""
    if err := _require(bool(values), "values list is empty"):
        return err
    stmt = sql.SQL("CREATE TYPE {} AS ENUM ({})").format(
        _ident(schema, name), sql.SQL(", ").join(sql.Literal(v) for v in values))
    return _write(stmt)


@mcp.tool()
def add_enum_value(type_name: str, value: str, schema: str = "public",
                   before: Optional[str] = None, after: Optional[str] = None) -> str:
    """Append a new value to an existing enum type (optionally positioned BEFORE or
    AFTER an existing value)."""
    stmt = sql.SQL("ALTER TYPE {} ADD VALUE IF NOT EXISTS {}").format(
        _ident(schema, type_name), sql.Literal(value))
    if before:
        stmt += sql.SQL(" BEFORE {}").format(sql.Literal(before))
    elif after:
        stmt += sql.SQL(" AFTER {}").format(sql.Literal(after))
    return _admin(stmt)   # ALTER TYPE ADD VALUE cannot run inside a transaction (< PG12 semantics; safe everywhere)


# ==========================================================================
# 9. TABLE DDL
# ==========================================================================

@mcp.tool()
def create_table(table: str, columns: list[dict], schema: str = "public",
                 primary_key: Optional[list[str]] = None,
                 if_not_exists: bool = True) -> str:
    """Create a table. columns is a list of objects:
    {"name": "id", "type": "bigserial", "nullable": false, "default": "now()",
     "primary_key": true, "unique": false, "references": "other_table(id)"}.
    Only name and type are required. Composite PKs go in the primary_key list."""
    if err := _require(bool(columns), "columns list is empty"):
        return err
    try:
        col_defs = []
        inline_pk = []
        for c in columns:
            name, ctype = c.get("name"), c.get("type")
            if not name or not ctype:
                return json.dumps({"error": f"column entry missing name/type: {c}"})
            if not re.fullmatch(r"[A-Za-z0-9_ \[\]().,]+", ctype):
                return json.dumps({"error": f"suspicious column type: {ctype!r}"})
            d = sql.SQL("{} ").format(_ident(name)) + sql.SQL(ctype)
            if c.get("nullable") is False:
                d += sql.SQL(" NOT NULL")
            if c.get("default") is not None:
                d += sql.SQL(" DEFAULT ") + sql.SQL(str(c["default"]))
            if c.get("unique"):
                d += sql.SQL(" UNIQUE")
            if c.get("references"):
                d += sql.SQL(" REFERENCES ") + sql.SQL(str(c["references"]))
            if c.get("primary_key"):
                inline_pk.append(name)
            col_defs.append(d)
        pk = primary_key or inline_pk
        if pk:
            col_defs.append(sql.SQL("PRIMARY KEY ({})").format(_cols(pk)))
        stmt = sql.SQL("CREATE TABLE {ine}{tbl} ({cols})").format(
            ine=sql.SQL("IF NOT EXISTS ") if if_not_exists else sql.SQL(""),
            tbl=_table_ref(table, schema),
            cols=sql.SQL(", ").join(col_defs))
        return _write(stmt)
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


@mcp.tool()
def drop_table(table: str, schema: str = "public", cascade: bool = False,
               if_exists: bool = True) -> str:
    """Drop a table. cascade=true also drops dependent objects (DESTRUCTIVE)."""
    stmt = sql.SQL("DROP TABLE {ie}{tbl}").format(
        ie=sql.SQL("IF EXISTS ") if if_exists else sql.SQL(""),
        tbl=_table_ref(table, schema))
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


@mcp.tool()
def rename_table(table: str, new_name: str, schema: str = "public") -> str:
    """Rename a table within its schema."""
    return _write(sql.SQL("ALTER TABLE {} RENAME TO {}").format(
        _table_ref(table, schema), _ident(new_name)))


@mcp.tool()
def add_column(table: str, column: str, type: str, schema: str = "public",
               nullable: bool = True, default: Optional[str] = None) -> str:
    """Add a column to a table. default is a SQL expression (e.g. "0", "''", "now()")."""
    if not re.fullmatch(r"[A-Za-z0-9_ \[\]().,]+", type):
        return json.dumps({"error": f"suspicious column type: {type!r}"})
    stmt = sql.SQL("ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} ").format(
        _table_ref(table, schema), _ident(column)) + sql.SQL(type)
    if default is not None:
        stmt += sql.SQL(" DEFAULT ") + sql.SQL(default)
    if not nullable:
        stmt += sql.SQL(" NOT NULL")
    return _write(stmt)


@mcp.tool()
def drop_column(table: str, column: str, schema: str = "public",
                cascade: bool = False) -> str:
    """Drop a column from a table (DESTRUCTIVE — data in the column is lost)."""
    stmt = sql.SQL("ALTER TABLE {} DROP COLUMN IF EXISTS {}").format(
        _table_ref(table, schema), _ident(column))
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


@mcp.tool()
def rename_column(table: str, column: str, new_name: str,
                  schema: str = "public") -> str:
    """Rename a column."""
    return _write(sql.SQL("ALTER TABLE {} RENAME COLUMN {} TO {}").format(
        _table_ref(table, schema), _ident(column), _ident(new_name)))


@mcp.tool()
def alter_column(table: str, column: str, schema: str = "public",
                 new_type: Optional[str] = None, using: Optional[str] = None,
                 set_default: Optional[str] = None, drop_default: bool = False,
                 set_not_null: bool = False, drop_not_null: bool = False) -> str:
    """Alter a column: change type (with optional USING cast expression), set/drop
    DEFAULT, set/drop NOT NULL. Multiple changes apply atomically."""
    actions = []
    tbl, col = _table_ref(table, schema), _ident(column)
    if new_type:
        if not re.fullmatch(r"[A-Za-z0-9_ \[\]().,]+", new_type):
            return json.dumps({"error": f"suspicious column type: {new_type!r}"})
        a = sql.SQL("ALTER COLUMN {} TYPE ").format(col) + sql.SQL(new_type)
        if using:
            a += sql.SQL(" USING ") + sql.SQL(using)
        actions.append(a)
    if set_default is not None:
        actions.append(sql.SQL("ALTER COLUMN {} SET DEFAULT ").format(col)
                       + sql.SQL(set_default))
    if drop_default:
        actions.append(sql.SQL("ALTER COLUMN {} DROP DEFAULT").format(col))
    if set_not_null:
        actions.append(sql.SQL("ALTER COLUMN {} SET NOT NULL").format(col))
    if drop_not_null:
        actions.append(sql.SQL("ALTER COLUMN {} DROP NOT NULL").format(col))
    if err := _require(bool(actions), "no alteration specified"):
        return err
    stmt = sql.SQL("ALTER TABLE {} ").format(tbl) + sql.SQL(", ").join(actions)
    return _write(stmt)


@mcp.tool()
def set_comment(object_type: str, name: str, comment: Optional[str],
                schema: str = "public", column: Optional[str] = None) -> str:
    """Set (or clear, with comment=null) a comment on a table, column, view, index or
    schema. object_type: table|column|view|index|schema. For columns pass the table as
    name and the column name in the column param."""
    types = {"table": "TABLE", "view": "VIEW", "index": "INDEX", "schema": "SCHEMA",
             "column": "COLUMN"}
    if err := _require(object_type in types,
                       "object_type must be table|column|view|index|schema"):
        return err
    if object_type == "column":
        if err := _require(bool(column), "column parameter required"):
            return err
        target = sql.SQL("COLUMN {}.{}").format(_table_ref(name, schema), _ident(column))
    elif object_type == "schema":
        target = sql.SQL("SCHEMA {}").format(_ident(name))
    else:
        target = sql.SQL(types[object_type] + " ") + _ident(schema, name)
    stmt = sql.SQL("COMMENT ON ") + target + sql.SQL(" IS {}").format(
        sql.Literal(comment) if comment is not None else sql.SQL("NULL"))
    return _write(stmt)


# ==========================================================================
# 10. ROW OPERATIONS
# ==========================================================================

@mcp.tool()
def select_rows(table: str, schema: str = "public",
                columns: Optional[list[str]] = None, where: Optional[str] = None,
                where_params: Optional[list] = None, order_by: Optional[str] = None,
                descending: bool = False, limit: Optional[int] = None,
                offset: int = 0) -> str:
    """Read rows from a table. where is a SQL condition with %s placeholders bound from
    where_params (e.g. where="status = %s AND age > %s", where_params=["active", 30]).
    order_by is a column name."""
    stmt = sql.SQL("SELECT {cols} FROM {tbl}").format(
        cols=_cols(columns) if columns else sql.SQL("*"),
        tbl=_table_ref(table, schema))
    params: list = []
    if where:
        stmt += sql.SQL(" WHERE ") + sql.SQL(where)
        params.extend(where_params or [])
    if order_by:
        stmt += sql.SQL(" ORDER BY {}{}").format(
            _ident(order_by), sql.SQL(" DESC") if descending else sql.SQL(""))
    lim = _clamp_limit(limit)
    stmt += sql.SQL(" LIMIT {} OFFSET {}").format(sql.Literal(lim + 1),
                                                  sql.Literal(max(0, offset)))
    return _query(stmt, params, lim)


@mcp.tool()
def count_rows(table: str, schema: str = "public", where: Optional[str] = None,
               where_params: Optional[list] = None) -> str:
    """Exact row count for a table, optionally filtered by a WHERE condition."""
    stmt = sql.SQL("SELECT count(*) AS count FROM {}").format(_table_ref(table, schema))
    params: list = []
    if where:
        stmt += sql.SQL(" WHERE ") + sql.SQL(where)
        params.extend(where_params or [])
    return _query(stmt, params)


@mcp.tool()
def insert_row(table: str, data: dict, schema: str = "public",
               returning: Optional[list[str]] = None) -> str:
    """Insert one row. data maps column names to values (JSON types map to SQL types;
    nested objects/arrays are sent as JSON). returning lists columns to return, e.g.
    ["id"] — defaults to all columns of the new row."""
    if err := _require(bool(data), "data is empty"):
        return err
    cols = list(data.keys())
    vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in data.values()]
    stmt = sql.SQL("INSERT INTO {tbl} ({cols}) VALUES ({ph}) RETURNING {ret}").format(
        tbl=_table_ref(table, schema), cols=_cols(cols),
        ph=sql.SQL(", ").join(sql.Placeholder() for _ in cols),
        ret=_cols(returning) if returning else sql.SQL("*"))
    return _write(stmt, vals)


@mcp.tool()
def insert_rows(table: str, rows: list[dict], schema: str = "public") -> str:
    """Bulk-insert many rows in one atomic transaction. All rows must share the same
    keys as the first row (missing keys become NULL). Returns the inserted count."""
    if err := _require(bool(rows), "rows list is empty"):
        return err
    cols = list(rows[0].keys())
    stmt = sql.SQL("INSERT INTO {tbl} ({cols}) VALUES ({ph})").format(
        tbl=_table_ref(table, schema), cols=_cols(cols),
        ph=sql.SQL(", ").join(sql.Placeholder() for _ in cols))
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.executemany(stmt, [
                [json.dumps(r.get(c)) if isinstance(r.get(c), (dict, list)) else r.get(c)
                 for c in cols] for r in rows])
            conn.commit()
        return _dumps({"status": "committed", "rows_inserted": len(rows)})
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


@mcp.tool()
def update_rows(table: str, data: dict, where: str,
                where_params: Optional[list] = None, schema: str = "public",
                returning: Optional[list[str]] = None) -> str:
    """Update rows matching a REQUIRED where condition. data maps columns to new values.
    Example: data={"status": "closed"}, where="id = %s", where_params=[42].
    Returns rows_affected (and RETURNING columns if requested)."""
    if err := _require(bool(data), "data is empty"):
        return err
    if err := _require(bool(where and where.strip()),
                       "where is required — full-table updates must use execute_write explicitly"):
        return err
    cols = list(data.keys())
    vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in data.values()]
    stmt = sql.SQL("UPDATE {tbl} SET {sets} WHERE ").format(
        tbl=_table_ref(table, schema),
        sets=sql.SQL(", ").join(
            sql.SQL("{} = {}").format(_ident(c), sql.Placeholder()) for c in cols),
    ) + sql.SQL(where)
    if returning:
        stmt += sql.SQL(" RETURNING {}").format(_cols(returning))
    return _write(stmt, vals + list(where_params or []))


@mcp.tool()
def delete_rows(table: str, where: str, where_params: Optional[list] = None,
                schema: str = "public", returning: Optional[list[str]] = None) -> str:
    """Delete rows matching a REQUIRED where condition (e.g. where="id = %s",
    where_params=[42]). Full-table deletes must use truncate_table or execute_write."""
    if err := _require(bool(where and where.strip()),
                       "where is required — use truncate_table for full-table deletes"):
        return err
    stmt = sql.SQL("DELETE FROM {tbl} WHERE ").format(
        tbl=_table_ref(table, schema)) + sql.SQL(where)
    if returning:
        stmt += sql.SQL(" RETURNING {}").format(_cols(returning))
    return _write(stmt, list(where_params or []))


@mcp.tool()
def upsert_row(table: str, data: dict, conflict_columns: list[str],
               schema: str = "public", update_columns: Optional[list[str]] = None) -> str:
    """Insert a row, or on conflict with conflict_columns update it instead
    (INSERT ... ON CONFLICT DO UPDATE). update_columns limits which columns are
    overwritten on conflict (default: all non-conflict columns)."""
    if err := _require(bool(data), "data is empty"):
        return err
    if err := _require(bool(conflict_columns), "conflict_columns is empty"):
        return err
    cols = list(data.keys())
    vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in data.values()]
    upd = update_columns or [c for c in cols if c not in conflict_columns]
    if err := _require(bool(upd), "no columns left to update on conflict"):
        return err
    stmt = sql.SQL(
        "INSERT INTO {tbl} ({cols}) VALUES ({ph}) "
        "ON CONFLICT ({conf}) DO UPDATE SET {sets} RETURNING *").format(
        tbl=_table_ref(table, schema), cols=_cols(cols),
        ph=sql.SQL(", ").join(sql.Placeholder() for _ in cols),
        conf=_cols(conflict_columns),
        sets=sql.SQL(", ").join(
            sql.SQL("{c} = EXCLUDED.{c}").format(c=_ident(c)) for c in upd))
    return _write(stmt, vals)


@mcp.tool()
def truncate_table(table: str, schema: str = "public", cascade: bool = False,
                   restart_identity: bool = False) -> str:
    """Remove ALL rows from a table (DESTRUCTIVE). restart_identity=true resets its
    sequences; cascade=true also truncates tables with FKs pointing here."""
    stmt = sql.SQL("TRUNCATE TABLE {}").format(_table_ref(table, schema))
    if restart_identity:
        stmt += sql.SQL(" RESTART IDENTITY")
    if cascade:
        stmt += sql.SQL(" CASCADE")
    return _write(stmt)


@mcp.tool()
def distinct_values(table: str, column: str, schema: str = "public",
                    limit: int = 100) -> str:
    """Distinct values of a column with their frequencies (most common first)."""
    stmt = sql.SQL(
        "SELECT {col} AS value, count(*) AS frequency FROM {tbl} "
        "GROUP BY {col} ORDER BY count(*) DESC").format(
        col=_ident(column), tbl=_table_ref(table, schema))
    return _query(stmt, None, limit)


@mcp.tool()
def column_stats(table: str, column: str, schema: str = "public") -> str:
    """Statistics for one column: nulls, distinct count, min/max, and avg/stddev for
    numeric columns."""
    tbl, col = _table_ref(table, schema), _ident(column)
    base = sql.SQL("""
        SELECT count(*) AS total_rows,
               count({col}) AS non_null,
               count(*) - count({col}) AS nulls,
               count(DISTINCT {col}) AS distinct_values,
               min({col})::text AS min, max({col})::text AS max
        FROM {tbl}""").format(col=col, tbl=tbl)
    try:
        with _connect(readonly=True) as conn, conn.cursor() as cur:
            cur.execute(base)
            stats = cur.fetchone()
            cur.execute("""
                SELECT atttypid::regtype::text AS type FROM pg_attribute
                WHERE attrelid = format('%%I.%%I', %s::text, %s::text)::regclass
                  AND attname = %s""", [schema, table, column])
            trow = cur.fetchone()
            if trow and any(k in trow["type"] for k in
                            ("int", "numeric", "real", "double", "float")):
                cur.execute(sql.SQL(
                    "SELECT round(avg({col})::numeric, 4) AS avg, "
                    "round(stddev({col})::numeric, 4) AS stddev FROM {tbl}").format(
                    col=col, tbl=tbl))
                stats.update(cur.fetchone())
            stats["type"] = trow["type"] if trow else None
        return _dumps(stats)
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


# ==========================================================================
# 11. MAINTENANCE
# ==========================================================================

@mcp.tool()
def vacuum_table(table: Optional[str] = None, schema: str = "public",
                 full: bool = False, analyze: bool = True) -> str:
    """VACUUM a table (or the whole database if table omitted). full=true rewrites the
    table and reclaims maximum space but takes an exclusive lock."""
    opts = []
    if full:
        opts.append("FULL")
    if analyze:
        opts.append("ANALYZE")
    stmt = sql.SQL("VACUUM")
    if opts:
        stmt += sql.SQL(" (" + ", ".join(opts) + ")")
    if table:
        stmt += sql.SQL(" ") + _table_ref(table, schema)
    return _admin(stmt)


@mcp.tool()
def analyze_table(table: Optional[str] = None, schema: str = "public") -> str:
    """Refresh planner statistics for a table (or the whole database if omitted)."""
    stmt = sql.SQL("ANALYZE")
    if table:
        stmt += sql.SQL(" ") + _table_ref(table, schema)
    return _admin(stmt)


# ==========================================================================
# 12. MONITORING & SESSIONS
# ==========================================================================

@mcp.tool()
def list_activity(state: Optional[str] = None, limit: int = 100) -> str:
    """Current connections/queries from pg_stat_activity. Filter by state:
    active|idle|'idle in transaction'. Shows pid, user, database, client, state,
    duration and the query text."""
    q = """
    SELECT pid, usename AS user, datname AS database, client_addr::text AS client,
           application_name, state, wait_event_type, wait_event,
           now() - backend_start AS connection_age,
           now() - query_start AS query_duration,
           left(query, 500) AS query
    FROM pg_stat_activity
    WHERE pid <> pg_backend_pid() AND (%s::text IS NULL OR state = %s)
    ORDER BY query_start ASC NULLS LAST
    """
    return _query(q, [state, state], limit)


@mcp.tool()
def long_running_queries(min_seconds: int = 60) -> str:
    """Queries that have been running longer than min_seconds — candidates for
    investigation or cancellation."""
    q = """
    SELECT pid, usename AS user, datname AS database, state,
           now() - query_start AS duration, left(query, 500) AS query
    FROM pg_stat_activity
    WHERE state = 'active' AND pid <> pg_backend_pid()
      AND now() - query_start > make_interval(secs => %s)
    ORDER BY query_start ASC
    """
    return _query(q, [min_seconds])


@mcp.tool()
def cancel_backend(pid: int) -> str:
    """Cancel the running query of a backend (pg_cancel_backend) — the connection
    survives, only the current query stops."""
    return _query("SELECT pg_cancel_backend(%s) AS cancelled", [pid], readonly=False)


@mcp.tool()
def terminate_backend(pid: int) -> str:
    """Kill a backend connection entirely (pg_terminate_backend). Requires
    POSTGRES_ALLOW_DANGEROUS=1."""
    if err := _require(ALLOW_DANGEROUS,
                       "terminate_backend disabled (set POSTGRES_ALLOW_DANGEROUS=1)"):
        return err
    return _query("SELECT pg_terminate_backend(%s) AS terminated", [pid],
                  readonly=False)


@mcp.tool()
def list_locks(granted_only: bool = False) -> str:
    """Current locks with the holding/waiting session and query."""
    q = """
    SELECT l.pid, l.locktype, l.mode, l.granted,
           coalesce(c.relname, l.locktype) AS object,
           a.usename AS user, a.state, left(a.query, 300) AS query
    FROM pg_locks l
    LEFT JOIN pg_class c ON c.oid = l.relation
    LEFT JOIN pg_stat_activity a ON a.pid = l.pid
    WHERE l.pid <> pg_backend_pid() AND (NOT %s OR l.granted)
    ORDER BY l.granted, l.pid
    """
    return _query(q, [granted_only])


@mcp.tool()
def blocking_queries() -> str:
    """Blocked sessions paired with the sessions blocking them — resolves lock waits
    fast (who is blocking whom, both query texts)."""
    q = """
    SELECT blocked.pid AS blocked_pid, blocked.usename AS blocked_user,
           now() - blocked.query_start AS blocked_for,
           left(blocked.query, 300) AS blocked_query,
           blocking.pid AS blocking_pid, blocking.usename AS blocking_user,
           blocking.state AS blocking_state, left(blocking.query, 300) AS blocking_query
    FROM pg_stat_activity blocked
    JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS bp(pid) ON true
    JOIN pg_stat_activity blocking ON blocking.pid = bp.pid
    """
    return _query(q)


@mcp.tool()
def cache_hit_ratio() -> str:
    """Buffer-cache hit ratios for tables and indexes (database-wide). Healthy OLTP
    systems are typically > 0.99."""
    q = """
    SELECT 'tables' AS kind,
           round(sum(heap_blks_hit)::numeric /
                 nullif(sum(heap_blks_hit) + sum(heap_blks_read), 0), 4) AS hit_ratio
    FROM pg_statio_user_tables
    UNION ALL
    SELECT 'indexes',
           round(sum(idx_blks_hit)::numeric /
                 nullif(sum(idx_blks_hit) + sum(idx_blks_read), 0), 4)
    FROM pg_statio_user_indexes
    """
    return _query(q)


@mcp.tool()
def replication_status() -> str:
    """Streaming-replication status (pg_stat_replication) plus whether this node is a
    replica (pg_is_in_recovery)."""
    try:
        with _connect(readonly=True) as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_is_in_recovery() AS is_replica")
            info = cur.fetchone()
            cur.execute("""
                SELECT client_addr::text, usename AS user, state, sync_state,
                       sent_lsn::text, replay_lsn::text,
                       replay_lag::text FROM pg_stat_replication""")
            info["replicas"] = cur.fetchall()
        return _dumps(info)
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


@mcp.tool()
def show_settings(pattern: Optional[str] = None, limit: int = 200) -> str:
    """Server configuration (pg_settings). pattern filters by name substring, e.g.
    'timeout', 'wal', 'memory'."""
    q = """
    SELECT name, setting, unit, category, short_desc, context, source
    FROM pg_settings
    WHERE %s::text IS NULL OR name ILIKE '%%' || %s || '%%'
    ORDER BY name
    """
    return _query(q, [pattern, pattern], limit)


# ==========================================================================
# 13. ROLES & PRIVILEGES
# ==========================================================================

@mcp.tool()
def list_roles() -> str:
    """List roles with login/superuser/createdb/createrole flags, membership, and
    connection limits."""
    q = """
    SELECT r.rolname AS role, r.rolsuper AS superuser, r.rolcanlogin AS can_login,
           r.rolcreatedb AS create_db, r.rolcreaterole AS create_role,
           r.rolreplication AS replication, r.rolconnlimit AS connection_limit,
           r.rolvaliduntil AS valid_until,
           ARRAY(SELECT b.rolname FROM pg_auth_members m
                 JOIN pg_roles b ON m.roleid = b.oid
                 WHERE m.member = r.oid) AS member_of
    FROM pg_roles r WHERE r.rolname NOT LIKE 'pg\\_%%' ORDER BY r.rolname
    """
    return _query(q)


@mcp.tool()
def create_role(name: str, login: bool = True, password: Optional[str] = None,
                superuser: bool = False, createdb: bool = False,
                createrole: bool = False, connection_limit: Optional[int] = None,
                in_role: Optional[str] = None) -> str:
    """Create a role/user. Password is transmitted as a bound literal, never logged.
    in_role grants membership in an existing role."""
    stmt = sql.SQL("CREATE ROLE {}").format(_ident(name))
    stmt += sql.SQL(" LOGIN") if login else sql.SQL(" NOLOGIN")
    if superuser:
        stmt += sql.SQL(" SUPERUSER")
    if createdb:
        stmt += sql.SQL(" CREATEDB")
    if createrole:
        stmt += sql.SQL(" CREATEROLE")
    if password:
        stmt += sql.SQL(" PASSWORD {}").format(sql.Literal(password))
    if connection_limit is not None:
        stmt += sql.SQL(" CONNECTION LIMIT {}").format(sql.Literal(connection_limit))
    if in_role:
        stmt += sql.SQL(" IN ROLE {}").format(_ident(in_role))
    return _write(stmt)


@mcp.tool()
def alter_role(name: str, password: Optional[str] = None,
               login: Optional[bool] = None, connection_limit: Optional[int] = None,
               valid_until: Optional[str] = None) -> str:
    """Alter a role: change password, login ability, connection limit, or password
    expiry (valid_until, ISO date)."""
    opts = []
    if password is not None:
        opts.append(sql.SQL("PASSWORD {}").format(sql.Literal(password)))
    if login is not None:
        opts.append(sql.SQL("LOGIN") if login else sql.SQL("NOLOGIN"))
    if connection_limit is not None:
        opts.append(sql.SQL("CONNECTION LIMIT {}").format(sql.Literal(connection_limit)))
    if valid_until is not None:
        opts.append(sql.SQL("VALID UNTIL {}").format(sql.Literal(valid_until)))
    if err := _require(bool(opts), "no alteration specified"):
        return err
    stmt = sql.SQL("ALTER ROLE {} ").format(_ident(name)) + sql.SQL(" ").join(opts)
    return _write(stmt)


@mcp.tool()
def drop_role(name: str) -> str:
    """Drop a role (fails if it still owns objects — reassign or drop those first)."""
    return _write(sql.SQL("DROP ROLE IF EXISTS {}").format(_ident(name)))


@mcp.tool()
def grant_privileges(role: str, privileges: list[str], table: Optional[str] = None,
                     schema: str = "public", all_tables_in_schema: bool = False) -> str:
    """GRANT privileges (SELECT/INSERT/UPDATE/DELETE/ALL/...) on a table — or on all
    tables in a schema with all_tables_in_schema=true — to a role."""
    privs = [p.upper().strip() for p in privileges]
    bad = [p for p in privs if p not in _VALID_PRIVILEGES]
    if err := _require(not bad, f"invalid privileges: {bad}"):
        return err
    if err := _require(bool(table) or all_tables_in_schema,
                       "give a table or set all_tables_in_schema=true"):
        return err
    target = sql.SQL("ALL TABLES IN SCHEMA {}").format(_ident(schema)) \
        if all_tables_in_schema else _table_ref(table, schema)
    stmt = sql.SQL("GRANT " + ", ".join(privs) + " ON ") + target + \
        sql.SQL(" TO {}").format(_ident(role))
    return _write(stmt)


@mcp.tool()
def revoke_privileges(role: str, privileges: list[str], table: Optional[str] = None,
                      schema: str = "public", all_tables_in_schema: bool = False) -> str:
    """REVOKE privileges on a table (or all tables in a schema) from a role."""
    privs = [p.upper().strip() for p in privileges]
    bad = [p for p in privs if p not in _VALID_PRIVILEGES]
    if err := _require(not bad, f"invalid privileges: {bad}"):
        return err
    if err := _require(bool(table) or all_tables_in_schema,
                       "give a table or set all_tables_in_schema=true"):
        return err
    target = sql.SQL("ALL TABLES IN SCHEMA {}").format(_ident(schema)) \
        if all_tables_in_schema else _table_ref(table, schema)
    stmt = sql.SQL("REVOKE " + ", ".join(privs) + " ON ") + target + \
        sql.SQL(" FROM {}").format(_ident(role))
    return _write(stmt)


@mcp.tool()
def list_table_privileges(table: str, schema: str = "public") -> str:
    """Show who holds which privileges on a table."""
    q = """
    SELECT grantee, string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges,
           bool_or(is_grantable = 'YES') AS grantable
    FROM information_schema.table_privileges
    WHERE table_schema = %s AND table_name = %s
    GROUP BY grantee ORDER BY grantee
    """
    return _query(q, [schema, table])


# ==========================================================================
# 14. CSV IMPORT / EXPORT
# ==========================================================================

def _copy_out(inner: sql.Composable, delimiter: str, header: bool) -> str:
    if err := _require(len(delimiter) == 1, "delimiter must be a single character"):
        return err
    try:
        with _connect(readonly=True) as conn, conn.cursor() as cur:
            stmt = sql.SQL("COPY ({q}) TO STDOUT WITH (FORMAT csv, HEADER {h}, DELIMITER {d})").format(
                q=inner, h=sql.SQL("true" if header else "false"),
                d=sql.Literal(delimiter))
            chunks: list[bytes] = []
            total = 0
            truncated = False
            with cur.copy(stmt) as copy:
                for chunk in copy:
                    total += len(chunk)
                    if total > MAX_RESULT_BYTES:
                        truncated = True
                        break
                    chunks.append(bytes(chunk))
            csv_text = b"".join(chunks).decode("utf-8", "replace")
        return _dumps({"csv": csv_text, "bytes": len(csv_text), "truncated": truncated})
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


@mcp.tool()
def export_query_csv(query: str, delimiter: str = ",", header: bool = True) -> str:
    """Run a read-only query and return the result as CSV text (COPY TO). Capped at
    1 MB of output."""
    return _copy_out(sql.SQL(query), delimiter, header)


@mcp.tool()
def export_table_csv(table: str, schema: str = "public", delimiter: str = ",",
                     header: bool = True, limit: Optional[int] = None) -> str:
    """Export a table as CSV text (optionally row-limited). Capped at 1 MB."""
    lim = _clamp_limit(limit) if limit else HARD_MAX_ROWS
    inner = sql.SQL("SELECT * FROM {} LIMIT {}").format(
        _table_ref(table, schema), sql.Literal(lim))
    return _copy_out(inner, delimiter, header)


@mcp.tool()
def import_csv(table: str, csv_data: str, schema: str = "public",
               delimiter: str = ",", header: bool = True,
               columns: Optional[list[str]] = None) -> str:
    """Load CSV text into an existing table via COPY FROM (fast bulk path, atomic).
    header=true skips the first line; columns restricts/orders the target columns."""
    if err := _require(bool(csv_data.strip()), "csv_data is empty"):
        return err
    if err := _require(len(delimiter) == 1, "delimiter must be a single character"):
        return err
    try:
        with _connect() as conn, conn.cursor() as cur:
            col_part = sql.SQL(" ({})").format(_cols(columns)) if columns else sql.SQL("")
            stmt = sql.SQL("COPY {tbl}{cols} FROM STDIN WITH (FORMAT csv, HEADER {h}, DELIMITER {d})").format(
                tbl=_table_ref(table, schema), cols=col_part,
                h=sql.SQL("true" if header else "false"), d=sql.Literal(delimiter))
            with cur.copy(stmt) as copy:
                copy.write(csv_data)
            rows = cur.rowcount
            conn.commit()
        return _dumps({"status": "committed", "rows_imported": rows})
    except Exception as e:                                    # noqa: BLE001
        return _err(e)


# ==========================================================================
# resources & prompts
# ==========================================================================

@mcp.resource("postgres://schema")
def schema_resource() -> str:
    """Readable resource: compact overview of all user schemas, tables and columns."""
    q = """
    SELECT table_schema, table_name,
           string_agg(column_name || ' ' || data_type, ', '
                      ORDER BY ordinal_position) AS columns
    FROM information_schema.columns
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
    GROUP BY table_schema, table_name ORDER BY table_schema, table_name
    """
    return _query(q, limit=1000)


@mcp.prompt()
def analyze_slow_query(query: str) -> str:
    """Prompt template: investigate why a query is slow and how to fix it."""
    return (f"Analyze this PostgreSQL query for performance problems:\n\n{query}\n\n"
            "1. Run explain_query with analyze=false first; only use analyze=true if "
            "the query is read-only.\n2. Check list_indexes on the tables involved.\n"
            "3. Check table_stats for dead-tuple bloat and stale statistics.\n"
            "4. Recommend concrete fixes: indexes, rewrites, or maintenance.")


if __name__ == "__main__":
    mcp.run()  # stdio
