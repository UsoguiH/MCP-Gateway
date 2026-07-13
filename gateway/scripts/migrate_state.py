"""One-shot state migration: flat files -> gwstate PostgreSQL (Phase 3, task 1).

Moves every durable store from DATA_DIR JSON/JSONL files into the shared gwstate
database, verifying the audit hash chain BEFORE and AFTER — a migration that
cannot prove the chain survived did not happen. Runtime state (sessions, rate
windows, breaker, taint, lockouts) deliberately does NOT migrate: it is
re-establishable by design.

The tool refuses to run against a non-empty target unless --wipe is given, so a
half-migrated database can never be silently double-loaded. Rollback is a full
export back to flat files (--rollback [--out DIR]) that reproduces a verifiable
audit JSONL — unset MCP_STATE_DB_URL afterwards and the gateway runs on files
again, no data lost.

Usage (from gateway/):
    # forward: files -> DB (the gateway should be stopped or in maintenance)
    MCP_STATE_DB_URL=postgresql://gwstate:...@host:5432/gwstate \
        python scripts/migrate_state.py

    # verify only (no writes): compare file chain vs DB chain + row counts
    python scripts/migrate_state.py --verify

    # rollback: DB -> flat files (writes into --out, default DATA_DIR)
    python scripts/migrate_state.py --rollback --out data.exported
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import statestore  # noqa: E402
from app.config import DATA_DIR  # noqa: E402

# (table, primary-key column, source file, kind)
#   kind "map":  file holds {key: record}        -> rows (key, doc)
#   kind "list": file holds [record with 'id']   -> rows (id, ts, doc)   (notifications)
#   kind "set":  file holds [key, ...]           -> rows (key)           (revoked)
#   kind "scalar-map": file holds {key: number}  -> rows (key, value)    (session_nb)
#   kind "blob-map": file holds {key: "string"}  -> rows (key, blob)     (mfa)
#   kind "kv":   whole file becomes ONE kv row
STORES = [
    ("approvals",        "approvals.json",       "approvals"),
    ("registry",         "tool_registry.json",   "registry_tools"),
    ("operators",        "operators.json",       "operators"),
    ("credentials",      "credentials.json",     "credentials"),
    ("mfa",              "mfa_secrets.json",     "mfa_secrets"),
    ("revoked",          "revoked.json",         "revoked_subjects"),
    ("session_nb",       "session_nb.json",      "session_nb"),
    ("oauth_clients",    "oauth_clients.json",   "oauth_clients"),
    ("oauth_refresh",    "oauth_refresh.json",   "oauth_refresh"),
    ("api_keys",         "api_keys.json",        "api_keys"),
    ("notifications",    "notifications.json",   "notifications"),
    ("killswitch",       "killswitch.json",      "killswitch"),
    ("drained",          "drained.json",         "drained"),
    ("settings",         "settings.json",        "settings"),
    ("servers_dynamic",  "servers_dynamic.json", "kv"),
    ("maintenance",      "maintenance.json",     "kv"),
]

DURABLE_TABLES = ["audit_log", "approvals", "approval_results", "registry_tools",
                  "operators", "credentials", "mfa_secrets", "revoked_subjects",
                  "session_nb", "oauth_clients", "oauth_refresh", "api_keys",
                  "notifications", "killswitch", "drained", "settings", "kv"]


def _read_json(name: str, default):
    p = DATA_DIR / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"  !! {name} unreadable ({e}) — treating as empty")
        return default


def _verify_file_chain() -> tuple[bool, str, int]:
    """Verify the JSONL chain directly (the gateway may be down)."""
    import hashlib
    import hmac as hmac_mod
    from app import audit
    log = DATA_DIR / "audit_log.jsonl"
    if not log.exists():
        return True, "empty log", 0
    prev, n = audit.GENESIS, 0
    key = audit._audit_key()
    with open(log, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            stored = entry.pop("hash")
            if entry["prev"] != prev:
                return False, f"broken link at line {i}", n
            payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode()
            if hmac_mod.new(key, payload, hashlib.sha256).hexdigest() != stored:
                return False, f"tampered content at line {i}", n
            prev = stored
            n += 1
    return True, f"chain intact: {n} records", n


def _db_counts() -> dict:
    return {t: statestore.one(f"SELECT count(*) FROM {t}")[0] for t in DURABLE_TABLES}


def migrate(wipe: bool):
    ok, msg, file_records = _verify_file_chain()
    print(f"[1/5] file audit chain: {msg}")
    if not ok:
        sys.exit("REFUSING to migrate a broken chain — investigate first "
                 "(a migration must never launder tampering into a fresh store).")

    counts = _db_counts()
    populated = {t: n for t, n in counts.items() if n}
    if populated and not wipe:
        sys.exit(f"REFUSING: target tables already hold rows {populated} — "
                 "run with --wipe to replace them (or point at an empty gwstate).")
    if populated and wipe:
        print(f"[2/5] wiping target tables: {sorted(populated)}")
        for t in DURABLE_TABLES:
            statestore.run(f"DELETE FROM {t}")
    else:
        print("[2/5] target is empty")

    # ---- audit chain: byte-exact rows, seq follows file order -----------------
    log = DATA_DIR / "audit_log.jsonl"
    inserted = 0
    if log.exists():
        with statestore.cx() as c, open(log, encoding="utf-8") as f, c.cursor() as cur:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                cur.execute(
                    "INSERT INTO audit_log (ts, event, usr, server, prev, hash, record) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (e.get("ts"), e.get("event", ""),
                     e.get("user") or e.get("sub") or e.get("by"),
                     e.get("server"), e["prev"], e["hash"], line))
                inserted += 1
    print(f"[3/5] audit chain: {inserted} records copied")

    # ---- the JSON stores ------------------------------------------------------
    for label, fname, table in STORES:
        n = _migrate_store(label, fname, table)
        print(f"      {label:<16} -> {table:<16} {n} row(s)")
    print("[4/5] stores migrated")

    # ---- prove the chain survived --------------------------------------------
    from app import audit
    ok, msg = audit.verify_chain()          # statestore is enabled -> walks the DB
    print(f"[5/5] DB audit chain: {msg}")
    if not ok or (file_records and f"{file_records} records" not in msg):
        sys.exit("MIGRATION FAILED VERIFICATION — the DB chain does not match the "
                 "file chain. The files are untouched; wipe the DB and retry.")
    print("\nDone. Set MCP_STATE_DB_URL on every gateway instance and restart. "
          "The flat files remain in place untouched (they are your rollback).")


def _migrate_store(label: str, fname: str, table: str) -> int:
    if table == "kv":
        doc = _read_json(fname, None)
        if doc is None:
            return 0
        statestore.run("INSERT INTO kv (name, doc, updated) VALUES (%s, %s, %s) "
                       "ON CONFLICT (name) DO UPDATE SET doc = EXCLUDED.doc",
                       (label, json.dumps(doc, ensure_ascii=False), time.time()))
        return 1
    if table == "revoked_subjects":
        subs = _read_json(fname, [])
        for s in subs:
            statestore.run("INSERT INTO revoked_subjects (sub) VALUES (%s) "
                           "ON CONFLICT DO NOTHING", (s,))
        return len(subs)
    if table == "drained":
        servers = _read_json(fname, [])
        for s in servers:
            statestore.run("INSERT INTO drained (server) VALUES (%s) "
                           "ON CONFLICT DO NOTHING", (s,))
        return len(servers)
    if table == "session_nb":
        m = _read_json(fname, {})
        for sub, nb in m.items():
            statestore.run("INSERT INTO session_nb (sub, nb) VALUES (%s, %s) "
                           "ON CONFLICT (sub) DO UPDATE SET nb = EXCLUDED.nb",
                           (sub, float(nb)))
        return len(m)
    if table == "mfa_secrets":
        m = _read_json(fname, {})
        for sub, blob in m.items():
            statestore.run("INSERT INTO mfa_secrets (sub, blob) VALUES (%s, %s) "
                           "ON CONFLICT (sub) DO UPDATE SET blob = EXCLUDED.blob",
                           (sub, blob))
        return len(m)
    if table == "notifications":
        items = _read_json(fname, [])
        for n in items:
            statestore.run(
                "INSERT INTO notifications (id, ts, key, doc) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc",
                (n.get("id"), n.get("ts") or 0, n.get("key"),
                 json.dumps(n, ensure_ascii=False)))
        return len(items)
    if table == "approvals":
        m = _read_json(fname, {})
        for aid, a in m.items():
            statestore.run(
                "INSERT INTO approvals (aid, status, requester, created, resolved_at, doc) "
                "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (aid) DO UPDATE SET "
                "status = EXCLUDED.status, resolved_at = EXCLUDED.resolved_at, "
                "doc = EXCLUDED.doc",
                (aid, a.get("status", "pending"), a.get("requester", "?"),
                 a.get("created", 0), a.get("resolved_at"),
                 json.dumps(a, ensure_ascii=False)))
        return len(m)
    # generic {key: doc} map tables
    key_col = {"registry_tools": "key", "operators": "sub", "credentials": "sub",
               "oauth_clients": "client_id", "api_keys": "kid",
               "oauth_refresh": "token_hash", "settings": "section",
               "killswitch": "scope"}[table]
    m = _read_json(fname, {})
    for key, doc in m.items():
        if table == "oauth_refresh":
            statestore.run(
                "INSERT INTO oauth_refresh (token_hash, exp, doc) VALUES (%s, %s, %s) "
                "ON CONFLICT (token_hash) DO UPDATE SET exp = EXCLUDED.exp, "
                "doc = EXCLUDED.doc",
                (key, float(doc.get("exp", 0)), json.dumps(doc, ensure_ascii=False)))
        else:
            statestore.run(
                f"INSERT INTO {table} ({key_col}, doc) VALUES (%s, %s) "
                f"ON CONFLICT ({key_col}) DO UPDATE SET doc = EXCLUDED.doc",
                (key, json.dumps(doc, ensure_ascii=False)))
    return len(m)


def rollback(out_dir: Path):
    """Export the DB back to flat files the gateway can run on (unset the URL)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    from app import audit
    ok, msg = audit.verify_chain()
    print(f"[1/3] DB audit chain: {msg}")
    if not ok:
        sys.exit("REFUSING to export a broken chain — investigate first.")

    with open(out_dir / "audit_log.jsonl", "w", encoding="utf-8") as f:
        for _seq, text in _iter_audit():
            f.write(text + "\n")
    print("[2/3] audit_log.jsonl exported")

    def dump(name: str, obj):
        (out_dir / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False),
                                    encoding="utf-8")

    dump("approvals.json", {aid: doc for aid, doc in
                            statestore.all_rows("SELECT aid, doc FROM approvals")})
    dump("tool_registry.json", {k: d for k, d in
                                statestore.all_rows("SELECT key, doc FROM registry_tools")})
    for fname, table, col in [("operators.json", "operators", "sub"),
                              ("credentials.json", "credentials", "sub"),
                              ("oauth_clients.json", "oauth_clients", "client_id"),
                              ("api_keys.json", "api_keys", "kid"),
                              ("settings.json", "settings", "section"),
                              ("killswitch.json", "killswitch", "scope"),
                              ("oauth_refresh.json", "oauth_refresh", "token_hash")]:
        dump(fname, {k: d for k, d in
                     statestore.all_rows(f"SELECT {col}, doc FROM {table}")})
    dump("mfa_secrets.json", {s: b for s, b in
                              statestore.all_rows("SELECT sub, blob FROM mfa_secrets")})
    dump("revoked.json", [r[0] for r in
                          statestore.all_rows("SELECT sub FROM revoked_subjects")])
    dump("drained.json", [r[0] for r in statestore.all_rows("SELECT server FROM drained")])
    dump("session_nb.json", {s: nb for s, nb in
                             statestore.all_rows("SELECT sub, nb FROM session_nb")})
    dump("notifications.json", [d for (d,) in statestore.all_rows(
        "SELECT doc FROM notifications ORDER BY ts")])
    for name in ("servers_dynamic", "maintenance"):
        row = statestore.one("SELECT doc FROM kv WHERE name = %s", (name,))
        if row:
            dump(f"{name}.json", row[0])
    print(f"[3/3] stores exported to {out_dir}")
    print("\nDone. Point DATA_DIR files at these (or export straight into data/), "
          "unset MCP_STATE_DB_URL, and restart — the gateway is back on flat files.")


def _iter_audit():
    with statestore.cx() as c:
        with c.transaction():                 # named cursors need a transaction block
            with c.cursor(name="rollback_walk") as cur:
                cur.itersize = 5000
                cur.execute("SELECT seq, record FROM audit_log ORDER BY seq")
                yield from cur


def verify():
    ok_f, msg_f, n_f = _verify_file_chain()
    print(f"file chain: {msg_f}")
    from app import audit
    ok_d, msg_d = audit.verify_chain()
    print(f"db chain:   {msg_d}")
    print("db rows:")
    for t, n in _db_counts().items():
        print(f"  {t:<18} {n}")
    sys.exit(0 if (ok_f and ok_d) else 1)


def main():
    global DATA_DIR
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rollback", action="store_true",
                    help="export the DB back to flat files instead of migrating")
    ap.add_argument("--verify", action="store_true",
                    help="verify both chains + show row counts; write nothing")
    ap.add_argument("--wipe", action="store_true",
                    help="allow migrating into a non-empty gwstate (deletes its rows)")
    ap.add_argument("--data-dir", default=None,
                    help="source data directory (default: gateway/data — pass the "
                         "unpacked gw-data volume when migrating a container's state)")
    ap.add_argument("--out", default=None,
                    help="rollback export directory (default: the data dir)")
    a = ap.parse_args()
    if a.data_dir:
        DATA_DIR = Path(a.data_dir)
    if a.out is None:
        a.out = str(DATA_DIR)

    if not statestore.enabled():
        sys.exit("MCP_STATE_DB_URL is not set — nothing to migrate to/from.")
    statestore.pool()            # fail fast (and create the schema) before any work

    try:
        if a.verify:
            verify()
        elif a.rollback:
            rollback(Path(a.out))
        else:
            migrate(a.wipe)
    finally:
        statestore.close()               # clean pool shutdown (no worker-thread warnings)


if __name__ == "__main__":
    main()
