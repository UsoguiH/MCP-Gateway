"""Purge pytest artifacts from the gateway data stores (Phase 2 task 2).

The live-QA walkthrough found test debris polluting the dev stores: pytest-echo
tools pending in the registry, dozens of pytest-mcp OAuth client registrations,
pytest-key API keys, tmpXXXXXX operators, and the notification noise all of it
generates. This script sweeps every store by prefix and leaves real records
untouched.

Run it with the gateway STOPPED (the app holds in-memory copies of these stores
and would clobber the cleaned files on its next save), or as the CI teardown
step after the e2e server is shut down.

Usage:
    python scripts/purge_test_artifacts.py                 # purge gateway/data
    python scripts/purge_test_artifacts.py --dry-run       # report only
    python scripts/purge_test_artifacts.py --data-dir PATH # e.g. a test fixture
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PREFIXES = ("pytest-",)                    # matches pytest-echo, pytest-mcp, pytest-key ...
_TMP_OPERATOR = re.compile(r"^tmp[0-9a-f]{6}$")   # test_operator_lifecycle naming
_TEST_OPERATOR_NAME = "pytest"                     # operators created as "Pytest Temp"


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _save(path: Path, data, dry_run: bool):
    if not dry_run:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _is_test_name(value: str | None, prefixes) -> bool:
    v = (value or "").lower()
    return any(v.startswith(p) for p in prefixes)


def _is_test_operator(sub: str, rec: dict) -> bool:
    name = (rec.get("name") or "").lower()
    return bool(_TMP_OPERATOR.match(sub)) or name.startswith(_TEST_OPERATOR_NAME)


def purge(data_dir: Path, prefixes=PREFIXES, dry_run: bool = False) -> dict[str, list[str]]:
    """Sweep every store; returns {store: [removed identifiers]}."""
    removed: dict[str, list[str]] = {}

    # 1. tool registry — entries whose server is a test fixture
    path = data_dir / "tool_registry.json"
    reg = _load(path)
    if isinstance(reg, dict):
        dead = [k for k, e in reg.items()
                if _is_test_name(k, prefixes) or _is_test_name(e.get("server"), prefixes)]
        if dead:
            for k in dead:
                reg.pop(k)
            _save(path, reg, dry_run)
            removed["tool_registry"] = dead

    # 2. OAuth clients — and every refresh token they hold
    cpath = data_dir / "oauth_clients.json"
    clients = _load(cpath)
    dead_client_ids: set[str] = set()
    if isinstance(clients, dict):
        dead_client_ids = {cid for cid, c in clients.items()
                           if _is_test_name(c.get("client_name"), prefixes)}
        if dead_client_ids:
            for cid in dead_client_ids:
                clients.pop(cid)
            _save(cpath, clients, dry_run)
            removed["oauth_clients"] = sorted(dead_client_ids)
    rpath = data_dir / "oauth_refresh.json"
    refresh = _load(rpath)
    if isinstance(refresh, dict) and dead_client_ids:
        dead_r = [k for k, v in refresh.items() if v.get("client_id") in dead_client_ids]
        if dead_r:
            for k in dead_r:
                refresh.pop(k)
            _save(rpath, refresh, dry_run)
            removed["oauth_refresh"] = [f"{len(dead_r)} token(s)"]

    # 3. API keys
    path = data_dir / "api_keys.json"
    keys = _load(path)
    if isinstance(keys, dict):
        dead = [kid for kid, rec in keys.items() if _is_test_name(rec.get("name"), prefixes)]
        if dead:
            for kid in dead:
                keys.pop(kid)
            _save(path, keys, dry_run)
            removed["api_keys"] = dead

    # 4. operators (+ their credentials and MFA secrets)
    opath = data_dir / "operators.json"
    ops = _load(opath)
    dead_subs: list[str] = []
    if isinstance(ops, dict):
        dead_subs = [sub for sub, rec in ops.items() if _is_test_operator(sub, rec)]
        if dead_subs:
            for sub in dead_subs:
                ops.pop(sub)
            _save(opath, ops, dry_run)
            removed["operators"] = dead_subs
    for fname in ("credentials.json", "mfa_secrets.json"):
        path = data_dir / fname
        store = _load(path)
        if isinstance(store, dict):
            dead = [sub for sub in store if sub in dead_subs or _TMP_OPERATOR.match(sub)]
            if dead:
                for sub in dead:
                    store.pop(sub)
                _save(path, store, dry_run)
                removed[fname.removesuffix(".json")] = dead

    # 5. dynamically added/removed servers ({"added": [spec, ...], "removed": [name, ...]})
    path = data_dir / "servers_dynamic.json"
    dyn = _load(path)
    if isinstance(dyn, dict):
        added = dyn.get("added") or []
        dead_added = [s.get("name") for s in added
                      if isinstance(s, dict) and _is_test_name(s.get("name"), prefixes)]
        dead_removed = [n for n in (dyn.get("removed") or []) if _is_test_name(n, prefixes)]
        if dead_added or dead_removed:
            dyn["added"] = [s for s in added
                            if not (isinstance(s, dict) and _is_test_name(s.get("name"), prefixes))]
            dyn["removed"] = [n for n in (dyn.get("removed") or []) if n not in dead_removed]
            _save(path, dyn, dry_run)
            removed["servers_dynamic"] = dead_added + dead_removed

    # 6. notifications that reference any test artifact
    path = data_dir / "notifications.json"
    notifs = _load(path)
    if isinstance(notifs, list):
        needles = [p.rstrip("-") for p in prefixes] + dead_subs
        def _noisy(n: dict) -> bool:
            hay = " ".join(str(n.get(f, "")) for f in ("title", "detail", "key")).lower()
            return any(needle in hay for needle in needles)
        keep = [n for n in notifs if not _noisy(n)]
        if len(keep) != len(notifs):
            _save(path, keep, dry_run)
            removed["notifications"] = [f"{len(notifs) - len(keep)} notification(s)"]

    return removed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", default=str(Path(__file__).resolve().parents[1] / "data"))
    ap.add_argument("--prefix", action="append", default=None,
                    help="artifact name prefix (repeatable; default: pytest-)")
    ap.add_argument("--dry-run", action="store_true", help="report without writing")
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.is_dir():
        print(f"data dir not found: {data_dir}", file=sys.stderr)
        return 2
    prefixes = tuple(p.lower() for p in (args.prefix or PREFIXES))

    removed = purge(data_dir, prefixes, dry_run=args.dry_run)
    verb = "would remove" if args.dry_run else "removed"
    if not removed:
        print("clean — no test artifacts found")
    for store, items in removed.items():
        print(f"{store}: {verb} {len(items)} — {', '.join(items[:8])}"
              + (" …" if len(items) > 8 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
