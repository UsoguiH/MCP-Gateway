"""Guard: the committed ui/ bundle must match dashboard/src (Phase 2, H12).

The gateway serves `ui/` — a build artefact that is committed to the repo. Nothing forced
it to stay in step with `dashboard/src`, so it could silently drift: someone edits a page,
forgets to run `npm run build`, and the console keeps serving the OLD bundle. The code
review passes, the tests pass, and the deployed UI is simply not the one in the source tree.

This rebuilds the dashboard into a temporary directory and compares the emitted asset
filenames (Vite hashes each bundle by content, so a content change changes the name) with
what is committed. A mismatch fails CI with the exact command to fix it.

Usage:
    python scripts/check_ui_build.py          # verify (CI)
    python scripts/check_ui_build.py --fix    # rebuild in place
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"
UI = ROOT / "ui"


def _asset_names(index_html: Path) -> set[str]:
    """The hashed asset files the page actually loads. Vite names them by content hash, so
    this set changes whenever the built code changes."""
    html = index_html.read_text(encoding="utf-8")
    return set(re.findall(r'/ui/assets/([A-Za-z0-9._\-]+\.(?:js|css))', html))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fix", action="store_true", help="rebuild the committed bundle in place")
    args = ap.parse_args()

    if not (DASHBOARD / "package.json").exists():
        print("dashboard/ not found — nothing to check")
        return 0

    if args.fix:
        subprocess.run(["npm", "run", "build"], cwd=DASHBOARD, check=True, shell=True)
        print("rebuilt ui/ from dashboard/src")
        return 0

    committed_index = UI / "index.html"
    if not committed_index.exists():
        print("FAIL: ui/index.html is missing — the console has no bundle to serve.\n"
              "      Run: cd dashboard && npm run build", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "ui"
        r = subprocess.run(
            ["npm", "run", "build", "--", "--outDir", str(out), "--emptyOutDir"],
            cwd=DASHBOARD, capture_output=True, text=True, shell=True)
        if r.returncode != 0:
            print("FAIL: the dashboard does not build.\n" + (r.stderr or r.stdout)[-1500:],
                  file=sys.stderr)
            return 1

        fresh_index = out / "index.html"
        if not fresh_index.exists():
            print(f"FAIL: build produced no index.html in {out}", file=sys.stderr)
            return 1

        fresh, committed = _asset_names(fresh_index), _asset_names(committed_index)

    if fresh != committed:
        print("FAIL: the committed ui/ bundle does not match dashboard/src.\n"
              "      The console would serve a build that is not the code in this repo.\n"
              f"      committed: {sorted(committed)}\n"
              f"      from src : {sorted(fresh)}\n"
              "      Fix: cd dashboard && npm run build   (then commit ui/)", file=sys.stderr)
        return 1

    print(f"ok: committed ui/ bundle matches dashboard/src ({len(committed)} assets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
