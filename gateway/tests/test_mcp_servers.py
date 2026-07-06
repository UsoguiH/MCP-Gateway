"""End-to-end tests for the production MCP servers (postgres-mcp, gitea-mcp).

Each server is spawned over stdio exactly the way the gateway spawns it, and
driven through a full read/write lifecycle against a REAL backend:

  postgres — needs a reachable PostgreSQL, default postgresql://postgres:mcptest@localhost:15432/mcpdb
             (docker run -d --name mcp-test-pg -e POSTGRES_PASSWORD=mcptest
              -e POSTGRES_DB=mcpdb -p 15432:5432 postgres:17)
  gitea    — needs a reachable Gitea with an admin token, default http://localhost:13000
             (docker run -d --name mcp-test-gitea
              -e GITEA__security__INSTALL_LOCK=true -p 13000:3000 gitea/gitea:1.24
              + admin user & token; see scripts in the repo history / OPERATIONS.md)

Tests SKIP (not fail) when a backend is unreachable, so the main suite stays
green on machines without Docker.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client, get_default_environment

ROOT = Path(__file__).resolve().parent.parent

PG_URL = os.environ.get("TEST_POSTGRES_URL",
                        "postgresql://postgres:mcptest@localhost:15432/mcpdb")
GITEA_URL = os.environ.get("TEST_GITEA_URL", "http://localhost:13000")
GITEA_TOKEN = os.environ.get("TEST_GITEA_TOKEN", "")


def _backend_up(probe) -> bool:
    try:
        return probe()
    except Exception:
        return False


def _pg_up() -> bool:
    import psycopg
    with psycopg.connect(PG_URL, connect_timeout=3):
        return True


def _gitea_up() -> bool:
    import httpx
    r = httpx.get(f"{GITEA_URL}/api/v1/version", timeout=3)
    return r.status_code == 200


class Server:
    """Drive one stdio MCP server synchronously from tests."""

    def __init__(self, script: str, env: dict):
        self.params = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "servers" / script)],
            env={**get_default_environment(), **env},
        )

    async def _call(self, calls):
        results = []
        async with stdio_client(self.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                results.append([t.name for t in listing.tools])
                for name, args in calls:
                    res = await session.call_tool(name, args)
                    text = "".join(c.text for c in res.content
                                   if getattr(c, "text", None))
                    try:
                        results.append(json.loads(text))
                    except (json.JSONDecodeError, ValueError):
                        results.append({"_raw": text})
        return results

    def run(self, calls):
        """Returns [tool_names, result1, result2, ...] in call order."""
        return asyncio.run(self._call(calls))


# ==========================================================================
# postgres-mcp
# ==========================================================================

@pytest.mark.skipif(not _backend_up(_pg_up), reason="no test PostgreSQL reachable")
def test_postgres_full_lifecycle():
    srv = Server("postgres_server.py", {
        "POSTGRES_URL": PG_URL,
        "POSTGRES_MAX_ROWS": "500",
    })
    S = "mcp_e2e"
    out = srv.run([
        # -- info / inspection --------------------------------------------
        ("server_info", {}),                                            # 1
        ("list_databases", {}),                                         # 2
        # -- schema + DDL ---------------------------------------------------
        ("drop_schema", {"name": S, "cascade": True}),                  # 3 clean slate
        ("create_schema", {"name": S}),                                 # 4
        ("create_table", {"schema": S, "table": "employees", "columns": [
            {"name": "id", "type": "bigserial", "primary_key": True},
            {"name": "name", "type": "text", "nullable": False},
            {"name": "email", "type": "text", "unique": True},
            {"name": "salary", "type": "numeric(10,2)", "default": "0"},
            {"name": "meta", "type": "jsonb"},
        ]}),                                                            # 5
        ("add_column", {"schema": S, "table": "employees",
                        "column": "dept", "type": "text"}),             # 6
        ("create_index", {"schema": S, "table": "employees",
                          "columns": ["dept"]}),                        # 7
        ("add_constraint", {"schema": S, "table": "employees",
                            "constraint_name": "salary_positive",
                            "definition": "CHECK (salary >= 0)"}),      # 8
        # -- writes ----------------------------------------------------------
        ("insert_row", {"schema": S, "table": "employees",
                        "data": {"name": "Ahmed", "email": "a@x.sa",
                                 "salary": 100.5, "dept": "eng",
                                 "meta": {"grade": 7}}}),               # 9
        ("insert_rows", {"schema": S, "table": "employees", "rows": [
            {"name": "Sara", "email": "s@x.sa", "salary": 200, "dept": "eng"},
            {"name": "Omar", "email": "o@x.sa", "salary": 150, "dept": "hr"},
        ]}),                                                            # 10
        ("upsert_row", {"schema": S, "table": "employees",
                        "data": {"email": "a@x.sa", "name": "Ahmed A.",
                                 "salary": 120},
                        "conflict_columns": ["email"]}),                # 11
        ("update_rows", {"schema": S, "table": "employees",
                         "data": {"salary": 300},
                         "where": "dept = %s", "where_params": ["hr"]}),  # 12
        # -- reads -----------------------------------------------------------
        ("select_rows", {"schema": S, "table": "employees",
                         "where": "salary > %s", "where_params": [100],
                         "order_by": "salary", "descending": True}),    # 13
        ("count_rows", {"schema": S, "table": "employees"}),            # 14
        ("distinct_values", {"schema": S, "table": "employees",
                             "column": "dept"}),                        # 15
        ("column_stats", {"schema": S, "table": "employees",
                          "column": "salary"}),                         # 16
        ("describe_table", {"schema": S, "table": "employees"}),        # 17
        ("execute_query", {"query":
            f"SELECT dept, count(*) AS n FROM {S}.employees GROUP BY dept"}),  # 18
        ("explain_query", {"query": f"SELECT * FROM {S}.employees WHERE dept='eng'"}),  # 19
        # -- guards ----------------------------------------------------------
        ("execute_query", {"query":
            f"DELETE FROM {S}.employees"}),                             # 20 must FAIL (read-only)
        ("update_rows", {"schema": S, "table": "employees",
                         "data": {"salary": 0}, "where": ""}),          # 21 must FAIL (no where)
        # -- transaction + view + csv ----------------------------------------
        ("execute_transaction", {"statements": [
            f"INSERT INTO {S}.employees(name, email) VALUES ('T1', 't1@x.sa')",
            f"UPDATE {S}.employees SET dept = 'ops' WHERE email = 't1@x.sa'",
        ]}),                                                            # 22
        ("create_view", {"schema": S, "name": "eng_staff",
                         "query": f"SELECT name, salary FROM {S}.employees WHERE dept = 'eng'"}),  # 23
        ("get_view_definition", {"schema": S, "view": "eng_staff"}),    # 24
        ("import_csv", {"schema": S, "table": "employees",
                        "columns": ["name", "email", "salary"],
                        "csv_data": "name,email,salary\nLina,l@x.sa,90\nNoor,n@x.sa,95\n"}),  # 25
        ("export_table_csv", {"schema": S, "table": "employees"}),      # 26
        # -- maintenance / monitoring ----------------------------------------
        ("vacuum_table", {"schema": S, "table": "employees"}),          # 27
        ("table_stats", {"schema": S, "table": "employees"}),           # 28
        ("list_activity", {}),                                          # 29
        ("cache_hit_ratio", {}),                                        # 30
        # -- roles & grants ----------------------------------------------------
        ("create_role", {"name": "mcp_e2e_role", "login": False}),      # 31
        ("grant_privileges", {"role": "mcp_e2e_role", "privileges": ["SELECT"],
                              "schema": S, "table": "employees"}),      # 32
        ("list_table_privileges", {"schema": S, "table": "employees"}),  # 33
        ("revoke_privileges", {"role": "mcp_e2e_role", "privileges": ["SELECT"],
                               "schema": S, "table": "employees"}),     # 34
        ("drop_role", {"name": "mcp_e2e_role"}),                        # 35
        # -- row deletion + teardown -------------------------------------------
        ("delete_rows", {"schema": S, "table": "employees",
                         "where": "email = %s", "where_params": ["t1@x.sa"]}),  # 36
        ("truncate_table", {"schema": S, "table": "employees",
                            "restart_identity": True}),                 # 37
        ("drop_schema", {"name": S, "cascade": True}),                  # 38
    ])

    tools = out[0]
    assert len(tools) >= 80, f"expected 80+ postgres tools, got {len(tools)}"

    r = out[1:]
    assert "PostgreSQL" in r[0]["rows"][0]["version"]                   # server_info
    assert any(d["name"] == "mcpdb" for d in r[1]["rows"])              # list_databases
    assert r[3].get("status") == "committed"                            # create_schema
    assert r[4].get("status") == "committed"                            # create_table
    assert r[8]["rows"][0]["name"] == "Ahmed"                           # insert_row RETURNING
    assert r[8]["rows"][0]["meta"] == {"grade": 7} or \
        json.loads(r[8]["rows"][0]["meta"]) == {"grade": 7}             # jsonb round-trip
    assert r[9]["rows_inserted"] == 2                                   # insert_rows
    assert r[10]["rows"][0]["name"] == "Ahmed A."                       # upsert updated
    assert r[11]["rows_affected"] == 1                                  # update_rows (hr)
    sel = r[12]
    assert sel["row_count"] >= 2 and sel["rows"][0]["salary"] >= sel["rows"][-1]["salary"]
    assert r[13]["rows"][0]["count"] == 3                               # count_rows
    assert {v["value"] for v in r[14]["rows"]} == {"eng", "hr"}         # distinct_values
    assert r[15]["distinct_values"] >= 3                                # column_stats
    desc = r[16]
    assert desc["primary_key"] == ["id"]
    assert any(c["column"] == "dept" for c in desc["columns"])
    assert any(c["name"] == "salary_positive" for c in desc["constraints"])
    assert r[17]["row_count"] == 2                                      # group-by query
    assert "plan" in r[18]                                              # explain
    assert "error" in r[19] and "read-only" in r[19]["error"]           # RO guard
    assert "error" in r[20] and "where" in r[20]["error"]               # where guard
    assert r[21]["status"] == "committed" and r[21]["statements_run"] == 2
    assert r[23]["rows"][0]["definition"].strip().lower().startswith("select")  # view def
    assert r[24]["rows_imported"] == 2                                  # import_csv
    assert "Lina" in r[25]["csv"] and r[25]["truncated"] is False       # export csv
    assert r[26].get("status") == "ok"                                  # vacuum
    assert r[27]["rows"][0]["live_rows"] >= 0                           # table_stats
    assert r[28]["row_count"] >= 0                                      # list_activity
    assert r[29]["row_count"] == 2                                      # cache ratios
    assert r[30].get("status") == "committed"                           # create_role
    assert any(p["grantee"] == "mcp_e2e_role" for p in r[32]["rows"])   # grant visible
    assert r[35]["rows_affected"] == 1                                  # delete_rows
    assert r[36].get("status") == "committed"                           # truncate
    assert r[37].get("status") == "committed"                           # drop_schema


# ==========================================================================
# gitea-mcp
# ==========================================================================

@pytest.mark.skipif(not (_backend_up(_gitea_up) and GITEA_TOKEN),
                    reason="no test Gitea reachable (or TEST_GITEA_TOKEN unset)")
def test_gitea_full_lifecycle():
    srv = Server("gitea_server.py", {
        "GITEA_URL": GITEA_URL,
        "GITEA_TOKEN": GITEA_TOKEN,
    })
    R = "mcp-e2e-repo"
    pre = srv.run([("get_current_user", {})])
    me = pre[1]["login"]
    srv.run([("delete_repo", {"owner": me, "repo": R, "confirm": True})])  # clean slate

    out = srv.run([
        # -- server / repo -----------------------------------------------------
        ("get_server_version", {}),                                     # 1
        ("create_repo", {"name": R, "description": "e2e", "private": True,
                         "auto_init": True, "default_branch": "main"}),  # 2
        ("get_repo", {"owner": me, "repo": R}),                         # 3
        ("edit_repo", {"owner": me, "repo": R, "description": "e2e updated"}),  # 4
        ("set_repo_topics", {"owner": me, "repo": R, "topics": ["mcp", "e2e"]}),  # 5
        ("get_repo_topics", {"owner": me, "repo": R}),                  # 6
        # -- contents ---------------------------------------------------------
        ("create_file", {"owner": me, "repo": R, "path": "src/app.py",
                         "content": "print('v1')\n", "message": "add app"}),  # 7
        ("update_file", {"owner": me, "repo": R, "path": "src/app.py",
                         "content": "print('v2')\n", "message": "bump"}),  # 8
        ("get_file", {"owner": me, "repo": R, "path": "src/app.py"}),   # 9
        ("get_raw_file", {"owner": me, "repo": R, "path": "src/app.py"}),  # 10
        ("list_directory", {"owner": me, "repo": R, "path": "src"}),    # 11
        ("modify_files", {"owner": me, "repo": R, "message": "batch",
                          "files": [
                              {"operation": "create", "path": "docs/a.md",
                               "content": "# A"},
                              {"operation": "update", "path": "src/app.py",
                               "content": "print('v3')\n"}]}),          # 12
        # -- branches / commits -------------------------------------------------
        ("create_branch", {"owner": me, "repo": R, "new_branch": "feature"}),  # 13
        ("list_branches", {"owner": me, "repo": R}),                    # 14
        ("create_file", {"owner": me, "repo": R, "path": "feature.txt",
                         "content": "feat\n", "message": "feat commit",
                         "branch": "feature"}),                         # 15
        ("list_commits", {"owner": me, "repo": R, "ref": "feature"}),   # 16
        # -- labels / milestones / issues ----------------------------------------
        ("create_label", {"owner": me, "repo": R, "name": "bug",
                          "color": "#ff0000"}),                         # 17
        ("create_milestone", {"owner": me, "repo": R, "title": "v1.0"}),  # 18
        ("create_issue", {"owner": me, "repo": R, "title": "Crash on start",
                          "body": "boom", "labels": ["bug"]}),          # 19
        ("create_issue_comment", {"owner": me, "repo": R, "index": 1,
                                  "body": "investigating"}),            # 20
        ("edit_issue", {"owner": me, "repo": R, "index": 1,
                        "state": "closed"}),                            # 21
        ("list_issues", {"owner": me, "repo": R, "state": "closed"}),   # 22
        # -- pull request full flow ---------------------------------------------
        ("create_pull_request", {"owner": me, "repo": R, "title": "Feature",
                                 "head": "feature", "base": "main",
                                 "body": "adds feature"}),              # 23
        ("list_pull_request_files", {"owner": me, "repo": R, "index": 2}),  # 24
        ("get_pull_request_diff", {"owner": me, "repo": R, "index": 2}),  # 25
        ("create_pull_review", {"owner": me, "repo": R, "index": 2,
                                "event": "COMMENT", "body": "lgtm-ish"}),  # 26
        ("merge_pull_request", {"owner": me, "repo": R, "index": 2,
                                "method": "squash",
                                "delete_branch_after": True}),          # 27
        ("is_pull_request_merged", {"owner": me, "repo": R, "index": 2}),  # 28
        # -- tags / releases -----------------------------------------------------
        ("create_tag", {"owner": me, "repo": R, "tag_name": "v0.1",
                        "message": "first"}),                           # 29
        ("create_release", {"owner": me, "repo": R, "tag_name": "v0.1",
                            "name": "v0.1", "body": "notes"}),          # 30
        ("get_latest_release", {"owner": me, "repo": R}),               # 31
        # -- webhooks -------------------------------------------------------------
        ("create_webhook", {"owner": me, "repo": R,
                            "url": "http://127.0.0.1:9/hook"}),         # 32
        ("list_webhooks", {"owner": me, "repo": R}),                    # 33
        # -- guards + teardown ----------------------------------------------------
        ("delete_repo", {"owner": me, "repo": R}),                      # 34 must FAIL (no confirm)
        ("delete_repo", {"owner": me, "repo": R, "confirm": True}),     # 35
    ])

    tools = out[0]
    assert len(tools) >= 100, f"expected 100+ gitea tools, got {len(tools)}"

    r = out[1:]
    assert "version" in r[0]                                            # server version
    assert r[1]["name"] == R                                            # create_repo
    assert r[2]["default_branch"] == "main"                             # get_repo
    assert r[3]["description"] == "e2e updated"                         # edit_repo
    assert set(r[5]["topics"]) == {"mcp", "e2e"}                        # topics
    assert r[6]["content"]["path"] == "src/app.py"                      # create_file
    assert r[8]["content"] == "print('v2')\n" or "v2" in str(r[8])      # get_file decoded
    assert "v2" in r[9]["content"] or "v3" in r[9]["content"]           # raw file
    assert r[10][0]["name"] == "app.py"                                 # list_directory
    assert isinstance(r[11], dict)                                      # modify_files commit
    assert any(b["name"] == "feature" for b in r[13])                   # branches
    assert len(r[15]) >= 2                                              # commits on feature
    assert r[16]["name"] == "bug"                                       # label
    assert r[17]["title"] == "v1.0"                                     # milestone
    issue = r[18]
    assert issue["number"] == 1 and any(l["name"] == "bug"
                                        for l in issue["labels"])       # label by NAME resolved
    assert r[19]["body"] == "investigating"                             # comment
    assert r[20]["state"] == "closed"                                   # edit_issue
    assert any(i["number"] == 1 for i in r[21])                         # list closed
    pr = r[22]
    assert pr["number"] == 2 and pr["head"]["ref"] == "feature"         # PR created
    assert any(f["filename"] == "feature.txt" for f in r[23])           # PR files
    assert "feature.txt" in r[24]["content"]                            # PR diff text
    assert r[25]["state"] in {"COMMENT", "PENDING"}                     # review
    assert r[26].get("status") in {"ok", None} or "error" not in r[26]  # merge ok
    assert r[27]["merged"] is True                                      # merged check
    assert r[28]["name"] == "v0.1"                                      # tag
    assert r[29]["tag_name"] == "v0.1"                                  # release
    assert r[30]["tag_name"] == "v0.1"                                  # latest release
    assert r[31]["config"]["url"].endswith("/hook")                     # webhook
    assert len(r[32]) == 1                                              # list webhooks
    assert "error" in r[33] and "confirm" in r[33]["error"]             # delete guard
    assert r[34].get("status") == "ok"                                  # deleted
