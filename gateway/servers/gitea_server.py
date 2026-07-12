"""gitea-mcp — full-featured Gitea MCP server (read + write).

A production-grade MCP server covering the Gitea REST API v1:

  * Server & users    — version, current user, user lookup/search, SSH keys,
                        notifications
  * Repositories      — list/search/get/create/edit/delete/fork/transfer,
                        topics, stars, watching
  * Branches & tags   — CRUD plus branch protection rules
  * Commits           — history, single commit, diffs, compare, commit statuses
  * Contents          — read files/directories/raw, create/update/delete files
                        (auto-resolves blob SHAs), batch multi-file commits
  * Issues            — full CRUD, comments, label assignment (accepts label
                        names or ids), search across repos
  * Labels/milestones — full CRUD
  * Pull requests     — full CRUD, merge (all strategies), diff, commits,
                        files, update-branch, reviews (create/dismiss),
                        reviewer requests
  * Releases          — full CRUD incl. latest-release lookup
  * Webhooks & keys   — repo webhooks and deploy keys CRUD
  * Collaboration     — collaborators, organizations, teams and membership

Configuration via environment (never via model-visible args):
  GITEA_URL       base URL, e.g. https://git.internal or http://localhost:3000
  GITEA_TOKEN     personal access token (Settings → Applications)
  GITEA_TIMEOUT   HTTP timeout seconds (default 30)

Every tool returns a JSON string; errors come back as
{"error": ..., "status": <http-status>} — never as exceptions.

Runs over stdio; the gateway spawns it.
"""
import base64
import json
import os
from typing import Any, Optional

import httpx

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gitea")

GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3000").rstrip("/")


def _token() -> str:
    """GITEA_TOKEN_FILE (Docker secret) wins over GITEA_TOKEN — same file-first
    convention as the gateway's own secrets."""
    path = os.environ.get("GITEA_TOKEN_FILE", "").strip()
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""
    return os.environ.get("GITEA_TOKEN", "")


GITEA_TOKEN = _token()
TIMEOUT = float(os.environ.get("GITEA_TIMEOUT", "30"))
MAX_RESULT_BYTES = 1_000_000
MAX_PAGE_LIMIT = 50
# Identity attribution: when set, every API call is made ON BEHALF OF this Gitea
# user via the Sudo header, so writes are attributed to a real account in Gitea's
# audit trail instead of the raw token owner. Requires an admin token. Leave unset
# to act as the token owner. Least-privilege guidance: use a DEDICATED machine
# account with a SCOPED token (only the repo/org/issue scopes you need), NOT a
# personal admin token.
GITEA_SUDO = os.environ.get("GITEA_SUDO", "").strip()


def _client() -> httpx.Client:
    headers = {"Accept": "application/json"}
    if GITEA_TOKEN:
        headers["Authorization"] = f"token {GITEA_TOKEN}"
    if GITEA_SUDO:
        headers["Sudo"] = GITEA_SUDO            # act as this user (admin token required)
    return httpx.Client(base_url=f"{GITEA_URL}/api/v1", headers=headers,
                        timeout=TIMEOUT, follow_redirects=True)


def _dumps(obj: Any) -> str:
    out = json.dumps(obj, ensure_ascii=False, default=str)
    if len(out.encode("utf-8", "ignore")) > MAX_RESULT_BYTES:
        return json.dumps({"error": "result too large",
                           "hint": "use pagination (page/limit) or request less data",
                           "size_bytes": len(out)})
    return out


def _req(method: str, path: str, params: Optional[dict] = None,
         body: Optional[dict] = None, text_response: bool = False) -> str:
    """Perform one API call and serialize the outcome. Strips None params/body keys
    so optional tool arguments never overwrite server-side defaults."""
    params = {k: v for k, v in (params or {}).items() if v is not None} or None
    if body is not None:
        body = {k: v for k, v in body.items() if v is not None}
    try:
        with _client() as c:
            r = c.request(method, path, params=params, json=body)
    except httpx.HTTPError as e:
        return json.dumps({"error": f"cannot reach Gitea at {GITEA_URL}: {e}",
                           "type": type(e).__name__})
    if r.status_code >= 400:
        try:
            detail = r.json()
            message = detail.get("message") or detail.get("errors") or detail
        except Exception:                                     # noqa: BLE001
            message = r.text[:500]
        return json.dumps({"error": message, "status": r.status_code,
                           "path": path}, ensure_ascii=False, default=str)
    if r.status_code == 204 or not r.content:
        return json.dumps({"status": "ok", "http_status": r.status_code})
    if text_response:
        return _dumps({"content": r.text[:MAX_RESULT_BYTES],
                       "truncated": len(r.text) > MAX_RESULT_BYTES})
    try:
        return _dumps(r.json())
    except Exception:                                         # noqa: BLE001
        return _dumps({"content": r.text[:10000]})


def _page(page: int, limit: int) -> dict:
    return {"page": max(1, page), "limit": min(max(1, limit), MAX_PAGE_LIMIT)}


def _json_or_err(raw: str) -> Any:
    """Parse an internal _req result; returns dict/list (error dicts pass through)."""
    return json.loads(raw)


def _resolve_label_ids(owner: str, repo: str, labels: list) -> list[int] | dict:
    """Gitea's issue APIs want label IDs. Accept names or ids; resolve names
    against repo + org labels."""
    ids: list[int] = []
    names = [l for l in labels if not isinstance(l, int)
             and not (isinstance(l, str) and l.isdigit())]
    lookup: dict[str, int] = {}
    if names:
        raw = _json_or_err(_req("GET", f"/repos/{owner}/{repo}/labels",
                                params={"limit": 50}))
        if isinstance(raw, dict) and "error" in raw:
            return raw
        lookup = {l["name"].lower(): l["id"] for l in raw}
        missing = [n for n in names if str(n).lower() not in lookup]
        if missing:
            org_raw = _json_or_err(_req("GET", f"/orgs/{owner}/labels",
                                        params={"limit": 50}))
            if isinstance(org_raw, list):
                for l in org_raw:
                    lookup.setdefault(l["name"].lower(), l["id"])
    for l in labels:
        if isinstance(l, int) or (isinstance(l, str) and l.isdigit()):
            ids.append(int(l))
        elif str(l).lower() in lookup:
            ids.append(lookup[str(l).lower()])
        else:
            return {"error": f"label not found in {owner}/{repo}: {l!r}"}
    return ids


# ==========================================================================
# 1. SERVER & USERS
# ==========================================================================

@mcp.tool()
def get_server_version() -> str:
    """Gitea server version — also the quickest connectivity/auth check."""
    return _req("GET", "/version")


@mcp.tool()
def get_current_user() -> str:
    """The authenticated user (whose token this server uses)."""
    return _req("GET", "/user")


@mcp.tool()
def get_user(username: str) -> str:
    """Public profile of a user."""
    return _req("GET", f"/users/{username}")


@mcp.tool()
def search_users(query: str, page: int = 1, limit: int = 20) -> str:
    """Search users by keyword."""
    return _req("GET", "/users/search", params={"q": query, **_page(page, limit)})


@mcp.tool()
def list_my_orgs(page: int = 1, limit: int = 30) -> str:
    """Organizations the authenticated user belongs to."""
    return _req("GET", "/user/orgs", params=_page(page, limit))


@mcp.tool()
def list_user_orgs(username: str, page: int = 1, limit: int = 30) -> str:
    """Public organizations of a user."""
    return _req("GET", f"/users/{username}/orgs", params=_page(page, limit))


@mcp.tool()
def list_my_ssh_keys() -> str:
    """SSH public keys registered on the authenticated account."""
    return _req("GET", "/user/keys")


@mcp.tool()
def add_ssh_key(title: str, key: str) -> str:
    """Register an SSH public key on the authenticated account."""
    return _req("POST", "/user/keys", body={"title": title, "key": key})


@mcp.tool()
def delete_ssh_key(key_id: int) -> str:
    """Remove an SSH key from the authenticated account by id."""
    return _req("DELETE", f"/user/keys/{key_id}")


@mcp.tool()
def list_notifications(unread_only: bool = True, page: int = 1, limit: int = 30) -> str:
    """Notification threads for the authenticated user."""
    params: dict[str, Any] = _page(page, limit)
    if not unread_only:
        params["all"] = "true"
    return _req("GET", "/notifications", params=params)


@mcp.tool()
def mark_notifications_read() -> str:
    """Mark all notifications as read."""
    return _req("PUT", "/notifications")


# ==========================================================================
# 2. REPOSITORIES
# ==========================================================================

@mcp.tool()
def list_my_repos(page: int = 1, limit: int = 30) -> str:
    """Repositories the authenticated user owns or has access to."""
    return _req("GET", "/user/repos", params=_page(page, limit))


@mcp.tool()
def list_user_repos(username: str, page: int = 1, limit: int = 30) -> str:
    """Public repositories of a user."""
    return _req("GET", f"/users/{username}/repos", params=_page(page, limit))


@mcp.tool()
def list_org_repos(org: str, page: int = 1, limit: int = 30) -> str:
    """Repositories of an organization."""
    return _req("GET", f"/orgs/{org}/repos", params=_page(page, limit))


@mcp.tool()
def search_repos(query: str, private: Optional[bool] = None,
                 sort: str = "updated", order: str = "desc",
                 page: int = 1, limit: int = 20) -> str:
    """Search repositories by keyword. sort: alpha|created|updated|size|id."""
    return _req("GET", "/repos/search",
                params={"q": query, "private": private, "sort": sort,
                        "order": order, **_page(page, limit)})


@mcp.tool()
def get_repo(owner: str, repo: str) -> str:
    """Full metadata for one repository (default branch, permissions, counts, urls)."""
    return _req("GET", f"/repos/{owner}/{repo}")


@mcp.tool()
def create_repo(name: str, description: str = "", private: bool = True,
                auto_init: bool = True, default_branch: str = "main",
                gitignores: Optional[str] = None, license: Optional[str] = None,
                readme: str = "Default") -> str:
    """Create a repository for the authenticated user. auto_init=true creates the
    first commit (README, optional .gitignore template and license)."""
    return _req("POST", "/user/repos", body={
        "name": name, "description": description, "private": private,
        "auto_init": auto_init, "default_branch": default_branch,
        "gitignores": gitignores, "license": license, "readme": readme})


@mcp.tool()
def create_org_repo(org: str, name: str, description: str = "",
                    private: bool = True, auto_init: bool = True,
                    default_branch: str = "main") -> str:
    """Create a repository inside an organization."""
    return _req("POST", f"/orgs/{org}/repos", body={
        "name": name, "description": description, "private": private,
        "auto_init": auto_init, "default_branch": default_branch})


@mcp.tool()
def edit_repo(owner: str, repo: str, description: Optional[str] = None,
              private: Optional[bool] = None, default_branch: Optional[str] = None,
              website: Optional[str] = None, archived: Optional[bool] = None,
              has_issues: Optional[bool] = None, has_wiki: Optional[bool] = None,
              allow_merge_commits: Optional[bool] = None,
              allow_squash_merge: Optional[bool] = None,
              allow_rebase: Optional[bool] = None) -> str:
    """Edit repository settings — only the fields you pass are changed."""
    return _req("PATCH", f"/repos/{owner}/{repo}", body={
        "description": description, "private": private,
        "default_branch": default_branch, "website": website,
        "archived": archived, "has_issues": has_issues, "has_wiki": has_wiki,
        "allow_merge_commits": allow_merge_commits,
        "allow_squash_merge": allow_squash_merge, "allow_rebase": allow_rebase})


@mcp.tool()
def delete_repo(owner: str, repo: str, confirm: bool = False) -> str:
    """Delete a repository permanently (DESTRUCTIVE). Requires confirm=true."""
    if not confirm:
        return json.dumps({"error": "refusing to delete without confirm=true",
                           "repo": f"{owner}/{repo}"})
    return _req("DELETE", f"/repos/{owner}/{repo}")


@mcp.tool()
def fork_repo(owner: str, repo: str, organization: Optional[str] = None,
              name: Optional[str] = None) -> str:
    """Fork a repository to the authenticated user (or into an organization)."""
    return _req("POST", f"/repos/{owner}/{repo}/forks",
                body={"organization": organization, "name": name})


@mcp.tool()
def list_forks(owner: str, repo: str, page: int = 1, limit: int = 30) -> str:
    """List forks of a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/forks", params=_page(page, limit))


@mcp.tool()
def transfer_repo(owner: str, repo: str, new_owner: str) -> str:
    """Transfer repository ownership to another user or organization."""
    return _req("POST", f"/repos/{owner}/{repo}/transfer",
                body={"new_owner": new_owner})


@mcp.tool()
def get_repo_topics(owner: str, repo: str) -> str:
    """List the topics (tags/keywords) of a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/topics")


@mcp.tool()
def set_repo_topics(owner: str, repo: str, topics: list[str]) -> str:
    """Replace the full topic list of a repository."""
    return _req("PUT", f"/repos/{owner}/{repo}/topics", body={"topics": topics})


@mcp.tool()
def star_repo(owner: str, repo: str) -> str:
    """Star a repository as the authenticated user."""
    return _req("PUT", f"/user/starred/{owner}/{repo}")


@mcp.tool()
def unstar_repo(owner: str, repo: str) -> str:
    """Remove your star from a repository."""
    return _req("DELETE", f"/user/starred/{owner}/{repo}")


@mcp.tool()
def watch_repo(owner: str, repo: str) -> str:
    """Subscribe to (watch) a repository's activity."""
    return _req("PUT", f"/repos/{owner}/{repo}/subscription")


@mcp.tool()
def unwatch_repo(owner: str, repo: str) -> str:
    """Unsubscribe from a repository."""
    return _req("DELETE", f"/repos/{owner}/{repo}/subscription")


# ==========================================================================
# 3. BRANCHES & PROTECTION
# ==========================================================================

@mcp.tool()
def list_branches(owner: str, repo: str, page: int = 1, limit: int = 30) -> str:
    """List branches with head commit and protection status."""
    return _req("GET", f"/repos/{owner}/{repo}/branches", params=_page(page, limit))


@mcp.tool()
def get_branch(owner: str, repo: str, branch: str) -> str:
    """Details of one branch (head commit, protection)."""
    return _req("GET", f"/repos/{owner}/{repo}/branches/{branch}")


@mcp.tool()
def create_branch(owner: str, repo: str, new_branch: str,
                  from_ref: Optional[str] = None) -> str:
    """Create a branch. from_ref is the source branch/tag/commit (default: the
    repository's default branch)."""
    return _req("POST", f"/repos/{owner}/{repo}/branches",
                body={"new_branch_name": new_branch, "old_ref_name": from_ref})


@mcp.tool()
def delete_branch(owner: str, repo: str, branch: str) -> str:
    """Delete a branch (fails on the default or a protected branch)."""
    return _req("DELETE", f"/repos/{owner}/{repo}/branches/{branch}")


@mcp.tool()
def list_branch_protections(owner: str, repo: str) -> str:
    """List branch protection rules of a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/branch_protections")


@mcp.tool()
def create_branch_protection(owner: str, repo: str, branch_name: str,
                             required_approvals: int = 0,
                             enable_push: bool = True,
                             push_whitelist_usernames: Optional[list[str]] = None,
                             block_on_rejected_reviews: bool = True) -> str:
    """Protect a branch: require approvals before merge, restrict direct pushes
    (push_whitelist_usernames implies whitelist mode), block merge on rejections."""
    body: dict[str, Any] = {
        "branch_name": branch_name,
        "required_approvals": required_approvals,
        "enable_push": enable_push,
        "block_on_rejected_reviews": block_on_rejected_reviews,
    }
    if push_whitelist_usernames:
        body["enable_push_whitelist"] = True
        body["push_whitelist_usernames"] = push_whitelist_usernames
    return _req("POST", f"/repos/{owner}/{repo}/branch_protections", body=body)


@mcp.tool()
def delete_branch_protection(owner: str, repo: str, branch_name: str) -> str:
    """Remove a branch protection rule."""
    return _req("DELETE", f"/repos/{owner}/{repo}/branch_protections/{branch_name}")


# ==========================================================================
# 4. TAGS
# ==========================================================================

@mcp.tool()
def list_tags(owner: str, repo: str, page: int = 1, limit: int = 30) -> str:
    """List tags with their target commits."""
    return _req("GET", f"/repos/{owner}/{repo}/tags", params=_page(page, limit))


@mcp.tool()
def get_tag(owner: str, repo: str, tag: str) -> str:
    """Details of one tag."""
    return _req("GET", f"/repos/{owner}/{repo}/tags/{tag}")


@mcp.tool()
def create_tag(owner: str, repo: str, tag_name: str, target: Optional[str] = None,
               message: str = "") -> str:
    """Create a tag on a branch or commit (default: default branch head)."""
    return _req("POST", f"/repos/{owner}/{repo}/tags",
                body={"tag_name": tag_name, "target": target, "message": message})


@mcp.tool()
def delete_tag(owner: str, repo: str, tag: str) -> str:
    """Delete a tag."""
    return _req("DELETE", f"/repos/{owner}/{repo}/tags/{tag}")


# ==========================================================================
# 5. COMMITS
# ==========================================================================

@mcp.tool()
def list_commits(owner: str, repo: str, ref: Optional[str] = None,
                 path: Optional[str] = None, page: int = 1, limit: int = 20) -> str:
    """Commit history (optionally of one branch/ref and/or one file path)."""
    return _req("GET", f"/repos/{owner}/{repo}/commits",
                params={"sha": ref, "path": path, "stat": "true",
                        **_page(page, limit)})


@mcp.tool()
def get_commit(owner: str, repo: str, sha: str) -> str:
    """One commit with author, message, stats and affected files."""
    return _req("GET", f"/repos/{owner}/{repo}/git/commits/{sha}")


@mcp.tool()
def get_commit_diff(owner: str, repo: str, sha: str) -> str:
    """Unified diff text of a commit."""
    return _req("GET", f"/repos/{owner}/{repo}/git/commits/{sha}.diff",
                text_response=True)


@mcp.tool()
def compare_commits(owner: str, repo: str, base: str, head: str) -> str:
    """Compare two refs (branch/tag/sha): commits between base and head."""
    return _req("GET", f"/repos/{owner}/{repo}/compare/{base}...{head}")


@mcp.tool()
def list_commit_statuses(owner: str, repo: str, sha: str,
                         page: int = 1, limit: int = 30) -> str:
    """CI/status checks reported for a commit."""
    return _req("GET", f"/repos/{owner}/{repo}/statuses/{sha}",
                params=_page(page, limit))


@mcp.tool()
def create_commit_status(owner: str, repo: str, sha: str, state: str,
                         context: str = "default", description: str = "",
                         target_url: str = "") -> str:
    """Report a status check on a commit. state: pending|success|error|failure|warning."""
    if state not in {"pending", "success", "error", "failure", "warning"}:
        return json.dumps({"error": "state must be pending|success|error|failure|warning"})
    return _req("POST", f"/repos/{owner}/{repo}/statuses/{sha}",
                body={"state": state, "context": context,
                      "description": description, "target_url": target_url})


# ==========================================================================
# 6. FILE CONTENTS
# ==========================================================================

def _get_file_sha(owner: str, repo: str, path: str, ref: Optional[str]) -> str | None:
    raw = _json_or_err(_req("GET", f"/repos/{owner}/{repo}/contents/{path}",
                            params={"ref": ref}))
    if isinstance(raw, dict):
        return raw.get("sha")
    return None


@mcp.tool()
def get_file(owner: str, repo: str, path: str, ref: Optional[str] = None) -> str:
    """Read a file: returns decoded text content plus metadata (sha, size, url).
    ref is a branch/tag/commit (default: default branch)."""
    raw = _json_or_err(_req("GET", f"/repos/{owner}/{repo}/contents/{path}",
                            params={"ref": ref}))
    if isinstance(raw, dict) and raw.get("content") is not None:
        try:
            decoded = base64.b64decode(raw["content"]).decode("utf-8")
            raw["content"] = decoded[:MAX_RESULT_BYTES]
            raw["encoding"] = "utf-8"
        except (UnicodeDecodeError, ValueError):
            raw["encoding"] = "base64"   # binary file: leave base64 as-is
    return _dumps(raw)


@mcp.tool()
def list_directory(owner: str, repo: str, path: str = "",
                   ref: Optional[str] = None) -> str:
    """List a directory (path='' for repo root): names, types, sizes, shas."""
    raw = _json_or_err(_req("GET", f"/repos/{owner}/{repo}/contents/{path}",
                            params={"ref": ref}))
    if isinstance(raw, list):
        return _dumps([{"name": e.get("name"), "path": e.get("path"),
                        "type": e.get("type"), "size": e.get("size"),
                        "sha": e.get("sha")} for e in raw])
    return _dumps(raw)


@mcp.tool()
def get_raw_file(owner: str, repo: str, path: str, ref: Optional[str] = None) -> str:
    """Raw text content of a file (no metadata)."""
    return _req("GET", f"/repos/{owner}/{repo}/raw/{path}",
                params={"ref": ref}, text_response=True)


@mcp.tool()
def create_file(owner: str, repo: str, path: str, content: str, message: str,
                branch: Optional[str] = None, new_branch: Optional[str] = None) -> str:
    """Create a new file with a commit. content is plain text (encoded internally).
    new_branch creates the commit on a fresh branch off `branch`."""
    return _req("POST", f"/repos/{owner}/{repo}/contents/{path}", body={
        "content": base64.b64encode(content.encode()).decode(),
        "message": message, "branch": branch, "new_branch": new_branch})


@mcp.tool()
def update_file(owner: str, repo: str, path: str, content: str, message: str,
                branch: Optional[str] = None, sha: Optional[str] = None,
                new_branch: Optional[str] = None) -> str:
    """Update an existing file with a commit. The file's current blob sha is resolved
    automatically if not provided."""
    if not sha:
        sha = _get_file_sha(owner, repo, path, branch)
        if not sha:
            return json.dumps({"error": f"file not found (cannot resolve sha): {path}",
                               "hint": "use create_file for new files"})
    return _req("PUT", f"/repos/{owner}/{repo}/contents/{path}", body={
        "content": base64.b64encode(content.encode()).decode(),
        "message": message, "branch": branch, "sha": sha, "new_branch": new_branch})


@mcp.tool()
def delete_file(owner: str, repo: str, path: str, message: str,
                branch: Optional[str] = None, sha: Optional[str] = None) -> str:
    """Delete a file with a commit (blob sha auto-resolved if not provided)."""
    if not sha:
        sha = _get_file_sha(owner, repo, path, branch)
        if not sha:
            return json.dumps({"error": f"file not found (cannot resolve sha): {path}"})
    return _req("DELETE", f"/repos/{owner}/{repo}/contents/{path}",
                body={"message": message, "branch": branch, "sha": sha})


@mcp.tool()
def modify_files(owner: str, repo: str, files: list[dict], message: str,
                 branch: Optional[str] = None, new_branch: Optional[str] = None) -> str:
    """Create/update/delete MULTIPLE files in ONE commit. Each entry:
    {"operation": "create"|"update"|"delete", "path": "...", "content": "text"}.
    Blob shas for update/delete are resolved automatically."""
    payload = []
    for f in files:
        op, path = f.get("operation"), f.get("path")
        if op not in {"create", "update", "delete"} or not path:
            return json.dumps({"error": f"bad file entry (need operation+path): {f}"})
        entry: dict[str, Any] = {"operation": op, "path": path}
        if op in {"create", "update"}:
            entry["content"] = base64.b64encode(
                str(f.get("content", "")).encode()).decode()
        if op in {"update", "delete"}:
            sha = f.get("sha") or _get_file_sha(owner, repo, path, branch)
            if not sha:
                return json.dumps({"error": f"cannot resolve sha for {path}"})
            entry["sha"] = sha
        payload.append(entry)
    return _req("POST", f"/repos/{owner}/{repo}/contents", body={
        "files": payload, "message": message, "branch": branch,
        "new_branch": new_branch})


# ==========================================================================
# 7. ISSUES
# ==========================================================================

@mcp.tool()
def list_issues(owner: str, repo: str, state: str = "open",
                labels: Optional[str] = None, query: Optional[str] = None,
                milestone: Optional[str] = None, assignee: Optional[str] = None,
                page: int = 1, limit: int = 20) -> str:
    """List issues (not PRs) in a repo. state: open|closed|all. labels is a
    comma-separated name list."""
    return _req("GET", f"/repos/{owner}/{repo}/issues",
                params={"state": state, "labels": labels, "q": query,
                        "milestones": milestone, "assigned_by": None,
                        "type": "issues", "assignee": assignee,
                        **_page(page, limit)})


@mcp.tool()
def search_issues(query: str, state: str = "open", include_prs: bool = False,
                  page: int = 1, limit: int = 20) -> str:
    """Search issues across ALL repositories accessible to the token."""
    return _req("GET", "/repos/issues/search",
                params={"q": query, "state": state,
                        "type": None if include_prs else "issues",
                        **_page(page, limit)})


@mcp.tool()
def get_issue(owner: str, repo: str, index: int) -> str:
    """One issue by its number (title, body, labels, assignees, state, timestamps)."""
    return _req("GET", f"/repos/{owner}/{repo}/issues/{index}")


@mcp.tool()
def create_issue(owner: str, repo: str, title: str, body: str = "",
                 assignees: Optional[list[str]] = None,
                 labels: Optional[list[str]] = None,
                 milestone: Optional[int] = None,
                 due_date: Optional[str] = None) -> str:
    """Create an issue. labels accepts names or ids; due_date is ISO 8601
    (e.g. 2026-08-01T00:00:00Z)."""
    label_ids = None
    if labels:
        resolved = _resolve_label_ids(owner, repo, labels)
        if isinstance(resolved, dict):
            return json.dumps(resolved)
        label_ids = resolved
    return _req("POST", f"/repos/{owner}/{repo}/issues", body={
        "title": title, "body": body, "assignees": assignees,
        "labels": label_ids, "milestone": milestone, "due_date": due_date})


@mcp.tool()
def edit_issue(owner: str, repo: str, index: int, title: Optional[str] = None,
               body: Optional[str] = None, state: Optional[str] = None,
               assignees: Optional[list[str]] = None,
               milestone: Optional[int] = None,
               due_date: Optional[str] = None) -> str:
    """Edit an issue — only passed fields change. state: open|closed."""
    if state is not None and state not in {"open", "closed"}:
        return json.dumps({"error": "state must be open|closed"})
    return _req("PATCH", f"/repos/{owner}/{repo}/issues/{index}", body={
        "title": title, "body": body, "state": state, "assignees": assignees,
        "milestone": milestone, "due_date": due_date})


@mcp.tool()
def list_issue_comments(owner: str, repo: str, index: int,
                        page: int = 1, limit: int = 30) -> str:
    """Comments on an issue or pull request."""
    return _req("GET", f"/repos/{owner}/{repo}/issues/{index}/comments",
                params=_page(page, limit))


@mcp.tool()
def create_issue_comment(owner: str, repo: str, index: int, body: str) -> str:
    """Add a comment to an issue or pull request."""
    return _req("POST", f"/repos/{owner}/{repo}/issues/{index}/comments",
                body={"body": body})


@mcp.tool()
def edit_issue_comment(owner: str, repo: str, comment_id: int, body: str) -> str:
    """Edit a comment by its id (ids come from list_issue_comments)."""
    return _req("PATCH", f"/repos/{owner}/{repo}/issues/comments/{comment_id}",
                body={"body": body})


@mcp.tool()
def delete_issue_comment(owner: str, repo: str, comment_id: int) -> str:
    """Delete a comment by its id."""
    return _req("DELETE", f"/repos/{owner}/{repo}/issues/comments/{comment_id}")


@mcp.tool()
def add_issue_labels(owner: str, repo: str, index: int, labels: list[str]) -> str:
    """Add labels (names or ids) to an issue/PR, keeping existing ones."""
    resolved = _resolve_label_ids(owner, repo, labels)
    if isinstance(resolved, dict):
        return json.dumps(resolved)
    return _req("POST", f"/repos/{owner}/{repo}/issues/{index}/labels",
                body={"labels": resolved})


@mcp.tool()
def replace_issue_labels(owner: str, repo: str, index: int, labels: list[str]) -> str:
    """Replace ALL labels on an issue/PR (empty list clears them)."""
    resolved = _resolve_label_ids(owner, repo, labels) if labels else []
    if isinstance(resolved, dict):
        return json.dumps(resolved)
    return _req("PUT", f"/repos/{owner}/{repo}/issues/{index}/labels",
                body={"labels": resolved})


@mcp.tool()
def remove_issue_label(owner: str, repo: str, index: int, label: str) -> str:
    """Remove one label (name or id) from an issue/PR."""
    resolved = _resolve_label_ids(owner, repo, [label])
    if isinstance(resolved, dict):
        return json.dumps(resolved)
    return _req("DELETE", f"/repos/{owner}/{repo}/issues/{index}/labels/{resolved[0]}")


# ==========================================================================
# 8. LABELS & MILESTONES
# ==========================================================================

@mcp.tool()
def list_labels(owner: str, repo: str, page: int = 1, limit: int = 50) -> str:
    """Labels defined in a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/labels", params=_page(page, limit))


@mcp.tool()
def create_label(owner: str, repo: str, name: str, color: str = "#00aabb",
                 description: str = "") -> str:
    """Create a label. color is a hex code like #ff0000."""
    if not color.startswith("#"):
        color = f"#{color}"
    return _req("POST", f"/repos/{owner}/{repo}/labels",
                body={"name": name, "color": color, "description": description})


@mcp.tool()
def edit_label(owner: str, repo: str, label: str, name: Optional[str] = None,
               color: Optional[str] = None, description: Optional[str] = None) -> str:
    """Edit a label (referenced by current name or id)."""
    resolved = _resolve_label_ids(owner, repo, [label])
    if isinstance(resolved, dict):
        return json.dumps(resolved)
    if color and not color.startswith("#"):
        color = f"#{color}"
    return _req("PATCH", f"/repos/{owner}/{repo}/labels/{resolved[0]}",
                body={"name": name, "color": color, "description": description})


@mcp.tool()
def delete_label(owner: str, repo: str, label: str) -> str:
    """Delete a label (by name or id)."""
    resolved = _resolve_label_ids(owner, repo, [label])
    if isinstance(resolved, dict):
        return json.dumps(resolved)
    return _req("DELETE", f"/repos/{owner}/{repo}/labels/{resolved[0]}")


@mcp.tool()
def list_milestones(owner: str, repo: str, state: str = "open",
                    page: int = 1, limit: int = 30) -> str:
    """Milestones in a repo. state: open|closed|all."""
    return _req("GET", f"/repos/{owner}/{repo}/milestones",
                params={"state": state, **_page(page, limit)})


@mcp.tool()
def get_milestone(owner: str, repo: str, milestone_id: int) -> str:
    """One milestone by id."""
    return _req("GET", f"/repos/{owner}/{repo}/milestones/{milestone_id}")


@mcp.tool()
def create_milestone(owner: str, repo: str, title: str, description: str = "",
                     due_on: Optional[str] = None) -> str:
    """Create a milestone. due_on is ISO 8601 (e.g. 2026-09-30T00:00:00Z)."""
    return _req("POST", f"/repos/{owner}/{repo}/milestones",
                body={"title": title, "description": description, "due_on": due_on})


@mcp.tool()
def edit_milestone(owner: str, repo: str, milestone_id: int,
                   title: Optional[str] = None, description: Optional[str] = None,
                   due_on: Optional[str] = None, state: Optional[str] = None) -> str:
    """Edit a milestone. state: open|closed."""
    return _req("PATCH", f"/repos/{owner}/{repo}/milestones/{milestone_id}",
                body={"title": title, "description": description,
                      "due_on": due_on, "state": state})


@mcp.tool()
def delete_milestone(owner: str, repo: str, milestone_id: int) -> str:
    """Delete a milestone."""
    return _req("DELETE", f"/repos/{owner}/{repo}/milestones/{milestone_id}")


# ==========================================================================
# 9. PULL REQUESTS & REVIEWS
# ==========================================================================

@mcp.tool()
def list_pull_requests(owner: str, repo: str, state: str = "open",
                       sort: str = "recentupdate", page: int = 1,
                       limit: int = 20) -> str:
    """List pull requests. state: open|closed|all;
    sort: oldest|recentupdate|leastupdate|mostcomment|leastcomment|priority."""
    return _req("GET", f"/repos/{owner}/{repo}/pulls",
                params={"state": state, "sort": sort, **_page(page, limit)})


@mcp.tool()
def get_pull_request(owner: str, repo: str, index: int) -> str:
    """One pull request: branches, mergeability, review/merge state, stats."""
    return _req("GET", f"/repos/{owner}/{repo}/pulls/{index}")


@mcp.tool()
def create_pull_request(owner: str, repo: str, title: str, head: str, base: str,
                        body: str = "", assignees: Optional[list[str]] = None,
                        labels: Optional[list[str]] = None,
                        milestone: Optional[int] = None) -> str:
    """Open a pull request from head branch into base branch. For cross-fork PRs use
    head='forkowner:branch'. labels accepts names or ids."""
    label_ids = None
    if labels:
        resolved = _resolve_label_ids(owner, repo, labels)
        if isinstance(resolved, dict):
            return json.dumps(resolved)
        label_ids = resolved
    return _req("POST", f"/repos/{owner}/{repo}/pulls", body={
        "title": title, "head": head, "base": base, "body": body,
        "assignees": assignees, "labels": label_ids, "milestone": milestone})


@mcp.tool()
def edit_pull_request(owner: str, repo: str, index: int,
                      title: Optional[str] = None, body: Optional[str] = None,
                      state: Optional[str] = None, base: Optional[str] = None,
                      assignees: Optional[list[str]] = None,
                      milestone: Optional[int] = None) -> str:
    """Edit a pull request — only passed fields change. state: open|closed."""
    return _req("PATCH", f"/repos/{owner}/{repo}/pulls/{index}", body={
        "title": title, "body": body, "state": state, "base": base,
        "assignees": assignees, "milestone": milestone})


@mcp.tool()
def merge_pull_request(owner: str, repo: str, index: int, method: str = "merge",
                       title: Optional[str] = None, message: Optional[str] = None,
                       delete_branch_after: bool = False) -> str:
    """Merge a pull request. method: merge|rebase|rebase-merge|squash|
    fast-forward-only. Optionally override the merge commit title/message and delete
    the head branch afterwards."""
    valid = {"merge", "rebase", "rebase-merge", "squash", "fast-forward-only"}
    if method not in valid:
        return json.dumps({"error": f"method must be one of {sorted(valid)}"})
    return _req("POST", f"/repos/{owner}/{repo}/pulls/{index}/merge", body={
        "Do": method, "MergeTitleField": title, "MergeMessageField": message,
        "delete_branch_after_merge": delete_branch_after})


@mcp.tool()
def is_pull_request_merged(owner: str, repo: str, index: int) -> str:
    """Check whether a pull request has been merged (true/false)."""
    raw = _req("GET", f"/repos/{owner}/{repo}/pulls/{index}/merge")
    parsed = _json_or_err(raw)
    if isinstance(parsed, dict) and parsed.get("status") == "ok":
        return json.dumps({"merged": True})
    if isinstance(parsed, dict) and parsed.get("status") == 404:
        return json.dumps({"merged": False})
    return raw


@mcp.tool()
def get_pull_request_diff(owner: str, repo: str, index: int) -> str:
    """Unified diff text of a pull request."""
    return _req("GET", f"/repos/{owner}/{repo}/pulls/{index}.diff",
                text_response=True)


@mcp.tool()
def list_pull_request_commits(owner: str, repo: str, index: int,
                              page: int = 1, limit: int = 30) -> str:
    """Commits contained in a pull request."""
    return _req("GET", f"/repos/{owner}/{repo}/pulls/{index}/commits",
                params=_page(page, limit))


@mcp.tool()
def list_pull_request_files(owner: str, repo: str, index: int,
                            page: int = 1, limit: int = 50) -> str:
    """Files changed by a pull request (with additions/deletions)."""
    return _req("GET", f"/repos/{owner}/{repo}/pulls/{index}/files",
                params=_page(page, limit))


@mcp.tool()
def update_pull_request_branch(owner: str, repo: str, index: int,
                               style: str = "merge") -> str:
    """Update a PR's head branch with the latest base branch. style: merge|rebase."""
    if style not in {"merge", "rebase"}:
        return json.dumps({"error": "style must be merge|rebase"})
    return _req("POST", f"/repos/{owner}/{repo}/pulls/{index}/update",
                params={"style": style})


@mcp.tool()
def list_pull_reviews(owner: str, repo: str, index: int) -> str:
    """Reviews on a pull request (approvals, change requests, comments)."""
    return _req("GET", f"/repos/{owner}/{repo}/pulls/{index}/reviews")


@mcp.tool()
def create_pull_review(owner: str, repo: str, index: int, event: str,
                       body: str = "", comments: Optional[list[dict]] = None) -> str:
    """Submit a review. event: APPROVED|REQUEST_CHANGES|COMMENT. comments is an
    optional list of inline comments: {"path": "file.py", "body": "...",
    "new_position": 12} (new_position = line in the new file)."""
    if event not in {"APPROVED", "REQUEST_CHANGES", "COMMENT"}:
        return json.dumps({"error": "event must be APPROVED|REQUEST_CHANGES|COMMENT"})
    return _req("POST", f"/repos/{owner}/{repo}/pulls/{index}/reviews",
                body={"event": event, "body": body, "comments": comments})


@mcp.tool()
def dismiss_pull_review(owner: str, repo: str, index: int, review_id: int,
                        message: str = "") -> str:
    """Dismiss a review (e.g. a stale approval) with an explanatory message."""
    return _req("POST",
                f"/repos/{owner}/{repo}/pulls/{index}/reviews/{review_id}/dismissals",
                body={"message": message})


@mcp.tool()
def request_reviewers(owner: str, repo: str, index: int,
                      reviewers: list[str]) -> str:
    """Request reviews from the given usernames on a pull request."""
    return _req("POST", f"/repos/{owner}/{repo}/pulls/{index}/requested_reviewers",
                body={"reviewers": reviewers})


@mcp.tool()
def remove_requested_reviewers(owner: str, repo: str, index: int,
                               reviewers: list[str]) -> str:
    """Cancel review requests for the given usernames."""
    return _req("DELETE", f"/repos/{owner}/{repo}/pulls/{index}/requested_reviewers",
                body={"reviewers": reviewers})


# ==========================================================================
# 10. RELEASES
# ==========================================================================

@mcp.tool()
def list_releases(owner: str, repo: str, page: int = 1, limit: int = 20) -> str:
    """List releases (newest first)."""
    return _req("GET", f"/repos/{owner}/{repo}/releases", params=_page(page, limit))


@mcp.tool()
def get_release(owner: str, repo: str, release_id: int) -> str:
    """One release by id."""
    return _req("GET", f"/repos/{owner}/{repo}/releases/{release_id}")


@mcp.tool()
def get_latest_release(owner: str, repo: str) -> str:
    """The latest published (non-draft, non-prerelease) release."""
    return _req("GET", f"/repos/{owner}/{repo}/releases/latest")


@mcp.tool()
def create_release(owner: str, repo: str, tag_name: str, name: Optional[str] = None,
                   body: str = "", target: Optional[str] = None,
                   draft: bool = False, prerelease: bool = False) -> str:
    """Create a release from a tag (the tag is created at target if it doesn't
    exist)."""
    return _req("POST", f"/repos/{owner}/{repo}/releases", body={
        "tag_name": tag_name, "name": name or tag_name, "body": body,
        "target_commitish": target, "draft": draft, "prerelease": prerelease})


@mcp.tool()
def edit_release(owner: str, repo: str, release_id: int,
                 name: Optional[str] = None, body: Optional[str] = None,
                 draft: Optional[bool] = None, prerelease: Optional[bool] = None) -> str:
    """Edit a release — only passed fields change."""
    return _req("PATCH", f"/repos/{owner}/{repo}/releases/{release_id}", body={
        "name": name, "body": body, "draft": draft, "prerelease": prerelease})


@mcp.tool()
def delete_release(owner: str, repo: str, release_id: int) -> str:
    """Delete a release (the git tag remains)."""
    return _req("DELETE", f"/repos/{owner}/{repo}/releases/{release_id}")


# ==========================================================================
# 11. WEBHOOKS & DEPLOY KEYS
# ==========================================================================

@mcp.tool()
def list_webhooks(owner: str, repo: str) -> str:
    """Webhooks configured on a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/hooks")


@mcp.tool()
def create_webhook(owner: str, repo: str, url: str,
                   events: Optional[list[str]] = None, secret: str = "",
                   active: bool = True, content_type: str = "json") -> str:
    """Create a webhook. events default to ["push"]; common events: push,
    create, delete, pull_request, issues, issue_comment, release."""
    return _req("POST", f"/repos/{owner}/{repo}/hooks", body={
        "type": "gitea", "active": active, "events": events or ["push"],
        "config": {"url": url, "content_type": content_type,
                   **({"secret": secret} if secret else {})}})


@mcp.tool()
def edit_webhook(owner: str, repo: str, hook_id: int,
                 url: Optional[str] = None, events: Optional[list[str]] = None,
                 active: Optional[bool] = None) -> str:
    """Edit a webhook (url/events/active)."""
    body: dict[str, Any] = {"events": events, "active": active}
    if url:
        body["config"] = {"url": url, "content_type": "json"}
    return _req("PATCH", f"/repos/{owner}/{repo}/hooks/{hook_id}", body=body)


@mcp.tool()
def delete_webhook(owner: str, repo: str, hook_id: int) -> str:
    """Delete a webhook."""
    return _req("DELETE", f"/repos/{owner}/{repo}/hooks/{hook_id}")


@mcp.tool()
def list_deploy_keys(owner: str, repo: str) -> str:
    """Deploy keys of a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/keys")


@mcp.tool()
def add_deploy_key(owner: str, repo: str, title: str, key: str,
                   read_only: bool = True) -> str:
    """Add a deploy key (SSH public key granting repo access to automation)."""
    return _req("POST", f"/repos/{owner}/{repo}/keys",
                body={"title": title, "key": key, "read_only": read_only})


@mcp.tool()
def delete_deploy_key(owner: str, repo: str, key_id: int) -> str:
    """Remove a deploy key."""
    return _req("DELETE", f"/repos/{owner}/{repo}/keys/{key_id}")


# ==========================================================================
# 12. COLLABORATORS, ORGS & TEAMS
# ==========================================================================

@mcp.tool()
def list_collaborators(owner: str, repo: str, page: int = 1, limit: int = 30) -> str:
    """Users with direct access to a repository."""
    return _req("GET", f"/repos/{owner}/{repo}/collaborators",
                params=_page(page, limit))


@mcp.tool()
def add_collaborator(owner: str, repo: str, username: str,
                     permission: str = "write") -> str:
    """Grant a user access to a repository. permission: read|write|admin."""
    if permission not in {"read", "write", "admin"}:
        return json.dumps({"error": "permission must be read|write|admin"})
    return _req("PUT", f"/repos/{owner}/{repo}/collaborators/{username}",
                body={"permission": permission})


@mcp.tool()
def remove_collaborator(owner: str, repo: str, username: str) -> str:
    """Revoke a user's access to a repository."""
    return _req("DELETE", f"/repos/{owner}/{repo}/collaborators/{username}")


@mcp.tool()
def get_org(org: str) -> str:
    """Organization profile."""
    return _req("GET", f"/orgs/{org}")


@mcp.tool()
def create_org(username: str, full_name: str = "", description: str = "",
               visibility: str = "private") -> str:
    """Create an organization. visibility: public|limited|private."""
    if visibility not in {"public", "limited", "private"}:
        return json.dumps({"error": "visibility must be public|limited|private"})
    return _req("POST", "/orgs", body={
        "username": username, "full_name": full_name,
        "description": description, "visibility": visibility})


@mcp.tool()
def edit_org(org: str, full_name: Optional[str] = None,
             description: Optional[str] = None,
             visibility: Optional[str] = None) -> str:
    """Edit organization settings — only passed fields change."""
    return _req("PATCH", f"/orgs/{org}", body={
        "full_name": full_name, "description": description,
        "visibility": visibility})


@mcp.tool()
def list_org_members(org: str, page: int = 1, limit: int = 30) -> str:
    """Members of an organization."""
    return _req("GET", f"/orgs/{org}/members", params=_page(page, limit))


@mcp.tool()
def list_org_teams(org: str, page: int = 1, limit: int = 30) -> str:
    """Teams in an organization."""
    return _req("GET", f"/orgs/{org}/teams", params=_page(page, limit))


@mcp.tool()
def create_team(org: str, name: str, description: str = "",
                permission: str = "write", can_create_org_repo: bool = False) -> str:
    """Create a team in an organization. permission: read|write|admin."""
    if permission not in {"read", "write", "admin"}:
        return json.dumps({"error": "permission must be read|write|admin"})
    return _req("POST", f"/orgs/{org}/teams", body={
        "name": name, "description": description, "permission": permission,
        "can_create_org_repo": can_create_org_repo,
        "units": ["repo.code", "repo.issues", "repo.pulls", "repo.releases",
                  "repo.wiki"]})


@mcp.tool()
def delete_team(team_id: int) -> str:
    """Delete a team by id."""
    return _req("DELETE", f"/teams/{team_id}")


@mcp.tool()
def add_team_member(team_id: int, username: str) -> str:
    """Add a user to a team."""
    return _req("PUT", f"/teams/{team_id}/members/{username}")


@mcp.tool()
def remove_team_member(team_id: int, username: str) -> str:
    """Remove a user from a team."""
    return _req("DELETE", f"/teams/{team_id}/members/{username}")


@mcp.tool()
def add_team_repo(team_id: int, org: str, repo: str) -> str:
    """Give a team access to a repository."""
    return _req("PUT", f"/teams/{team_id}/repos/{org}/{repo}")


@mcp.tool()
def remove_team_repo(team_id: int, org: str, repo: str) -> str:
    """Revoke a team's access to a repository."""
    return _req("DELETE", f"/teams/{team_id}/repos/{org}/{repo}")


# ==========================================================================
# resources & prompts
# ==========================================================================

@mcp.resource("gitea://profile")
def profile_resource() -> str:
    """Readable resource: the authenticated user and server version."""
    return json.dumps({
        "server": _json_or_err(_req("GET", "/version")),
        "user": _json_or_err(_req("GET", "/user")),
    }, ensure_ascii=False, default=str)


@mcp.prompt()
def triage_repository(owner: str, repo: str) -> str:
    """Prompt template: triage a repository's open work."""
    return (f"Triage the repository {owner}/{repo}:\n"
            "1. list_issues and list_pull_requests (state=open).\n"
            "2. Flag PRs with failing statuses (list_commit_statuses on their heads).\n"
            "3. Flag issues with no assignee and no labels.\n"
            "4. Summarize: what needs review, what is blocked, what is stale.")


if __name__ == "__main__":
    mcp.run()  # stdio
