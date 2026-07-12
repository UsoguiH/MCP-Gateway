"""qdrant-mcp — governed vector search / semantic memory for the gateway.

Gives an AI a searchable long-term memory: store passages, find them again by meaning
rather than keyword. That is genuinely useful — and it is also a place where organizational
knowledge accumulates outside your normal document controls, so it is governed like any
other data source.

Configuration (environment; never via model-visible args):

  QDRANT_URL         REQUIRED, e.g. http://qdrant:6333
  QDRANT_API_KEY     optional (or QDRANT_API_KEY_FILE for a Docker secret — the file wins)
  QDRANT_COLLECTIONS REQUIRED. Comma-separated collection allow-list, optionally with an
                     NDMO classification and a read-only marker:
                       notes:restricted, kb:public:ro, hr-memory:secret
                     A collection that is not listed does not exist as far as this server
                     is concerned — it cannot be read, written, or even seen.
  QDRANT_EMBED_MODEL fastembed model for text→vector (default BAAI/bge-small-en-v1.5).
                     Without fastembed installed, text tools return a structured error and
                     the vector tools still work.
  QDRANT_MAX_RESULTS      cap on returned points (default 50)
  QDRANT_MAX_TEXT_BYTES   cap on the text stored in one point (default 20_000)
  QDRANT_ALLOW_DELETE_COLLECTION  "1" to expose delete_collection. OFF by default:
                     dropping a collection destroys knowledge irreversibly, and no amount
                     of approval workflow un-deletes it.

Safety model:
  * **Allow-list first.** Every operation resolves the collection against
    QDRANT_COLLECTIONS. Unlisted ⇒ refused, and not enumerated.
  * **Per-collection classification.** Every returned point carries its collection's NDMO
    label, so the gateway's clearance gate and DLP treat retrieved passages exactly like
    any other document. A vector store must not become a laundering route for secrets.
  * **Read-only collections.** Mark a collection `:ro` and every write to it is refused at
    this layer, independently of the caller's role.
  * **DLP still applies.** Text is returned as text; the gateway masks Saudi PII on the way
    out, as it does for any tool result.
  * **Destructive operations are opt-in and narrow.** delete_collection is off by default;
    delete_points requires an explicit filter or explicit ids — never "delete everything".
  * Lazy connect: with nothing configured the server still boots and every call returns a
    structured error, so the gateway never crashes on discovery.
"""
import contextlib
import io
import json
import os
import uuid
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("qdrant")

# The HTTP client logs every request at INFO. Depending on how logging is configured that
# can reach stdout — which is the MCP protocol channel. Keep the channel clean.
import logging  # noqa: E402
for _noisy in ("httpx", "httpcore", "qdrant_client", "fastembed"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

MAX_RESULTS = int(os.environ.get("QDRANT_MAX_RESULTS", 50))
MAX_TEXT = int(os.environ.get("QDRANT_MAX_TEXT_BYTES", 20_000))
EMBED_MODEL = os.environ.get("QDRANT_EMBED_MODEL", "BAAI/bge-small-en-v1.5")

_client = None
_embedder = None


def _err(msg: str, **extra) -> str:
    return json.dumps({"error": msg, **extra}, ensure_ascii=False)


def _api_key() -> Optional[str]:
    f = os.environ.get("QDRANT_API_KEY_FILE", "").strip()
    if f and Path(f).exists():
        return Path(f).read_text(encoding="utf-8").strip()      # Docker secret wins
    return os.environ.get("QDRANT_API_KEY") or None


# --------------------------------------------------------------------------
# collection allow-list:  name[:classification[:ro]]
# --------------------------------------------------------------------------

def _collections() -> dict[str, dict]:
    raw = (os.environ.get("QDRANT_COLLECTIONS") or "").strip()
    out: dict[str, dict] = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = [p.strip() for p in chunk.split(":")]
        name = parts[0]
        classification = parts[1] if len(parts) > 1 and parts[1] else "restricted"
        readonly = len(parts) > 2 and parts[2].lower() in ("ro", "readonly", "read-only")
        out[name] = {"classification": classification, "readonly": readonly}
    return out


def _admit(name: str, write: bool = False) -> tuple[Optional[dict], Optional[str]]:
    cols = _collections()
    if not cols:
        return None, ("qdrant-mcp is not configured: set QDRANT_COLLECTIONS to a "
                      "comma-separated allow-list, e.g. 'notes:restricted, kb:public:ro'")
    spec = cols.get(name)
    if not spec:
        # Do not reveal whether it exists in Qdrant — unlisted means invisible.
        return None, f"collection '{name}' is not allow-listed. Available: {sorted(cols)}"
    if write and spec["readonly"]:
        return None, (f"collection '{name}' is read-only on this gateway "
                      "(marked ':ro' in QDRANT_COLLECTIONS)")
    return spec, None


def _connect():
    global _client
    if _client is not None:
        return _client, None
    url = (os.environ.get("QDRANT_URL") or "").strip()
    if not url:
        return None, "qdrant-mcp is not configured: set QDRANT_URL (e.g. http://qdrant:6333)"
    try:
        from qdrant_client import QdrantClient
    except ImportError:
        return None, "qdrant-client is not installed on the gateway host"
    try:
        _client = QdrantClient(url=url, api_key=_api_key(), timeout=20)
        _client.get_collections()                    # fail fast, with a clear message
    except Exception as e:
        _client = None
        return None, f"cannot reach Qdrant at {url}: {type(e).__name__}: {str(e)[:160]}"
    return _client, None


def _embed_blocking(texts: list[str]) -> tuple[Optional[list[list[float]]], Optional[str]]:
    """Text → vectors, via fastembed (local, offline model — nothing leaves the host).

    stdout is muzzled: fastembed prints a model-download progress bar, and THIS SERVER
    SPEAKS MCP OVER STDOUT. Those progress bytes would land inside the JSON-RPC stream and
    desynchronise the transport. Nothing but MCP frames may reach stdout.
    """
    global _embedder
    try:
        from fastembed import TextEmbedding
    except ImportError:
        return None, ("text search needs fastembed (pip install fastembed), or pass vectors "
                      "directly to search_vectors / upsert_vectors")
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if _embedder is None:
                _embedder = TextEmbedding(model_name=EMBED_MODEL)
            return [list(map(float, v)) for v in _embedder.embed(texts)], None
    except Exception as e:
        return None, f"embedding failed: {type(e).__name__}: {str(e)[:160]}"


async def _embed(texts: list[str]) -> tuple[Optional[list[list[float]]], Optional[str]]:
    """Embed OFF the event loop. Running a CPU-bound model inline would freeze the server:
    it stops answering MCP frames, the client times out, and it looks like a hang."""
    import anyio
    return await anyio.to_thread.run_sync(_embed_blocking, texts)


def _query(client, collection: str, vector: list[float], limit: int,
           score_threshold: Optional[float] = None) -> list:
    """Vector search across qdrant-client versions.

    1.12+ replaced `search()` with `query_points()` (and returns a wrapper with `.points`).
    Older versions only have `search()`. Supporting both means an operator can pin whichever
    client their environment already has, instead of a version bump silently turning search
    into an error at runtime.
    """
    if hasattr(client, "query_points"):
        res = client.query_points(collection_name=collection, query=vector, limit=limit,
                                  score_threshold=score_threshold, with_payload=True)
        return list(getattr(res, "points", res))
    return client.search(collection_name=collection, query_vector=vector, limit=limit,
                         score_threshold=score_threshold, with_payload=True)


def _cap_text(t: str) -> str:
    raw = (t or "").encode("utf-8")
    return raw[:MAX_TEXT].decode("utf-8", "ignore") if len(raw) > MAX_TEXT else (t or "")


def _point_out(p, classification: str) -> dict:
    payload = dict(getattr(p, "payload", None) or {})
    return {
        "id": str(getattr(p, "id", "")),
        "score": round(float(p.score), 5) if getattr(p, "score", None) is not None else None,
        "text": payload.pop("text", None),
        "metadata": payload,
        "classification": classification,     # governed like any other document
    }


# --------------------------------------------------------------------------
# tools — read
# --------------------------------------------------------------------------

@mcp.tool()
def list_collections() -> str:
    """The collections this gateway permits, with their classification, whether they are
    read-only, and how many points each holds. Unlisted collections are invisible."""
    cols = _collections()
    if not cols:
        return _err("qdrant-mcp is not configured: set QDRANT_COLLECTIONS")
    client, why = _connect()
    if why:
        return _err(why)
    out = []
    for name, spec in sorted(cols.items()):
        row = {"name": name, "classification": spec["classification"],
               "readonly": spec["readonly"]}
        try:
            info = client.get_collection(name)
            row["points"] = info.points_count
            row["vector_size"] = (info.config.params.vectors.size
                                  if hasattr(info.config.params.vectors, "size") else None)
            row["exists"] = True
        except Exception:
            row["exists"] = False
            row["points"] = 0
        out.append(row)
    return json.dumps({"collections": out, "count": len(out)}, ensure_ascii=False)


@mcp.tool()
async def search(collection: str, query: str, limit: int = 5,
           score_threshold: float = 0.0) -> str:
    """Semantic search: find the passages that MEAN the same thing as `query`, not just the
    ones containing the same words. This is the tool you want most of the time."""
    spec, why = _admit(collection)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    if not (query or "").strip():
        return _err("query is required")

    vectors, why = await _embed([query])
    if why:
        return _err(why, hint="or use search_vectors with a precomputed vector")

    limit = max(1, min(int(limit), MAX_RESULTS))
    try:
        hits = _query(client, collection, vectors[0], limit,
                      score_threshold=score_threshold or None)
    except Exception as e:
        return _err(f"search failed: {type(e).__name__}: {str(e)[:160]}",
                    collection=collection)
    return json.dumps({
        "collection": collection, "query": query,
        "classification": spec["classification"],
        "results": [_point_out(h, spec["classification"]) for h in hits],
        "count": len(hits),
    }, ensure_ascii=False)


@mcp.tool()
def search_vectors(collection: str, vector: list, limit: int = 5) -> str:
    """Search with a vector you already have — for callers that do their own embedding, or
    when fastembed is not installed on the gateway host."""
    if not isinstance(vector, list) or not vector:
        return _err("vector must be a non-empty array of numbers")
    try:
        vec = [float(x) for x in vector]
    except (TypeError, ValueError):
        return _err("vector must contain only numbers")
    spec, why = _admit(collection)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)

    limit = max(1, min(int(limit), MAX_RESULTS))
    try:
        hits = _query(client, collection, vec, limit)
    except Exception as e:
        return _err(f"search failed: {type(e).__name__}: {str(e)[:160]}",
                    collection=collection)
    return json.dumps({
        "collection": collection, "classification": spec["classification"],
        "results": [_point_out(h, spec["classification"]) for h in hits],
        "count": len(hits),
    }, ensure_ascii=False)


@mcp.tool()
def get_point(collection: str, point_id: str) -> str:
    """Retrieve one stored passage by its id."""
    spec, why = _admit(collection)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    try:
        got = client.retrieve(collection_name=collection, ids=[point_id],
                              with_payload=True)
    except Exception as e:
        return _err(f"retrieve failed: {type(e).__name__}: {str(e)[:160]}")
    if not got:
        return _err(f"no point '{point_id}' in '{collection}'")
    return json.dumps({"collection": collection,
                       "point": _point_out(got[0], spec["classification"])},
                      ensure_ascii=False)


@mcp.tool()
def count_points(collection: str) -> str:
    """How many passages a collection holds."""
    spec, why = _admit(collection)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    try:
        n = client.count(collection_name=collection, exact=True).count
    except Exception as e:
        return _err(f"count failed: {type(e).__name__}: {str(e)[:160]}")
    return json.dumps({"collection": collection, "points": n,
                       "classification": spec["classification"]}, ensure_ascii=False)


# --------------------------------------------------------------------------
# tools — write
# --------------------------------------------------------------------------

@mcp.tool()
def create_collection(collection: str, vector_size: int = 384,
                      distance: str = "Cosine") -> str:
    """Create an allow-listed collection that does not exist yet. The name must already be
    in QDRANT_COLLECTIONS — this server cannot invent new governed namespaces at runtime."""
    spec, why = _admit(collection, write=True)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    if distance not in ("Cosine", "Euclid", "Dot", "Manhattan"):
        return _err("distance must be one of Cosine, Euclid, Dot, Manhattan")
    try:
        from qdrant_client.models import Distance, VectorParams
        if client.collection_exists(collection):
            return _err(f"collection '{collection}' already exists")
        client.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=int(vector_size),
                                        distance=Distance[distance.upper()]))
    except Exception as e:
        return _err(f"create failed: {type(e).__name__}: {str(e)[:160]}")
    return json.dumps({"created": collection, "vector_size": int(vector_size),
                       "distance": distance,
                       "classification": spec["classification"]}, ensure_ascii=False)


@mcp.tool()
async def store(collection: str, text: str, metadata: Optional[dict] = None,
          point_id: str = "") -> str:
    """Store a passage so it can be found later by meaning. The text is embedded locally —
    nothing is sent to an external service."""
    spec, why = _admit(collection, write=True)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    text = _cap_text(text)
    if not text.strip():
        return _err("text is required")

    vectors, why = await _embed([text])
    if why:
        return _err(why, hint="or use upsert_vectors with a precomputed vector")

    pid = point_id or str(uuid.uuid4())
    payload = {"text": text, **(metadata or {})}
    try:
        from qdrant_client.models import PointStruct
        client.upsert(collection_name=collection,
                      points=[PointStruct(id=pid, vector=vectors[0], payload=payload)])
    except Exception as e:
        return _err(f"store failed: {type(e).__name__}: {str(e)[:160]}",
                    hint="does the collection exist? create_collection first")
    return json.dumps({"stored": pid, "collection": collection,
                       "text_bytes": len(text.encode("utf-8")),
                       "classification": spec["classification"]}, ensure_ascii=False)


@mcp.tool()
def upsert_vectors(collection: str, points: list) -> str:
    """Insert or update points with vectors you supply.
    `points` is [{"id","vector":[...],"payload":{...}}, ...]."""
    if not isinstance(points, list) or not points:
        return _err("points must be a non-empty array")
    if len(points) > MAX_RESULTS:
        return _err(f"at most {MAX_RESULTS} points per call")
    spec, why = _admit(collection, write=True)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)

    try:
        from qdrant_client.models import PointStruct
        structs = []
        for p in points:
            if not isinstance(p, dict) or "vector" not in p:
                return _err("each point needs a 'vector'")
            payload = dict(p.get("payload") or {})
            if "text" in payload:
                payload["text"] = _cap_text(payload["text"])
            structs.append(PointStruct(id=p.get("id") or str(uuid.uuid4()),
                                       vector=[float(x) for x in p["vector"]],
                                       payload=payload))
        client.upsert(collection_name=collection, points=structs)
    except Exception as e:
        return _err(f"upsert failed: {type(e).__name__}: {str(e)[:160]}")
    return json.dumps({"upserted": len(structs), "collection": collection,
                       "classification": spec["classification"]}, ensure_ascii=False)


@mcp.tool()
def delete_points(collection: str, point_ids: list) -> str:
    """Delete specific passages by id.

    Explicit ids only — there is deliberately no "delete everything matching" form, because
    an AI that misreads a filter should not be able to empty a knowledge base in one call.
    """
    # Validate the request BEFORE touching the network: a caller who sent nonsense should be
    # told that, not handed a connection error that hides it.
    if not isinstance(point_ids, list) or not point_ids:
        return _err("point_ids must be a non-empty array of ids")
    if len(point_ids) > MAX_RESULTS:
        return _err(f"at most {MAX_RESULTS} ids per call")
    spec, why = _admit(collection, write=True)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    try:
        client.delete(collection_name=collection,
                      points_selector=[str(i) for i in point_ids])
    except Exception as e:
        return _err(f"delete failed: {type(e).__name__}: {str(e)[:160]}")
    return json.dumps({"deleted": len(point_ids), "collection": collection},
                      ensure_ascii=False)


@mcp.tool()
def delete_collection(collection: str, confirm: bool = False) -> str:
    """Destroy a collection and everything in it.

    Disabled unless QDRANT_ALLOW_DELETE_COLLECTION=1, and requires confirm=true. There is no
    undo: an approval workflow can stop the call, but nothing brings the knowledge back.
    """
    if os.environ.get("QDRANT_ALLOW_DELETE_COLLECTION", "") not in ("1", "true", "yes"):
        return _err("delete_collection is disabled on this gateway "
                    "(set QDRANT_ALLOW_DELETE_COLLECTION=1 to enable)")
    if not confirm:
        return _err("refusing to drop a collection without confirm=true — this is "
                    "irreversible and destroys every passage in it")
    _spec, why = _admit(collection, write=True)
    if why:
        return _err(why)
    client, why = _connect()
    if why:
        return _err(why)
    try:
        client.delete_collection(collection_name=collection)
    except Exception as e:
        return _err(f"delete failed: {type(e).__name__}: {str(e)[:160]}")
    return json.dumps({"deleted_collection": collection}, ensure_ascii=False)


if __name__ == "__main__":
    # Warm the embedding model BEFORE the MCP transport takes over stdout. fastembed's first
    # use loads (and on a cold host, downloads) the model, printing a progress bar and doing
    # blocking I/O. Triggered inside the first `search`, in a process whose stdout is the MCP
    # pipe, that stalled the request. Pay it once, at boot, with stdout muzzled. It is
    # best-effort: a host without fastembed still serves the vector-only tools.
    try:
        _embed_blocking(["warmup"])
    except Exception:
        pass
    mcp.run()   # stdio
