"""
Recon cache — incremental/cached recon.

Re-running a scan against the same target used to redo subdomain
enumeration, OpenAPI discovery, JS mining, and the full crawl from scratch
every single time. For a target scanned repeatedly (continuous monitoring,
iterative bug hunting over a few days) that's pure wasted time re-deriving
data that almost certainly hasn't changed. This caches everything
ReconModule writes into ctx, keyed by target, with a TTL — a fresh-enough
cache is loaded straight into ctx and the crawl/subdomain-enum/JS-mining
phases are skipped entirely. `--fresh-recon` forces a full re-crawl.
"""
import json
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".yata-recon" / "recon_cache"
DEFAULT_TTL = 6 * 3600  # 6 hours

# Only these keys are ever cached — everything else in ctx (auth headers,
# captured credentials, the baseline profile, second-identity creds, ...)
# is per-scan state that should never be silently reused across runs.
CACHED_KEYS = [
    "subdomains", "endpoints", "forms", "api_endpoints", "api_spec_url",
    "js_params", "harvested_object_ids", "probe_targets", "base_url",
    "ai_priority_endpoints",
]


def _cache_path(target: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)
    return CACHE_DIR / f"{safe}.json"


def load(target: str, ttl: int = DEFAULT_TTL) -> dict | None:
    """Return a cached ctx-subset dict if one exists and is fresh enough,
    else None (caller should do a normal full recon)."""
    path = _cache_path(target)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    age = time.time() - data.get("_cached_at", 0)
    if age > ttl:
        return None

    ctx = data.get("ctx", {})
    if "harvested_object_ids" in ctx:
        ctx["harvested_object_ids"] = set(ctx["harvested_object_ids"])  # serialized as a list
    return ctx


def save(target: str, ctx: dict):
    """Persist the cacheable subset of ctx for this target."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        snapshot = {}
        for key in CACHED_KEYS:
            if key not in ctx:
                continue
            val = ctx[key]
            if isinstance(val, set):
                val = sorted(val)
            snapshot[key] = val
        with open(_cache_path(target), "w", encoding="utf-8") as f:
            json.dump({"_cached_at": time.time(), "ctx": snapshot}, f, indent=2, ensure_ascii=False)
    except Exception:
        pass  # caching is a pure optimization — never let it break a scan


def clear(target: str | None = None):
    """Delete one target's cache, or the whole cache dir if target is None."""
    if target is None:
        if CACHE_DIR.exists():
            for f in CACHE_DIR.glob("*.json"):
                try:
                    f.unlink()
                except Exception:
                    pass
        return
    path = _cache_path(target)
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass
