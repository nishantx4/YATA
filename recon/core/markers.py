"""
Deterministic, per-scan probe markers.

Injection modules (SSTI, CMDi, second-order, stored-XSS, LDAP/XPath, …)
sprinkle unique random markers into payloads and then look for them coming
back, so a reflected marker proves evaluation/persistence rather than
coincidence. Two problems with ad-hoc random markers:

  * Reproducibility — a confirmed finding's exact payload couldn't be
    regenerated for a report or a re-test, because the marker was lost the
    moment the process exited.
  * Collision safety — nothing guaranteed two concurrent modules wouldn't
    pick the same short token and cross-match each other's reflections.

A per-scan seed (derived from the target + a scan nonce) gives every marker a
stable, namespaced, collision-resistant value: the same scan regenerates the
same sequence, and the token embeds a scan-unique prefix so no two scans — or
two modules — ever share one.
"""
import hashlib
import itertools
import threading
import time

_LOCK = threading.Lock()
_STATE = {"seed": None, "counter": itertools.count(1)}


def seed_scan(target: str, nonce: str | None = None):
    """Seed the marker namespace for a scan. Call once at scan start."""
    base = f"{target}|{nonce or time.time()}"
    digest = hashlib.sha256(base.encode("utf-8", "replace")).hexdigest()
    with _LOCK:
        _STATE["seed"] = digest[:8]
        _STATE["counter"] = itertools.count(1)


def _seed() -> str:
    with _LOCK:
        if _STATE["seed"] is None:
            # Not explicitly seeded (e.g. a module run standalone in a test):
            # fall back to a time-based seed so markers are still unique.
            _STATE["seed"] = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        return _STATE["seed"]


def marker(prefix: str = "gr") -> str:
    """A scan-unique, lowercase, alphanumeric marker safe to embed in HTML,
    JSON, shell, SQL, and template contexts (no quotes, spaces, or markup
    characters). Deterministic within a seeded scan."""
    with _LOCK:
        n = next(_STATE["counter"])
    tok = hashlib.sha1(f"{_seed()}:{n}".encode()).hexdigest()[:10]
    return f"{prefix}{tok}"


def marker_pair(prefix: str = "gr") -> tuple[str, str]:
    """A (left, right) wrapper pair, e.g. for `left<payload>right` discipline
    where you want to prove the thing BETWEEN the markers was transformed."""
    m = marker(prefix)
    return f"{m}a", f"{m}b"
