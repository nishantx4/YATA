"""
False-positive feedback loop — lets the person running a scan mark a
specific finding as a false positive, then feeds that back into confidence
scoring for every finding (this scan and future scans) that matches the
same pattern. Stored at ~/.yata-recon/fp_feedback.json.

Findings are matched by a NORMALIZED signature, not an exact (title, url)
string — a title template already collapses per-object IDs in some
modules (e.g. idor.py reports "...at {prefix}<id>{suffix}"), but plenty of
modules report the concrete URL. Marking one IDOR false positive at
/api/user/104 should also suppress the same pattern recurring at
/api/user/205 on a later scan, which is why the URL is shape-normalized
(digits and UUIDs collapsed to placeholders) before hashing.
"""
import json
import re
import urllib.parse
from pathlib import Path

FEEDBACK_FILE = Path.home() / ".yata-recon" / "fp_feedback.json"

_NUM_RE = re.compile(r'\b\d+\b')
_UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')


def _load() -> dict:
    if not FEEDBACK_FILE.exists():
        return {}
    try:
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    try:
        FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _normalize_url_shape(url: str) -> str:
    shaped = _UUID_RE.sub('{uuid}', url or "")
    shaped = _NUM_RE.sub('{n}', shaped)
    try:
        parsed = urllib.parse.urlparse(shaped)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower()
    except Exception:
        return shaped.lower()


def _signature(title: str, url: str) -> str:
    # Title is also digit/uuid-normalized for the same reason as the URL —
    # e.g. "JWT Weak HMAC Secret ('secret')" style titles that embed a
    # discovered value shouldn't each get their own independent signature.
    title_shaped = _NUM_RE.sub('{n}', (title or "").lower().strip())
    return f"{title_shaped}|{_normalize_url_shape(url)}"


def mark_false_positive(title: str, url: str, note: str = "") -> str:
    """Record one false-positive marking. Returns the signature it was
    filed under (useful for confirming what will be suppressed)."""
    data = _load()
    sig = _signature(title, url)
    entry = data.setdefault(sig, {"count": 0, "title": title, "url_example": url, "notes": []})
    entry["count"] += 1
    entry["title"] = title  # keep the most recent human-readable example
    entry["url_example"] = url
    if note:
        entry["notes"].append(note)
        entry["notes"] = entry["notes"][-10:]  # cap growth
    _save(data)
    return sig


def is_known_false_positive(title: str, url: str) -> tuple[bool, int]:
    """Returns (is_fp, times_marked)."""
    data = _load()
    entry = data.get(_signature(title, url))
    if not entry:
        return False, 0
    return True, entry.get("count", 0)


def confidence_penalty(title: str, url: str) -> int:
    """
    Points to subtract from a new finding's confidence_score when it
    matches a signature marked false-positive before. Scales with how many
    times the SAME pattern has been marked — a pattern dismissed 5 times
    across different scans/targets is much stronger evidence than a single
    one-off marking, so it's downweighted harder (but never to zero on its
    own — a human should still see it was flagged and can override).
    """
    is_fp, count = is_known_false_positive(title, url)
    if not is_fp:
        return 0
    return min(60, 20 + count * 10)


def list_feedback() -> dict:
    return _load()


def clear_feedback():
    _save({})
