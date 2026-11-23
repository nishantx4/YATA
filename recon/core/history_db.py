"""
Persistent finding history — a local SQLite database of every past
scan/finding per target, at ~/.yata-recon/history.db.

Diff mode (core/diff.py) only ever compares against the single most recent
previous scan. This is the real trend-tracking store behind it: every scan
this tool ever runs gets recorded here, so "how has this target's risk
posture changed over the last N scans" or "when did this specific finding
first appear" are answerable without re-parsing old JSON report files.
"""
import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path.home() / ".yata-recon" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT NOT NULL,
    timestamp     REAL NOT NULL,
    modules       TEXT,
    finding_count INTEGER,
    risk_score    INTEGER,
    sev_critical  INTEGER DEFAULT 0,
    sev_high      INTEGER DEFAULT 0,
    sev_medium    INTEGER DEFAULT 0,
    sev_low       INTEGER DEFAULT 0,
    sev_info      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id),
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    url              TEXT,
    module           TEXT,
    confidence       TEXT,
    confidence_score INTEGER,
    cvss             TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_title_url ON findings(title, url);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")  # tolerate concurrent module writes without locking errors
    conn.executescript(_SCHEMA)
    return conn


def record_scan(target: str, findings: list, modules: list, risk_score: int) -> int | None:
    """Persist one completed scan and all its findings. Returns the new
    scan id, or None on any failure — history is a nice-to-have, never
    something that should break a scan's normal save/report flow."""
    try:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1

        conn = _connect()
        with conn:
            cur = conn.execute(
                "INSERT INTO scans (target, timestamp, modules, finding_count, risk_score, "
                "sev_critical, sev_high, sev_medium, sev_low, sev_info) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (target, time.time(), json.dumps(modules), len(findings), risk_score,
                 counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]),
            )
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO findings (scan_id, title, severity, url, module, confidence, "
                "confidence_score, cvss) VALUES (?,?,?,?,?,?,?,?)",
                [(scan_id, f.get("title", ""), f.get("severity", "info"), f.get("url", ""),
                  f.get("module", ""), f.get("confidence", ""), f.get("confidence_score", 0),
                  f.get("cvss")) for f in findings],
            )
        conn.close()
        return scan_id
    except Exception:
        return None


def get_scan_history(target: str, limit: int = 20) -> list[dict]:
    """Return this target's past scans, most recent first."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT id, timestamp, finding_count, risk_score, sev_critical, sev_high, "
            "sev_medium, sev_low, sev_info FROM scans WHERE target = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        conn.close()
        return [
            {"id": r[0], "timestamp": r[1], "finding_count": r[2], "risk_score": r[3],
             "critical": r[4], "high": r[5], "medium": r[6], "low": r[7], "info": r[8]}
            for r in rows
        ]
    except Exception:
        return []


def get_finding_first_seen(target: str, title: str, url: str) -> float | None:
    """Return the timestamp this exact (title, url) finding was FIRST
    recorded for this target, or None if it's never been seen before."""
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT MIN(s.timestamp) FROM findings f JOIN scans s ON f.scan_id = s.id "
            "WHERE s.target = ? AND f.title = ? AND f.url = ?",
            (target, title, url),
        ).fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None


def get_global_stats(target: str | None = None) -> dict:
    """Aggregate personal scan stats across all history (or one target):
    totals, severity tally, busiest module, and the most-found finding title.
    Everything is best-effort — returns {} on any failure."""
    try:
        conn = _connect()
        scan_where = "WHERE target = ?" if target else ""
        scan_args = (target,) if target else ()
        srow = conn.execute(
            f"SELECT COUNT(*), COUNT(DISTINCT target), COALESCE(SUM(finding_count),0), "
            f"COALESCE(MAX(risk_score),0), COALESCE(AVG(risk_score),0), MIN(timestamp), MAX(timestamp) "
            f"FROM scans {scan_where}", scan_args).fetchone()

        join = "JOIN scans s ON f.scan_id = s.id"
        fwhere = "WHERE s.target = ?" if target else ""
        fargs = (target,) if target else ()
        sev = dict(conn.execute(
            f"SELECT f.severity, COUNT(*) FROM findings f {join} {fwhere} GROUP BY f.severity", fargs).fetchall())
        top_mod = conn.execute(
            f"SELECT f.module, COUNT(*) c FROM findings f {join} {fwhere} "
            f"GROUP BY f.module ORDER BY c DESC LIMIT 1", fargs).fetchone()
        top_title = conn.execute(
            f"SELECT f.title, COUNT(*) c FROM findings f {join} {fwhere} "
            f"GROUP BY f.title ORDER BY c DESC LIMIT 1", fargs).fetchone()
        conn.close()
        return {
            "scans": srow[0], "targets": srow[1], "findings": srow[2],
            "max_risk": srow[3], "avg_risk": round(srow[4], 1),
            "first_scan": srow[5], "last_scan": srow[6],
            "severity": sev,
            "top_module": (top_mod[0], top_mod[1]) if top_mod else None,
            "top_finding": (top_title[0], top_title[1]) if top_title else None,
        }
    except Exception:
        return {}


def get_all_targets(limit: int = 100) -> list[str]:
    """Return every distinct target ever scanned, most recently scanned first."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT target, MAX(timestamp) AS last_seen FROM scans "
            "GROUP BY target ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception:
        return []
