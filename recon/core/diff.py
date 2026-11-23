"""
Diff / continuous-monitoring mode — compares this scan's findings against
the most recent previous scan of the same target and reports what's NEW
(and what's been FIXED) since last time, instead of re-presenting the whole
finding set on every re-run of a target you monitor over time.
"""
import glob
import json
import os


def _finding_key(f):
    return (f.get('title', '').lower().strip(), f.get('url', '').lower().strip())


def _safe_base(target: str) -> str:
    base = target
    for ch in (':', '/', '\\', '*', '?', '"', '<', '>', '|'):
        base = base.replace(ch, '_')
    return base


def find_previous_report(output_dir: str, target: str, exclude_path: str | None = None) -> str | None:
    """Return the path to the most recent previous JSON report for this
    target in output_dir (excluding the one this exact scan just wrote)."""
    pattern = os.path.join(output_dir, f"yata_recon_{_safe_base(target)}_*.json")
    candidates = [p for p in glob.glob(pattern) if p != exclude_path]
    if not candidates:
        return None
    candidates.sort(key=os.path.getmtime, reverse=True)
    return candidates[0]


def diff_findings(previous_path: str, current_findings: list) -> dict:
    """Compare (title, url)-keyed findings between a previous report and the
    current scan. Returns {'new', 'fixed', 'unchanged', 'previous_scan_time'}."""
    try:
        with open(previous_path, 'r', encoding='utf-8') as f:
            prev_data = json.load(f)
    except Exception:
        return {"new": current_findings, "fixed": [], "unchanged": [], "previous_scan_time": None}

    prev_findings = prev_data.get('findings', [])
    prev_keys = {_finding_key(f) for f in prev_findings}
    curr_keys = {_finding_key(f) for f in current_findings}

    new_findings = [f for f in current_findings if _finding_key(f) not in prev_keys]
    fixed_findings = [f for f in prev_findings if _finding_key(f) not in curr_keys]
    unchanged = [f for f in current_findings if _finding_key(f) in prev_keys]

    return {
        "new": new_findings,
        "fixed": fixed_findings,
        "unchanged": unchanged,
        "previous_scan_time": prev_data.get('meta', {}).get('scan_time'),
    }
