"""
FindingsDB — central store for all vulnerabilities discovered during a scan
"""
import threading
from datetime import datetime


# Confidence label -> a sensible score floor, used ONLY to repair findings
# that were added with a confidence *label* but no explicit numeric score
# (they fell back to the add() default of 50). Historically many modules —
# sqli.py being the most important — report `confidence="high"` with no
# `confidence_score`, so every one of their findings scored a flat 50. That
# made the --confidence threshold meaningless (a CONFIRMED SQLi and a weak
# heuristic guess both scored 50) and is why --confidence was effectively
# dead. Normalizing from the label makes the threshold do what it says.
_LABEL_FLOOR = {"CONFIRMED": 95, "HIGH": 85, "MEDIUM": 60, "LOW": 35}

# Most-severe → least-severe; a lower index is more severe.
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


class FindingsDB:
    def __init__(self, event_callback=None, min_confidence=0, min_severity=None):
        self.findings = []
        self._seen = set()
        self.event_callback = event_callback
        # --confidence gate (0 = report everything). A finding whose
        # effective confidence score is below this is dropped rather than
        # recorded — this is the knob the near-zero-false-positive policy
        # actually hangs off of, and it was previously parsed on the CLI but
        # never wired to anything. Suppressed findings are counted so the
        # scan summary can say how many were filtered (transparency: the
        # user shouldn't silently lose findings they can't see a reason for).
        self.min_confidence = max(0, min(100, int(min_confidence or 0)))
        # --min-severity: drop anything LESS severe than this floor (e.g.
        # 'high' keeps only critical+high). None = no severity filtering.
        ms = (min_severity or "").lower().strip()
        self._min_sev_idx = _SEV_ORDER.index(ms) if ms in _SEV_ORDER else None
        self.suppressed = 0
        # Modules now run concurrently (core/session.py parallelizes
        # independent modules) — add() does a check-then-append on
        # self._seen/self.findings that's only safe under a lock once more
        # than one thread can call it at the same time.
        self._lock = threading.Lock()

    def add(self, title, severity, url, module, description='', remediation='',
            cvss=None, evidence=None, references=None, confidence='MEDIUM',
            confidence_score=50, validation_steps=None, external_tool=None):
        """
        Add a finding. Deduplicates on (title, url) pair.
        """
        key = (title.lower().strip(), url.lower().strip())
        sev = severity.lower()
        if sev not in ('critical', 'high', 'medium', 'low', 'info'):
            sev = 'info'

        # Normalize confidence label
        conf = confidence.upper()
        if conf not in ('CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'):
            conf = 'MEDIUM'

        score = max(0, min(100, confidence_score))
        # Repair a label-only finding: if the caller left confidence_score at
        # the add() default (50) but gave a meaningful label, derive the score
        # from the label so --confidence can actually discriminate. Callers
        # that pass an explicit score (anything != 50) are left untouched.
        if confidence_score == 50:
            score = _LABEL_FLOOR.get(conf, 50)

        # ── False-positive feedback loop ──────────────────────────────────
        # If a person previously marked a matching finding (same
        # title/url-shape signature — see core/fp_feedback.py) as a false
        # positive, downweight it here rather than silently suppressing it
        # outright: a human should still SEE it was flagged before and can
        # override, but it shouldn't compete for attention at its original
        # confidence. Never raises — a missing/corrupt feedback file must
        # never affect whether a finding gets recorded.
        fp_note = None
        try:
            from recon.core.fp_feedback import confidence_penalty
            penalty = confidence_penalty(title, url)
            if penalty:
                score = max(1, score - penalty)
                fp_note = f"Matches a pattern marked as a false positive in a previous scan (confidence reduced by {penalty})."
                if conf == 'CONFIRMED' and score < 95:
                    conf = 'HIGH'
                if conf == 'HIGH' and score < 75:
                    conf = 'MEDIUM'
                if conf == 'MEDIUM' and score < 50:
                    conf = 'LOW'
        except Exception:
            pass

        with self._lock:
            # Severity gate (--min-severity) — drop anything below the floor.
            if self._min_sev_idx is not None and _SEV_ORDER.index(sev) > self._min_sev_idx:
                self.suppressed += 1
                return False
            # Confidence gate (--confidence). Applied after label
            # normalization and the FP-feedback penalty so the number being
            # compared is the finding's true, final confidence.
            if score < self.min_confidence:
                self.suppressed += 1
                return False
            if key in self._seen:
                return False
            self._seen.add(key)

            ev = list(evidence or [])
            if fp_note:
                ev.append(fp_note)

            finding = {
                'id':               len(self.findings) + 1,
                'title':            title,
                'severity':         sev,
                'url':              url,
                'module':           module,
                'description':      description,
                'remediation':      remediation,
                'cvss':             cvss,
                'evidence':         ev,
                'references':       references or [],
                'confidence':       conf,
                'confidence_score': score,
                'validation_steps': validation_steps or [],
                'external_tool':    external_tool,
                'timestamp':        datetime.now().isoformat(),
            }
            self.findings.append(finding)

        if self.event_callback:
            try:
                self.event_callback("finding_added", finding)
                self.event_callback("severity_updated", self.severity_counts())
            except Exception:
                pass
                
        return True

    def restore(self, findings):
        """Bulk-load already-validated finding dicts from a scan checkpoint
        (ScanSession's --resume support) — these were already recorded
        (deduplicated, scored, FP-penalty-adjusted) by the run that got
        interrupted, so this re-seeds dedup state and renumbers ids without
        re-running add()'s validation. Called once, before any module of the
        resumed run has a chance to add() a new finding, so `findings` is
        the full restored set at call time."""
        restored = []
        with self._lock:
            for f in findings:
                key = (f['title'].lower().strip(), f['url'].lower().strip())
                if key in self._seen:
                    continue
                self._seen.add(key)
                nf = dict(f)
                nf['id'] = len(self.findings) + 1
                self.findings.append(nf)
                restored.append(nf)

        if self.event_callback:
            for nf in restored:
                try:
                    self.event_callback("finding_added", nf)
                except Exception:
                    pass
            try:
                self.event_callback("severity_updated", self.severity_counts())
            except Exception:
                pass
        return len(restored)

    def by_severity(self, sev):
        return [f for f in self.findings if f['severity'] == sev]

    def severity_counts(self):
        counts = {}
        for f in self.findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
        return counts

    def to_summary_list(self):
        return [
            f"[{f['severity'].upper()}] {f['title']} — {f['url']}"
            for f in self.findings
        ]

    def to_detail_list(self):
        lines = []
        for f in self.findings:
            lines.append(
                f"[{f['severity'].upper()}] {f['title']}\n"
                f"URL: {f['url']}\n"
                f"CVSS: {f.get('cvss','N/A')}\n"
                f"Description: {f['description']}\n"
                f"Remediation: {f['remediation']}"
            )
        return lines
