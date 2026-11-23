"""
YATA RECON palette — single source of truth for colors used in Rich markup
inside widget code. Keep these in sync with the $variables at the top of
tui/styles/recon.tcss (which controls widget/panel chrome).

No emoji, no dingbats. Sigils used in the TUI are structural ASCII only
(`· > + x`) plus box/block glyphs — see the ui-identity design rules.
"""

BG          = "#0a0b0d"
BG_PANEL    = "#0d1014"
BG_ELEVATED = "#14181d"
BG_SELECT   = "#1b2b2a"   # teal-tinted selection ground (derived from accent-dim)

BORDER        = "#222932"
BORDER_STRONG = "#3a4048"

TEXT       = "#c9d1d9"
TEXT_DIM   = "#68717f"
TEXT_FAINT = "#3b424c"

ACCENT     = "#45d1c4"
ACCENT_DIM = "#245853"

OK   = "#4ba876"
CRIT = "#e5484d"
HIGH = "#d97a4d"
MED  = "#c9a227"
LOW  = "#4a90c4"
INFO = "#4a90c4"

SEVERITY = {
    "critical": CRIT,
    "high":     HIGH,
    "medium":   MED,
    "low":      LOW,
    "info":     INFO,
}

# Fixed-width severity tags used in dense feeds (keeps rows aligned on a
# 4-char rail). Centralised so the feed, the detail modal and the report
# band never drift apart.
SEV_LABEL = {
    "critical": "CRIT",
    "high":     "HIGH",
    "medium":   "MED",
    "low":      "LOW",
    "info":     "INFO",
}

# The scan's phase accent — the module spine / info bar show which phase of
# the run is active. Phases are emitted by the session as `phase_started`.
PHASE = ACCENT

# A compact sigil (matches recon/core/banner.py's wordmark language) available
# to widgets that want the mark inline. Structural block glyphs, not emoji.
SIGIL_MARK = "▛▜"  # radar mark


def severity_color(sev: str) -> str:
    return SEVERITY.get(str(sev).lower(), INFO)


def severity_label(sev: str) -> str:
    sev = str(sev).lower()
    return SEV_LABEL.get(sev, sev.upper()[:4])


def risk_grade(score) -> tuple:
    """Map a 0–100 risk score to (grade, color) for the report band."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ("—", TEXT_DIM)
    if s >= 80:
        return ("CRITICAL", CRIT)
    if s >= 50:
        return ("HIGH", HIGH)
    if s >= 20:
        return ("MODERATE", MED)
    if s > 0:
        return ("LOW", LOW)
    return ("CLEAN", OK)
