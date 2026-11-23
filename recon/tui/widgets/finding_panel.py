from textual.widgets import Static, ListView, ListItem
from textual.app import ComposeResult
from textual.reactive import reactive

from recon.tui.theme import SEVERITY, SEV_LABEL, TEXT, TEXT_DIM, TEXT_FAINT, ACCENT


class FindingPanel(Static):
    """Live findings feed — a selectable list, one row per finding, with a
    severity rail. Each row carries its full finding dict so the dashboard can
    open a detail drill-down, mark it a false positive, or copy it as curl."""

    finding_count = reactive(0)

    def compose(self) -> ComposeResult:
        self.counter_widget = Static(self._counts_markup(0, 0, 0, 0), id="finding_counter", markup=True)
        yield self.counter_widget
        yield ListView(id="finding_list")

    def on_mount(self) -> None:
        self.border_title = "findings"
        self.border_subtitle = "enter detail · f fp · c curl · 1-5 filter · 0 all"
        self._filter = None            # active severity filter, or None = all
        self._items = []               # all ListItems, for filtering

    # ── live feed ────────────────────────────────────────────────────────
    def add_finding(self, finding: dict):
        """finding: the full finding dict emitted by the scan session."""
        self.finding_count += 1
        sev = str(finding.get("severity", "info")).lower()
        color = SEVERITY.get(sev, SEVERITY["info"])
        label = SEV_LABEL.get(sev, sev.upper()[:4])
        title = finding.get("title", "Unknown")
        url = finding.get("url", "")
        module = finding.get("module", "")
        confidence = finding.get("confidence", "")
        score = finding.get("confidence_score", "")

        lines = [f"[{color} b]{label:<4}[/] [{TEXT}]{self._esc(title)}[/{TEXT}]"]
        if url:
            lines.append(f"     [{TEXT_DIM}]└ {self._esc(url)}[/{TEXT_DIM}]")
        meta = []
        if module:
            meta.append(f"module {module}")
        if confidence:
            cs = f"{confidence}" + (f" {score}" if score != "" else "")
            meta.append(f"confidence {cs}")
        if meta:
            lines.append(f"     [{TEXT_FAINT}]{self._esc(' · '.join(meta))}[/{TEXT_FAINT}]")

        item = ListItem(Static("\n".join(lines), markup=True), classes=f"finding-item finding-{sev}")
        item.finding = dict(finding)        # full data for drill-down / triage
        item.sev = sev
        self._items.append(item)
        lv = self.query_one("#finding_list", ListView)
        lv.append(item)
        if self._filter and self._filter != sev:
            item.display = False
        lv.scroll_end(animate=False)

    # ── selection / triage helpers (called by the dashboard) ──────────────
    def selected_finding(self):
        try:
            child = self.query_one("#finding_list", ListView).highlighted_child
            return getattr(child, "finding", None) if child else None
        except Exception:
            return None

    def mark_selected_as_fp(self):
        """Mark the highlighted finding as a false positive and dim it."""
        try:
            child = self.query_one("#finding_list", ListView).highlighted_child
        except Exception:
            child = None
        finding = getattr(child, "finding", None) if child else None
        if not finding:
            return None
        from recon.core.fp_feedback import mark_false_positive
        mark_false_positive(finding.get("title", ""), finding.get("url", ""))
        child.add_class("finding-fp")
        child.finding["_fp"] = True
        return finding

    def set_severity_filter(self, sev):
        """sev: 'critical'|'high'|'medium'|'low'|'info' or None for all."""
        self._filter = sev
        for item in self._items:
            item.display = (sev is None or item.sev == sev)
        self.border_subtitle = (f"filtered: {sev}" if sev
                                else "enter detail · f fp · c curl · 1-5 filter · 0 all")
        return sev

    def update_counts(self, critical, high, medium, low):
        self.counter_widget.update(self._counts_markup(critical, high, medium, low))

    @staticmethod
    def _esc(text: str) -> str:
        return str(text).replace("[", r"\[")

    @staticmethod
    def _counts_markup(critical, high, medium, low) -> str:
        c, h, m, lo = SEVERITY["critical"], SEVERITY["high"], SEVERITY["medium"], SEVERITY["low"]
        total = critical + high + medium + low

        def chip(name, n, col):
            bright = col if n else TEXT_FAINT
            return f"[{bright}]{name} {n}[/{bright}]"

        return (
            f"[{TEXT_DIM}]total[/{TEXT_DIM}] [{ACCENT} b]{total}[/]    "
            f"{chip('crit', critical, c)}  {chip('high', high, h)}  "
            f"{chip('med', medium, m)}  {chip('low', low, lo)}"
        )
