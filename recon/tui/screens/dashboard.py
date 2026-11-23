from textual.screen import Screen
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import ListView, RichLog

from recon.tui.widgets.scan_info_bar import ScanInfoBar
from recon.tui.widgets.scan_progress import ScanProgress
from recon.tui.widgets.finding_panel import FindingPanel
from recon.tui.widgets.ai_analysis_panel import AIAnalysisPanel
from recon.tui.screens.finding_detail import FindingDetailScreen


class DashboardScreen(Screen):
    """Live scan dashboard — info bar, three live panels, findings feed.

    The findings feed is interactive: select a row and press Enter to drill
    into the full evidence/remediation, f to mark it a false positive (fed
    straight back into confidence scoring), c to copy it as a curl command,
    and 1–5 / 0 to filter the feed by severity."""

    BINDINGS = [
        ("s", "skip_module", "Skip module"),
        ("f", "mark_fp", "Mark FP"),
        ("c", "copy_curl", "Copy curl"),
        ("1", "filter('critical')", "Crit"),
        ("2", "filter('high')", "High"),
        ("3", "filter('medium')", "Med"),
        ("4", "filter('low')", "Low"),
        ("5", "filter('info')", "Info"),
        ("0", "filter('')", "All"),
    ]

    def compose(self) -> ComposeResult:
        # Telemetry strip on top; then three zones — the module spine (left),
        # the findings feed over the live engine output (center), and the AI
        # analysis rail (right).
        yield ScanInfoBar(id="info_bar")
        with Horizontal(id="dash_body"):
            yield ScanProgress(id="progress_panel")
            with Vertical(id="center_col"):
                yield FindingPanel(id="finding_panel")
                # One shared, module-tagged live log that fills the panel.
                # (Per-module Collapsibles each needed a fixed-height RichLog —
                # RichLog can't auto-size inside a Collapsible, it resolves to
                # height 0 — which left big empty boxes AND raced on mount,
                # spawning duplicate boxes. A single filling log is cleaner.)
                with Container(id="tool_execution_panel") as live:
                    live.border_title = "live output"
                    live.border_subtitle = "engine"
                    yield RichLog(highlight=False, markup=True, wrap=True,
                                  max_lines=2000, auto_scroll=True, id="live_log")
            yield AIAnalysisPanel(id="ai_panel")

    # ── module spine interaction ───────────────────────────────────────────
    def action_skip_module(self) -> None:
        """Skip the highlighted module in the spine: a queued one is dropped
        before it runs, a running one aborts at its next request (and its
        subprocess, e.g. nuclei, is killed)."""
        try:
            progress = self.query_one("#progress_panel", ScanProgress)
            mod, state = progress.highlighted_module()
        except Exception:
            mod, state = None, None
        if not mod:
            self.app.notify("Tab to the modules panel and arrow to a module, then press s.",
                            severity="warning", timeout=4)
            return
        if state in ("complete", "failed", "skipped"):
            self.app.notify(f"'{mod}' already {state} — nothing to skip.", timeout=3)
            return
        session = getattr(self.app, "session", None)
        if session is None or not hasattr(session, "skip"):
            self.app.notify("Scan isn't running yet.", severity="warning", timeout=3)
            return
        session.skip.request(mod)
        self.app.notify(f"Skipping '{mod}' — it will stop shortly.", title="triage", timeout=4)

    # ── findings-feed interaction ──────────────────────────────────────────
    def _panel(self) -> FindingPanel:
        return self.query_one("#finding_panel", FindingPanel)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Enter on a finding row → open the drill-down."""
        finding = getattr(event.item, "finding", None)
        if finding:
            self.app.push_screen(FindingDetailScreen(finding))

    def action_mark_fp(self) -> None:
        try:
            finding = self._panel().mark_selected_as_fp()
        except Exception:
            finding = None
        if finding:
            self.app.notify(f"Marked as false positive — downweighted in future scans:\n"
                            f"{finding.get('title','')}", title="triage", timeout=5)
        else:
            self.app.notify("Select a finding first (click or arrow-key to it), then press f.",
                            severity="warning", timeout=4)

    def action_copy_curl(self) -> None:
        try:
            finding = self._panel().selected_finding()
        except Exception:
            finding = None
        if not finding:
            self.app.notify("Select a finding first, then press c.", severity="warning", timeout=4)
            return
        try:
            from recon.core.exporters import finding_to_curl
            self.app.copy_to_clipboard(finding_to_curl(finding))
            self.app.notify("curl command copied to clipboard.", title="triage", timeout=4)
        except Exception as e:
            self.app.notify(f"Copy failed: {e}", severity="warning")

    def action_filter(self, sev: str) -> None:
        try:
            applied = self._panel().set_severity_filter(sev or None)
        except Exception:
            return
        self.app.notify(f"Findings filter: {applied or 'all severities'}", timeout=3)
