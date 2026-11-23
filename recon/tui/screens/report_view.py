import os

from textual.screen import Screen
from textual.widgets import Markdown, Button, Static
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.app import ComposeResult

from recon.tui.theme import SEVERITY, ACCENT, TEXT, TEXT_DIM, TEXT_FAINT, OK, risk_grade

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


class ReportViewScreen(Screen):
    """Post-scan report: a severity summary band over the full markdown report
    the session already wrote to disk (falling back to one built live from the
    findings the dashboard collected)."""

    def compose(self) -> ComposeResult:
        findings = list(getattr(self.app, "_findings", []) or [])
        report_path = getattr(self.app, "_report_path", None)
        risk = getattr(self.app, "_risk_score", None)

        yield Static(self._summary_markup(findings, risk), id="report_summary", markup=True)
        yield VerticalScroll(Markdown(self._report_markdown(findings, report_path)), id="report_body")
        yield Horizontal(
            Button("New scan", id="new_scan_btn", variant="primary"),
            Button("Report path", id="export_btn"),
            Button("Quit", id="quit_btn"),
            id="report_actions",
        )

    # ── content ──
    def _summary_markup(self, findings, risk) -> str:
        counts = {s: 0 for s in _SEV_ORDER}
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        total = len(findings)

        def tile(s):
            col = SEVERITY[s]
            n = counts[s]
            bright = col if n else TEXT_FAINT
            return f"[{bright} b]{n}[/] [{bright}]{s}[/{bright}]"

        cells = "    ".join(tile(s) for s in _SEV_ORDER)
        head = (f"[{ACCENT} b]scan report[/]   "
                f"[{TEXT_DIM}]findings[/{TEXT_DIM}] [{TEXT} b]{total}[/]")
        risk_txt = ""
        if risk is not None:
            grade, gcol = risk_grade(risk)
            risk_txt = f"      [{TEXT_DIM}]risk[/{TEXT_DIM}] [{gcol} b]{risk}/100[/] [{gcol}]{grade}[/{gcol}]"
        return f"{head}      {cells}{risk_txt}"

    def _report_markdown(self, findings, report_path) -> str:
        # Prefer the full report the session already saved (rich: evidence,
        # remediation, references) — show exactly what shipped to disk.
        if report_path and os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as fh:
                    text = fh.read().strip()
                if text:
                    return text
            except Exception:
                pass
        return self._build_from_findings(findings)

    def _build_from_findings(self, findings) -> str:
        if not findings:
            return "# Scan report\n\nNo findings were recorded for this scan."
        by_sev = {s: [] for s in _SEV_ORDER}
        for f in findings:
            by_sev.setdefault(f.get("severity", "info").lower(), []).append(f)

        lines = ["# Scan report", ""]
        for sev in _SEV_ORDER:
            items = by_sev.get(sev) or []
            if not items:
                continue
            lines.append(f"## {sev.upper()} ({len(items)})")
            lines.append("")
            for f in items:
                lines.append(f"### {f.get('title', 'Finding')}")
                if f.get("url"):
                    lines.append(f"- **URL:** {f['url']}")
                if f.get("module"):
                    lines.append(f"- **Module:** {f['module']}")
                if f.get("confidence"):
                    lines.append(f"- **Confidence:** {f['confidence']}")
                if f.get("cvss"):
                    lines.append(f"- **CVSS:** {f['cvss']}")
                if f.get("description"):
                    lines.append("")
                    lines.append(str(f["description"]))
                if f.get("remediation"):
                    lines.append("")
                    lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")
        return "\n".join(lines)

    # ── actions ──
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new_scan_btn":
            self.app.push_screen("setup")
        elif event.button.id == "export_btn":
            self.app.action_export()
        elif event.button.id == "quit_btn":
            self.app.exit()
