from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.containers import VerticalScroll, Container
from textual.widgets import Static

from recon.tui.theme import SEVERITY, SEV_LABEL, TEXT, TEXT_DIM, TEXT_FAINT, ACCENT, OK, MED

_LABEL = SEV_LABEL


class FindingDetailScreen(ModalScreen):
    """Drill-down for a single finding: the full description, the evidence and
    validation steps that make it a real finding, and remediation — the 'why
    this is real' trail that the one-line feed can't show."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
        ("c", "copy_curl", "Copy curl"),
    ]

    def __init__(self, finding: dict):
        super().__init__()
        self.finding = finding or {}

    def compose(self) -> ComposeResult:
        f = self.finding
        sev = str(f.get("severity", "info")).lower()
        color = SEVERITY.get(sev, SEVERITY["info"])
        label = _LABEL.get(sev, sev.upper()[:4])

        def esc(s):
            return str(s).replace("[", r"\[")

        rows = []
        rows.append(f"[{color} b]{label}[/]  [{TEXT} b]{esc(f.get('title',''))}[/]")
        meta = f"[{TEXT_DIM}]module[/] {esc(f.get('module','—'))}   " \
               f"[{TEXT_DIM}]confidence[/] {esc(f.get('confidence','—'))} " \
               f"({f.get('confidence_score','—')})   [{TEXT_DIM}]cvss[/] {esc(f.get('cvss','—'))}"
        rows.append(meta)
        if f.get("url"):
            rows.append(f"[{TEXT_DIM}]url[/] [{ACCENT}]{esc(f.get('url'))}[/]")
        if f.get("_fp"):
            rows.append(f"[{MED}]! marked as a false positive this session[/]")

        rows.append("")
        rows.append(f"[{ACCENT} b]Description[/]")
        rows.append(f"[{TEXT}]{esc(f.get('description','(none)'))}[/]")

        steps = f.get("validation_steps") or []
        if steps:
            rows.append("")
            rows.append(f"[{OK} b]Why this is real — validation steps[/]")
            for s in steps:
                rows.append(f"  [{OK}]+[/] [{TEXT}]{esc(s)}[/]")

        ev = f.get("evidence") or []
        if ev:
            rows.append("")
            rows.append(f"[{ACCENT} b]Evidence[/]")
            for e in ev:
                rows.append(f"  [{TEXT_DIM}]·[/] [{TEXT}]{esc(e)}[/]")

        if f.get("remediation"):
            rows.append("")
            rows.append(f"[{ACCENT} b]Remediation[/]")
            rows.append(f"[{TEXT}]{esc(f.get('remediation'))}[/]")

        refs = f.get("references") or []
        if refs:
            rows.append("")
            rows.append(f"[{ACCENT} b]References[/]")
            for r in refs:
                rows.append(f"  [{TEXT_FAINT}]{esc(r)}[/]")

        body = VerticalScroll(Static("\n".join(rows), markup=True, id="detail_body"), id="detail_scroll")
        box = Container(body, id="detail_box")
        box.border_title = f"finding detail · {label.lower()}"
        box.border_subtitle = "esc close · c copy curl"
        yield box

    def action_dismiss(self) -> None:
        self.dismiss()

    def action_copy_curl(self) -> None:
        try:
            from recon.core.exporters import finding_to_curl
            cmd = finding_to_curl(self.finding)
            self.app.copy_to_clipboard(cmd)
            self.app.notify("curl command copied to clipboard.", title="yata-recon", timeout=4)
        except Exception as e:
            self.app.notify(f"Copy failed: {e}", severity="warning")
