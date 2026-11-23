"""
AIAnalysisPanel — the AI analysis rail.

Each AI engine call shows as a collapsible entry: a plain title (module/
context) coloured by CSS, expanding to the full response. Titles are kept
plain text (no inline markup, ASCII +/- expand sigils) to stay inside the
no-dingbat design rules.
"""
import json

from textual.widgets import Static, Collapsible
from textual.containers import VerticalScroll
from textual.app import ComposeResult
from textual.reactive import reactive

from recon.tui.theme import ACCENT, TEXT, TEXT_DIM, TEXT_FAINT


class AIAnalysisPanel(Static):
    """Scrollable panel capturing all AI engine activity."""

    analysis_count = reactive(0)

    def compose(self) -> ComposeResult:
        self._counter = Static(f"[{TEXT_FAINT}]idle[/{TEXT_FAINT}]", id="ai_counter", classes="ai-counter", markup=True)
        yield self._counter
        self._scroll = VerticalScroll(id="ai_entries")
        yield self._scroll

    def on_mount(self) -> None:
        self.border_title = "ai analysis"

    def watch_analysis_count(self, value: int) -> None:
        try:
            noun = "analysis" if value == 1 else "analyses"
            self._counter.update(f"[{ACCENT} b]{value}[/] [{TEXT_DIM}]{noun}[/{TEXT_DIM}]")
            self.border_subtitle = str(value) if value else ""
        except Exception:
            pass

    def add_ai_start(self, method: str, context: str) -> str:
        """Record the start of an AI call. Returns an entry ID for later completion."""
        self.analysis_count += 1
        entry_id = f"ai_entry_{self.analysis_count}"

        label = method.replace("_", " ")
        title_text = f"{label} — {context}" if context else label

        entry = Collapsible(
            Static(f"[{TEXT_DIM}]waiting for response…[/{TEXT_DIM}]", id=f"{entry_id}_body", markup=True),
            title=title_text,
            collapsed=True,
            collapsed_symbol="+",
            expanded_symbol="-",
            id=entry_id,
        )
        self._scroll.mount(entry)
        self._scroll.scroll_end(animate=False)
        return entry_id

    def complete_ai_entry(self, entry_id: str, response: str) -> None:
        """Fill in the AI response for a previously started entry."""
        try:
            body = self._scroll.query_one(f"#{entry_id}_body", Static)
            display_text = self._format_response(response) if response else f"[{TEXT_DIM}]no response[/{TEXT_DIM}]"
            body.update(display_text[:1500])
        except Exception:
            pass

    @staticmethod
    def _format_response(response: str) -> str:
        """Render a JSON array/object response as a readable list instead of
        dumping the raw JSON (or stray model reasoning) verbatim."""
        text = response.strip()
        start_arr, start_obj = text.find("["), text.find("{")
        candidates = [p for p in (start_arr, start_obj) if p != -1]
        if not candidates:
            return text
        start = min(candidates)
        end = max(text.rfind("]"), text.rfind("}")) + 1
        if end <= start:
            return text
        try:
            parsed = json.loads(text[start:end])
        except Exception:
            return text
        if isinstance(parsed, list):
            return "\n".join(f"{i+1}. {item}" for i, item in enumerate(parsed))
        if isinstance(parsed, dict):
            return "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in parsed.items())
        return text

    def add_ai_note(self, text: str) -> None:
        """Add a simple note (e.g. 'AI engine not configured')."""
        note = Static(f"[{TEXT_DIM}]{text}[/{TEXT_DIM}]", classes="ai-note", markup=True)
        self._scroll.mount(note)
