from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Input, RichLog

from tui.markup import esc
from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class ChatScreen(Screen):
    """Mission-grounded chat with YATA's assistant.

    No tools yet: the conversation is grounded in a single ChatContext
    snapshot taken from the mission state when this screen mounts, and
    doesn't update if the repository or findings change afterward.
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("less_than_sign", "go_back", "Back", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.session = None  # chat_agent.ChatSession, built in on_mount

    def compose(self) -> ComposeResult:
        yield YataHeader(id="chat-header")
        with Container(classes="main-container"):
            yield RichLog(id="chat-log", highlight=True, markup=True, wrap=True)
            yield Input(placeholder="Ask YATA about this assessment...", id="chat-input")
        yield YataFooter(id="chat-footer")

    def on_mount(self) -> None:
        from chat_agent import ChatSession, build_context_from_mission_state

        state = self.app.mission_state
        header = self.query_one("#chat-header", YataHeader)
        header.status = "CHAT"
        header.target_name = state.target_name
        header.breadcrumbs = f"Mission › {state.target_name} › Chat"

        footer = self.query_one("#chat-footer", YataFooter)
        footer.help_text = "ENTER Send   </ESC Back"

        context = build_context_from_mission_state(state)
        self.session = ChatSession(context)

        log = self.query_one("#chat-log", RichLog)
        log.write(f"[dim]Grounded on {esc(context.target_name)} -- {len(context.findings)} finding(s).[/dim]")
        if not self.session.is_available:
            log.write(f"[bold red]{esc(self.session.unavailable_reason())}[/bold red]")

        self.query_one("#chat-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text or self.session is None:
            return

        input_widget = self.query_one("#chat-input", Input)
        input_widget.value = ""
        input_widget.disabled = True

        log = self.query_one("#chat-log", RichLog)
        log.write(f"[bold cyan]you>[/bold cyan] {esc(text)}")
        self._ask_worker(text)

    @work(thread=True)
    def _ask_worker(self, text: str) -> None:
        if self.session is None:
            return
        reply = self.session.send(text)
        self.app.call_from_thread(self._show_reply, reply)

    def _show_reply(self, reply: str) -> None:
        try:
            log = self.query_one("#chat-log", RichLog)
            log.write(f"[bold magenta]yata>[/bold magenta] {esc(reply)}")
            input_widget = self.query_one("#chat-input", Input)
            input_widget.disabled = False
            input_widget.focus()
        except Exception:
            pass

    def action_go_back(self) -> None:
        self.app.pop_screen()
