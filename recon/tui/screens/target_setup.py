from textual.screen import Screen
from textual.widgets import Label, Button, Input, Checkbox, Static
from textual.containers import Vertical, Horizontal, Grid, ScrollableContainer
from textual.app import ComposeResult

from recon.core.banner import logo_block, VERSION, TAGLINE
from recon.core.session import MODULE_LABELS, PRESETS
import recon.core.config as config


class TargetSetupScreen(Screen):
    """Initial screen to setup target and scan options."""

    def compose(self) -> ComposeResult:
        api_key = config.get_api_key()
        status_text  = "configured" if api_key else "not set — local engine only"
        status_class = "status-success" if api_key else "status-fail"

        standard_set = set(PRESETS["standard"])
        module_checkboxes = [
            Checkbox(
                label, id=f"mod_{mod_id}", value=mod_id in standard_set,
                classes="module-checkbox",
            )
            for mod_id, label in MODULE_LABELS.items() if mod_id != "report"
        ]

        with ScrollableContainer(id="setup_scroll"):
            yield Static("\n".join(logo_block()), classes="banner", markup=False)
            yield Static(f"{TAGLINE} · v{VERSION}", classes="subtitle")

            # Two columns so the form uses the width of a full-screen terminal
            # instead of a narrow centred strip: target/engine/start on the
            # left, the tall module picker on the right.
            with Horizontal(id="setup_cols"):
                with Vertical(id="setup_left"):
                    with Vertical(classes="setup-card") as target_card:
                        target_card.border_title = "target"
                        yield Label("Target domain", classes="section-label-first")
                        yield Input(placeholder="example.com", id="target_input")
                        with Horizontal(classes="dual-row"):
                            with Vertical():
                                yield Label("Threads", classes="section-label")
                                yield Input(value="10", id="thread_input")
                            with Vertical():
                                yield Label("Request delay (s)", classes="section-label")
                                yield Input(value="0.5", id="delay_input")
                        yield Label("Auth — optional, to scan authenticated areas", classes="section-label")
                        yield Static('"Name: Value" header, or  Cookie: session=abc123', classes="field-hint")
                        yield Input(placeholder="X-Auth-Token: abc123", id="auth_header_input")
                        yield Checkbox("Resume an interrupted scan of this target", id="resume_checkbox", value=False)

                    with Vertical(classes="setup-card") as eng_card:
                        eng_card.border_title = "engine"
                        with Horizontal(classes="status-row"):
                            yield Label("AI engine", classes="status-label")
                            yield Label(status_text, classes=status_class, id="api_status")

                    yield Button("Start scan", id="start_btn", variant="success")

                with Vertical(id="setup_right"):
                    with Vertical(classes="setup-card") as mod_card:
                        mod_card.border_title = "modules"
                        with Horizontal(classes="profile-buttons"):
                            yield Button("quick", id="profile_quick")
                            yield Button("standard", id="profile_standard")
                            yield Button("full", id="profile_full")
                        yield Grid(*module_checkboxes, id="module_grid")

    def _set_modules(self, preset: str) -> None:
        selected = set(PRESETS.get(preset, PRESETS["standard"]))
        for cb in self.query(".module-checkbox"):
            mod_id = cb.id[len("mod_"):]
            cb.value = mod_id in selected

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "profile_quick":
            self._set_modules("quick")
        elif event.button.id == "profile_standard":
            self._set_modules("standard")
        elif event.button.id == "profile_full":
            self._set_modules("full")
        elif event.button.id == "start_btn":
            self._start_scan()

    def _start_scan(self) -> None:
        target = self.query_one("#target_input", Input).value.strip()
        if not target:
            self.app.notify("Enter a target domain first.", severity="error")
            return

        try:
            threads = int(self.query_one("#thread_input", Input).value.strip() or "10")
        except ValueError:
            threads = 10

        try:
            delay = max(0.0, float(self.query_one("#delay_input", Input).value.strip() or "0.5"))
        except ValueError:
            delay = 0.5

        selected_modules = [
            cb.id[len("mod_"):] for cb in self.query(".module-checkbox") if cb.value
        ]
        if not selected_modules:
            self.app.notify("Select at least one module.", severity="error")
            return
        selected_modules.append("report")

        auth_headers, auth_cookies = {}, {}
        auth_line = self.query_one("#auth_header_input", Input).value.strip()
        if auth_line:
            name, sep, value = auth_line.partition(":")
            if sep:
                name, value = name.strip(), value.strip()
                if name.lower() == "cookie":
                    for pair in value.split(";"):
                        cname, csep, cval = pair.strip().partition("=")
                        if csep:
                            auth_cookies[cname.strip()] = cval.strip()
                else:
                    auth_headers[name] = value
            else:
                self.app.notify('Auth header ignored — expected "Name: Value" format.', severity="warning")

        self.app.start_scan_from_setup({
            "target": target,
            "api_key": config.get_api_key(),
            "modules": selected_modules,
            "threads": threads,
            "timeout": 10,
            "delay": delay,
            "output_dir": "./yata_recon_output",
            "auth_headers": auth_headers,
            "auth_cookies": auth_cookies,
            "resume": self.query_one("#resume_checkbox", Checkbox).value,
        })
