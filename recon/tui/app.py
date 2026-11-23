import threading

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer
from recon.tui.screens.target_setup import TargetSetupScreen
from recon.tui.screens.dashboard import DashboardScreen
from recon.tui.screens.report_view import ReportViewScreen

class ReconApp(App):
    """Main Textual application for YATA RECON."""

    CSS_PATH = "styles/recon.tcss"
    TITLE = "yata-recon"
    SUB_TITLE = "web application security scanner · v5.0"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("e", "export", "Report path"),
    ]

    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        self.scan_config = config or {}
        self.session = None                # live ScanSession (for operator skip)
        # Log events are high-frequency (a fast scan emits hundreds of lines a
        # second). Rendering each one on its own call_from_thread saturates the
        # UI thread and makes the whole TUI stutter, so they're buffered here
        # (filled from the worker thread) and flushed to the live log in one
        # batch on a timer — one refresh per tick instead of per line.
        self._log_buffer = []
        self._log_lock = threading.Lock()
        self._ai_entry_map = {}            # track AI call entry IDs
        self._findings = []                # accumulated for the report screen
        self._report_path = None           # markdown report saved by the session
        self._risk_score = None
        self._scan_done = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app mounts."""
        self.install_screen(TargetSetupScreen(), name="setup")
        self.install_screen(DashboardScreen(), name="dashboard")
        self.install_screen(ReportViewScreen(), name="report")
        # Drain the live-log buffer a few times a second (cheap no-op when empty).
        self.set_interval(0.12, self._flush_logs)

        if self.scan_config.get("target"):
            self.push_screen("dashboard")
            # push_screen() only *schedules* the dashboard's compose/mount —
            # it hasn't happened yet when this line runs, so #info_bar
            # doesn't exist in the DOM yet and query_one() would raise.
            # call_after_refresh() defers until after that mount completes.
            self.call_after_refresh(self._init_info_bar)
            self.run_worker(self._run_scan, thread=True)
        else:
            self.push_screen("setup")

    def start_scan_from_setup(self, config: dict) -> None:
        """Called by TargetSetupScreen once the user presses Start Scan."""
        self.scan_config = config
        self.push_screen("dashboard")
        self.call_after_refresh(self._init_info_bar)
        self.run_worker(self._run_scan, thread=True)

    def _init_info_bar(self):
        """Set initial values on the info bar from scan config."""
        try:
            dashboard = self.get_screen("dashboard")
            from recon.tui.widgets.scan_info_bar import ScanInfoBar
            info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
            info_bar.target_name = self.scan_config.get("target", "—")
            info_bar.ai_active = bool(self.scan_config.get("api_key"))
            info_bar.start_timer()
        except Exception as e:
            self.notify(f"Info bar init failed: {e}", severity="warning")
            
    def _run_scan(self) -> None:
        from recon.core.session import ScanSession
        from recon.core.ui import UI
        
        class TUIEmitter(UI):
            def __init__(self, callback):
                super().__init__(no_color=True)
                self.callback = callback
            def _print(self, *args, **kwargs):
                msg = " ".join(str(a) for a in args)
                if msg:
                    # Tag the line with whichever module is running on this
                    # thread (set by ScanSession._run_module) so the TUI can
                    # route it to that module's own log box instead of one
                    # shared stream where parallel modules' output interleaves.
                    self.callback("log", {"text": msg, "module": self.current_module})
                
        ui = TUIEmitter(self._handle_event)
        
        session = ScanSession(
            target=self.scan_config.get("target"),
            api_key=self.scan_config.get("api_key"),
            modules=self.scan_config.get("modules"),
            threads=self.scan_config.get("threads", 10),
            timeout=self.scan_config.get("timeout", 10),
            delay=self.scan_config.get("delay", 0.5),
            output_dir=self.scan_config.get("output_dir", "./yata_recon_output"),
            ui=ui,
            event_callback=self._handle_event,
            auto_install_tools=self.scan_config.get("auto_install_tools", True),
            auth_headers=self.scan_config.get("auth_headers"),
            auth_cookies=self.scan_config.get("auth_cookies"),
            auth_headers_b=self.scan_config.get("auth_headers_b"),
            auth_cookies_b=self.scan_config.get("auth_cookies_b"),
            parallel_modules=self.scan_config.get("parallel_modules", True),
            module_workers=self.scan_config.get("module_workers"),
            fresh_recon=self.scan_config.get("fresh_recon", False),
            recon_cache_ttl=self.scan_config.get("recon_cache_ttl", 6 * 3600),
            sign_reports=self.scan_config.get("sign_reports", False),
            resume=self.scan_config.get("resume", False),
            min_confidence=self.scan_config.get("min_confidence", 0),
            min_severity=self.scan_config.get("min_severity"),
            sarif=self.scan_config.get("sarif", False),
            scope=self.scan_config.get("scope"),
            scope_file=self.scan_config.get("scope_file"),
            out_of_scope=self.scan_config.get("out_of_scope"),
            proxy=self.scan_config.get("proxy"),
            share_card=self.scan_config.get("share_card", False),
        )
        self.session = session   # lets the dashboard request an operator skip
        try:
            session.run()
        except Exception as e:
            self.call_from_thread(self.notify, f"Scan failed: {e}", severity="error")
            
    def _handle_event(self, event_type: str, data: dict):
        """Called by ScanSession from the worker thread. Dispatch to main thread."""
        # High-frequency log lines are buffered (drained by _flush_logs on a
        # timer) instead of hopping to the UI thread one-by-one — that per-line
        # hop is what made a fast scan stutter. Everything else is comparatively
        # rare and dispatched immediately.
        if event_type == "log":
            with self._log_lock:
                self._log_buffer.append(data)
                if len(self._log_buffer) > 4000:   # bound memory if the UI stalls
                    del self._log_buffer[:-4000]
            return
        self.call_from_thread(self._process_event, event_type, data)

    def _flush_logs(self) -> None:
        """Write all buffered log lines to the live log in one batch (runs on
        the UI thread via set_interval)."""
        if not self._log_buffer:
            return
        with self._log_lock:
            batch = self._log_buffer
            self._log_buffer = []
        try:
            dashboard = self.get_screen("dashboard")
            if not dashboard.is_current:
                return
            from textual.widgets import RichLog
            from recon.tui.theme import ACCENT_DIM, TEXT_FAINT
            log_widget = dashboard.query_one("#live_log", RichLog)
        except Exception:
            return
        for data in batch:
            module = data.get("module")
            safe = str(data.get("text", "")).replace("[", r"\[")
            if module:
                tag = f"[{ACCENT_DIM}]{module[:11]:<11}[/]"
            else:
                tag = f"[{TEXT_FAINT}]{'·':<11}[/]"
            log_widget.write(f"{tag} {safe}")
        
    def _process_event(self, event_type: str, data: dict):
        """Process event in the main thread (update UI)."""
        try:
            dashboard = self.get_screen("dashboard")
            if not dashboard.is_current:
                return

            from recon.tui.widgets.scan_info_bar import ScanInfoBar
            from recon.tui.widgets.ai_analysis_panel import AIAnalysisPanel
                
            if event_type == "scan_started":
                progress = dashboard.query_one("#progress_panel")
                progress.init_modules(data.get("modules", []))
                # Update info bar module count
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_total = len(data.get("modules", []))
                    info_bar.phase = "scanning"
                except Exception:
                    pass

            elif event_type == "phase_started":
                # Phases the session announces around the module run (target
                # profiling, chain verification, AI chain analysis). Surfaced
                # in the telemetry strip; previously ignored by the TUI.
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.phase = str(data.get("name", "")).lower() or info_bar.phase
                except Exception:
                    pass

            elif event_type == "profiling_complete":
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.phase = "scanning"
                except Exception:
                    pass
                
            elif event_type == "module_started":
                progress = dashboard.query_one("#progress_panel")
                progress.start_module(data.get("module"))
                
            elif event_type == "module_completed":
                progress = dashboard.query_one("#progress_panel")
                progress.complete_module(data.get("module"))
                # Update info bar
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_done += 1
                except Exception:
                    pass

            elif event_type == "module_failed":
                progress = dashboard.query_one("#progress_panel")
                progress.fail_module(data.get("module"), data.get("error", ""))
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_done += 1
                except Exception:
                    pass

            elif event_type == "module_skipped":
                progress = dashboard.query_one("#progress_panel")
                progress.skip_module(data.get("module"))
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_done += 1
                except Exception:
                    pass
                
            elif event_type == "finding_added":
                # Keep a copy for the report screen (decoupled from the session
                # object, which lives on the worker thread).
                self._findings.append(dict(data))
                finding_panel = dashboard.query_one("#finding_panel")
                finding_panel.add_finding(dict(data))
                
            elif event_type == "severity_updated":
                panel = dashboard.query_one("#finding_panel")
                panel.update_counts(
                    critical=data.get("critical", 0),
                    high=data.get("high", 0),
                    medium=data.get("medium", 0),
                    low=data.get("low", 0)
                )
                # Update info bar finding counts
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.finding_counts = data
                except Exception:
                    pass

            elif event_type == "ai_call_started":
                try:
                    ai_panel = dashboard.query_one("#ai_panel", AIAnalysisPanel)
                    method = data.get("method", "unknown")
                    context = data.get("context", "")
                    entry_id = ai_panel.add_ai_start(method, context)
                    # Store with a key so we can complete it later
                    call_key = f"{method}:{context}"
                    self._ai_entry_map[call_key] = entry_id
                except Exception:
                    pass

            elif event_type == "ai_call_completed":
                try:
                    ai_panel = dashboard.query_one("#ai_panel", AIAnalysisPanel)
                    method = data.get("method", "unknown")
                    context = data.get("context", "")
                    response = data.get("response", "")
                    call_key = f"{method}:{context}"
                    entry_id = self._ai_entry_map.pop(call_key, None)
                    if entry_id:
                        ai_panel.complete_ai_entry(entry_id, response)
                except Exception:
                    pass
                
            # "log" events are not handled here — they're buffered in
            # _handle_event and batch-flushed by _flush_logs (see above).

            elif event_type == "scan_completed":
                self._flush_logs()   # don't drop the last buffered lines
                self._scan_done = True
                self._report_path = data.get("report_path")
                self._risk_score = data.get("risk_score")
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.stop_timer()
                    info_bar.phase = "complete"
                except Exception:
                    pass
                n = data.get("findings", len(self._findings))
                self.notify(f"Scan complete — {n} finding(s). Showing report.",
                            title="yata-recon", timeout=6)
                self.push_screen("report")
        except Exception as e:
            self.notify(f"UI Error: {e}", severity="error")

    def action_export(self) -> None:
        """Surface where the full markdown report was written (the session
        saves it automatically at scan end)."""
        if self._report_path:
            self.notify(f"Report saved to:\n{self._report_path}", title="Export", timeout=10)
        elif self._scan_done:
            self.notify("Report is in the output directory (./yata_recon_output).",
                        title="Export", timeout=8)
        else:
            self.notify("The report is available once the scan finishes.",
                        title="Export", severity="warning")

if __name__ == "__main__":
    app = ReconApp()
    app.run()
