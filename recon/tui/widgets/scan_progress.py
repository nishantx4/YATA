from textual.widgets import Static, ProgressBar, ListView, ListItem
from textual.app import ComposeResult

from recon.tui.theme import ACCENT, TEXT_DIM, TEXT_FAINT, OK, CRIT


class ScanProgress(Static):
    """The module spine — the whole run at a glance, and selectable so the
    operator can skip a module mid-scan.

    A live header (how many modules are running / queued / done) sits over a
    selectable list of every module, each tagged with an ASCII state sigil
    (`· > + x -` = pending / running / done / failed / skipped), with an
    overall bar at the foot. Navigate with the arrow keys; `s` on the
    dashboard skips the highlighted module. No emoji/dingbats."""

    _SIGIL = {
        "pending":  (TEXT_FAINT, "·", TEXT_DIM),
        "running":  (ACCENT,     ">", ACCENT),
        "complete": (OK,         "+", TEXT_DIM),
        "failed":   (CRIT,       "x", CRIT),
        "skipped":  (TEXT_FAINT, "-", TEXT_FAINT),
    }

    def compose(self) -> ComposeResult:
        self._header = Static("", id="phase_label", markup=True)
        yield self._header
        self._list = ListView(id="module_list")
        yield self._list
        self._count_label = Static("0 / 0", id="module_count_label", classes="module-count", markup=True)
        yield self._count_label
        self.progress = ProgressBar(total=100, show_eta=False, show_percentage=True, id="scan_progress_bar")
        yield self.progress

    def on_mount(self) -> None:
        self.border_title = "modules"
        self.border_subtitle = ""
        self.module_status = {}
        self._rows = {}           # mod_name -> Static inside its ListItem
        self.total_modules = 0
        self.completed_modules = 0
        self._update_header()

    # ── lifecycle ──
    def init_modules(self, modules):
        self._list.clear()
        self.module_status = {}
        self._rows = {}
        for mod in modules:
            row = Static(self._fmt(mod, "pending"), markup=True)
            item = ListItem(row)
            item.mod_name = mod
            self._list.append(item)
            self._rows[mod] = row
            self.module_status[mod] = "pending"
        self.total_modules = len(modules)
        self.completed_modules = 0
        self.progress.total = max(1, self.total_modules)
        self.progress.progress = 0
        self._update_count()
        self._update_header()

    def start_module(self, mod_name):
        self._set_state(mod_name, "running")

    def complete_module(self, mod_name):
        if self.module_status.get(mod_name) not in ("complete", "failed", "skipped"):
            self._set_state(mod_name, "complete", advance=True)

    def fail_module(self, mod_name, error=""):
        if self.module_status.get(mod_name) not in ("complete", "failed", "skipped"):
            self._set_state(mod_name, "failed", advance=True)

    def skip_module(self, mod_name):
        if self.module_status.get(mod_name) not in ("complete", "failed", "skipped"):
            self._set_state(mod_name, "skipped", advance=True)

    # ── operator interaction ──
    def highlighted_module(self):
        """(mod_name, state) of the highlighted row, or (None, None)."""
        try:
            item = self._list.highlighted_child
        except Exception:
            item = None
        if item is None:
            return None, None
        mod = getattr(item, "mod_name", None)
        return mod, self.module_status.get(mod)

    # ── helpers ──
    def _fmt(self, mod, state):
        col, sigil, name_col = self._SIGIL.get(state, self._SIGIL["pending"])
        bold = " b" if state == "running" else ""
        return f"[{col}]{sigil}[/{col}] [{name_col}{bold}]{mod}[/]"

    def _set_state(self, mod_name, state, advance=False):
        if mod_name not in self.module_status:
            return
        prev = self.module_status[mod_name]
        self.module_status[mod_name] = state
        row = self._rows.get(mod_name)
        if row is not None:
            row.update(self._fmt(mod_name, state))
        if advance and prev not in ("complete", "failed", "skipped"):
            self.completed_modules += 1
            self.progress.progress = self.completed_modules
            self._update_count()
        self._update_header()

    def _update_count(self):
        total = getattr(self, "total_modules", 0)
        done = getattr(self, "completed_modules", 0)
        failed = sum(1 for v in self.module_status.values() if v == "failed")
        skipped = sum(1 for v in self.module_status.values() if v == "skipped")
        tail = ""
        if failed:
            tail += f"   [{CRIT}]{failed} failed[/{CRIT}]"
        if skipped:
            tail += f"   [{TEXT_FAINT}]{skipped} skipped[/{TEXT_FAINT}]"
        try:
            self._count_label.update(f"[{ACCENT}]{done}[/{ACCENT}] [{TEXT_DIM}]/ {total} complete[/{TEXT_DIM}]{tail}")
        except Exception:
            pass
        self.border_subtitle = f"{done}/{total}" if total else ""

    def _update_header(self):
        running = sum(1 for v in self.module_status.values() if v == "running")
        pending = sum(1 for v in self.module_status.values() if v == "pending")
        parts = []
        if running:
            parts.append(f"[{ACCENT}]{running} running[/{ACCENT}]")
        if pending:
            parts.append(f"[{TEXT_DIM}]{pending} queued[/{TEXT_DIM}]")
        if not parts:
            parts.append(f"[{TEXT_DIM}]{'idle' if not self.total_modules else 'done'}[/{TEXT_DIM}]")
        status_line = "  ".join(parts)
        hint_line = f"[{TEXT_FAINT}]s skip[/{TEXT_FAINT}]"
        try:
            self._header.update(f"{status_line}\n{hint_line}")
        except Exception:
            pass
