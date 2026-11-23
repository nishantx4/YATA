"""
ScanInfoBar — the telemetry strip across the top of the dashboard.

A single dense line: target · phase · elapsed · live request rate · module
progress · finding tallies · a findings-over-time trend sparkline. Flat (a
bottom rule, not a boxed panel) so it reads as instrumentation, not a card.
"""
import time
from collections import deque
from textual.widgets import Static
from textual.containers import Horizontal
from textual.app import ComposeResult
from textual.reactive import reactive

from recon.tui.theme import ACCENT, TEXT, TEXT_DIM, TEXT_FAINT, OK, CRIT, HIGH, MED, LOW

_SPARK = " ▁▂▃▄▅▆▇█"


class ScanInfoBar(Static):
    """Horizontal telemetry strip. Reactive attributes are driven by the app
    from scan events; the per-second tick updates elapsed, request rate and
    the trend sparkline."""

    target_name = reactive("—")
    phase = reactive("idle")
    elapsed = reactive(0.0)
    modules_done = reactive(0)
    modules_total = reactive(0)
    ai_active = reactive(False)
    finding_counts = reactive({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})

    def compose(self) -> ComposeResult:
        yield Horizontal(
            Static("", id="info_target", classes="info-cell", markup=True),
            Static("", id="info_phase", classes="info-cell", markup=True),
            Static("", id="info_time", classes="info-cell", markup=True),
            Static("", id="info_rate", classes="info-cell", markup=True),
            Static("", id="info_modules", classes="info-cell", markup=True),
            Static("", id="info_findings", classes="info-cell", markup=True),
            Static("", id="info_trend", classes="info-cell", markup=True),
            id="info_bar_row",
        )

    _spark = None
    _last_total = 0
    _last_req_count = 0
    _rate = 0
    _start_time: float | None = None

    def on_mount(self) -> None:
        self._spark = deque(maxlen=22)
        self._last_total = 0
        self._last_req_count = self._read_req_count()
        self._refresh_all()
        self.set_interval(1.0, self._tick_timer)

    # ── per-second tick ──
    def _tick_timer(self) -> None:
        if self._start_time is not None:
            self.elapsed = time.time() - self._start_time
        self._update_rate()
        self._update_spark()

    @staticmethod
    def _read_req_count() -> int:
        try:
            from recon.modules import request_count
            return request_count()
        except Exception:
            return 0

    def _update_rate(self) -> None:
        """Live request throughput — requests observed in the last tick. A
        visible pulse that the scan is actually moving (and fast, now that the
        global-throttle bottleneck is gone)."""
        now = self._read_req_count()
        self._rate = max(0, now - self._last_req_count)
        self._last_req_count = now
        if self._start_time is None:
            cell = f"[{TEXT_DIM}]rate[/{TEXT_DIM}] [{TEXT_FAINT}]—[/{TEXT_FAINT}]"
        elif self._rate > 0:
            cell = f"[{TEXT_DIM}]rate[/{TEXT_DIM}] [{ACCENT}]{self._rate}[/{ACCENT}][{TEXT_DIM}]/s[/{TEXT_DIM}]"
        else:
            cell = f"[{TEXT_DIM}]rate[/{TEXT_DIM}] [{TEXT_FAINT}]0/s[/{TEXT_FAINT}]"
        self._update_cell("info_rate", cell)

    def _update_spark(self) -> None:
        """Record findings discovered in the last tick and render a trend
        sparkline — shows WHEN findings landed over the scan, not just a
        running total."""
        if self._spark is None:
            return
        fc = self.finding_counts or {}
        total = sum(fc.get(s, 0) for s in ("critical", "high", "medium", "low", "info"))
        delta = max(0, total - self._last_total)
        self._last_total = total
        self._spark.append(delta)
        if not any(self._spark):
            spark = ""
        else:
            peak = max(self._spark) or 1
            spark = "".join(_SPARK[min(len(_SPARK) - 1, round(v / peak * (len(_SPARK) - 1)))]
                            for v in self._spark)
        self._update_cell("info_trend",
                          f"[{TEXT_DIM}]trend[/{TEXT_DIM}] [{ACCENT}]{spark}[/{ACCENT}]"
                          if spark else f"[{TEXT_DIM}]trend[/{TEXT_DIM}] [{TEXT_FAINT}]{'·' * 10}[/{TEXT_FAINT}]")

    def start_timer(self) -> None:
        self._start_time = time.time()
        self._last_req_count = self._read_req_count()

    def stop_timer(self) -> None:
        if self._start_time is not None:
            self.elapsed = time.time() - self._start_time

    # ── watchers ──
    def watch_target_name(self, value: str) -> None:
        self._update_cell("info_target",
                          f"[{TEXT_DIM}]target[/{TEXT_DIM}] [{ACCENT}]{self._esc(value)}[/{ACCENT}]")

    def watch_phase(self, value: str) -> None:
        done = str(value).lower() in ("complete", "done")
        col = OK if done else ACCENT if value and value != "idle" else TEXT_FAINT
        self._update_cell("info_phase", f"[{TEXT_DIM}]phase[/{TEXT_DIM}] [{col}]{self._esc(value)}[/{col}]")

    def watch_elapsed(self, value: float) -> None:
        m, s = divmod(int(value), 60)
        self._update_cell("info_time", f"[{TEXT_DIM}]elapsed[/{TEXT_DIM}] [{TEXT}]{m:02d}:{s:02d}[/{TEXT}]")

    def watch_modules_done(self, value: int) -> None:
        self._refresh_modules()

    def watch_modules_total(self, value: int) -> None:
        self._refresh_modules()

    def watch_ai_active(self, value: bool) -> None:
        # Folded into the modules cell's trailing marker; kept as a watcher so
        # the app can still flip it. Rendering happens in _refresh_modules.
        self._refresh_modules()

    def watch_finding_counts(self, value: dict) -> None:
        c = value.get("critical", 0); h = value.get("high", 0)
        m = value.get("medium", 0); lo = value.get("low", 0)
        total = c + h + m + lo + value.get("info", 0)

        def chip(n, col):
            return f"[{col}]{n}[/{col}]" if n else f"[{TEXT_FAINT}]{n}[/{TEXT_FAINT}]"

        self._update_cell(
            "info_findings",
            f"[{TEXT_DIM}]findings[/{TEXT_DIM}] [{TEXT}]{total}[/{TEXT}] "
            f"{chip(c, CRIT)} {chip(h, HIGH)} {chip(m, MED)} {chip(lo, LOW)}",
        )

    # ── helpers ──
    def _refresh_modules(self) -> None:
        ai = (f"  [{TEXT_DIM}]ai[/{TEXT_DIM}] [{ACCENT}]on[/{ACCENT}]"
              if self.ai_active else f"  [{TEXT_DIM}]ai[/{TEXT_DIM}] [{TEXT_FAINT}]local[/{TEXT_FAINT}]")
        self._update_cell(
            "info_modules",
            f"[{TEXT_DIM}]modules[/{TEXT_DIM}] [{TEXT}]{self.modules_done}[/{TEXT}]"
            f"[{TEXT_DIM}]/{self.modules_total}[/{TEXT_DIM}]{ai}",
        )

    def _refresh_all(self) -> None:
        self.watch_target_name(self.target_name)
        self.watch_phase(self.phase)
        self.watch_elapsed(self.elapsed)
        self._update_rate()
        self._refresh_modules()
        self.watch_finding_counts(self.finding_counts)
        self._update_spark()

    @staticmethod
    def _esc(text) -> str:
        return str(text).replace("[", r"\[")

    def _update_cell(self, cell_id: str, text: str) -> None:
        try:
            self.query_one(f"#{cell_id}", Static).update(text)
        except Exception:
            pass
