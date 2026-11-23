"""
Console UI for YATA RECON — the "YATA RECON" signature look.

Design rules (shared with the Textual TUI in tui/):
  * one cold accent (teal), muted semantic severity scale, near-black ground;
  * a 2-space gutter on every line, left-anchored;
  * findings stand out (colored severity tag, no timestamp); ambient log lines
    recede (dim timestamp + a single sigil);
  * section headers are a label + a thin rule that fills the width, never a box;
  * color is used for meaning, not decoration — no emoji, no rainbow.

Colors are truecolor (24-bit) and match tui/theme.py exactly so the headless
output and the live TUI read as the same product. no_color drops every escape.
"""
import os
import re
import sys
import time
import shutil
import threading
from datetime import datetime


def _fg(hex_str):
    r, g, b = int(hex_str[0:2], 16), int(hex_str[2:4], 16), int(hex_str[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"


def _bg(hex_str):
    r, g, b = int(hex_str[0:2], 16), int(hex_str[2:4], 16), int(hex_str[4:6], 16)
    return f"\033[48;2;{r};{g};{b}m"


class Colors:
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"

    # ── YATA RECON palette (keep in sync with tui/theme.py) ──
    ACCENT     = _fg("45d1c4")
    ACCENT_DIM = _fg("245853")
    TEXT       = _fg("c9d1d9")
    TEXT_DIM   = _fg("5b6472")
    TEXT_FAINT = _fg("383e47")
    OK         = _fg("4ba876")
    CRIT       = _fg("e5484d")
    HIGH       = _fg("d97a4d")
    MED        = _fg("c9a227")
    LOW        = _fg("4a90c4")
    INFO       = _fg("4a90c4")
    AI         = _fg("9a86fd")
    BORDER     = _fg("3a4048")

    # ── Back-compat aliases (old names used by modules/interactive/banner) ──
    RED     = CRIT
    GREEN   = OK
    YELLOW  = MED
    BLUE    = LOW
    MAGENTA = AI
    CYAN    = ACCENT
    WHITE   = TEXT
    ORANGE  = HIGH
    PINK    = ACCENT
    TEAL    = ACCENT
    PURPLE  = AI
    GRAY    = TEXT_DIM
    BG_RED  = _bg("e5484d")
    BG_DARK = _bg("171b20")


_SEV = {
    "critical": (Colors.CRIT, "CRIT"),
    "high":     (Colors.HIGH, "HIGH"),
    "medium":   (Colors.MED,  "MED"),
    "low":      (Colors.LOW,  "LOW"),
    "info":     (Colors.INFO, "INFO"),
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class UI:
    def __init__(self, no_color=False):
        self.no_color = no_color
        self._lock = threading.Lock()
        self._spinner_active = False
        self._spinner_thread = None
        self._module_ctx = threading.local()

    # ── module tagging (thread-local; TUI routes log lines by it) ──
    def set_module(self, name):
        self._module_ctx.name = name

    @property
    def current_module(self):
        return getattr(self._module_ctx, "name", None)

    # ── primitives ──
    def c(self, color, text):
        if self.no_color:
            return text
        return f"{color}{text}{Colors.RESET}"

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S")

    def _print(self, *args, **kwargs):
        with self._lock:
            try:
                print(*args, **kwargs)
            except UnicodeEncodeError:
                # Legacy console (e.g. Windows cp1252) that can't encode the
                # box-drawing/block glyphs the signature look uses. Degrade to
                # ASCII rather than crash the scan mid-output.
                print(*[self._ascii_safe(a) for a in args], **kwargs)

    @staticmethod
    def _strip(text):
        return _ANSI_RE.sub("", text)

    def _width(self):
        try:
            w = shutil.get_terminal_size(fallback=(80, 24)).columns
        except Exception:
            w = 80
        return max(52, min(w - 2, 92))

    # ── structural ──
    def rule(self, width=None, char="─", indent=2):
        w = width if width is not None else self._width() - indent
        self._print(" " * indent + self.c(Colors.BORDER, char * w))

    def section(self, title):
        """A left-anchored accent label followed by a thin rule filling the row."""
        title = str(title).strip()
        w = self._width()
        head = f"{self.c(Colors.BOLD, self.c(Colors.ACCENT, title))} "
        used = 2 + len(title) + 1   # gutter + title + trailing space
        fill = max(3, w - used)
        self._print("")
        self._print("  " + head + self.c(Colors.BORDER, "─" * fill))

    def subsection(self, title):
        self._print("")
        self._print("  " + self.c(Colors.ACCENT_DIM, "┆") + " " + self.c(Colors.BOLD, self.c(Colors.TEXT, str(title))))

    def config_line(self, pairs):
        """Compact 'key value · key value' row (dim keys, bright values)."""
        sep = self.c(Colors.TEXT_FAINT, " · ")
        parts = [
            f"{self.c(Colors.TEXT_DIM, str(k))} {self.c(Colors.TEXT, str(v))}"
            for k, v in pairs
        ]
        self._print("  " + sep.join(parts))

    # ── log levels (dim timestamp + single sigil, so they recede) ──
    def _log(self, sigil_color, sigil, msg, msg_color=None):
        ts = self.c(Colors.TEXT_FAINT, self._ts())
        body = self.c(msg_color, msg) if msg_color else msg
        self._print(f"  {ts} {self.c(sigil_color, sigil)} {body}")

    def info(self, msg):
        self._log(Colors.TEXT_DIM, "·", msg)

    def ok(self, msg):
        self._log(Colors.OK, "+", msg)

    def warn(self, msg):
        self._log(Colors.MED, "!", msg)

    def error(self, msg):
        self._log(Colors.CRIT, "x", msg)

    def ai(self, msg):
        self._log(Colors.AI, "*", msg)

    def cmd(self, msg):
        self._log(Colors.ACCENT, "$", msg, msg_color=Colors.TEXT_DIM)

    # ── findings (the star; colored severity tag, no timestamp) ──
    def find(self, severity, title, url=""):
        color, label = _SEV.get(str(severity).lower(), (Colors.TEXT, "----"))
        tag = self.c(color, self.c(Colors.BOLD, f"{label:<4}"))
        self._print(f"  {tag}  {self.c(Colors.TEXT, title)}")
        if url:
            self._print(f"        {self.c(Colors.TEXT_DIM, '└ ' + url)}")

    def bullet(self, msg, indent=4):
        self._print(f"{' ' * indent}{self.c(Colors.ACCENT_DIM, '·')} {self.c(Colors.TEXT_DIM, str(msg))}")

    def badge(self, severity):
        color, label = _SEV.get(str(severity).lower(), (Colors.TEXT, severity.upper()))
        return self.c(color, self.c(Colors.BOLD, f" {label} "))

    # ── summary widgets ──
    def sev_bar(self, counts):
        """Single-line stacked severity bar + a compact legend."""
        order = [("critical", Colors.CRIT), ("high", Colors.HIGH),
                 ("medium", Colors.MED), ("low", Colors.LOW), ("info", Colors.INFO)]
        total = sum(counts.get(s, 0) for s, _ in order) or 1
        span = min(48, self._width() - 4)
        bar = ""
        for sev, col in order:
            n = counts.get(sev, 0)
            seg = max(0, round(span * n / total))
            if n and seg == 0:
                seg = 1
            bar += self.c(col, "█" * seg)
        legend = self.c(Colors.TEXT_FAINT, "   ").join(
            f"{self.c(col, sev)} {self.c(Colors.TEXT, str(counts.get(sev, 0)))}"
            for sev, col in order
        )
        self._print("  " + bar)
        self._print("  " + legend)

    def panel(self, title, lines, color=None):
        """A light titled block — title inline on the top rule, no inner
        separator row (reads less like a dialog box than a full border)."""
        accent = color or Colors.ACCENT
        visibles = [len(self._strip(ln)) for ln in lines]
        inner = max([len(title) + 4] + visibles) + 2
        inner = min(inner, self._width() - 4)

        # Top rule must span the same width as a content row (inner + 2):
        #   "─ " (2) + title + " " (1) + top_fill  ==  inner + 2
        top_fill = max(2, inner - len(title) - 1)
        self._print("")
        self._print("  " + self.c(accent, "╭─ ") + self.c(Colors.BOLD, self.c(Colors.TEXT, title))
                    + " " + self.c(accent, "─" * top_fill + "╮"))
        for ln in lines:
            pad = max(0, inner - len(self._strip(ln)))
            self._print("  " + self.c(accent, "│") + " " + ln + " " * pad + " " + self.c(accent, "│"))
        self._print("  " + self.c(accent, "╰" + "─" * (inner + 2) + "╯"))

    def table(self, headers, rows, col_widths=None):
        if not rows:
            self.info("No data to display.")
            return
        if not col_widths:
            col_widths = [max(len(str(r[i])) for r in [headers] + list(rows)) + 2
                          for i in range(len(headers))]

        def line(cells, sepc="│"):
            return "  " + self.c(Colors.BORDER, sepc) + self.c(Colors.BORDER, sepc).join(cells) + self.c(Colors.BORDER, sepc)

        bar = "  " + self.c(Colors.BORDER, "┼".join("─" * w for w in col_widths).join(("├", "┤")))
        top = "  " + self.c(Colors.BORDER, "┬".join("─" * w for w in col_widths).join(("┌", "┐")))
        bot = "  " + self.c(Colors.BORDER, "┴".join("─" * w for w in col_widths).join(("└", "┘")))

        hdr = line([self.c(Colors.BOLD, self.c(Colors.ACCENT, str(h).center(col_widths[i])))
                    for i, h in enumerate(headers)])
        self._print(top)
        self._print(hdr)
        self._print(bar)
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                s = str(cell)
                color, _ = _SEV.get(s.lower(), (None, None))
                if headers[i] in ("Severity", "SEV") and color:
                    cells.append(self.c(color, s.center(col_widths[i])))
                else:
                    s = s[:col_widths[i] - 2] if len(s) > col_widths[i] - 2 else s
                    cells.append(self.c(Colors.TEXT, " " + s.ljust(col_widths[i] - 1)))
            self._print(line(cells))
        self._print(bot)

    # ── misc ──
    def blank(self):
        self._print()

    def raw(self, msg, end="\n", flush=False):
        with self._lock:
            try:
                print(msg, end=end, flush=flush)
            except UnicodeEncodeError:
                print(self._ascii_safe(msg), end=end, flush=flush)

    @staticmethod
    def _ascii_safe(value):
        if not isinstance(value, str):
            return value
        try:
            from recon.core.console import ascii_fallback
            return ascii_fallback(value)
        except Exception:
            return value.encode("ascii", "replace").decode("ascii")

    def input(self, prompt):
        return input(f"  {self.c(Colors.ACCENT, '›')} {prompt}")

    def confirm(self, prompt):
        ans = self.input(f"{prompt} {self.c(Colors.TEXT_DIM, '[Y/n]')} ").strip().lower()
        return ans in ("", "y", "yes")

    # ── spinner ──
    def _stdout_isatty(self):
        try:
            return bool(sys.stdout.isatty())
        except Exception:
            return False

    def start_spinner(self, msg):
        """Show an indeterminate 'working…' indicator for a long step with no
        measurable total (where progress_bar can't apply).

        Animates a \\r spinner only on an interactive, color-capable TTY. Under
        the TUI (no_color; stdout owned by Textual and routed via _print) or
        when output is piped/redirected, a carriage-return animation would
        corrupt the display — so we emit a single static line through _print
        instead and never spawn the thread."""
        self._spinner_msg = msg

        if self.no_color or not self._stdout_isatty():
            self._spinner_active = False
            self._print(f"  {self.c(Colors.ACCENT, '·')} {self.c(Colors.TEXT_DIM, msg)}")
            return

        self._spinner_active = True
        try:
            from recon.core.console import supports_unicode
            _uni = supports_unicode()
        except Exception:
            _uni = False
        # A quiet "haunting" spinner — Braille dots when the terminal can
        # render them, plain ASCII otherwise (legacy Windows consoles).
        _frames = (["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
                   if _uni else ["|", "/", "-", "\\"])

        def _spin(frames=_frames):
            i = 0
            while self._spinner_active:
                with self._lock:
                    sys.stdout.write(f"\r  {self.c(Colors.ACCENT, frames[i % len(frames)])} "
                                     f"{self.c(Colors.TEXT_DIM, self._spinner_msg)}   ")
                    sys.stdout.flush()
                i += 1
                time.sleep(0.08)

        self._spinner_thread = threading.Thread(target=_spin, daemon=True)
        self._spinner_thread.start()

    def stop_spinner(self, final_msg=None):
        was_animating = self._spinner_active
        self._spinner_active = False
        if self._spinner_thread:
            self._spinner_thread.join(timeout=0.5)
            self._spinner_thread = None
        # Only the animated path leaves a dirty \r line to wipe; the static
        # fallback already printed a normal, complete line.
        if was_animating:
            with self._lock:
                sys.stdout.write("\r" + " " * (self._width() + 4) + "\r")
                sys.stdout.flush()
        if final_msg:
            self.ok(final_msg)

    # ── progress ──
    def progress_bar(self, current, total, label="", width=None):
        width = width or min(40, self._width() - 24)
        pct = current / total if total else 0
        filled = int(width * pct)
        bar = self.c(Colors.ACCENT, "█" * filled) + self.c(Colors.TEXT_FAINT, "░" * (width - filled))
        with self._lock:
            sys.stdout.write(f"\r  {bar} {self.c(Colors.TEXT_DIM, f'{pct*100:3.0f}%')} {label}")
            sys.stdout.flush()
            if current >= total:
                sys.stdout.write("\n")
