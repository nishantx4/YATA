"""
YATA RECON identity — a single hand-built monospace wordmark used by both the
console/headless output and the Textual TUI setup screen. Deliberately NOT a
figlet dump, no emoji, no marketing tagline: a signature mark, a version, and
one line that says what the module is.

Includes a small radar sigil to the left of the wordmark, a compact one-line
variant that auto-selects on narrow terminals, and a pure-ASCII fallback for
legacy consoles that can't render box-drawing/block glyphs (so the banner
degrades cleanly on a Windows cp1252 console instead of throwing or printing
mojibake). All of it stays inside the signature-mark language — box/block
glyphs in the one cold accent, nothing decorative.
"""
import shutil

VERSION = "1.0"
TAGLINE = "deployment-side reconnaissance & live exploitation"

# Signature wordmark spelling YATA (box-drawing). Three equal-width rows so it
# aligns under a 2-space gutter in any monospace terminal.
LOGO_LINES = [
    "┬ ┬ ┌─┐ ┌┬┐ ┌─┐",
    "└┬┘ ├─┤  │  ├─┤",
    " ┴  ┴ ┴  ┴  ┴ ┴",
]
# A compact monospace wordmark for the ASCII fallback (same three-row shape,
# drawn with ASCII only).
LOGO_LINES_ASCII = [
    "__   __ _  _____  _   ",
    "\ \ / // \|_   _|/ \  ",
    " \ V // _ \ | | / _ \ ",
]

# A small 3-row radar sigil that sits to the left of the wordmark.
SIGIL = [
    "▛▀▜",
    "▌◉▐",
    "▙▄▟",
]
SIGIL_ASCII = [
    "[+]",
    "|o|",
    "[_]",
]

# Back-compat: some callers imported the logo as a single BANNER string.
BANNER = "\n".join(LOGO_LINES)


def logo_block(unicode_ok: bool = True) -> list:
    """The radar sigil joined to the wordmark, row-for-row — used by the TUI
    setup screen (which always renders in a Unicode-capable Textual surface)
    and anywhere a single centered logo block is wanted."""
    sigil = SIGIL if unicode_ok else SIGIL_ASCII
    word = LOGO_LINES if unicode_ok else LOGO_LINES_ASCII
    return [f"{s}  {w}" for s, w in zip(sigil, word)]


def _term_cols() -> int:
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        return 80


def print_banner(ui, info=None):
    """Render the radar sigil + wordmark, version + tagline, and an optional
    aligned config block. `info` is an iterable of (label, value) pairs
    printed as a compact 'key value · key value' line under the rule.

    Automatically falls back to a compact one-line mark on a narrow terminal,
    and to pure ASCII on a console that can't render the box/block glyphs."""
    from recon.core.ui import Colors
    try:
        from recon.core.console import supports_unicode
        unicode_ok = supports_unicode()
    except Exception:
        unicode_ok = True

    cols = _term_cols()
    # The full sigil+wordmark needs ~40 columns incl. gutters; drop to the
    # compact one-liner below that so it never wraps into a mangled block.
    compact = cols < 44

    ui.blank()
    if compact:
        _print_compact(ui, Colors, unicode_ok)
    else:
        _print_full(ui, Colors, unicode_ok)

    # Contained header width — a tidy block under the wordmark, not a rule
    # stretched across a wide terminal.
    w = min(max(40, cols - 2), 60)
    ui.rule(width=w)
    if info:
        ui.config_line(info)
        ui.rule(width=w)
    ui.blank()


def _print_full(ui, Colors, unicode_ok):
    sigil = SIGIL if unicode_ok else SIGIL_ASCII
    word = LOGO_LINES if unicode_ok else LOGO_LINES_ASCII
    # Zip the sigil and wordmark row-for-row (both are 3 rows).
    for i, (srow, wrow) in enumerate(zip(sigil, word)):
        line = "  " + ui.c(Colors.ACCENT, srow) + "  " + ui.c(Colors.ACCENT, wrow)
        if i == len(word) - 1:
            line += "  " + ui.c(Colors.TEXT_DIM, "v" + VERSION)
        ui.raw(line)
    ui.raw("  " + ui.c(Colors.TEXT_DIM, "RECON · " + TAGLINE))


def _print_compact(ui, Colors, unicode_ok):
    mark = "▛▜" if unicode_ok else "[o]"
    ui.raw("  " + ui.c(Colors.ACCENT, mark) + " "
           + ui.c(Colors.BOLD, ui.c(Colors.ACCENT, "yata recon"))
           + " " + ui.c(Colors.TEXT_DIM, "v" + VERSION))
    ui.raw("  " + ui.c(Colors.TEXT_DIM, TAGLINE))
