"""
Console capability detection — one honest answer to "can this terminal render
the box-drawing/sigil glyphs the signature mark uses, or do we fall back to
pure ASCII?"

Windows legacy consoles (cp1252/cp437) and any stream whose encoding can't
represent '─'/'█'/'▚' will raise UnicodeEncodeError or print mojibake the
moment the banner or a spinner writes one. yata recon reconfigures stdout
to UTF-8 at startup when it can; this module reports whether that actually
took, so the banner and spinner can pick a glyph set that will not crash.
"""
import os
import sys

# A couple of the glyphs the UI actually emits — if the active encoding can
# round-trip these, it can handle the rest of the signature-mark set.
_PROBE = "─█▚┌┐└┘│·"

_cached = None


def supports_unicode() -> bool:
    """True when it is safe to emit box-drawing / block glyphs on stdout."""
    global _cached
    if _cached is not None:
        return _cached

    # An explicit override always wins (useful for CI logs / piping to files).
    force = os.environ.get("YATA_RECON_ASCII", "").strip().lower()
    if force in ("1", "true", "yes"):
        _cached = False
        return _cached

    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    if not enc:
        _cached = False
        return _cached
    if "utf" in enc:
        _cached = True
        return _cached
    # Non-UTF encoding: only keep Unicode if every probe glyph can be encoded.
    try:
        _PROBE.encode(enc)
        _cached = True
    except (UnicodeEncodeError, LookupError, Exception):
        _cached = False
    return _cached


def ascii_fallback(text: str) -> str:
    """Transliterate the glyphs the UI emits into ASCII for streams that can't
    render them, and GUARANTEE the result is pure ASCII (any character not in
    the table is forced with a replacement) — this is the retry path for a
    failed encode, so it must never itself produce an unencodable character.

    ANSI color escapes (ESC[..m) are preserved; only printable glyphs are
    transliterated."""
    table = {
        "─": "-", "━": "=", "│": "|", "┆": ":", "┼": "+",
        "┌": "+", "┐": "+", "└": "+", "┘": "+", "├": "+", "┤": "+",
        "┬": "+", "┴": "+", "╭": "+", "╮": "+", "╰": "+", "╯": "+",
        "█": "#", "░": ".", "▚": "#", "▞": "#", "▙": "#", "▟": "#", "▀": "#", "▌": "#", "▐": "#",
        "·": ".", "•": "*", "›": ">", "«": "<<", "»": ">>", "–": "-", "—": "-",
        "’": "'", "‘": "'", "“": '"', "”": '"', "…": "...", "✓": "+", "✗": "x", "⚑": "!",
        "μ": "u", "σ": "s", "±": "+/-", "×": "x", "→": "->", "←": "<-",
        "▁": "_", "▂": "_", "▃": "-", "▄": "-", "▅": "=", "▆": "=", "▇": "#",
        "⠋": "*", "⠙": "*", "⠹": "*", "⠸": "*", "⠼": "*", "⠴": "*", "⠦": "*", "⠧": "*", "⠇": "*", "⠏": "*",
    }
    mapped = "".join(table.get(ch, ch) for ch in text)
    # Final guarantee: keep ASCII (incl. the ESC char used by color codes) and
    # replace anything else so the subsequent encode can never fail.
    out = []
    for ch in mapped:
        if ch == "\x1b" or ord(ch) < 128:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)
