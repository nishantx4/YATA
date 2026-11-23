from __future__ import annotations

from rich.markup import escape


def esc(value: object) -> str:
    """Escape a dynamic value before interpolating it into Rich console markup.

    Rich's markup parser silently swallows single-token bracket content
    (e.g. "[password]") instead of rendering it literally, which drops
    payloads/evidence/report text pulled from scans, exploits, or the LLM.
    """
    return escape(str(value))
