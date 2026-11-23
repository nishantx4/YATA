from __future__ import annotations

from pathlib import Path


def bound_and_store(
    text: str,
    tool_call_id: str,
    store_dir: Path,
    *,
    max_chars: int = 4000,
    max_lines: int = 200,
) -> tuple[str, Path]:
    """Truncate `text` to a head+tail preview and spill the full text to
    `store_dir/<tool_call_id>.txt`. Returns (display_text, full_path).

    Mirrors Strix's output_store.py pattern: never hand an LLM an unbounded
    blob, but never silently drop data either -- the full text is always on
    disk, and the truncation marker tells the model exactly where.
    """
    store_dir.mkdir(parents=True, exist_ok=True)
    full_path = store_dir / f"{tool_call_id}.txt"
    full_path.write_text(text, encoding="utf-8", errors="replace")

    lines = text.splitlines()
    if len(text) <= max_chars and len(lines) <= max_lines:
        return text, full_path

    half_lines = max(max_lines // 2, 1)
    half_chars = max(max_chars // 2, 1)

    head_lines = lines[:half_lines]
    tail_lines = lines[-half_lines:] if len(lines) > half_lines else []
    head = "\n".join(head_lines)[:half_chars]
    tail = "\n".join(tail_lines)[-half_chars:] if tail_lines else ""

    omitted = len(lines) - len(head_lines) - len(tail_lines)
    marker = f"\n[... truncated, {max(omitted, 0)} more line(s) -- full output saved to {full_path} ...]\n"

    display = head + marker + tail
    return display, full_path
