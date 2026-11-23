"""
Screenshot capture — visual evidence for confirmed findings (an XSS payload
actually EXECUTING via a fired JS dialog, a clickjacking iframe embed
actually rendering), strengthening bug bounty reports significantly beyond
raw HTTP response text. playwright is an optional dependency (`pip install
playwright && playwright install chromium`); every function here degrades
to a no-op (returns None) when it isn't installed rather than failing the
scan — callers must never withhold/downgrade a finding just because a
screenshot couldn't be captured.
"""
import time
from pathlib import Path

_AVAILABLE = None


def available() -> bool:
    global _AVAILABLE
    if _AVAILABLE is None:
        try:
            import playwright.sync_api  # noqa: F401
            _AVAILABLE = True
        except ImportError:
            _AVAILABLE = False
    return _AVAILABLE


def _out_path(output_dir: str, filename_hint: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in filename_hint)[:80]
    ts = int(time.time() * 1000)
    out_dir = Path(output_dir or ".") / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{safe}_{ts}.png"


def capture_url(url: str, output_dir: str, filename_hint: str, wait_ms: int = 1500) -> dict | None:
    """
    Navigate to `url` in headless Chromium and screenshot it, capturing any
    JS dialog (alert/confirm/prompt) that fires — the strongest possible
    proof a reflected-XSS payload actually EXECUTED, not just that it's
    present unescaped in the response text. Returns
    {"path": str, "dialogs": [str, ...]}, or None if playwright isn't
    installed or the capture failed for any reason.
    """
    if not available():
        return None
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    out_path = _out_path(output_dir, filename_hint)
    dialogs: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
                page.goto(url, timeout=15000, wait_until="domcontentloaded")
                page.wait_for_timeout(wait_ms)
                page.screenshot(path=str(out_path), full_page=True)
            finally:
                browser.close()
    except Exception:
        return None
    return {"path": str(out_path), "dialogs": dialogs}


def capture_iframe_embed(target_url: str, output_dir: str, filename_hint: str, wait_ms: int = 1500) -> str | None:
    """
    Build a minimal local HTML page that embeds `target_url` in an
    <iframe> and screenshot it — direct visual proof the target actually
    renders inside a third-party frame (clickjacking), rather than only
    inferring it from the absence of X-Frame-Options/CSP frame-ancestors.
    Returns the saved PNG path, or None.
    """
    if not available():
        return None
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    out_path = _out_path(output_dir, filename_hint)
    html = (
        "<!doctype html><html><body style='margin:0'>"
        f"<iframe src='{target_url}' style='width:1280px;height:800px;border:4px solid red'></iframe>"
        "</body></html>"
    )
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
            try:
                context = browser.new_context(ignore_https_errors=True, viewport={"width": 1300, "height": 850})
                page = context.new_page()
                page.set_content(html)
                page.wait_for_timeout(wait_ms)
                page.screenshot(path=str(out_path))
            finally:
                browser.close()
    except Exception:
        return None
    return str(out_path)
