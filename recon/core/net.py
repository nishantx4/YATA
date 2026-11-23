"""
Central network policy — process-wide HTTP proxy and scope enforcement that
every module's requests.Session routes through, set up once per scan.

Two long-standing gaps this closes:
  * --proxy had nowhere to live. Now a single set_proxy() call makes every
    session created by BaseModule, the Validator, and the baseline profiler
    route through an upstream proxy (Burp/ZAP/mitmproxy) — the thing every
    operator wants after an automated pass, to replay and hand-verify
    findings in their own tooling.
  * Scope was never enforced at the request layer. install_guards() mounts a
    tiny adapter that refuses any out-of-scope request BEFORE it leaves the
    process, so a synthesized bucket host, an open-redirect follow, or a
    stray absolute URL can never touch something the engagement forbids.

Everything is best-effort and defensive: if requests isn't importable, or a
session is odd, guard installation silently no-ops rather than breaking a
scan.
"""
from __future__ import annotations

import threading

_LOCK = threading.Lock()
_PROXIES: dict | None = None
_SCOPE = None            # a core.scope.ScopeEngine or None
_BLOCKED = [0]           # count of requests refused as out-of-scope (telemetry)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.exceptions import RequestException

    class OutOfScopeError(RequestException):
        """Raised in place of sending a request to an out-of-scope host.
        Subclasses RequestException so every module's existing
        `except RequestException` / `except Exception` path treats it as a
        dead request (no response) instead of crashing."""

    class _GuardAdapter(HTTPAdapter):
        """Transport adapter that consults the active ScopeEngine before any
        request is actually sent."""

        def send(self, request, *args, **kwargs):
            scope = get_scope()
            if scope is not None:
                try:
                    ok = scope.is_in_scope(request.url)
                except Exception:
                    ok = True  # never let a scope bug block a legitimate request
                if not ok:
                    with _LOCK:
                        _BLOCKED[0] += 1
                    raise OutOfScopeError(f"Blocked out-of-scope request: {request.url}")
            return super().send(request, *args, **kwargs)

    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover - requests should always be present
    _HAVE_REQUESTS = False

    class OutOfScopeError(Exception):
        pass


def set_proxy(proxy: str | None):
    """proxy: e.g. 'http://127.0.0.1:8080'. Applied to both http and https."""
    global _PROXIES
    with _LOCK:
        _PROXIES = {"http": proxy, "https": proxy} if proxy else None


def get_proxies() -> dict | None:
    with _LOCK:
        return dict(_PROXIES) if _PROXIES else None


def set_scope(engine):
    global _SCOPE
    with _LOCK:
        _SCOPE = engine


def get_scope():
    with _LOCK:
        return _SCOPE


def blocked_count() -> int:
    with _LOCK:
        return _BLOCKED[0]


def in_scope(url: str) -> bool:
    """Direct check for the few call sites that use requests.* at module level
    rather than a guarded session (e.g. session.py chain verification)."""
    scope = get_scope()
    if scope is None:
        return True
    try:
        return scope.is_in_scope(url)
    except Exception:
        return True


def apply(session):
    """Apply the active proxy + scope guard to a requests.Session. Returns the
    same session for convenience. Safe to call on every session created."""
    if not _HAVE_REQUESTS or session is None:
        return session
    try:
        proxies = get_proxies()
        if proxies:
            session.proxies.update(proxies)
        # Mount the scope guard unconditionally — it's a cheap no-op when no
        # ScopeEngine is active, and this way a scope set mid-scan still takes
        # effect on sessions that were created earlier.
        adapter = _GuardAdapter()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    except Exception:
        pass
    return session
