"""
YATA RECON modules package.
BaseModule is the shared base class for all scan modules.
"""

import collections
import time
import threading

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None


# Per-worker throttle so each thread honours --delay without the whole scan
# collapsing to a single global request/`delay`. _LAST_REQUEST is kept for
# back-compat but is no longer the gate; pacing is tracked per-thread below.
_RATE_LOCK = threading.Lock()
_LAST_REQUEST = [0.0]
_THREAD_PACE = threading.local()

# ── Adaptive throttling ─────────────────────────────────────────────────────
# --delay is a fixed floor, not a full rate-limiting strategy: it's the same
# number whether the target is healthy and fast or already struggling. This
# tracks response latency/status codes process-wide (fed by a response hook
# attached to every session _session() hands out) and derives a multiplier
# applied on top of --delay: back off automatically on 429/5xx or rising
# latency, relax back toward the user's own --delay once the target looks
# healthy again.
_ADAPTIVE_LOCK = threading.Lock()
_ADAPTIVE_STATE = {"multiplier": 1.0, "latencies": collections.deque(maxlen=25), "error_streak": 0}
_BASELINE_LATENCY = [None]

# Process-wide count of HTTP responses seen through any module session — a
# cheap liveness/throughput signal the TUI samples to show a live req/s rate
# (and the aggregate request total). Incremented in the response hook below.
_REQUEST_COUNT = [0]


def request_count() -> int:
    """Total HTTP responses observed across all module sessions this run."""
    return _REQUEST_COUNT[0]


class ModuleSkipped(Exception):
    """Raised inside a module when the operator asks to skip it mid-scan (see
    core/skip.py). BaseModule._throttle() raises it before the next request, so
    an HTTP-bound module stops almost immediately; _run_module catches it and
    marks the module skipped rather than failed."""


def _adaptive_response_hook(resp, *args, **kwargs):
    _REQUEST_COUNT[0] += 1  # telemetry only; GIL makes this good enough
    try:
        elapsed = resp.elapsed.total_seconds()
    except Exception:
        return resp
    with _ADAPTIVE_LOCK:
        state = _ADAPTIVE_STATE
        if resp.status_code in (429, 503):
            state["error_streak"] += 1
            state["multiplier"] = min(8.0, state["multiplier"] * 1.8)
        elif resp.status_code >= 500:
            state["error_streak"] += 1
            state["multiplier"] = min(6.0, state["multiplier"] * 1.3)
        else:
            state["error_streak"] = 0
            state["latencies"].append(elapsed)
            if len(state["latencies"]) >= 5:
                recent = list(state["latencies"])[-5:]
                avg_recent = sum(recent) / len(recent)
                baseline = _BASELINE_LATENCY[0]
                if baseline is None:
                    _BASELINE_LATENCY[0] = avg_recent
                elif avg_recent > baseline * 2.5:
                    state["multiplier"] = min(5.0, state["multiplier"] * 1.15)  # target slowing — ease off
                elif avg_recent < baseline * 1.3 and state["multiplier"] > 1.0:
                    state["multiplier"] = max(1.0, state["multiplier"] * 0.9)   # healthy again — relax
    return resp

# Field names that plausibly hold a live session/API token in a JSON response.
_TOKEN_FIELD_NAMES = {
    "token", "access_token", "accesstoken", "jwt", "id_token",
    "session_id", "sessionid", "session_token", "api_key", "apikey",
    "auth_token", "bearer", "authtoken",
}


_TOKEN_LEAF_KEYS = {"id", "value", "key", "code", "hash", "secret", "string"}


def _looks_like_token_value(s: str) -> bool:
    """Reject obviously-non-token strings (dates, sentences) that would
    otherwise be the first string a naive walk stumbles onto — a token/id
    value never contains whitespace."""
    return len(s) >= 8 and " " not in s


def _first_string_leaf(data, depth=0, max_depth=3):
    """Find the first plausible string value nested inside a token-shaped
    subtree, e.g. {"token": {"id": "86462f8c...", "expires": "Thu Sep..."}}
    — the key that matched ("token") isn't itself a string, and the real
    value is one level deeper under a generic name ("id") that isn't
    independently recognizable as token-like anywhere else in a JSON body.
    Prefers identifier-shaped keys and rejects date/sentence-shaped values
    (containing whitespace) so a sibling "expires" timestamp doesn't win
    over the actual token just by appearing first in the dict."""
    if depth > max_depth:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and isinstance(k, str) and k.lower() in _TOKEN_LEAF_KEYS and _looks_like_token_value(v):
                return k, v
        for k, v in data.items():
            if isinstance(v, str) and _looks_like_token_value(v):
                return k, v
        for v in data.values():
            found = _first_string_leaf(v, depth + 1, max_depth)
            if found:
                return found
    elif isinstance(data, list) and data:
        return _first_string_leaf(data[0], depth + 1, max_depth)
    return None


def _find_token_in_json(data, depth=0):
    """Recursively search a decoded JSON body for a plausible token field.
    Returns (key, value) or None."""
    if depth > 4:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(k, str) or k.lower() not in _TOKEN_FIELD_NAMES:
                continue
            if isinstance(v, str) and _looks_like_token_value(v):
                return k, v
            if isinstance(v, (dict, list)):
                nested = _first_string_leaf(v)
                if nested:
                    return f"{k}.{nested[0]}", nested[1]
        for v in data.values():
            found = _find_token_in_json(v, depth + 1)
            if found:
                return found
    elif isinstance(data, list):
        for item in data[:20]:
            found = _find_token_in_json(item, depth + 1)
            if found:
                return found
    return None


class BaseModule:
    NAME = "Base"

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=10, verbose=False, ai=None, output_dir=None):
        self.target     = target
        self.db         = db
        self.ui         = ui
        self.ctx        = context
        self.timeout    = timeout
        self.delay      = delay
        self.threads    = threads
        self.verbose    = verbose
        self.ai         = ai
        self.output_dir = output_dir
        # Set by ScanSession._run_module after construction; used by _throttle
        # to honour an operator skip request for THIS module (shared across the
        # module's own worker threads, unlike ui.current_module which is
        # thread-local and unset inside a module's internal ThreadPoolExecutor).
        self.module_id  = None
        # Prefer the base URL recon actually resolved (ctx['base_url']) over a
        # naive https:// guess. recon runs first and records the real scheme
        # after an HTTPS→HTTP auto-detect, so every module instantiated after
        # it connects with the right scheme — otherwise an HTTP-only target
        # made every self.base_url-using module (headers, cors, clickjacking,
        # host_header, secrets, redirect, crlf, …) fail on a dead https:// URL.
        self.base_url   = context.get("base_url") or (
            f"https://{target}" if not target.startswith("http") else target
        )
        
        # Instantiate common tools
        try:
            from recon.core.validator import Validator
            self.validator = Validator()
        except ImportError:
            self.validator = None
            
        try:
            from recon.core.tool_runner import ExternalToolRunner
            self.tool_runner = ExternalToolRunner(self.ui)
        except ImportError:
            self.tool_runner = None

    def _throttle(self):
        """Per-worker rate limiter: ensure at least `delay * adaptive_multiplier`
        between two requests MADE BY THE SAME WORKER THREAD.

        This used to be a *process-wide* gate — one lock + one global
        timestamp — so every module's ThreadPoolExecutor was silently
        serialized down to a single request every `delay` seconds no matter
        how many workers (or how many parallel modules) were running. A heavy
        scan is tens of thousands of requests; at the default 0.5s global
        spacing that is hours of pure sleep, which is exactly the "it's stuck
        for hours" symptom. Pacing each worker independently restores the
        concurrency the modules were written to use. Aggregate load stays
        bounded by the thread-pool sizes and self-corrects through the global
        adaptive multiplier, which stretches every worker's delay the moment
        the target starts returning 429/5xx or slowing down."""
        # Operator skip: abort before the next request. Checked first so it
        # works even with --delay 0, and via the instance (module_id) so it
        # also fires inside the module's internal worker threads.
        mid = self.module_id
        if mid:
            sc = self.ctx.get("_skip_controller")
            if sc is not None and sc.is_requested(mid):
                raise ModuleSkipped(mid)
        if self.delay <= 0:
            return
        # Unlocked read of a single float: a slightly stale multiplier is
        # harmless and avoids making every request contend on one lock.
        effective_delay = self.delay * _ADAPTIVE_STATE["multiplier"]
        last = getattr(_THREAD_PACE, "last", 0.0)
        wait = (last + effective_delay) - time.time()
        if wait > 0:
            time.sleep(wait)
        _THREAD_PACE.last = time.time()
        _LAST_REQUEST[0] = _THREAD_PACE.last  # best-effort, for any external reader

    def _next_allowed(self, effective_delay=None):
        d = self.delay if effective_delay is None else effective_delay
        return getattr(_THREAD_PACE, "last", 0.0) + d

    def _session(self):
        if not requests:
            return None
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 YATA RECON/5.0"})
        s.verify = False
        # Feeds the process-wide adaptive-throttle state from every request
        # made through this session, regardless of which HTTP verb/helper a
        # module used to send it.
        s.hooks.setdefault("response", []).append(_adaptive_response_hook)
        # Apply scan-wide network policy — upstream proxy (--proxy) and the
        # scope guard that blocks out-of-scope requests before they're sent.
        try:
            from recon.core import net
            net.apply(s)
        except Exception:
            pass
        return s

    def _get(self, url, params=None):
        try:
            self._throttle()
            # Reuse ONE session across _get calls for connection pooling /
            # keep-alive — the old code built a fresh requests.Session() (new
            # TCP + TLS handshake) on every single call, which is pure
            # overhead for the many light modules that probe a target through
            # _get in a loop. _session() is deliberately left creating fresh
            # sessions, since some callers (e.g. broken_auth token sampling)
            # rely on that isolation.
            if getattr(self, "_shared_session", None) is None:
                self._shared_session = self._session()
            s = self._shared_session
            if s is None:
                return None
            return s.get(url, params=params, timeout=self.timeout)
        except Exception:
            return None

    @staticmethod
    def _is_html_response(resp) -> bool:
        """Whether a browser would parse this response as HTML — the only
        kind of response in which reflected markup can execute. A JSON /
        plain-text / octet-stream / image response that merely echoes a
        payload is inert, and flagging it is a false positive. A missing or
        empty Content-Type defaults to HTML (that is how browsers treat it)."""
        if resp is None or not hasattr(resp, "headers"):
            return False
        ct = (resp.headers.get("Content-Type", "") or "").split(";", 1)[0].strip().lower()
        if not ct:
            return True
        return ct in ("text/html", "application/xhtml+xml", "application/xml", "text/xml")

    # ── Live credential propagation ─────────────────────────────────────────
    # Most scanners test every endpoint unauthenticated in isolation. Here,
    # any module that stumbles onto a real working credential (an auth-bypass
    # SQLi that returns a live token, a forged JWT that gets accepted, a
    # cracked login) can register it so every module that runs afterward
    # automatically attaches it — turning a set of isolated blind probes into
    # a stateful, authenticated deep scan of the target.
    def capture_credential(self, kind: str, value, source: str = ""):
        """
        Register a live credential discovered during the scan.
        kind: 'header' (value is a {name: value} dict), 'cookie' (value is a
        {name: value} dict), or 'bearer' (value is a raw token string, sent
        as an Authorization: Bearer header).
        """
        store = self.ctx.setdefault("captured_credentials", [])
        store.append({"kind": kind, "value": value, "source": source, "module": self.NAME})

        if kind == "header" and isinstance(value, dict):
            self.ctx.setdefault("auth_headers", {}).update(value)
        elif kind == "cookie" and isinstance(value, dict):
            self.ctx.setdefault("auth_cookies", {}).update(value)
        elif kind == "bearer" and isinstance(value, str):
            self.ctx.setdefault("auth_headers", {})["Authorization"] = f"Bearer {value}"

        if self.ui:
            self.ui.warn(
                f"Captured live credential ({kind}) from {source or self.NAME} "
                f"— propagating to remaining modules"
            )

    def auth_headers(self) -> dict:
        """Headers to attach to authenticated probes: OpenAPI-derived example
        headers merged with any live credential captured so far this scan."""
        return dict(self.ctx.get("auth_headers", {}))

    def auth_cookies(self) -> dict:
        return dict(self.ctx.get("auth_cookies", {}))

    def try_capture_credential_from_response(self, resp, source: str = ""):
        """
        Heuristic scan of a response for a live token/session worth reusing.
        Safe to call on any response — a no-op unless something token-shaped
        is actually present. Looks at JSON body fields (token/access_token/
        jwt/session_id/api_key/...) and Set-Cookie headers for a
        session-shaped cookie name.
        """
        if resp is None or not hasattr(resp, "headers"):
            return

        try:
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct.lower():
                import json as _json
                data = _json.loads(resp.text)
                found = _find_token_in_json(data)
                if found:
                    key, val = found
                    self.capture_credential("bearer", val, source=f"{source} (field '{key}')")
        except Exception:
            pass

        try:
            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie and self.validator:
                cookie_kv = set_cookie.split(";", 1)[0]
                cname, _, cval = cookie_kv.partition("=")
                cname = cname.strip()
                if cname and self.validator.validate_cookie_is_session(cname):
                    self.capture_credential("cookie", {cname: cval.strip()}, source=source)
        except Exception:
            pass


# ─── Headers Module ───────────────────────────────────────────────────────────