"""
RaceConditionModule — TOCTOU / limit-overrun race detection.

The highest-value bug class a request-at-a-time scanner structurally cannot
see: a server-side check and the action it guards are not atomic, so firing
the same request many times *at once* slips more through than the rule should
ever allow (coupon redeemed twice, one-vote-per-user voted N times, a
withdrawal that overdraws, an OTP/login limiter bypassed by concurrency).

It holds the near-zero-false-positive bar by reporting ONLY a reproducible
differential, never a flood:

  1. SEQUENTIAL CONTROL — send the same action one-at-a-time until the server
     starts refusing it (429 / 409 / 403, or a body that says limit/already/
     duplicate). If the action is NOT limited sequentially, there is nothing
     to race — the endpoint is skipped and nothing is reported. This is what
     keeps the module quiet on the vast majority of endpoints.
  2. CONCURRENT BURST — only for an endpoint that demonstrably enforced a
     limit, fire a small, bounded burst of identical requests released as
     simultaneously as possible (a barrier) and count how many SUCCEEDED.
  3. CONFIRM — a finding requires the concurrent run to let through
     materially more than the sequential limit, AND a second independent
     burst to reproduce it. Overrunning a limit you could not overrun one
     request at a time is the proof.

Safety: every phase is tightly capped (a handful of endpoints, ~16 requests
per burst) — this is bounded authorized testing to prove a logic flaw, not a
denial-of-service. Destructive-looking endpoints (delete/remove/purge) are
never raced.
"""
import math
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule
from recon.core import cancellation

# Endpoints whose *name* suggests a limited, state-changing action worth racing.
ACTION_HINTS = [
    "redeem", "coupon", "voucher", "promo", "gift", "claim", "apply", "vote",
    "like", "follow", "subscribe", "rsvp", "reserve", "book", "purchase",
    "checkout", "order", "transfer", "withdraw", "topup", "deposit", "invite",
    "refer", "rate", "review", "upvote", "star", "join", "enroll", "register",
    "verify", "confirm", "otp", "login", "token", "request-reset",
]
# Never race anything that looks destructive — a race on delete has no safe
# differential to measure and could do real damage.
DESTRUCTIVE_HINTS = ["delete", "remove", "destroy", "purge", "drop", "wipe", "cancel", "revoke"]

# Response signals that a limit / idempotency guard kicked in.
LIMIT_STATUS = {409, 429}
LIMIT_KEYWORDS = [
    "rate limit", "too many", "already", "duplicate", "limit reached",
    "limit exceeded", "only once", "has been used", "already redeemed",
    "already claimed", "already voted", "no longer available", "out of stock",
    "quota", "throttl",
]


class RaceConditionModule(BaseModule):
    NAME = "Race Condition"
    MODULE_ID = "race"
    MODULE_LABEL = "Race Conditions (TOCTOU)"

    MAX_ENDPOINTS = 6          # how many distinct actions we'll probe at all
    SEQ_PROBES = 6             # sequential requests to find the limit
    BURST = 16                 # concurrent requests per burst (bounded)

    def __init__(self, target, db, ui, context, timeout=12, delay=0.3,
                 threads=10, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self._found = 0

    def run(self):
        self.ui.section("Race Conditions — TOCTOU / Limit-Overrun Detection")
        if not requests:
            self.ui.info("requests not available — skipping.")
            return

        actions = self._collect_actions()
        if not actions:
            self.ui.info("No limited, state-changing action endpoints identified to race — skipping.")
            return
        self.ui.info(f"Evaluating {len(actions)} candidate action(s) for non-atomic limit enforcement.")

        for act in actions:
            if cancellation.is_cancelled():
                break
            try:
                self._race_one(act)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"race error on {act.get('url')}: {e}")

        if self._found == 0:
            self.ui.info("No race conditions confirmed (no limit was overrun under concurrency).")
        else:
            self.ui.ok(f"Race-condition scan complete — {self._found} confirmed finding(s).")

    # ──────────────────────────────────────────────────────────────────────
    def _collect_actions(self):
        """Build a capped worklist of limited-action candidates from forms,
        API endpoints, and action-named query endpoints."""
        actions, seen = [], set()

        def add(url, method, data=None, json_body=None):
            low = url.lower()
            if any(d in low for d in DESTRUCTIVE_HINTS):
                return
            key = (url.split("#", 1)[0], method)
            if key in seen or len(actions) >= self.MAX_ENDPOINTS:
                return
            seen.add(key)
            actions.append({"url": url, "method": method.upper(),
                            "data": data, "json": json_body})

        # HTML forms whose action/method look like a limited operation.
        for form in self.ctx.get("forms", []):
            method = (form.get("method") or "POST").upper()
            url = form.get("action") or self.base_url
            if method == "GET":
                continue
            if any(h in url.lower() for h in ACTION_HINTS) or any(
                    h in (" ".join(form.get("inputs", {}).keys())).lower() for h in ACTION_HINTS):
                data = {k: (v or "1") for k, v in form.get("inputs", {}).items()}
                add(url, method, data=data)

        # OpenAPI/discovered API endpoints.
        for api in self.ctx.get("api_endpoints", []):
            method = (api.get("method") or "POST").upper()
            url = api.get("url", "")
            if method in ("GET", "HEAD", "OPTIONS") or not url:
                continue
            if "{" in url:
                continue  # unresolved path param — skip rather than guess
            if any(h in url.lower() for h in ACTION_HINTS):
                body = {p: "1" for p in api.get("json_props", [])} or None
                add(url, method, json_body=body)

        # Action-named plain endpoints (treated as idempotent-looking GET/POST).
        for ep in self.ctx.get("endpoints", []):
            low = ep.lower()
            if any(h in low for h in ACTION_HINTS):
                parsed = urllib.parse.urlparse(ep)
                add(ep, "POST" if parsed.query else "GET")

        return actions

    def _send(self, act, session=None):
        s = session or self.session_for_thread()
        headers = self.auth_headers()
        cookies = self.auth_cookies()
        try:
            if act["method"] == "GET":
                return s.get(act["url"], timeout=self.timeout, headers=headers, cookies=cookies)
            if act["json"] is not None:
                return s.request(act["method"], act["url"], json=act["json"],
                                 timeout=self.timeout, headers=headers, cookies=cookies)
            return s.request(act["method"], act["url"], data=act["data"] or {},
                             timeout=self.timeout, headers=headers, cookies=cookies)
        except RequestException:
            return None
        except Exception:
            return None

    def session_for_thread(self):
        return self._session()

    @staticmethod
    def _is_limited(resp) -> bool:
        if resp is None:
            return False
        if resp.status_code in LIMIT_STATUS:
            return True
        body = (resp.text or "").lower()[:4000]
        return any(k in body for k in LIMIT_KEYWORDS)

    @staticmethod
    def _is_success(resp) -> bool:
        return resp is not None and resp.status_code < 400

    def _race_one(self, act):
        # ── Phase 1: sequential control — does a limit even exist? ──
        s = self._session()
        seq_success = 0
        limit_seen = False
        for _ in range(self.SEQ_PROBES):
            if cancellation.is_cancelled():
                return
            self._throttle()
            r = self._send(act, session=s)
            if r is None:
                continue
            if self._is_limited(r):
                limit_seen = True
                break
            if self._is_success(r):
                seq_success += 1
        if not limit_seen:
            return  # not sequentially limited → nothing to race → stay silent

        # ── Phase 2 & 3: concurrent burst, then a confirmation burst ──
        first = self._burst(act)
        if first is None:
            return
        # A race is interesting only if concurrency clearly beat the
        # sequential limit: more successes than sequential allowed, by a
        # margin, and more than one (one success is just the legitimate action).
        margin = max(2, math.ceil(0.4 * self.BURST))
        if not (first > 1 and first > seq_success + margin):
            return
        if cancellation.is_cancelled():
            return
        second = self._burst(act)
        if second is None or not (second > 1 and second > seq_success + margin):
            return  # not reproducible — refuse to report

        self._report(act, seq_success, first, second)

    def _burst(self, act):
        """Release BURST identical requests as simultaneously as possible with
        a barrier, so they collide inside any non-atomic check. Returns the
        count of successful (non-limited) responses, or None on total failure."""
        n = self.BURST
        barrier = threading.Barrier(n, timeout=self.timeout + 5)
        results = []
        lock = threading.Lock()
        sessions = [self._session() for _ in range(n)]

        def worker(idx):
            try:
                barrier.wait()
            except Exception:
                pass
            r = self._send(act, session=sessions[idx])
            with lock:
                results.append(r)

        with ThreadPoolExecutor(max_workers=n) as ex:
            list(ex.map(worker, range(n)))

        if not any(r is not None for r in results):
            return None
        return sum(1 for r in results if self._is_success(r) and not self._is_limited(r))

    def _report(self, act, seq_success, first, second):
        url = act["url"]
        added = self.db.add(
            title=f"Race Condition (non-atomic limit) on {act['method']} action",
            severity="high", url=url, module=self.NAME,
            description=(
                f"The {act['method']} action at {url} enforces a limit when requests arrive "
                f"one at a time (it began refusing after {seq_success} sequential request(s) "
                f"with a rate-limit/duplicate/already-done response), but a bounded burst of "
                f"{self.BURST} simultaneous identical requests slipped {first} (and {second} on a "
                "second independent burst) through successfully. The check that enforces the limit "
                "and the action it guards are not atomic (a TOCTOU race): an attacker can exceed the "
                "intended limit — redeem a one-time coupon multiple times, overrun a per-user cap, "
                "double-spend, or bypass an anti-automation/OTP limiter — simply by sending requests "
                "concurrently."
            ),
            remediation=(
                "Make the check-and-act atomic: use a database transaction with row locking "
                "(SELECT ... FOR UPDATE) or a unique constraint / idempotency key so concurrent "
                "requests cannot both pass the guard, and enforce rate limits with an atomic "
                "counter (e.g. Redis INCR) rather than read-modify-write."
            ),
            cvss="8.1", confidence="CONFIRMED", confidence_score=90,
            validation_steps=["sequential_limit_observed", "concurrent_burst_overran_limit",
                              "second_burst_reproduced"],
            evidence=[f"Method: {act['method']}", f"Sequential successes before limit: {seq_success}",
                      f"Concurrent successes (burst 1): {first}/{self.BURST}",
                      f"Concurrent successes (burst 2): {second}/{self.BURST}"],
            references=[
                "https://portswigger.net/web-security/race-conditions",
                "https://owasp.org/www-community/vulnerabilities/Race_condition",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("high", f"Race condition — limit overrun via concurrency", url)
            self.ui.bullet(f"sequential limit ~{seq_success} → concurrent {first}/{self.BURST}", indent=12)
            self.ctx.setdefault("race_findings", []).append({"url": url, "method": act["method"]})
