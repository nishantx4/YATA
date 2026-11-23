"""
HTTPMethodsModule — YATA RECON module.

Audits which HTTP methods a target exposes, and confirms Cross-Site Tracing
(XST) via TRACE. Deliberately READ-ONLY and low-false-positive by design:

  * It never sends a state-changing request (no PUT/DELETE/PATCH with a body)
    against a live target — that could create, overwrite, or delete real
    resources. Dangerous methods are only ever *reported as advertised* from
    the OPTIONS `Allow` header, at LOW confidence, as something to verify by
    hand — never auto-"confirmed" by mutating the server.
  * XST is the one thing confirmed outright, because TRACE is non-mutating:
    a unique canary header is sent, and the finding fires only if the server
    returns 200 AND echoes that exact canary back in the body (which is what
    TRACE does, and what makes it exploitable for header/cookie disclosure).

Complements the header/CORS/clickjacking config checks — enabled methods are
a config-surface those modules don't cover.
"""
import threading
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


# Methods that are a real liability when genuinely enabled on an app endpoint.
_DANGEROUS = {"PUT", "DELETE", "PATCH", "TRACE", "TRACK", "CONNECT"}


class HTTPMethodsModule(BaseModule):
    NAME = "HTTP Methods"

    # Keep the request budget bounded — one OPTIONS per distinct path, a
    # handful of paths. Method posture is a property of the server/route,
    # not of every crawled URL, so a small sample is representative.
    MAX_PATHS = 8

    def run(self):
        self.ui.section("HTTP Methods — Verb Enumeration & XST Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        self._found_lock = threading.Lock()
        self._found = 0

        # Distinct path targets: base URL + a capped set of crawled endpoints,
        # deduplicated by scheme+host+path (query strings don't change which
        # verbs a route accepts).
        seen, targets = set(), []
        for ep in [self.base_url] + self.ctx.get("endpoints", []):
            try:
                p = urllib.parse.urlparse(ep)
                key = f"{p.scheme}://{p.netloc}{p.path or '/'}"
            except Exception:
                continue
            if key in seen:
                continue
            seen.add(key)
            targets.append(key)
            if len(targets) >= self.MAX_PATHS:
                break

        self.ui.info(f"Enumerating HTTP methods across {len(targets)} path(s)...")

        with ThreadPoolExecutor(max_workers=max(1, min(self.threads, len(targets) or 1))) as ex:
            futures = [ex.submit(self._audit_path, s, url) for url in targets]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"HTTP-methods thread error: {e}")

        # XST only needs one confirmation against the origin.
        self._test_xst(s, self.base_url)

        if self._found == 0:
            self.ui.info("No risky HTTP-method exposure detected.")

    def _audit_path(self, s, url):
        headers = {**self.auth_headers()}
        cookies = self.auth_cookies()
        self._throttle()
        try:
            resp = s.options(url, timeout=self.timeout, headers=headers, cookies=cookies)
        except RequestException:
            return

        allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        if not allow:
            return
        advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(advertised & _DANGEROUS)
        if not risky:
            return

        # Advertised-only: LOW confidence on purpose. OPTIONS saying PUT is
        # allowed does NOT mean an unauthenticated attacker can actually write
        # a file — it very often sits behind auth or a WebDAV handler that
        # rejects real writes. We refuse to confirm this by actually mutating
        # the server, so it is reported as a lead to verify by hand, not a
        # confirmed vulnerability. (TRACE is confirmed separately in _test_xst,
        # which is non-mutating.)
        non_trace = [m for m in risky if m not in ("TRACE", "TRACK")]
        if not non_trace:
            return  # TRACE/TRACK are handled (and actually confirmed) by _test_xst

        added = self.db.add(
            title=f"Potentially Dangerous HTTP Methods Advertised ({', '.join(non_trace)})",
            severity="low", url=url, module=self.NAME,
            description=(
                f"The OPTIONS response for {url} advertises the method(s): {', '.join(non_trace)} "
                f"(full Allow: {allow}). If any of these are genuinely handled without "
                "authentication/authorization they could permit arbitrary file upload (PUT), "
                "deletion (DELETE), or resource modification (PATCH). This is reported from the "
                "advertised Allow header only — YATA RECON does NOT send a state-changing request "
                "to confirm it, so verify manually (safely, against a resource you own) before acting."
            ),
            remediation=(
                "Disable any HTTP method the application does not require at the web-server/"
                "framework level. Restrict write methods (PUT/DELETE/PATCH) to authenticated, "
                "authorized callers only, and ensure WebDAV is turned off unless explicitly needed."
            ),
            cvss="4.3", confidence="LOW", confidence_score=40,
            validation_steps=["options_allow_enumerated"],
            evidence=[f"Allow: {allow}", f"URL: {url}"],
        )
        if added:
            with self._found_lock:
                self._found += 1
            self.ui.find("low", f"Dangerous methods advertised: {', '.join(non_trace)}", url)

    def _test_xst(self, s, url):
        """Confirm Cross-Site Tracing: TRACE is non-mutating, so we can
        actually confirm it. Fire a TRACE with a unique canary request header;
        a vulnerable server returns 200 and echoes the whole request — canary
        header included — back in the body."""
        canary = f"X-YATA RECON-XST-{uuid.uuid4().hex[:10]}"
        self._throttle()
        try:
            resp = s.request("TRACE", url, timeout=self.timeout,
                             headers={**self.auth_headers(), canary: "1"},
                             cookies=self.auth_cookies())
        except RequestException:
            return
        except Exception:
            return  # some adapters refuse TRACE outright — treat as not-enabled

        # Confirmed only when the server both accepts TRACE (200) and reflects
        # our unique header back (the echo that makes XST exploitable).
        if resp.status_code == 200 and canary.lower() in (resp.text or "").lower():
            added = self.db.add(
                title="Cross-Site Tracing (XST) — TRACE Method Enabled",
                severity="medium", url=url, module=self.NAME,
                description=(
                    "The server responds to HTTP TRACE with 200 and echoes the full request "
                    "(a unique canary request header was reflected verbatim in the response body). "
                    "TRACE combined with a scripting or header-injection foothold can be abused to "
                    "read otherwise-protected headers (including HttpOnly cookies and Authorization) "
                    "— Cross-Site Tracing."
                ),
                remediation="Disable the TRACE (and TRACK) method at the web server / load balancer.",
                cvss="5.3", confidence="CONFIRMED", confidence_score=90,
                validation_steps=["trace_returned_200", "canary_request_header_echoed"],
                evidence=[f"Canary header echoed: {canary}", f"URL: {url}"],
            )
            if added:
                with self._found_lock:
                    self._found += 1
                self.ui.find("medium", "Cross-Site Tracing (TRACE enabled)", url)
