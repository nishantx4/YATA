"""
CRLFModule — YATA RECON module.
Detects HTTP Response Splitting via CRLF injection in parameters.
"""
import time
import uuid
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


def _qjoin(endpoint: str, query_suffix: str) -> str:
    """Append a raw (already-encoded) query suffix to an endpoint that may
    already have its own query string. `f"{endpoint}?{param}=..."` blindly
    assumes no existing '?', which breaks every endpoint recon.py seeds via
    _probe_common_paths() (e.g. /index.php?id=1) into a malformed
    double-'?' URL that never reaches the target parameter."""
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{query_suffix}"


class CRLFModule(BaseModule):
    NAME = "CRLF Injection"

    CRLF_PARAMS = [
        "url", "redirect", "next", "return", "goto", "dest",
        "redirect_uri", "return_to", "continue", "target", "path",
        "callback", "rurl", "returnUrl", "view", "page",
    ]

    def run(self):
        self.ui.section("CRLF Injection — HTTP Response Splitting Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        self._found_lock = threading.Lock()
        self._found = 0
        self._canary = f"X-YATA RECON-CRLF-{uuid.uuid4().hex[:8]}"

        # Payloads that inject a custom header via CRLF
        self._payloads = [
            f"%0d%0a{self._canary}:true",
            f"%0d%0a%0d%0a<h1>yata_recon_crlf</h1>",
            f"%0a{self._canary}:true",
            f"\\r\\n{self._canary}:true",
            # Double URL-encoding — bypasses a naive filter/WAF/proxy layer
            # that decodes the value exactly once (stripping %0d%0a) before
            # handing it to application code that decodes it AGAIN itself
            # (common when a reverse proxy and the app both do their own
            # single-pass decode of what looks like the same raw value).
            f"%250d%250a{self._canary}:true",
            f"%25%30%64%25%30%61{self._canary}:true",  # fully re-encoded %0d%0a, one layer deeper
        ]

        # Test discovered params + common redirect params.
        test_params = set(self.CRLF_PARAMS)
        for ep in self.ctx.get("discovered_params", []):
            if isinstance(ep, dict):
                test_params.update(ep.get("params", {}).keys())
            elif isinstance(ep, str):
                test_params.add(ep)

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]
        seen, worklist = set(), []
        for endpoint in endpoints:
            path_key = endpoint.split("#", 1)[0].split("?", 1)[0]
            for param in test_params:
                key = (path_key, param)
                if key in seen:
                    continue
                seen.add(key)
                worklist.append((endpoint, param))

        self.ui.info(
            f"Testing {len(worklist)} (endpoint, param) pair(s) for CRLF injection "
            f"(liveness-filtered, {self.threads} workers)"
        )

        # Parallelized + liveness-gated: the old version was a serial
        # endpoints x params x payloads matrix paced by time.sleep(delay).
        with ThreadPoolExecutor(max_workers=max(1, self.threads)) as ex:
            futures = [ex.submit(self._test_param, s, ep, param) for ep, param in worklist]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"CRLF thread error: {e}")

        if self._found == 0:
            self.ui.info("No CRLF injection vulnerabilities detected.")

    def _test_param(self, s, endpoint, param):
        # Liveness: a param whose value is never reflected into any response
        # header or the body cannot produce an in-band CRLF/header injection —
        # skip the payload set for it entirely.
        token = "grcrlf" + uuid.uuid4().hex[:8]
        self._throttle()
        try:
            probe = s.get(_qjoin(endpoint, f"{param}={token}"), timeout=self.timeout, allow_redirects=False)
        except Exception:
            return
        if token not in str(probe.headers) and token not in (probe.text or ""):
            return

        for payload in self._payloads:
            self._throttle()
            try:
                resp = s.get(_qjoin(endpoint, f"{param}={payload}"), timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue

            # Check 1: our custom header was injected as a REAL, separate
            # response header — an actual CRLF split the server emitted — not
            # merely present as a substring of some existing header's value.
            #
            # The old `self._canary in str(resp.headers)` test stringified the
            # whole header dict and substring-matched, so it fired whenever a
            # server 30x-redirected and reflected the STILL-ENCODED parameter
            # in its Location header: the canary NAME then appears inside that
            # Location value (…?dest=%0d%0aX-YATA RECON-CRLF-xxxx:true) while
            # the %0d%0a was never decoded and no header was ever injected.
            # A proper header-name lookup only succeeds when the server truly
            # emitted `X-YATA RECON-CRLF-xxxx: true` as its own header line.
            injected = resp.headers.get(self._canary)
            if injected is not None and injected.strip().lower() == "true":
                self._report(
                    endpoint, f"CRLF Injection — Header Injection via '{param}'", "high", "CONFIRMED", 95,
                    f"Parameter '{param}' allows CRLF injection. Injected header '{self._canary}' appeared "
                    "in response headers. This enables session fixation, XSS via Set-Cookie, and cache poisoning.",
                    ["canary_header_injected"], f"CRLF Header Injection via '{param}'",
                )
                return

            # Check 2: the HTML tag from the payload was reflected UNENCODED
            # into the body. This is unencoded-HTML-reflection (HTML injection),
            # not true response splitting — relabeled accordingly so it isn't
            # over-claimed as header/response splitting when it's really a body
            # reflection the XSS module characterizes more precisely.
            if "<h1>yata_recon_crlf</h1>" in (resp.text or ""):
                self._report(
                    endpoint, f"HTML Injection — Unencoded Reflection via '{param}'", "medium", "HIGH", 80,
                    f"Parameter '{param}' is reflected into the response body without HTML-encoding: an "
                    "injected <h1> tag rendered verbatim. (This is body HTML injection, not HTTP response "
                    "splitting — the XSS module assesses executable-script impact separately.)",
                    ["unencoded_html_reflected"], f"HTML Injection via '{param}'",
                )
                return

    def _report(self, url, title, severity, confidence, score, description, steps, find_label):
        added = self.db.add(
            title=title, severity=severity, url=url, module=self.NAME,
            description=description,
            remediation="Strip or encode CR (\\r) and LF (\\n) characters from all user input used in "
                        "HTTP headers, and HTML-encode user input reflected into response bodies.",
            cvss="7.5", confidence=confidence, confidence_score=score,
            validation_steps=steps,
        )
        if added:
            with self._found_lock:
                self._found += 1
            self.ui.find(severity, find_label, url)
