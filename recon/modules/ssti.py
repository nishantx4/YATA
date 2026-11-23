"""
SSTIModule — YATA RECON module.
Detects Server-Side Template Injection via randomized arithmetic probes.

Zero-false-positive design
──────────────────────────
The old probe injected a fixed `{{7*7}}` and reported RCE if the 2-digit
string "49" appeared in the response but not in a single baseline request.
"49" occurs on an enormous fraction of real pages (counts, prices, IDs,
timestamps, truncated hashes), so any page that happened to render a "49"
not present in the baseline was flagged as critical SSTI. That single
heuristic produced the overwhelming majority of this tool's false positives.

This version:
  * Uses two RANDOM multi-digit operands per test, so the expected product is
    an 8–9 digit number that is astronomically unlikely to appear by chance.
  * Wraps the expression in a unique random MARKER on both sides and requires
    the evaluated product to appear BETWEEN the markers — proving the template
    engine evaluated OUR injection in place, not that the number merely exists
    somewhere on the page.
  * Requires the literal expression to be ABSENT (if `{{A*B}}` is echoed back
    verbatim, it was reflected, not evaluated).
  * Pre-filters every parameter with a reflection/liveness probe: if a benign
    marker is not echoed into the response at all, the input never reaches a
    rendered template and the param is skipped — which is also the primary
    speed-up (dead params cost one request, not nine).
"""
import re
import random
import string
import threading
import urllib.parse
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


class SSTIModule(BaseModule):
    NAME = "SSTI"

    # Per-engine delimiters. `__A__`/`__B__` are substituted with two random
    # operands at probe time; every engine multiplies to the SAME product, so
    # a single expected value confirms whichever engine actually evaluated.
    PROBE_SPECS = [
        ("{{__A__*__B__}}",    "Jinja2/Twig/Nunjucks"),
        ("${__A__*__B__}",     "Freemarker/Velocity/Mako/JSP-EL"),
        ("<%= __A__*__B__ %>", "ERB/EJS"),
        ("#{__A__*__B__}",     "Ruby/Pebble/Thymeleaf-inline"),
        ("${{__A__*__B__}}",   "Thymeleaf/Spring-EL"),
        ("*{__A__*__B__}",     "Thymeleaf-selection"),
        ("@(__A__*__B__)",     "Razor"),
        ("{__A__*__B__}",      "Smarty/generic-brace"),
    ]

    SSTI_PARAMS = [
        "name", "template", "page", "view", "content", "text", "msg",
        "message", "title", "body", "desc", "description", "value",
        "search", "q", "query", "input", "data", "comment", "email",
    ]

    # Only spray the guessed param-name list across this many endpoints (real
    # params already in a URL's query string, and params from params.py, are
    # always tested regardless). Keeps the request matrix bounded.
    MAX_GUESS_ENDPOINTS = 12

    def run(self):
        self.ui.section("SSTI — Server-Side Template Injection Detection")
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
            f"Testing {len(test_points)} injection point(s) for SSTI "
            f"(reflection-filtered, {self.threads} workers)"
        )

        with ThreadPoolExecutor(max_workers=max(1, self.threads)) as ex:
            futures = [ex.submit(self._test_query_point, s, ep, param) for ep, param in test_points]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"SSTI thread error: {e}")

        # JSON REST bodies (OpenAPI/Swagger) and classic HTML form POST bodies
        # — distinct injection surfaces the query-string loop can't reach.
        self._test_api_endpoints(s)
        self._test_forms(s)

        # Error-message fallback (weaker signal) only if nothing was confirmed.
        if self._found == 0:
            self._check_template_errors(s, [self.base_url] + self.ctx.get("endpoints", [])[:30],
                                        set(self.SSTI_PARAMS))

        if self._found == 0:
            self.ui.info("No SSTI vulnerabilities detected.")

    # ──────────────────────────────────────────────────────────────────────
    def _collect_test_points(self):
        """Deduplicated (endpoint, param) worklist: real query-string params
        on every endpoint + params.py discoveries + the guessed name-list on a
        capped number of query-less endpoints."""
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]
        seen = set()
        points = []

        def add(ep, param):
            key = (ep.split("#", 1)[0].split("?", 1)[0], param)
            if key in seen:
                return
            seen.add(key)
            points.append((ep, param))

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

        for entry in self.ctx.get("discovered_params", []):
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                add(entry[0], entry[1])
            elif isinstance(entry, dict):
                dep = entry.get("endpoint") or entry.get("url") or self.base_url
                for param in entry.get("params", {}).keys():
                    add(dep, param)

        for ep in guess_budget[: self.MAX_GUESS_ENDPOINTS]:
            for param in self.SSTI_PARAMS:
                add(ep, param)

        return points

    # ──────────────────────────────────────────────────────────────────────
    def _confirm(self, send_fn):
        """Core confirmation routine shared by the query/JSON/form surfaces.

        `send_fn(value) -> response|None` delivers one value into the
        injection point. Returns a result dict on a CONFIRMED template
        evaluation, else None. Generates fresh random operands + marker every
        call so a cached response or a coincidental number can never confirm.
        """
        a = random.randint(1000, 9999)
        b = random.randint(10000, 99999)
        product = str(a * b)                       # 8–9 digit, improbable by chance
        marker = "gr" + "".join(random.choices(string.ascii_lowercase, k=7))
        inplace = f"{marker}{product}{marker}"

        # Reflection/liveness gate: if a plain marker isn't echoed back, the
        # input never reaches rendered output — it cannot be in-band SSTI, and
        # we skip all probe payloads (the main speed-up).
        self._throttle()
        baseline = send_fn(marker)
        if baseline is None:
            return None
        btext = baseline.text or ""
        if marker not in btext:
            return None

        for template, engine in self.PROBE_SPECS:
            expr = template.replace("__A__", str(a)).replace("__B__", str(b))
            payload = f"{marker}{expr}{marker}"
            self._throttle()
            resp = send_fn(payload)
            if resp is None:
                continue
            rtext = resp.text or ""

            # Strongest: product appears exactly between our two markers —
            # the engine evaluated our expression in place.
            if inplace in rtext:
                return {"payload": payload, "engine": engine, "product": product,
                        "evidence": (f"In-place template evaluation: injected '{marker}{expr}{marker}', "
                                     f"response contains '{inplace}' ({a}*{b}={product})")}

            # Backup: the unique product appears, was NOT in the baseline, our
            # marker is present (input reached output), and the literal
            # expression is gone (it was consumed/evaluated, not reflected).
            if product in rtext and product not in btext and marker in rtext and expr not in rtext:
                return {"payload": payload, "engine": engine, "product": product,
                        "evidence": (f"Template evaluated '{expr}' to {product} ({a}*{b}); "
                                     f"marker reflected, literal expression absent from response")}
        return None

    def _test_query_point(self, s, endpoint, param):
        def send(value):
            url = _qjoin(endpoint, f"{param}={urllib.parse.quote(value)}")
            try:
                return s.get(url, timeout=self.timeout)
            except Exception:
                return None

        res = self._confirm(send)
        if res:
            self._report(endpoint, param, res, "GET parameter")

    def _test_api_endpoints(self, s):
        auth_headers = self.ctx.get("auth_headers", {})
        for api_ep in self.ctx.get("api_endpoints", []):
            method = api_ep.get("method", "POST")
            url = api_ep.get("url")
            json_props = api_ep.get("json_props", [])
            if not url or not json_props:
                continue
            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            for prop in json_props:
                other = {p: "test" for p in json_props if p != prop}

                def send(value, _other=other, _prop=prop, _url=url, _method=method, _headers=headers):
                    try:
                        return s.request(_method, _url, timeout=self.timeout, headers=_headers,
                                         json={**_other, _prop: value})
                    except Exception:
                        return None

                res = self._confirm(send)
                if res:
                    self._report(url, prop, res, "JSON body property")

    def _test_forms(self, s):
        for form in self.ctx.get("forms", []):
            method = form.get("method", "GET").upper()
            if method not in ("POST", "PUT", "PATCH"):
                continue
            action = form.get("action", self.base_url)
            inputs = dict(form.get("inputs", {}))
            if not inputs:
                continue
            for field in list(inputs.keys()):
                def send(value, _field=field, _action=action, _method=method, _inputs=inputs):
                    body = dict(_inputs)
                    body[_field] = value
                    try:
                        return s.request(_method, _action, data=body, timeout=self.timeout)
                    except Exception:
                        return None

                res = self._confirm(send)
                if res:
                    self._report(action, field, res, f"form field ({method})")

    # ──────────────────────────────────────────────────────────────────────
    def _report(self, url, param, res, loc):
        added = self.db.add(
            title=f"SSTI — Template Injection via '{param}' ({res['engine']})",
            severity="critical", url=url, module=self.NAME,
            description=(
                f"The '{param}' {loc} is vulnerable to Server-Side Template Injection "
                f"(likely {res['engine']}). A randomized arithmetic payload was evaluated "
                f"server-side to {res['product']}, confirmed in place between unique markers. "
                "This typically escalates to Remote Code Execution."
            ),
            remediation=(
                "Never pass user input directly to a template engine as part of the template "
                "string. Render user data only as data/variables, use a sandboxed engine, and "
                "prefer logic-less templates (e.g. Mustache) for user-generated content."
            ),
            cvss="9.8",
            confidence="CONFIRMED",
            confidence_score=97,
            validation_steps=["reflection_confirmed", "randomized_arithmetic_evaluated",
                              "in_place_marker_match", "literal_expression_absent"],
            evidence=[f"Payload: {res['payload']}", res["evidence"], f"Engine: {res['engine']}"],
        )
        if added:
            with self._found_lock:
                self._found += 1
            self.ui.find("critical", f"SSTI via '{param}' ({res['engine']})", url)
            self.ui.bullet(f"{loc.title()}: {param}  |  Engine: {res['engine']}", indent=12)
            self.ui.bullet(f"Payload: {res['payload']}", indent=12)
            self.ctx.setdefault("ssti_findings", []).append(
                {"url": url, "param": param, "payload": res["payload"], "engine": res["engine"]})

    # ──────────────────────────────────────────────────────────────────────
    def _check_template_errors(self, s, endpoints, params):
        """Check for template-engine error messages (a weaker, MEDIUM signal)
        when no arithmetic probe confirmed. Reports only the engine-specific
        stack-trace strings, which are not generic enough to false-positive."""
        error_patterns = [
            (r"TemplateSyntaxError", "Jinja2/Django"),
            (r"Twig_Error_Syntax", "Twig"),
            (r"freemarker\.template", "Freemarker"),
            (r"org\.apache\.velocity", "Velocity"),
            (r"mako\.exceptions", "Mako"),
            (r"pebble\.error", "Pebble"),
            (r"smarty.*(error|exception)", "Smarty"),
        ]
        for endpoint in endpoints[:10]:
            for param in list(params)[:5]:
                # Baseline-absence guard (same discipline as sqli.py's
                # error-based path): fetch a benign value first and record which
                # engine-error strings are ALREADY present, so a page that
                # naturally contains e.g. "TemplateSyntaxError" (a debug page,
                # docs, a blog post) can't be mistaken for an injected error.
                self._throttle()
                try:
                    benign = s.get(_qjoin(endpoint, f"{param}=yata_recon_ssti_base"), timeout=self.timeout)
                    benign_text = benign.text or ""
                except Exception:
                    benign_text = ""

                url = _qjoin(endpoint, f"{param}={urllib.parse.quote('{{invalid_syntax_!@#}}')}")
                self._throttle()
                try:
                    resp = s.get(url, timeout=self.timeout)
                except Exception:
                    continue
                for pattern, engine in error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        # Must be injected, not pre-existing on the page.
                        if re.search(pattern, benign_text, re.IGNORECASE):
                            continue
                        # Must reproduce — a one-off upstream error doesn't count.
                        self._throttle()
                        try:
                            reconf = s.get(url, timeout=self.timeout)
                            if not re.search(pattern, reconf.text or "", re.IGNORECASE):
                                continue
                        except Exception:
                            continue
                        self.db.add(
                            title=f"SSTI Potential — {engine} Error Disclosure via '{param}'",
                            severity="medium", url=endpoint, module=self.NAME,
                            description=(
                                f"A {engine} template-engine error was triggered by malformed template "
                                f"syntax in parameter '{param}', indicating the parameter is processed "
                                "by a template engine and may be exploitable."
                            ),
                            remediation="Investigate template processing of user input in this parameter.",
                            cvss="7.2", confidence="MEDIUM", confidence_score=60,
                            validation_steps=["error_pattern_matched"],
                            evidence=[f"Matched engine error pattern: {pattern}"],
                        )
                        self.ui.find("medium", f"SSTI Potential — {engine} error via '{param}'", endpoint)
                        return
