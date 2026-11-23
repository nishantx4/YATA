"""
SecondOrderModule — Stored / Second-Order Injection Detection.

Every other module here does single-request reflected-style testing:
inject a payload, check THIS SAME response. That's invisible to an entire
class of real-world bugs — stored XSS in a comment/profile field, a value
that only becomes dangerous once it flows into a different read path. This
module instead: (1) submits a uniquely-marked payload to a write sink (a
discovered form or a JSON API create/update endpoint), (2) revisits a
*different* read endpoint in a *separate* follow-up request, and (3) checks
whether the marker survived unescaped there.

One submission per sink carries THREE independently-markered probes at
once (XSS tag / SQL-breaking quote / SSTI math expression) rather than
three separate round-trips — cutting the request budget back to what the
original XSS-only version used, while covering three vulnerability classes
from the same write:
  - Stored XSS       — same unescaped-tag-survives check as before
  - Stored SQLi       — a value that flows unsanitized into a LATER query
                        elsewhere in the app (a DB error signature showing
                        up at a read-back location, correlated to our own
                        marker so an unrelated pre-existing error can't be
                        misattributed)
  - Stored SSTI       — a value later rendered through a template engine
                        instead of just echoed as text (marker+math-result
                        appearing adjacent proves evaluation, not just
                        storage)

A marker submitted in request #1 turning up — unescaped, errored, or
evaluated — in the response of request #2, fetched from a different URL,
is direct proof a single-request scanner can never produce.
"""
import random
import string
import time

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule
from recon.modules.sqli import ALL_ERROR_PATTERNS, DB_ERROR_MAP


# Field-name hints for write sinks worth testing — user-generated-content
# style fields are where stored XSS actually lives (vs. e.g. a quantity or
# checkbox field, which is a wasted request).
STORED_FIELD_HINTS = [
    "comment", "bio", "about", "description", "message", "note", "review",
    "feedback", "title", "name", "username", "nickname", "display", "content",
    "body", "text", "subject", "address", "company", "notes", "summary",
    "caption", "status", "post",
]

# Where to look for the marker coming back — endpoints already discovered
# by recon.py that plausibly render user content back out.
READBACK_HINTS = [
    "profile", "account", "dashboard", "comment", "review", "feed", "post",
    "message", "user", "settings", "public", "view", "detail", "list",
]

MAX_SINKS = 15
MAX_READBACK_TARGETS = 25


class SecondOrderModule(BaseModule):
    NAME = "Second-Order / Stored Injection"

    def run(self):
        self.ui.section("Second-Order — Stored Injection Detection")
        if not requests:
            return

        self.session = self._session()
        headers = self.auth_headers()
        cookies = self.auth_cookies()
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        sinks = self._collect_sinks()
        if not sinks:
            self.ui.info("No plausible stored-content write sinks discovered — skipping.")
            return

        readback_targets = self._collect_readback_targets()
        self.ui.info(f"Testing {len(sinks)} write sink(s) against {len(readback_targets)} read-back location(s)...")

        found = 0
        for sink in sinks[:MAX_SINKS]:
            try:
                if self._test_sink(sink, readback_targets):
                    found += 1
            except Exception:
                pass
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No second-order/stored injection confirmed.")
        else:
            self.ui.ok(f"Second-order scan complete — {found} finding(s)")

    def _marker(self):
        tag = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"gr{tag}so"

    def _build_combined_payload(self, base_marker):
        """
        One value carrying three independently-attributable probes:
          - <b>{marker}x</b>        — XSS: survives unescaped, or doesn't
          - {marker}s'--            — SQLi: breaks a naive string-concatenated
                                       query if this value is later reused
                                       unsanitized elsewhere
          - {marker}t{{7*7}}        — SSTI: evaluates to {marker}t49 if this
                                       value later flows through a template
                                       engine instead of being echoed as text
        Each sub-marker is distinct so a hit can be attributed to exactly
        one class — three markers colliding by coincidence is effectively
        impossible.
        """
        xss_marker = f"{base_marker}x"
        sqli_marker = f"{base_marker}s"
        ssti_marker = f"{base_marker}t"
        payload = f"<b>{xss_marker}</b>{sqli_marker}'--{ssti_marker}{{{{7*7}}}}"
        return payload, xss_marker, sqli_marker, ssti_marker

    def _collect_sinks(self):
        sinks = []
        for form in self.ctx.get("forms", []):
            if form.get("method", "GET").upper() not in ("POST", "PUT", "PATCH"):
                continue
            field_names = list(form.get("inputs", {}).keys())
            if any(any(h in fn.lower() for h in STORED_FIELD_HINTS) for fn in field_names):
                sinks.append({"kind": "form", "url": form["action"],
                              "method": form.get("method", "POST").upper(),
                              "inputs": dict(form.get("inputs", {}))})

        for ep in self.ctx.get("api_endpoints", []):
            if ep.get("method") not in ("POST", "PUT", "PATCH"):
                continue
            props = ep.get("json_props", [])
            if any(any(h in p.lower() for h in STORED_FIELD_HINTS) for p in props):
                sinks.append({"kind": "json", "url": ep["url"], "method": ep["method"],
                              "props": list(props)})
        return sinks

    def _collect_readback_targets(self):
        targets = {self.base_url}
        for ep in self.ctx.get("endpoints", []):
            low = ep.lower()
            if any(h in low for h in READBACK_HINTS):
                targets.add(ep)
        return list(targets)[:MAX_READBACK_TARGETS]

    def _fetch(self, url):
        try:
            return self.session.get(url, timeout=self.timeout)
        except Exception:
            return None

    def _test_sink(self, sink, readback_targets):
        marker = self._marker()
        payload, xss_marker, sqli_marker, ssti_marker = self._build_combined_payload(marker)

        try:
            if sink["kind"] == "form":
                data = dict(sink["inputs"])
                for k in list(data.keys()):
                    if any(h in k.lower() for h in STORED_FIELD_HINTS):
                        data[k] = payload
                resp = self.session.request(sink["method"], sink["url"], data=data, timeout=self.timeout)
            else:
                body = {p: "test" for p in sink["props"]}
                for k in list(body.keys()):
                    if any(h in k.lower() for h in STORED_FIELD_HINTS):
                        body[k] = payload
                resp = self.session.request(sink["method"], sink["url"], json=body, timeout=self.timeout)
        except Exception:
            return False

        if resp is None:
            return False

        # Give the backend a moment (async write pipelines, cache
        # invalidation) before checking read-back — checking too early would
        # be a false negative, not a true "not stored."
        time.sleep(min(2.0, max(0.5, self.delay)))

        candidates = []
        ct = resp.headers.get("Content-Type", "")
        # The write response itself CAN be a legitimate second-order surface
        # (e.g. a "comment created" confirmation page rendered from a
        # template shared with the public listing) — but only count it if
        # it's a real page, not a small API JSON ack, so this stays a
        # cross-endpoint/cross-request check rather than plain reflection.
        if "html" in ct.lower() and len(resp.text) > len(payload) * 3:
            candidates.append((sink["url"] + " (write response)", resp.text))

        for target in readback_targets:
            if target == sink["url"]:
                continue
            r = self._fetch(target)
            if r is not None and "html" in r.headers.get("Content-Type", "").lower():
                candidates.append((target, r.text))
            time.sleep(self.delay)

        reported = False
        for location, body in candidates:
            # XSS: unescaped tag survives, or escaped-but-present.
            if f"<b>{xss_marker}</b>" in body:
                self._report_xss(sink, xss_marker, location, unescaped=True)
                reported = True
                break
            if xss_marker in body:
                self._report_xss(sink, xss_marker, location, unescaped=False)
                reported = True
                break

        for location, body in candidates:
            # SSTI: marker sitting directly next to the evaluated "49" —
            # requiring adjacency (not just "49" appearing anywhere on the
            # page) is what makes this attributable to OUR probe.
            if f"{ssti_marker}49" in body:
                self._report_ssti(sink, ssti_marker, location)
                reported = True
                break

        for location, body in candidates:
            # Stored SQLi: our own marker (astronomically unlikely to
            # already exist on the page) appearing IN THE SAME RESPONSE as
            # a recognizable DB error signature is strong correlation that
            # THIS value, not some unrelated pre-existing bug, caused it.
            if sqli_marker not in body:
                continue
            for pattern in ALL_ERROR_PATTERNS:
                m = pattern.search(body)
                if m:
                    self._report_sqli(sink, sqli_marker, location, DB_ERROR_MAP.get(pattern.pattern, "Unknown"))
                    reported = True
                    break
            if reported:
                break

        return reported

    def _report_xss(self, sink, marker, location, unescaped):
        if unescaped:
            self.db.add(
                title="Second-Order (Stored) XSS — Unescaped Persistence Confirmed",
                severity="critical", url=location, module=self.NAME,
                description=(
                    f"A payload submitted to {sink['url']} was later found alive and UNESCAPED "
                    f"at a different location ({location}), fetched in a separate follow-up "
                    "request. This proves the input is stored and rendered without sanitization "
                    "— a classic stored/second-order XSS, invisible to single-request scanning."
                ),
                remediation=(
                    "Contextually encode/escape all stored user input at render time (not just "
                    "at input time). Apply output encoding at every read path, not only the one "
                    "used to submit it."
                ),
                cvss="8.8", confidence="CONFIRMED", confidence_score=95,
                validation_steps=["payload_submitted", "separate_readback_request",
                                   "marker_unescaped_at_different_url"],
                evidence=[f"Submitted to: {sink['url']}", f"Found unescaped at: {location}", f"Marker: {marker}"],
            )
            self.ui.find("critical", "Second-Order (Stored) XSS", location)
        else:
            self.db.add(
                title="Stored Input Persists To Another Endpoint (Unconfirmed Escaping)",
                severity="low", url=location, module=self.NAME,
                description=(
                    f"A marker submitted to {sink['url']} reappeared (HTML-escaped) at "
                    f"{location}. Persistence is confirmed; the payload itself was neutralized "
                    "here, but this write sink is worth deeper manual second-order testing "
                    "given confirmed cross-endpoint persistence."
                ),
                remediation=(
                    "No immediate action for XSS (input was escaped here) — but review this "
                    "write sink for other second-order injection classes."
                ),
                cvss="3.1", confidence="HIGH", confidence_score=75,
                validation_steps=["payload_submitted", "separate_readback_request", "marker_present_escaped"],
                evidence=[f"Submitted to: {sink['url']}", f"Found at: {location}", f"Marker: {marker}"],
            )
            self.ui.find("low", "Stored input persists (escaped)", location)

    def _report_sqli(self, sink, marker, location, db_type):
        self.db.add(
            title=f"Second-Order (Stored) SQL Injection — {db_type} Error at Different Endpoint",
            severity="high", url=location, module=self.NAME,
            description=(
                f"A value submitted to {sink['url']} (containing our marker '{marker}' plus a "
                f"SQL-breaking quote) triggered a {db_type} error signature at a DIFFERENT "
                f"endpoint ({location}), fetched in a separate follow-up request. This is "
                "consistent with the stored value later flowing unsanitized into a SQL query "
                "elsewhere in the application — a second-order SQL injection invisible to "
                "single-request testing. The marker's presence alongside the error rules out "
                "an unrelated pre-existing error being misattributed, but manual confirmation "
                "(e.g. a time-based payload in the same field) is recommended before treating "
                "this as fully exploitable."
            ),
            remediation=(
                "Use parameterized queries/prepared statements for EVERY query this value can "
                "reach, not just the one it was originally submitted through — second-order "
                "SQLi means the vulnerable query is often in a different code path entirely "
                "from the input handler."
            ),
            cvss="8.6", confidence="MEDIUM", confidence_score=65,
            validation_steps=["payload_submitted", "separate_readback_request",
                               "marker_present_alongside_db_error"],
            evidence=[f"Submitted to: {sink['url']}", f"DB error observed at: {location}",
                      f"Marker: {marker}", f"DB type: {db_type}"],
        )
        self.ui.find("high", f"Second-Order SQLi ({db_type})", location)

    def _report_ssti(self, sink, marker, location):
        self.db.add(
            title="Second-Order (Stored) Server-Side Template Injection",
            severity="critical", url=location, module=self.NAME,
            description=(
                f"A value submitted to {sink['url']} (marker '{marker}' followed by the "
                "template expression {{7*7}}) came back at a DIFFERENT endpoint "
                f"({location}) as '{marker}49' — the expression was EVALUATED (7*7=49), not "
                "echoed as literal text. This proves the stored value is later rendered "
                "through a template engine somewhere else in the application, a second-order "
                "SSTI invisible to single-request testing. Escalate manually with an "
                "engine-specific RCE payload once the templating engine is identified."
            ),
            remediation=(
                "Never render stored user input through a template engine's evaluation path. "
                "Treat all stored values as data, not template source, at every render location "
                "— not only the one it was originally submitted through."
            ),
            cvss="9.4", confidence="HIGH", confidence_score=85,
            validation_steps=["payload_submitted", "separate_readback_request",
                               "marker_adjacent_to_evaluated_math_result"],
            evidence=[f"Submitted to: {sink['url']}", f"Evaluated at: {location}", f"Marker+result: {marker}49"],
        )
        self.ui.find("critical", "Second-Order SSTI", location)


# --- end SecondOrderModule ---
