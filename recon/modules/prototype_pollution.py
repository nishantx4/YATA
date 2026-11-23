"""
PrototypePollutionModule — YATA RECON module.
Detects server-side Prototype Pollution via JSON request bodies (the
primary real-world vector — deep-merge libraries like lodash.merge,
Express's qs, or hand-rolled recursive-assign helpers) and, as a
secondary/legacy vector, query-string bracket-notation payloads.

Detection approach: differential comparison against a shape-matched control.
A raw "did this cause a 500?" check (the previous approach) is extremely
false-positive prone — almost any unexpected nested object can crash a
strict endpoint for reasons that have nothing to do with prototype
pollution. Instead, every `__proto__`/`constructor.prototype` payload is
compared against a CONTROL payload with the exact same JSON shape and size,
but a harmless key name instead of a magic one. Only a payload that behaves
differently from its shape-matched control (crashes when the control
doesn't, or produces a structurally different response) is reported —
isolating the special key name as the actual cause.
"""
import random
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


class PrototypePollutionModule(BaseModule):
    NAME = "Prototype Pollution"

    # (pollution key path, harmless control key path — same nesting depth)
    POLLUTION_KEYS = [
        (["__proto__", "yata_recon_pp"], ["yata-reconHarmless", "yata_recon_pp"]),
        (["constructor", "prototype", "yata_recon_pp"], ["yata-reconOuter", "yata-reconInner", "yata_recon_pp"]),
    ]

    def run(self):
        self.ui.section("Prototype Pollution Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        # 1. JSON body endpoints from an OpenAPI spec — the highest-signal
        # vector, since it targets real accepted request shapes.
        for api_ep in self.ctx.get("api_endpoints", []):
            if api_ep.get("json_props") and api_ep.get("method") in ("POST", "PUT", "PATCH"):
                if self._test_json_endpoint(s, api_ep):
                    found += 1

        # 2. Generic probes against crawled endpoints — JSON body (for APIs
        # without a spec) and legacy query-string bracket notation.
        tested_bases = set()
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:15]
        for endpoint in endpoints:
            base = endpoint.split("?")[0]
            if base in tested_bases:
                continue
            tested_bases.add(base)

            if self._differential_json_test(s, base, "POST", {}, {}, base):
                found += 1
            if self._test_query_string(s, base):
                found += 1
            if self._test_form_body(s, base):
                found += 1

        if found == 0:
            self.ui.info("No Prototype Pollution vulnerabilities detected.")

    # ─────────────────────────────────────────────────────────────────────
    def _test_json_endpoint(self, s, api_ep):
        url = api_ep["url"]
        method = api_ep["method"]
        headers = {name: str(example) for name, example in api_ep.get("header_params", []) if example}
        base_body = {p: "test" for p in api_ep.get("json_props", [])}
        return self._differential_json_test(s, url, method, base_body, headers, url)

    def _differential_json_test(self, s, url, method, base_body, headers, report_url):
        for pollute_path, control_path in self.POLLUTION_KEYS:
            marker = f"gr_pp_{random.randint(100000, 999999)}"

            def send_pair(pp=pollute_path, cp=control_path, mk=marker):
                pollute_body = self._deep_copy(base_body)
                control_body = self._deep_copy(base_body)
                self._set_nested(pollute_body, pp, mk)
                self._set_nested(control_body, cp, mk)
                try:
                    rp = s.request(method, url, json=pollute_body, headers=headers, timeout=self.timeout)
                    rc = s.request(method, url, json=control_body, headers=headers, timeout=self.timeout)
                except Exception:
                    return None
                return (rp, rc)

            verdict, strong = self._confirmed_verdict(send_pair)
            if verdict:
                self._report(report_url, method, ".".join(pollute_path[:-1]), marker, verdict, strong)
                return True
        return False

    def _test_query_string(self, s, base_url):
        marker = f"gr_pp_{random.randint(100000, 999999)}"

        def send_pair():
            try:
                rp = s.get(base_url, params={f"__proto__[{marker}]": "1"}, timeout=self.timeout)
                rc = s.get(base_url, params={f"yata-reconHarmless[{marker}]": "1"}, timeout=self.timeout)
            except Exception:
                return None
            return (rp, rc)

        verdict, strong = self._confirmed_verdict(send_pair)
        if verdict:
            self._report(base_url, "GET", "__proto__ (query string)", marker, verdict, strong)
            return True
        return False

    def _test_form_body(self, s, base_url):
        """
        application/x-www-form-urlencoded bodies get the SAME bracket-
        notation treatment as the query string above (Node's qs/body-parser
        middleware parses both identically into nested objects), but this
        is a genuinely separate request/content-type a server-side router
        can handle completely differently from a query string — a target
        that strips '__proto__' from URL query parsing but not from its
        POST body parser (or vice versa) is a realistic split, so testing
        only one is a real coverage gap, not redundant with the other.
        """
        marker = f"gr_pp_{random.randint(100000, 999999)}"

        def send_pair():
            try:
                rp = s.post(base_url, data={f"__proto__[{marker}]": "1"}, timeout=self.timeout)
                rc = s.post(base_url, data={f"yata-reconHarmless[{marker}]": "1"}, timeout=self.timeout)
            except Exception:
                return None
            return (rp, rc)

        verdict, strong = self._confirmed_verdict(send_pair)
        if verdict:
            self._report(base_url, "POST", "__proto__ (form-urlencoded body)", marker, verdict, strong)
            return True
        return False

    # ─────────────────────────────────────────────────────────────────────
    def _compare(self, resp_pollute, resp_control):
        """Compare a pollution response against its shape-matched control.

        Returns (verdict_str, strong) or (None, False). `strong` is True only
        for the reliable crash differential; the length-diff signal is marked
        weak because the pollute and control key names differ in length
        (`__proto__` vs `yata-reconHarmless`), so a server that merely echoes
        the submitted key/body produces a DETERMINISTIC length difference that
        has nothing to do with prototype pollution — the historical false
        positive. A weak signal is reported only as a below-gate lead."""
        # Signal 1 (strong): the magic key crashes the app while the harmless,
        # identically-shaped control does not.
        if resp_pollute.status_code >= 500 and resp_control.status_code < 500:
            return (f"__proto__ payload caused HTTP {resp_pollute.status_code}, "
                    f"harmless-shaped control returned {resp_control.status_code}"), True

        # Signal 2 (weak): different response length at the same status. On its
        # own this does not distinguish pollution from the app simply reflecting
        # the (different-length) key name, so it never confirms outright.
        if resp_pollute.status_code == resp_control.status_code:
            len_p, len_c = len(resp_pollute.text), len(resp_control.text)
            threshold = max(30, len_c * 0.05)
            if abs(len_p - len_c) > threshold:
                return (f"Same HTTP status ({resp_pollute.status_code}) but response length diverged: "
                        f"{len_p}b (polluted) vs {len_c}b (control), threshold {threshold:.0f}b"), False

        return None, False

    def _confirmed_verdict(self, send_pair):
        """Run a pollute/control request pair TWICE and require the same signal
        class both times. send_pair() returns (resp_pollute, resp_control) or
        None. A one-off 500 or a transient length blip will not reproduce; a
        real server-side merge difference will. Returns (verdict, strong) or
        (None, False)."""
        first = send_pair()
        if first is None:
            return None, False
        v1, s1 = self._compare(*first)
        if not v1:
            return None, False
        second = send_pair()
        if second is None:
            return None, False
        v2, s2 = self._compare(*second)
        if not v2 or s2 != s1:
            return None, False
        return v1, s1

    def _report(self, url, method, key_path, marker, verdict, strong):
        # A reproduced CRASH differential (the magic key 500s while the
        # shape-matched control does not) is a reliable SSPP signal → reported.
        # A length-only difference is NOT: the pollute and control key names
        # differ in length, so an app that merely echoes the key produces a
        # deterministic, reproducible length diff that is not pollution. It is
        # kept as a below-default-gate lead rather than a HIGH finding.
        if strong:
            severity, confidence, score = "high", "HIGH", 80
            steps = ["differential_vs_shape_matched_control", "crash_reproduced"]
            weak_note = ""
        else:
            severity, confidence, score = "low", "LOW", 40
            steps = ["differential_vs_shape_matched_control", "length_only_difference_unconfirmed"]
            weak_note = (" NOTE: this is a response-LENGTH difference only, which can also be "
                         "caused by the app echoing the (different-length) key name — it is a "
                         "lead for manual review, not a confirmed vulnerability.")
        self.db.add(
            title=f"Server-Side Prototype Pollution via '{key_path}'",
            severity=severity, url=url, module=self.NAME,
            description=(
                f"A {method} request to {url} with a '{key_path}' key in the body/query "
                f"produced measurably different behavior than an identically-shaped request "
                f"using a harmless key name, indicating the server merges user-controlled "
                f"keys into an object without filtering '__proto__'/'constructor.prototype'. "
                f"{verdict}. Depending on how polluted properties are later read by the "
                f"application, this can lead to privilege escalation, denial of service, or "
                f"in some frameworks (e.g. gadget chains in template engines) remote code execution."
                f"{weak_note}"
            ),
            remediation=(
                "Reject or strip '__proto__', 'constructor', and 'prototype' keys before merging "
                "user-controlled objects. Use `Object.create(null)` for maps built from user input, "
                "or a merge utility with prototype-pollution protection (e.g. lodash >= 4.17.21)."
            ),
            cvss="7.3" if strong else "3.1",
            confidence=confidence,
            confidence_score=score,
            evidence=[f"Marker: {marker}", verdict],
            references=[
                "https://portswigger.net/web-security/prototype-pollution",
                "https://learn.snyk.io/lesson/prototype-pollution/",
            ],
            validation_steps=steps,
        )
        if strong:
            self.ui.find(severity, f"Prototype Pollution via '{key_path}'", url)
        else:
            self.ui.info(f"Prototype-pollution lead via '{key_path}' (length-only diff, below default confidence) — {url}")

    @staticmethod
    def _deep_copy(d):
        import copy
        return copy.deepcopy(d)

    @staticmethod
    def _set_nested(d, path, value):
        cur = d
        for i, key in enumerate(path):
            if i == len(path) - 1:
                cur[key] = value
            else:
                cur = cur.setdefault(key, {})
