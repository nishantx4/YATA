"""
ParamModule — YATA RECON module.

Parameter tampering: numeric boundary values (negative/zero/overflow) and
boolean/privilege-flag flips (admin=0 -> admin=1, etc.), validated against a
baseline + control-recovery check so a genuine, stable behavior change is
required before anything is flagged — not just "the response looked
different" (which is noisy on any page with dynamic content).
"""
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


PRIVILEGE_PARAM_NAMES = {
    "admin", "is_admin", "isadmin", "administrator", "debug", "test",
    "bypass", "verified", "is_verified", "premium", "role", "access",
    "authenticated", "is_authenticated", "superuser", "root", "privileged",
}

BOOLEAN_FLIPS = {
    "0": "1", "1": "0",
    "false": "true", "true": "false",
    "no": "yes", "yes": "no",
    "n": "y", "y": "n",
}

# Server-side error/exception signatures that a tampered value may surface but
# a benign baseline does not. A length diff alone is NOT a vulnerability — any
# functional parameter (page, q, id, filter) changes the response when its
# value changes; that's the parameter working, not tampering. We only flag the
# two signals that actually indicate broken server-side handling: an
# authorization gate opening (403/401 -> 200) or the app throwing an error on
# the unexpected value.
_ERROR_SIGNATURES = (
    "stack trace", "traceback (most recent call last)", "exception in thread",
    "java.lang.", "javax.servlet", "system.nullreferenceexception",
    "system.invalidoperationexception", ".cs:line ", "at System.",
    "org.springframework", "org.hibernate", "sqlalchemy", "psycopg2",
    "warning: ", "fatal error:", "uncaught exception", "undefined index",
    "notice: undefined", "ora-0", "pg::", "mysqli_", "runtimeexception",
    "whoops, looks like something went wrong",  # Laravel debug page
)


def _error_surfaced(resp) -> str | None:
    """Return the matched error signature if `resp` looks like a server-side
    error/exception page, else None. Requires an actual exception/stack
    fingerprint — a bare 500 status is too flaky on its own to flag."""
    if resp is None:
        return None
    body = (resp.text or "").lower()
    for sig in _ERROR_SIGNATURES:
        if sig in body:
            return sig
    return None


class ParamModule(BaseModule):
    NAME = "Parameter Tampering"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = self._session()

    def run(self):
        self.ui.section("Parameter Tampering")
        if not requests:
            return

        endpoints = self.ctx.get("endpoints", [self.base_url])
        params_found = []
        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep)
            if not parsed.query:
                continue
            base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
            qs = urllib.parse.parse_qs(parsed.query)
            for k, v in qs.items():
                params_found.append((base_url, k, v[0] if v else "", qs))

        self.ui.info(f"Parameters in scope: {len(params_found)} from {len(endpoints)} endpoints")
        # Preserve the (endpoint, param) tuple shape other code already reads.
        self.ctx["discovered_params"] = [(ep, k) for ep, k, _, _ in params_found]

        found = 0
        tested = 0
        for base_url, param, value, qs in params_found[:60]:  # cap for scan time
            other = {k: v[0] for k, v in qs.items() if k != param and v}
            candidates = self._build_candidates(param, value)
            if not candidates:
                continue
            tested += 1
            try:
                if self._test_param(base_url, param, value, other, candidates):
                    found += 1
            except Exception:
                continue
            time.sleep(self.delay)

        # JSON body properties from an OpenAPI/Swagger spec — the GET
        # query-string loop above has zero surface on a pure JSON REST API,
        # which is exactly the shape most modern "tamper a numeric/boolean/
        # privilege field" targets actually are.
        found += self._test_json_bodies()

        self.ui.info(f"Tested {tested} parameter(s) for tampering")
        if found == 0:
            self.ui.info("No parameter tampering issues detected.")

    def _test_json_bodies(self) -> int:
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})

        for api_ep in self.ctx.get("api_endpoints", []):
            if api_ep.get("method") not in ("POST", "PUT", "PATCH"):
                continue
            json_props = api_ep.get("json_props", [])
            if not json_props:
                continue

            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            base_body = {p: "test" for p in json_props}
            try:
                baseline_resp = self.session.request(api_ep["method"], api_ep["url"], json=base_body,
                                                       headers=headers, timeout=self.timeout)
            except RequestException:
                continue
            baseline_len = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code

            for prop in json_props:
                # Only test props that look numeric/boolean/privilege-shaped
                # by name — probing every string field with boundary values
                # is mostly wasted requests.
                candidates = self._build_candidates(prop, "1" if prop.lower() in PRIVILEGE_PARAM_NAMES else "test")
                if not candidates and prop.lower() not in PRIVILEGE_PARAM_NAMES:
                    continue
                if prop.lower() in PRIVILEGE_PARAM_NAMES:
                    candidates = list(dict.fromkeys(candidates + ["1", "true", "admin", "yes"]))

                for candidate in candidates[:4]:
                    tampered_body = {**base_body, prop: candidate}
                    try:
                        resp = self.session.request(api_ep["method"], api_ep["url"], json=tampered_body,
                                                      headers=headers, timeout=self.timeout)
                    except RequestException:
                        continue

                    # Same discipline as the query path: a length diff is not
                    # a finding. Require an auth gate opening (401/403 -> 200)
                    # or a server error the baseline didn't have.
                    gate_opened = baseline_status in (401, 403) and resp.status_code == 200
                    cand_err = _error_surfaced(resp)
                    crashed = bool(cand_err) and not _error_surfaced(baseline_resp)
                    if not (gate_opened or crashed):
                        continue

                    try:
                        confirm = self.session.request(api_ep["method"], api_ep["url"],
                                                        json={**base_body, prop: candidate},
                                                        headers=headers, timeout=self.timeout)
                        control = self.session.request(api_ep["method"], api_ep["url"], json=base_body,
                                                       headers=headers, timeout=self.timeout)
                    except RequestException:
                        continue

                    if gate_opened:
                        if not (confirm.status_code == 200 and control.status_code in (401, 403)):
                            continue
                        signal = f"access gate opened: {baseline_status} -> 200 (control re-blocked at {control.status_code})"
                        steps = ["gate_was_blocked", "candidate_opened_200", "control_reblocked"]
                    else:
                        reconf_err = _error_surfaced(confirm)
                        if not reconf_err or _error_surfaced(control):
                            continue
                        signal = f"server error surfaced ('{reconf_err}') on tampered value but not on baseline"
                        steps = ["baseline_clean", "candidate_errored", "error_reproduced", "control_clean"]

                    self.db.add(
                        title=f"Parameter Tampering: '{prop}' JSON body property mishandles unexpected value",
                        severity="medium", url=api_ep["url"], module=self.NAME,
                        description=(
                            f"Sending '{prop}={candidate}' in the JSON body of a {api_ep['method']} "
                            f"request to {api_ep['url']} {signal}. The value is not properly authorized "
                            "or validated server-side."
                        ),
                        remediation="Enforce server-side authorization and validation for this field; never trust client-supplied values for privilege or business-logic decisions.",
                        cvss="6.5", confidence="HIGH", confidence_score=80,
                        validation_steps=steps,
                        evidence=[f"Original: {prop}=test", f"Tampered: {prop}={candidate}",
                                  f"Signal: {signal}"],
                    )
                    self.ui.find("medium", f"Parameter Tampering (JSON): '{prop}'", api_ep["url"])
                    found += 1
                    break
                time.sleep(self.delay)
            if found > 10:
                return found
        return found

    def _build_candidates(self, param, value):
        candidates = []
        if value.isdigit():
            n = int(value)
            candidates.append(str(-n) if n else "-1")
            candidates.append("0")
            candidates.append(str(n * 1000 + 99999))
        if value.lower() in BOOLEAN_FLIPS:
            candidates.append(BOOLEAN_FLIPS[value.lower()])
        if param.lower() in PRIVILEGE_PARAM_NAMES:
            candidates += ["1", "true", "admin", "yes"]

        seen = set()
        out = []
        for c in candidates:
            if c != value and c not in seen:
                seen.add(c)
                out.append(c)
        return out

    def _test_param(self, url, param, orig_value, other, candidates):
        baseline_resp = self._send(url, param, orig_value, other)
        if baseline_resp is None:
            return False
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code

        for candidate in candidates:
            resp = self._send(url, param, candidate, other)
            if resp is None:
                continue

            # A length diff is NOT a finding — a functional param changing its
            # output is the param doing its job. Only two signals count:
            #   (a) an authorization gate opening: 401/403 -> 200; or
            #   (b) the unexpected value surfacing a server error/exception
            #       that the benign baseline did not.
            baseline_err = _error_surfaced(baseline_resp)
            cand_err = _error_surfaced(resp)
            gate_opened = baseline_status in (401, 403) and resp.status_code == 200
            crashed = bool(cand_err) and not baseline_err

            if not (gate_opened or crashed):
                continue

            # Reproduce the exact signal and confirm the ORIGINAL value does
            # not share it — kills jitter/flaky-5xx and A/B-rendered pages.
            confirm = self._send(url, param, candidate, other)
            control = self._send(url, param, orig_value, other)
            if confirm is None or control is None:
                continue

            if gate_opened:
                if not (confirm.status_code == 200 and control.status_code in (401, 403)):
                    continue
                conf, score = "HIGH", 80
                signal = f"access gate opened: {baseline_status} -> 200 (control re-blocked at {control.status_code})"
                steps = ["gate_was_blocked", "candidate_opened_200", "control_reblocked"]
            else:  # crashed
                reconf_err = _error_surfaced(confirm)
                if not reconf_err or _error_surfaced(control):
                    continue  # not reproducible, or the baseline errors too
                conf, score = "HIGH", 82
                signal = f"server error surfaced ('{reconf_err}') on tampered value but not on baseline"
                steps = ["baseline_clean", "candidate_errored", "error_reproduced", "control_clean"]

            title = f"Parameter Tampering: '{param}' mishandles unexpected value"
            desc = (
                f"Changing '{param}' from '{orig_value}' to '{candidate}' {signal}. "
                f"This indicates the value is not properly authorized/validated server-side."
            )
            added = self.db.add(
                title=title, severity="medium", url=url, module=self.NAME,
                description=desc,
                remediation="Enforce server-side authorization and validation for this parameter; "
                            "never trust client-supplied values for privilege or business-logic decisions.",
                cvss="6.5",
                confidence=conf, confidence_score=score,
                validation_steps=steps,
                evidence=[
                    f"Original: {param}={orig_value}", f"Tampered: {param}={candidate}",
                    f"Signal: {signal}",
                ],
            )
            if added:
                self.ui.find("medium", title, url)
                self.ui.bullet(f"{param}: {orig_value} -> {candidate}", indent=12)
                return True
        return False

    def _send(self, url, param, value, other):
        try:
            params = {**other, param: value}
            return self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
        except RequestException:
            return None
