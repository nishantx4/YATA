"""
MassAssignmentModule — YATA RECON module.
Detects Mass Assignment by injecting a privilege field (isAdmin/role/...)
alongside the endpoint's real (schema-declared, when known) body fields, then
requiring the injected key+value to show up in a *parsed* JSON response that
did NOT contain it in a baseline request lacking that field. A raw substring
match on the request echo (the previous approach) false-positives on any
endpoint that simply mirrors the request body back, which is extremely
common and proves nothing about whether the field was actually bound.
"""
import json
import time

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


PRIVILEGE_FIELDS = [
    ("isAdmin", True), ("is_admin", True), ("admin", True),
    ("role", "admin"), ("roleId", 1), ("permissions", ["admin"]),
    ("verified", True), ("is_verified", True), ("premium", True),
    # Framework-convention privilege flags (Django/Rails-style).
    ("is_staff", True), ("is_superuser", True), ("staff", True),
    # Business-logic / financial fields — mass assignment here isn't
    # privilege escalation, it's direct monetary impact (free/discounted
    # orders, inflated balances), just as real-world and just as commonly
    # missed by an allow-list that was only ever written with "role" in mind.
    ("price", 0), ("amount", 0), ("total", 0), ("discount", 100),
    ("balance", 999999), ("credit", 999999), ("plan", "enterprise"),
    ("tier", "enterprise"), ("subscription", "premium"), ("quota", 999999),
]


class MassAssignmentModule(BaseModule):
    NAME = "Mass Assignment"

    def run(self):
        self.ui.section("Mass Assignment Detection")
        if not requests:
            return

        s = self._session()
        targets = self._collect_targets() + self._collect_form_targets()
        if not targets:
            self.ui.info("No suitable JSON endpoints or forms found for Mass Assignment testing.")
            return

        found = 0
        for target in targets[:15]:
            try:
                if self._test_target(s, target):
                    found += 1
            except Exception:
                continue
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No Mass Assignment vulnerabilities detected.")

    def _collect_targets(self):
        """Prefer real OpenAPI-declared JSON body endpoints (method + real
        field names + required auth headers); fall back to guessing on
        endpoints whose URL suggests an API/user resource."""
        targets = []
        for api_ep in self.ctx.get("api_endpoints", []):
            if api_ep.get("method") not in ("POST", "PUT", "PATCH"):
                continue
            if not api_ep.get("json_props"):
                continue
            headers = {"Content-Type": "application/json"}
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)
            headers.update(self.ctx.get("auth_headers", {}))
            base_body = {p: "test" for p in api_ep["json_props"]}
            targets.append({
                "url": api_ep["url"], "method": api_ep["method"],
                "headers": headers, "base_body": base_body,
            })

        if not targets:
            for ep in self.ctx.get("endpoints", []):
                if "api" in ep.lower() or "user" in ep.lower():
                    targets.append({
                        "url": ep, "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                        "base_body": {},
                    })
        return targets

    def _collect_form_targets(self):
        """
        Classic HTML forms (profile/settings updates, checkout, account
        edit) are just as valid a mass-assignment surface as a JSON API —
        adding a hidden field to a form POST that the server-side handler
        blindly binds is the ORIGINAL mass-assignment vulnerability shape
        (predates JSON APIs entirely). Previously only JSON bodies were
        ever tested here.
        """
        targets = []
        for form in self.ctx.get("forms", []):
            if form.get("method", "GET").upper() not in ("POST", "PUT", "PATCH"):
                continue
            inputs = dict(form.get("inputs", {}))
            if not inputs:
                continue
            targets.append({
                "url": form.get("action", self.base_url),
                "method": form.get("method", "POST").upper(),
                "headers": {}, "base_body": inputs, "body_mode": "form",
            })
        return targets

    def _test_target(self, session, target):
        url, method, headers, base_body = (
            target["url"], target["method"], target["headers"], target["base_body"]
        )
        # "form" targets (classic HTML forms) send form-encoded bodies and
        # can't carry non-scalar values (list/dict PRIVILEGE_FIELDS entries
        # would just get str()-mangled by requests) — restrict candidates
        # to scalar values for those. JSON targets (OpenAPI/guessed API
        # endpoints) are unrestricted, same as before.
        is_form = target.get("body_mode") == "form"

        def send(body):
            if is_form:
                return session.request(method, url, data=body, headers=headers, timeout=self.timeout)
            return session.request(method, url, json=body, headers=headers, timeout=self.timeout)

        try:
            baseline_resp = send(base_body)
        except Exception:
            return False
        baseline_json = self._safe_json(baseline_resp)

        for field, value in PRIVILEGE_FIELDS:
            if field in base_body:
                continue  # already a legitimate field for this endpoint
            if is_form and isinstance(value, (list, dict)):
                continue  # can't express a non-scalar in a form-encoded body
            tampered_body = {**base_body, field: value}
            try:
                resp = send(tampered_body)
            except Exception:
                continue
            if resp.status_code not in (200, 201):
                continue

            resp_json = self._safe_json(resp)
            if resp_json is None:
                continue

            found_value = self._find_key(resp_json, field)
            if found_value is None:
                continue
            if self._stringify(found_value) != self._stringify(value):
                continue
            # The key must NOT already have been present (with any value) in
            # the baseline response — otherwise this is just the endpoint's
            # normal shape, not something our injection caused.
            if self._find_key(baseline_json, field) is not None:
                continue

            body_desc = "form-encoded body" if is_form else "JSON body"
            title = f"Mass Assignment: '{field}' field bound from client input"
            desc = (
                f"Sending an unexpected '{field}={value}' field in the {body_desc} of a {method} "
                f"request to {url} caused it to appear, with our exact value, in the parsed JSON "
                f"response — and it was absent from a baseline request that omitted the field. "
                f"This strongly suggests the field is bound directly onto an internal model/object "
                f"without an explicit allow-list."
            )
            self.db.add(
                title=title, severity="high", url=url, module=self.NAME,
                description=desc,
                remediation="Use explicit DTOs / allow-lists for request binding. Never bind raw "
                            "JSON input directly onto internal/persistence model objects.",
                cvss="7.1",
                confidence="MEDIUM", confidence_score=65,
                validation_steps=["baseline_captured", "field_injected", "field_bound_in_response",
                                   "absent_from_baseline"],
                evidence=[f"Injected: {field}={value}", f"Method: {method}", f"URL: {url}"],
            )
            self.ui.find("high", title, url)
            return True
        return False

    @staticmethod
    def _safe_json(resp):
        try:
            return resp.json()
        except Exception:
            return None

    @classmethod
    def _find_key(cls, obj, key):
        """Recursively search a parsed JSON structure for `key`, return its value or None."""
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                found = cls._find_key(v, key)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = cls._find_key(item, key)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _stringify(value):
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return str(value).lower()
