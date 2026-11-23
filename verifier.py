from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from dataclasses import dataclass
from pathlib import Path

from red_agent import VulnerabilityFinding


@dataclass(slots=True)
class VerificationResult:
    attack_succeeded: bool
    status_code: int
    response_text: str
    evidence: str


_PROOF_EXCERPT_CHARS = 500


def build_evidence_bundle(
    finding: VulnerabilityFinding,
    payload: str,
    vulnerable_check: VerificationResult,
    patched_check: VerificationResult,
) -> dict:
    """Structured proof attached to every reported round.

    The evidence gate: a finding is PROVEN only if the pre-patch exploit was
    observed to succeed AND the artifacts that let a reader re-check it (the
    payload, the verifier's evidence, and the captured response) are present.
    Anything missing is listed, never silently accepted.
    """
    relative_file = str(finding.metadata.get("relative_file", finding.affected_file))
    missing = []
    if not vulnerable_check.attack_succeeded:
        missing.append("exploit_not_reproduced")
    if not payload:
        missing.append("payload")
    if not vulnerable_check.evidence:
        missing.append("evidence")
    if not vulnerable_check.response_text:
        missing.append("response")

    digest_source = "|".join(
        [finding.vulnerability_type, relative_file, str(finding.line_number), payload, vulnerable_check.response_text]
    )

    def _phase(check: VerificationResult) -> dict:
        return {
            "attack_succeeded": check.attack_succeeded,
            "status_code": check.status_code,
            "evidence": check.evidence,
            "response_excerpt": check.response_text[:_PROOF_EXCERPT_CHARS],
        }

    return {
        "proof_id": hashlib.sha256(digest_source.encode("utf-8", errors="replace")).hexdigest()[:12],
        "proof_status": "PROVEN" if not missing else "UNPROVEN",
        "missing": missing,
        "vulnerability_type": finding.vulnerability_type,
        "language": getattr(finding, "language", "python"),
        "file": relative_file,
        "line_number": finding.line_number,
        "payload": payload,
        "pre_patch": _phase(vulnerable_check),
        "post_patch": _phase(patched_check),
    }


@dataclass(slots=True)
class RoundScore:
    round_number: int
    vulnerability_type: str
    attack_succeeded: bool
    patch_succeeded: bool
    score_before: int
    score_after: int
    score_delta: int


class Referee:
    RISK_WEIGHTS = {
        "SQL Injection": 60,
        "Hardcoded Secret": 35,
        "Cross-Site Scripting": 30,
        "Command Injection": 45,
        "Path Traversal": 30,
        "SSRF": 50,
        "Server-Side Template Injection": 55,
        "Open Redirect": 20,
        "Insecure Deserialization": 55,
    }

    def __init__(self) -> None:
        self.scorecard: list[RoundScore] = []

    def verify_exploit(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        slug = re.sub(r"[^a-z0-9]+", "_", finding.vulnerability_type.lower())
        language = getattr(finding, "language", "python")
        method_name = f"_verify_js_{slug}" if language == "javascript" else f"_verify_{slug}"
        verifier = getattr(self, method_name, None)
        if verifier is None:
            raise ValueError(f"No validator strategy registered for {finding.vulnerability_type} ({language})")
        return verifier(app_root.resolve(), finding, payload)

    def calculate_security_score(self, findings: list[VulnerabilityFinding]) -> int:
        total_risk = sum(self.RISK_WEIGHTS.get(finding.vulnerability_type, 20) for finding in findings)
        return max(0, 100 - min(total_risk, 100))

    def record_round(
        self,
        *,
        round_number: int,
        finding: VulnerabilityFinding,
        attack_verification: VerificationResult,
        patch_verification: VerificationResult,
        score_before: int,
        score_after: int,
    ) -> RoundScore:
        result = RoundScore(
            round_number=round_number,
            vulnerability_type=finding.vulnerability_type,
            attack_succeeded=attack_verification.attack_succeeded,
            patch_succeeded=not patch_verification.attack_succeeded,
            score_before=score_before,
            score_after=score_after,
            score_delta=score_after - score_before,
        )
        self.scorecard.append(result)
        return result

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented",
            "Hardcoded Secrets": "implemented",
            "Cross-Site Scripting": "implemented",
            "Command Injection": "implemented",
            "Path Traversal": "implemented",
            "SSRF": "implemented",
            "Server-Side Template Injection": "implemented",
            "Open Redirect": "implemented",
            "Insecure Deserialization": "implemented",
        }

    def _verify_path_traversal(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        import os
        old_cwd = os.getcwd()
        os.chdir(app_root)
        try:
            app_module = self._load_app_module(app_root / "app.py")
            app = app_module.create_app(str(app_root / "database.db"))
            profile = self._load_profile(app_root).get("path_traversal", {})
            method = str(profile.get("method", "GET")).upper()
            path = str(profile.get("path", "/download"))
            params = dict(profile.get("params", {"file": "__PAYLOAD__"}))
            success_status_code = int(profile.get("expected_status", 200))

            request_values = {
                key: payload if value == "__PAYLOAD__" else value
                for key, value in params.items()
            }

            with app.test_client() as client:
                if method == "GET":
                    response = client.get(path, query_string=request_values, follow_redirects=True)
                else:
                    response = client.post(path, data=request_values, follow_redirects=True)

            body = response.get_data(as_text=True)
            exploit_succeeded = "YATA_TRAVERSAL_SUCCESS" in body
            attack_succeeded = exploit_succeeded and response.status_code == success_status_code
            evidence = (
                f"Runtime exploit reproduced against {path}; retrieved YATA_TRAVERSAL_SUCCESS."
                if attack_succeeded
                else "Runtime exploit blocked or failed to retrieve YATA_TRAVERSAL_SUCCESS."
            )
            return VerificationResult(
                attack_succeeded=attack_succeeded,
                status_code=response.status_code,
                response_text=body,
                evidence=evidence,
            )
        finally:
            os.chdir(old_cwd)

    def _verify_sql_injection(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("sql_injection", {})
        method = str(profile.get("method", "POST")).upper()
        path = str(profile.get("path", "/login"))
        params = dict(profile.get("params", {"username": "__PAYLOAD__", "password": "anything"}))
        success_contains = str(profile.get("success_contains", "Welcome"))
        success_status_code = int(profile.get("success_status_code", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=True)
            else:
                response = client.post(path, data=request_values, follow_redirects=True)

        body = response.get_data(as_text=True)
        attack_succeeded = success_contains in body and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload triggered the success marker {success_contains!r}."
            if attack_succeeded
            else f"Runtime exploit no longer reached the expected success marker {success_contains!r}."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_hardcoded_secret(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        relative_file = Path(str(finding.metadata.get("relative_file", Path(finding.affected_file).name)))
        target_file = app_root / relative_file
        if not target_file.exists():
            return VerificationResult(
                attack_succeeded=False,
                status_code=204,
                response_text="",
                evidence="The original source file is no longer present in the target tree.",
            )

        source = target_file.read_text(encoding="utf-8")
        variable_name = str(finding.metadata.get("variable_name", "SECRET_VALUE"))
        env_var_name = str(finding.metadata.get("env_var_name", payload))
        literal_pattern = re.compile(rf"\b{re.escape(variable_name)}\b\s*=\s*['\"]")
        moved_to_env = (
            f'os.getenv("{env_var_name}", "")' in source
            or f"os.getenv('{env_var_name}', '')" in source
        )

        env_example_path = app_root / ".env.example"
        env_documented = False
        if env_example_path.exists():
            env_documented = any(
                line.strip().startswith(f"{env_var_name}=")
                for line in env_example_path.read_text(encoding="utf-8").splitlines()
            )

        attack_succeeded = bool(literal_pattern.search(source)) or not moved_to_env or not env_documented
        evidence = (
            "Credential literal is still recoverable from source or has not been fully externalized."
            if attack_succeeded
            else "Credential literal was removed from source and documented as an environment variable."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=200 if attack_succeeded else 204,
            response_text=source,
            evidence=evidence,
        )

    def _verify_command_injection(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("command_injection", {})
        method = str(profile.get("method", "POST")).upper()
        path = str(profile.get("path", "/ping"))
        params = dict(profile.get("params", {"host": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=True)
            else:
                response = client.post(path, data=request_values, follow_redirects=True)

        body = response.get_data(as_text=True)

        import getpass
        username = getpass.getuser()
        is_yata_success = "YATA_SUCCESS" in body
        is_id = "uid=" in body or "gid=" in body
        is_user = username.lower() in body.lower()
        is_dir = any(x in body for x in ("app.py", "database.db", "yata_profile.json", "yata.py", "red_agent.py", "blue_agent.py"))

        attack_succeeded = (is_yata_success or is_id or is_user or is_dir) and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload executed command successfully."
            if attack_succeeded
            else "Runtime exploit no longer executed command successfully."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_cross_site_scripting(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("cross_site_scripting", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/greet"))
        params = dict(profile.get("params", {"name": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=True)
            else:
                response = client.post(path, data=request_values, follow_redirects=True)

        body = response.get_data(as_text=True)
        attack_succeeded = payload in body and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload was reflected unescaped in the HTML response."
            if attack_succeeded
            else "Runtime exploit blocked; the payload was escaped or not reflected in the response."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_ssrf(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("ssrf", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/fetch"))
        params = dict(profile.get("params", {"url": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        # The verifier never lets the exploited code make a real outbound
        # network call. Instead it stands in for the "internal" target at the
        # network boundary (requests.get/post/request) and observes whether
        # the app's own code passed the unvalidated payload straight through.
        # A patch that resolves + rejects internal hosts before calling
        # requests.* will never trigger this fake, so the marker never reaches
        # the response body.
        import requests as requests_lib

        class _FakeSSRFResponse:
            status_code = 200
            text = "YATA_SSRF_SUCCESS: internal resource disclosed"
            content = b"YATA_SSRF_SUCCESS"

            def json(self):
                return {"status": "YATA_SSRF_SUCCESS"}

        def _fake_call(url, *args, **kwargs):
            return _FakeSSRFResponse()

        original_get = requests_lib.get
        original_post = requests_lib.post
        original_request = requests_lib.request
        requests_lib.get = _fake_call
        requests_lib.post = _fake_call
        requests_lib.request = lambda method_name, url, *a, **kw: _fake_call(url, *a, **kw)
        try:
            with app.test_client() as client:
                if method == "GET":
                    response = client.get(path, query_string=request_values, follow_redirects=True)
                else:
                    response = client.post(path, data=request_values, follow_redirects=True)
        finally:
            requests_lib.get = original_get
            requests_lib.post = original_post
            requests_lib.request = original_request

        body = response.get_data(as_text=True)
        attack_succeeded = "YATA_SSRF_SUCCESS" in body and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the server issued an outbound request to {payload!r} "
            "and disclosed the internal response."
            if attack_succeeded
            else "Runtime exploit blocked; the server rejected or did not forward the request to the internal target."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_server_side_template_injection(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("server_side_template_injection", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/hello"))
        params = dict(profile.get("params", {"name": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=True)
            else:
                response = client.post(path, data=request_values, follow_redirects=True)

        body = response.get_data(as_text=True)

        # Every payload/mutation is a {{A*B}} arithmetic expression. The
        # product only shows up in the response if the template engine
        # actually evaluated the expression server-side -- it never appears
        # in the raw, unevaluated payload text itself.
        match = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", payload)
        expected_marker = str(int(match.group(1)) * int(match.group(2))) if match else None

        attack_succeeded = bool(expected_marker) and expected_marker in body and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the template expression was evaluated server-side, "
            f"producing {expected_marker!r}."
            if attack_succeeded
            else "Runtime exploit blocked; the template expression was not evaluated (treated as literal/escaped text)."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_open_redirect(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("open_redirect", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/goto"))
        params = dict(profile.get("params", {"next": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 302))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        # Never follow the redirect -- the payload points at a domain that
        # does not exist, and we only need to inspect the Location header
        # the app itself produced.
        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=False)
            else:
                response = client.post(path, data=request_values, follow_redirects=False)

        location = response.headers.get("Location", "")
        attack_succeeded = location == payload and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the server issued a redirect straight to the "
            f"attacker-controlled target {payload!r}."
            if attack_succeeded
            else "Runtime exploit blocked; the server did not redirect to the unvalidated external target."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=location,
            evidence=evidence,
        )

    def _verify_insecure_deserialization(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("insecure_deserialization", {})
        method = str(profile.get("method", "POST")).upper()
        path = str(profile.get("path", "/load"))
        params = dict(profile.get("params", {"data": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=True)
            else:
                response = client.post(path, data=request_values, follow_redirects=True)

        body = response.get_data(as_text=True)
        attack_succeeded = "YATA_PICKLE_RCE" in body and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; deserializing the payload invoked an attacker-chosen "
            "callable and its result was disclosed in the response."
            if attack_succeeded
            else "Runtime exploit blocked; the payload was not deserialized as an executable object."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # JavaScript / TypeScript verifiers.
    #
    # There is no WSGI test_client() equivalent for Node, so these actually
    # spawn the target app as a real subprocess bound to a real loopback
    # port (see js_runtime.NodeAppProcess) and issue real HTTP requests --
    # the same "prove it happened at runtime" standard as the Python
    # verifiers above, just over a socket instead of an in-process test
    # client.
    # ------------------------------------------------------------------

    def _verify_js_command_injection(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        from js_runtime import NodeAppProcess, detect_entry_file

        profile = self._load_profile(app_root).get("command_injection", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/ping"))
        params = dict(profile.get("params", {"host": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))
        request_values = {k: (payload if v == "__PAYLOAD__" else v) for k, v in params.items()}

        entry_file = detect_entry_file(app_root)
        with NodeAppProcess(app_root, entry_file) as app:
            result = app.request(method, path, params=request_values, data=request_values)

        import getpass
        username = getpass.getuser()
        body = result.body
        is_yata_success = "YATA_SUCCESS" in body
        is_user = username.lower() in body.lower()
        attack_succeeded = (is_yata_success or is_user) and result.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload executed a command on the Node process."
            if attack_succeeded
            else "Runtime exploit no longer executed a command successfully."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=result.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_js_path_traversal(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        from js_runtime import NodeAppProcess, detect_entry_file

        profile = self._load_profile(app_root).get("path_traversal", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/download"))
        params = dict(profile.get("params", {"file": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))
        request_values = {k: (payload if v == "__PAYLOAD__" else v) for k, v in params.items()}

        entry_file = detect_entry_file(app_root)
        with NodeAppProcess(app_root, entry_file) as app:
            result = app.request(method, path, params=request_values, data=request_values)

        attack_succeeded = "YATA_TRAVERSAL_SUCCESS" in result.body and result.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; retrieved YATA_TRAVERSAL_SUCCESS."
            if attack_succeeded
            else "Runtime exploit blocked or failed to retrieve YATA_TRAVERSAL_SUCCESS."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=result.status_code,
            response_text=result.body,
            evidence=evidence,
        )

    def _verify_js_sql_injection(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        from js_runtime import NodeAppProcess, detect_entry_file

        profile = self._load_profile(app_root).get("sql_injection", {})
        method = str(profile.get("method", "POST")).upper()
        path = str(profile.get("path", "/login"))
        params = dict(profile.get("params", {"username": "__PAYLOAD__", "password": "anything"}))
        success_contains = str(profile.get("success_contains", "Welcome"))
        success_status_code = int(profile.get("success_status_code", 200))
        request_values = {k: (payload if v == "__PAYLOAD__" else v) for k, v in params.items()}

        entry_file = detect_entry_file(app_root)
        with NodeAppProcess(app_root, entry_file) as app:
            result = app.request(method, path, params=request_values, data=request_values)

        attack_succeeded = success_contains in result.body and result.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload triggered the success marker {success_contains!r}."
            if attack_succeeded
            else f"Runtime exploit no longer reached the expected success marker {success_contains!r}."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=result.status_code,
            response_text=result.body,
            evidence=evidence,
        )

    def _verify_js_cross_site_scripting(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        from js_runtime import NodeAppProcess, detect_entry_file

        profile = self._load_profile(app_root).get("cross_site_scripting", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/greet"))
        params = dict(profile.get("params", {"name": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 200))
        request_values = {k: (payload if v == "__PAYLOAD__" else v) for k, v in params.items()}

        entry_file = detect_entry_file(app_root)
        with NodeAppProcess(app_root, entry_file) as app:
            result = app.request(method, path, params=request_values, data=request_values)

        attack_succeeded = payload in result.body and result.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload was reflected unescaped in the HTML response."
            if attack_succeeded
            else "Runtime exploit blocked; the payload was escaped or not reflected in the response."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=result.status_code,
            response_text=result.body,
            evidence=evidence,
        )

    def _verify_js_ssrf(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        import http.server
        import threading
        from urllib.parse import urlsplit, urlunsplit

        from js_runtime import NodeAppProcess, detect_entry_file

        marker_body = b"YATA_SSRF_SUCCESS: internal resource disclosed"

        class _MarkerHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(marker_body)

            def log_message(self, *args: object) -> None:
                pass

        marker_server = http.server.HTTPServer(("127.0.0.1", 0), _MarkerHandler)
        marker_port = marker_server.server_address[1]
        marker_thread = threading.Thread(target=marker_server.serve_forever, daemon=True)
        marker_thread.start()

        try:
            parts = urlsplit(payload)
            host = parts.hostname or "127.0.0.1"
            netloc_host = f"[{host}]" if ":" in host else host
            rewritten_payload = urlunsplit(
                (parts.scheme or "http", f"{netloc_host}:{marker_port}", parts.path or "/", parts.query, parts.fragment)
            )

            profile = self._load_profile(app_root).get("ssrf", {})
            method = str(profile.get("method", "GET")).upper()
            path = str(profile.get("path", "/fetch"))
            params = dict(profile.get("params", {"url": "__PAYLOAD__"}))
            success_status_code = int(profile.get("expected_status", 200))
            request_values = {k: (rewritten_payload if v == "__PAYLOAD__" else v) for k, v in params.items()}

            entry_file = detect_entry_file(app_root)
            with NodeAppProcess(app_root, entry_file) as app:
                result = app.request(method, path, params=request_values, data=request_values)
        finally:
            marker_server.shutdown()
            marker_server.server_close()

        attack_succeeded = "YATA_SSRF_SUCCESS" in result.body and result.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the server issued an outbound request to {payload!r} "
            "and disclosed the internal response."
            if attack_succeeded
            else "Runtime exploit blocked; the server rejected or did not forward the request to the internal target."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=result.status_code,
            response_text=result.body,
            evidence=evidence,
        )

    def _verify_js_open_redirect(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        from js_runtime import NodeAppProcess, detect_entry_file

        profile = self._load_profile(app_root).get("open_redirect", {})
        method = str(profile.get("method", "GET")).upper()
        path = str(profile.get("path", "/goto"))
        params = dict(profile.get("params", {"next": "__PAYLOAD__"}))
        success_status_code = int(profile.get("expected_status", 302))
        request_values = {k: (payload if v == "__PAYLOAD__" else v) for k, v in params.items()}

        entry_file = detect_entry_file(app_root)
        with NodeAppProcess(app_root, entry_file) as app:
            result = app.request(method, path, params=request_values, data=request_values, allow_redirects=False)

        location = result.headers.get("Location", "")
        attack_succeeded = location == payload and result.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the server issued a redirect straight to the "
            f"attacker-controlled target {payload!r}."
            if attack_succeeded
            else "Runtime exploit blocked; the server did not redirect to the unvalidated external target."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=result.status_code,
            response_text=location,
            evidence=evidence,
        )

    def _load_profile(self, app_root: Path) -> dict[str, object]:
        profile_path = app_root / "yata_profile.json"
        if not profile_path.exists():
            return {}
        return json.loads(profile_path.read_text(encoding="utf-8"))

    def _load_app_module(self, app_path: Path):
        unique_name = f"yata_target_{abs(hash(str(app_path.resolve())))}"
        spec = importlib.util.spec_from_file_location(unique_name, app_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load app module from {app_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

