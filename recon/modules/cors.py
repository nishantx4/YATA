"""
CORSModule — YATA RECON module.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


class CORSModule(BaseModule):
    NAME = "CORS"

    def run(self):
        self.ui.section("CORS Misconfiguration Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        test_origins = [
            "https://evil.com",
            f"https://evil.{self.target}",
            f"https://{self.target}.evil.com",
            "null",
        ]
        s = self._session()

        for origin in test_origins:
            try:
                resp = s.get(self.base_url, headers={"Origin": origin}, timeout=self.timeout)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == origin or acao == "*":
                    creds_allowed = acac.lower() == "true"

                    # ── FP Fix: Wildcard without credentials is standard for public APIs ──
                    if acao == "*" and not creds_allowed:
                        # This is normal for public APIs/CDNs — downgrade to info
                        self.db.add(
                            title="CORS: Wildcard Origin (Public API — Informational)",
                            severity="info", url=self.base_url, module=self.NAME,
                            description=(
                                "The server returns Access-Control-Allow-Origin: * without credentials. "
                                "This is standard behavior for public APIs and CDN resources. "
                                "No authentication data can be stolen via this configuration."
                            ),
                            remediation="No action needed if this is intentionally a public endpoint.",
                            cvss="0.0",
                            confidence="CONFIRMED",
                            confidence_score=100,
                        )
                        self.ui.find("info", "CORS: Wildcard (public, no credentials)", self.base_url)
                        break

                    # Reflected origin WITH credentials — actually dangerous
                    if creds_allowed and acao != "*":
                        severity = "high"
                        confidence_score = 90
                        description = (
                            f"The server reflects the attacker-controlled Origin header "
                            f"('{origin}') back in Access-Control-Allow-Origin AND sets "
                            f"Access-Control-Allow-Credentials: true. Any site can make "
                            f"authenticated cross-origin requests using the victim's cookies/"
                            f"session and read the response, leading to full account "
                            f"compromise via CSRF-like data theft."
                        )
                    elif acao == "null":
                        severity = "medium"
                        confidence_score = 75
                        description = (
                            f"The server reflects the 'null' Origin in Access-Control-Allow-Origin. "
                            f"'null' is sent by sandboxed iframes and data:/file: origins, so an "
                            f"attacker can trivially craft a page that satisfies this check and "
                            f"read cross-origin responses."
                            + (" Combined with Access-Control-Allow-Credentials: true, this exposes "
                               "authenticated data." if creds_allowed else "")
                        )
                    else:
                        # Reflected origin WITHOUT credentials is equivalent in
                        # impact to `Access-Control-Allow-Origin: *` (which this
                        # module reports as INFO): no cookies/session are sent,
                        # so an attacker page can only read data that is already
                        # public to any unauthenticated client. Low, not medium,
                        # to avoid flooding reports with non-exploitable CORS
                        # noise (matters only for network-position-trusting or
                        # internal resources).
                        severity = "low"
                        confidence_score = 40
                        description = (
                            f"The server reflects the attacker-controlled Origin header "
                            f"('{origin}') back in Access-Control-Allow-Origin WITHOUT "
                            f"Access-Control-Allow-Credentials. No authenticated data is exposed "
                            f"(equivalent to a wildcard policy); this is only meaningful if the "
                            f"endpoint serves data trusted by network position rather than by session."
                        )

                    self.db.add(
                        title=f"CORS Misconfiguration — Reflected Origin: {acao}",
                        severity=severity, url=self.base_url, module=self.NAME,
                        description=description,
                        remediation=(
                            "Whitelist only trusted origins. Never reflect the Origin header blindly. "
                            "Do not combine Access-Control-Allow-Credentials: true with wildcard origins."
                        ),
                        cvss="7.4" if severity == "high" else "5.4",
                        confidence="HIGH" if creds_allowed else "MEDIUM",
                        confidence_score=confidence_score,
                        validation_steps=["origin_reflected", "credentials_checked"],
                    )
                    self.ui.find(severity, f"CORS Misconfiguration ({acao})", self.base_url)
                    break
                time.sleep(self.delay)
            except Exception:
                continue

        self._test_preflight(s)

    def _test_preflight(self, s):
        """
        Everything above is a simple cross-origin GET — real damage from a
        loose CORS policy usually needs a STATE-CHANGING method (POST/PUT/
        DELETE) with a custom header (e.g. Content-Type: application/json),
        which the browser only allows after a successful preflight OPTIONS
        exchange. A server can easily be loose on simple GETs (the test
        above) while its preflight handling is stricter, or vice versa —
        testing only one gives an incomplete picture of what's actually
        exploitable.
        """
        origin = f"https://evil.{self.target}"
        try:
            resp = s.options(
                self.base_url, timeout=self.timeout,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type,authorization",
                },
            )
        except Exception:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        origin_allowed = acao == origin or acao == "*"
        method_allowed = "POST" in acam.upper() or acam.strip() == "*"
        if not (origin_allowed and method_allowed):
            return

        # Without credentials, an approved preflight only lets an attacker page
        # make UNauthenticated cross-origin requests — something it could
        # already do from its own server — so it is not a real vulnerability
        # (low, suppressed by the default confidence gate). The credentialed
        # case is the genuine high-severity finding.
        creds_note = " AND permits credentials" if acac else " (credentials not permitted here, so impact is limited to non-credentialed data an attacker could already fetch directly)"
        self.db.add(
            title="CORS — Preflight Allows Cross-Origin State-Changing Requests",
            severity="high" if acac else "low", url=self.base_url, module=self.NAME,
            description=(
                f"An OPTIONS preflight from an attacker-controlled origin ('{origin}') requesting "
                f"POST + custom headers was APPROVED (Access-Control-Allow-Origin: {acao}, "
                f"Access-Control-Allow-Methods: {acam or '(unset, but POST implicitly allowed)'})"
                f"{creds_note}. This means a malicious page can issue real state-changing "
                "cross-origin requests (not just read-only GETs) against this endpoint."
            ),
            remediation=(
                "Restrict Access-Control-Allow-Origin to an explicit allow-list for any endpoint "
                "that accepts state-changing methods, and never combine a wildcard/reflected "
                "origin with Access-Control-Allow-Credentials: true."
            ),
            cvss="8.1" if acac else "6.1",
            confidence="HIGH" if acac else "LOW", confidence_score=80 if acac else 40,
            validation_steps=["preflight_origin_allowed", "preflight_method_allowed"],
            evidence=[f"Origin: {origin}", f"ACAO: {acao}", f"ACAM: {acam}", f"ACAH: {acah}",
                      f"Credentials allowed: {acac}"],
        )
        self.ui.find("high" if acac else "low", "CORS preflight allows state-changing cross-origin requests", self.base_url)


# ─── SSRF Module ───────────────────────────────────────────────────────────────