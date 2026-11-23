"""
HeadersModule — YATA RECON module.
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


class HeadersModule(BaseModule):
    NAME = "Security Headers"

    # (severity, cvss, impact, confidence_score)
    #
    # A missing security header is a DEFENSE-IN-DEPTH hardening gap, not an
    # exploitable vulnerability on its own — the header being absent is real,
    # but it only matters in combination with another bug (XSS for CSP, a
    # framing target for X-Frame-Options, an HTTP downgrade path for HSTS).
    # Reporting each one as a HIGH/CONFIRMED finding (the old behavior: no
    # explicit score → label floor 85) is exactly the "every scanner spams
    # missing-header warnings" noise this tool is supposed to avoid, so each is
    # scored at/below the default --confidence gate (60) — suppressed from the
    # default report, surfaced when the operator lowers --confidence. This
    # mirrors how clickjacking.py / cors.py already score header-hygiene gaps.
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("medium", "5.3", "Missing HSTS allows TLS-downgrade/SSL-strip attacks (only on an HTTP exposure)", 55),
        "Content-Security-Policy":   ("medium", "5.4", "Missing CSP removes a defense-in-depth layer against XSS (not itself an XSS)", 55),
        "X-Frame-Options":           ("low",    "4.3", "Missing X-Frame-Options allows framing (clickjacking only matters on pages with a state-changing action)", 45),
        "X-Content-Type-Options":    ("low",    "3.1", "Missing X-Content-Type-Options allows MIME sniffing", 40),
        "Referrer-Policy":           ("info",   "0.0", "Missing Referrer-Policy may leak sensitive URLs in the Referer header", 35),
        "Permissions-Policy":        ("info",   "0.0", "Missing Permissions-Policy — browser features uncontrolled", 30),
    }

    DANGEROUS_HEADERS = {
        "X-Powered-By":   ("info", "Reveals server technology stack"),
        "Server":         ("info", "Reveals server software and version"),
        "X-AspNet-Version": ("info", "Reveals ASP.NET version"),
    }

    # match_method (core/cve_enrichment.py) -> (confidence, score, human label)
    _CVE_MATCH_CONFIDENCE = {
        "cpe-range": ("HIGH", 80, "the CPE's declared version range covers this exact version"),
        "cpe-exact": ("HIGH", 75, "the CPE's own version field matches this exact version"),
        "text":      ("MEDIUM", 50, "a free-text mention of this version was found (no structured CPE range confirmed it)"),
    }

    def _enrich_with_cves(self, header_name, header_value):
        """
        CVE enrichment: a fingerprinted 'Server: nginx/1.31.6'-style header
        is cross-referenced against the public NVD feed for free
        'known-vuln-version' findings — no local CVE database to maintain,
        no extra scanning, just squeezing more value out of a banner we
        already grabbed. lookup_cves() parses NVD's structured CPE
        version-range configurations when present (precise: 'cpe-range'/
        'cpe-exact') and only falls back to a free-text version-string
        match ('text') for CVEs NVD hasn't fully structured — confidence is
        set per-match accordingly rather than one flat guess for all of them.
        """
        try:
            from recon.core.cve_enrichment import parse_product_version, lookup_cves
        except Exception:
            return

        for product, version in parse_product_version(header_value):
            try:
                cves = lookup_cves(product, version)
            except Exception:
                cves = []
            for cve in cves:
                score = cve.get("cvss") or 0
                sev = ("critical" if score >= 9 else "high" if score >= 7 else
                       "medium" if score >= 4 else "low")
                method = cve.get("match_method", "text")
                conf, conf_score, match_desc = self._CVE_MATCH_CONFIDENCE.get(
                    method, self._CVE_MATCH_CONFIDENCE["text"])
                self.db.add(
                    title=f"Known CVE For Fingerprinted Software: {cve['id']} ({product} {version})",
                    severity=sev, url=self.base_url, module=self.NAME,
                    description=(
                        f"The '{header_name}' header discloses {product} {version}. {cve['id']} "
                        f"(CVSS {score or 'N/A'}) is a publicly known CVE — {match_desc}: "
                        f"{cve['summary']}"
                    ),
                    remediation=(
                        f"Verify whether this specific deployment is actually affected by "
                        f"{cve['id']} and patch/upgrade {product} if so. Also consider hiding "
                        f"the '{header_name}' header to reduce fingerprinting surface regardless."
                    ),
                    cvss=str(score) if score else None,
                    confidence=conf, confidence_score=conf_score,
                    validation_steps=["version_fingerprinted_from_header", f"cve_matched_via_{method.replace('-', '_')}"],
                    evidence=[f"Header: {header_name}: {header_value}", f"CVE: {cve['url']}", f"Match method: {method}"],
                    references=[cve["url"]],
                )
                self.ui.find(sev, f"{cve['id']} — {product} {version}", self.base_url)

    def run(self):
        self.ui.section("Security Headers Analysis")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        resp = self._get(self.base_url)
        if resp is None:
            self.ui.error(f"Could not reach {self.base_url}")
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, cvss, impact, conf_score) in self.REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                label = ("HIGH" if conf_score >= 75 else "MEDIUM" if conf_score >= 50
                         else "LOW")
                added = self.db.add(
                    title=f"Missing Security Header: {header}",
                    severity=severity,
                    url=self.base_url,
                    module=self.NAME,
                    description=(
                        f"The {header} HTTP response header is not set. {impact}. "
                        "This is a defense-in-depth hardening gap, not an exploitable "
                        "vulnerability on its own."
                    ),
                    remediation=f"Add the '{header}' header to all responses.",
                    cvss=cvss,
                    confidence=label,
                    confidence_score=conf_score,
                    validation_steps=["header_absent_from_response"],
                )
                # Only echo to the live feed when it actually cleared the
                # confidence gate — otherwise it's recorded but not a reported
                # finding, and shouldn't look like one in the scroll.
                if added:
                    self.ui.find(severity, f"Missing: {header}", self.base_url)

        # A header being PRESENT doesn't mean it's configured safely — these
        # checks catch the common case of a header existing but effectively
        # disabled or too permissive to provide real protection.
        hsts_val = headers.get("strict-transport-security", "")
        if hsts_val:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age <= 0:
                self.db.add(
                    title="HSTS Present But Disabled (max-age=0)",
                    severity="high", url=self.base_url, module=self.NAME,
                    description=f"Strict-Transport-Security is set (\"{hsts_val}\") but max-age is {max_age}, which disables HSTS enforcement entirely.",
                    remediation="Set Strict-Transport-Security max-age to at least 31536000 (1 year), ideally with includeSubDomains and preload.",
                    cvss="6.5", confidence="high",
                )
                self.ui.find("high", "HSTS present but disabled (max-age=0)", self.base_url)
            elif max_age < 15552000:  # < ~6 months
                self.db.add(
                    title="Weak HSTS max-age",
                    severity="low", url=self.base_url, module=self.NAME,
                    description=f"Strict-Transport-Security max-age is only {max_age}s (~{max_age // 86400} days), below the widely recommended 1-year minimum.",
                    remediation="Increase Strict-Transport-Security max-age to at least 31536000 seconds (1 year).",
                    cvss="3.1", confidence="medium",
                )
                self.ui.find("low", "Weak HSTS max-age", self.base_url)

        csp_val = headers.get("content-security-policy", "")
        if csp_val:
            csp_lower = csp_val.lower()
            weak_reasons = []
            if "unsafe-inline" in csp_lower:
                weak_reasons.append("allows 'unsafe-inline' (defeats CSP's main XSS mitigation)")
            if "unsafe-eval" in csp_lower:
                weak_reasons.append("allows 'unsafe-eval'")
            if re.search(r"(default-src|script-src)\s+[^;]*\*", csp_lower):
                weak_reasons.append("uses a wildcard (*) source on default-src/script-src")
            if weak_reasons:
                self.db.add(
                    title="Weak Content-Security-Policy",
                    severity="medium", url=self.base_url, module=self.NAME,
                    description=f"A CSP is present but weakened: {'; '.join(weak_reasons)}.",
                    remediation="Remove 'unsafe-inline'/'unsafe-eval' in favor of nonces or hashes for inline scripts, and avoid wildcard sources.",
                    cvss="5.4", confidence="high",
                    evidence=[f"CSP: {csp_val[:300]}"],
                )
                self.ui.find("medium", "Weak CSP (unsafe directives / wildcard sources)", self.base_url)

        # Check for information disclosure headers
        for header, (severity, desc) in self.DANGEROUS_HEADERS.items():
            if header.lower() in headers:
                val = headers[header.lower()]
                self.db.add(
                    title=f"Information Disclosure: {header}: {val}",
                    severity=severity,
                    url=self.base_url,
                    module=self.NAME,
                    description=f"Response header '{header}: {val}' discloses server technology.",
                    remediation=f"Remove or obscure the '{header}' response header.",
                    confidence="high",
                )
                self._enrich_with_cves(header, val)

        # Check for insecure session cookies.
        #
        # broken_auth.py performs a strictly more thorough version of this
        # (HttpOnly + Secure + SameSite, token redaction, token-quality
        # sampling) reading attributes straight off the parsed cookie jar. If
        # it's enabled for this scan, defer to it entirely instead of emitting
        # near-duplicate findings for the same cookie. We only run the check
        # here for the presets that include headers but not broken_auth
        # (e.g. 'quick'/'standard').
        #
        # NOTE: the previous implementation string-parsed raw Set-Cookie
        # headers with a fallback that rebuilt them as "name=value" from
        # resp.cookies — which DROPS the HttpOnly/Secure flags entirely, so
        # that fallback reported *every* session cookie as missing both flags
        # (a false positive). Reading the flags off the cookie jar objects
        # (cookie.secure / has_nonstandard_attr) is both correct and
        # loss-free, and is exactly what broken_auth.py does.
        from recon.core.validator import Validator
        validator = Validator()

        if "broken_auth" not in self.ctx.get("enabled_modules", []):
            for cookie in resp.cookies:
                cookie_name = cookie.name
                if not validator.validate_cookie_is_session(cookie_name):
                    continue

                # Double-submit CSRF/XSRF cookies are intentionally JS-readable
                # (Angular XSRF-TOKEN, Django csrftoken) — "missing HttpOnly" on
                # them is by design, not a vulnerability.
                is_csrf_cookie = "csrf" in cookie_name.lower() or "xsrf" in cookie_name.lower()
                if not cookie.has_nonstandard_attr("HttpOnly") and not is_csrf_cookie:
                    self.db.add(
                        title=f"Session Cookie Missing HttpOnly Flag ({cookie_name})",
                        severity="high", url=self.base_url, module=self.NAME,
                        description=f"Session cookie '{cookie_name}' lacks HttpOnly flag — accessible to JavaScript (XSS theft).",
                        remediation="Set HttpOnly flag on all session cookies.",
                        cvss="5.4",
                        confidence="CONFIRMED",
                        confidence_score=95,
                        validation_steps=["is_session_cookie", "httponly_missing"]
                    )
                    self.ui.find("high", f"Cookie missing HttpOnly: {cookie_name}", self.base_url)

                if not cookie.secure and self.base_url.startswith("https"):
                    self.db.add(
                        title=f"Session Cookie Missing Secure Flag ({cookie_name})",
                        severity="high", url=self.base_url, module=self.NAME,
                        description=f"Session cookie '{cookie_name}' lacks Secure flag — transmitted over HTTP.",
                        remediation="Set Secure flag on all session cookies.",
                        cvss="5.4",
                        confidence="CONFIRMED",
                        confidence_score=95,
                        validation_steps=["is_session_cookie", "secure_missing"]
                    )

        # ── AI: assess combined header risk ──────────────────────────────
        if self.ai and self.ai.enabled:
            missing_names = [
                h for h in self.REQUIRED_HEADERS
                if h.lower() not in headers
            ]
            if missing_names:
                ai_note = self.ai.analyze_headers(
                    self.base_url,
                    dict(resp.headers),
                    missing_names,
                )
                if ai_note:
                    self.ui.subsection("AI Header Risk Assessment")
                    for line in ai_note.split("\n"):
                        self.ui.raw(f"    {line}")
                    self.ui.blank()

        self.ui.ok("Headers analysis complete")


# ─── JS Analysis Module ───────────────────────────────────────────────────────