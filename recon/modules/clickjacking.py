"""
ClickjackingModule — YATA RECON module.
Detects missing frame protection headers (X-Frame-Options, CSP frame-ancestors).
"""
import time

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


class ClickjackingModule(BaseModule):
    NAME = "Clickjacking"

    # Markers that a page actually has a state-changing action worth
    # hijacking. Clickjacking a static/content page is not an exploitable
    # bug — there's nothing for a victim's click to trigger.
    _ACTION_MARKERS = (
        "<form", 'type="password"', "type='password'",
        'name="csrf', "name='csrf", "csrf_token", "csrfmiddlewaretoken",
        '<button', 'role="button"', 'onclick=', 'type="submit"', "type='submit'",
    )

    def _has_sensitive_action(self, html: str) -> bool:
        """True if the page exposes an interactive/state-changing action that a
        clickjacking overlay could actually drive (a form, a submit/button, a
        password or anti-CSRF field)."""
        if not html:
            return False
        low = html.lower()
        return any(m in low for m in self._ACTION_MARKERS)

    def _capture_iframe_evidence(self):
        """Best-effort playwright screenshot of the target actually
        rendered inside a third-party iframe (see core/screenshot.py) —
        returns None immediately, cheaply, if playwright isn't installed."""
        try:
            from recon.core.screenshot import capture_iframe_embed
        except Exception:
            return None
        try:
            return capture_iframe_embed(self.base_url, self.output_dir, "clickjacking")
        except Exception:
            return None

    def run(self):
        self.ui.section("Clickjacking — Frame Protection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()

        try:
            resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            self.ui.error("Failed to connect to target.")
            return

        xfo = resp.headers.get("X-Frame-Options", "").strip().upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        has_xfo = xfo in ("DENY", "SAMEORIGIN")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if has_xfo and has_frame_ancestors:
            self.ui.info("Frame protection is properly configured (X-Frame-Options + CSP frame-ancestors).")
            return

        if not has_xfo and not has_frame_ancestors:
            evidence = ["X-Frame-Options: missing", "CSP frame-ancestors: missing"]
            sensitive = self._has_sensitive_action(resp.text)
            screenshot_path = self._capture_iframe_evidence()

            steps = ["xfo_missing", "csp_frame_ancestors_missing"]
            if screenshot_path:
                # Proven: the page really renders inside a third-party iframe.
                evidence.append(f"Screenshot (target rendered inside an iframe): {screenshot_path}")
                steps.append("iframe_render_screenshotted")
                severity, confidence, confidence_score = "medium", "CONFIRMED", 96
                extra = (" A screenshot confirms the page actually renders inside a third-party "
                         "iframe with no visible restriction.")
            elif sensitive:
                # Frameable AND has a real action an overlay could hijack.
                evidence.append("Page exposes a state-changing action (form/button) that an overlay could drive.")
                steps.append("sensitive_action_present")
                severity, confidence, confidence_score = "medium", "MEDIUM", 65
                extra = (" The page exposes an interactive action (form/button), so a framing overlay "
                         "has something to hijack.")
            else:
                # Header hygiene only — nothing on the page to hijack. Kept on
                # record but scored below the default --confidence gate so it
                # doesn't flood the report as an 'exploitable' finding.
                evidence.append("No state-changing action found on the page — header-hygiene gap, not a proven exploit.")
                steps.append("no_sensitive_action")
                severity, confidence, confidence_score = "low", "LOW", 35
                extra = (" However, no state-changing action was found on this page, so there is nothing "
                         "for a clickjacking overlay to actually trigger — this is a header-hygiene gap.")

            self.db.add(
                title="Clickjacking — No Frame Protection",
                severity=severity, url=self.base_url, module=self.NAME,
                description=(
                    "Neither X-Frame-Options nor Content-Security-Policy frame-ancestors "
                    "headers are set, so the page can be embedded in an iframe on any domain." + extra
                ),
                remediation=(
                    "Set X-Frame-Options: DENY or SAMEORIGIN on all responses. "
                    "Additionally, set Content-Security-Policy: frame-ancestors 'self'."
                ),
                cvss="4.7",
                confidence=confidence,
                confidence_score=confidence_score,
                validation_steps=steps,
                evidence=evidence,
            )
            if confidence_score >= 60:
                self.ui.find(severity, "Clickjacking — frame protection missing (actionable page)", self.base_url)
            else:
                self.ui.info("Frame-protection headers missing, but no sensitive action on the page — logged below default confidence.")
        elif not has_xfo:
            self.db.add(
                title="Clickjacking — Missing X-Frame-Options (CSP present)",
                severity="low", url=self.base_url, module=self.NAME,
                description=(
                    "X-Frame-Options header is not set, but CSP frame-ancestors is present. "
                    "Older browsers that don't support CSP may still be vulnerable."
                ),
                remediation="Add X-Frame-Options: DENY or SAMEORIGIN for defense-in-depth.",
                cvss="3.1",
                confidence="MEDIUM",
                confidence_score=60,
                validation_steps=["xfo_missing", "csp_present"],
            )
            self.ui.find("low", "Missing X-Frame-Options (CSP fallback exists)", self.base_url)
        else:
            self.db.add(
                title="Clickjacking — Missing CSP frame-ancestors (XFO present)",
                severity="info", url=self.base_url, module=self.NAME,
                description=(
                    "Content-Security-Policy frame-ancestors is not set, but X-Frame-Options is present. "
                    "Consider adding CSP frame-ancestors for modern browser support."
                ),
                remediation="Add Content-Security-Policy: frame-ancestors 'self' for defense-in-depth.",
                cvss="0.0",
                confidence="MEDIUM",
                confidence_score=60,
                validation_steps=["xfo_present", "csp_missing"],
            )
            self.ui.find("info", "Missing CSP frame-ancestors (XFO fallback exists)", self.base_url)
