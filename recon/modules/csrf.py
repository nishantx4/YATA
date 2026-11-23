"""
CSRFModule — YATA RECON module.
Detects missing CSRF protection on state-changing HTML forms.

Note: cookie SameSite/HttpOnly/Secure attributes are checked by
modules/broken_auth.py, not here — duplicating that here would just
produce two findings for the same underlying cookie flaw.
"""
import re

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule

# Frameworks commonly protect forms with a per-session CSRF token delivered
# via a <meta> tag + request header, or a double-submit cookie — NOT a hidden
# form field. A form without a hidden token is therefore not necessarily
# unprotected (Rails/Discourse, Django, Angular, Laravel all do this).
_CSRF_META_RE = re.compile(
    r'<meta[^>]+(?:name|id)\s*=\s*["\'](?:csrf-token|csrf-param|_?csrf|xsrf-token|'
    r'authenticity_token|requestverificationtoken)["\']', re.I)


class CSRFModule(BaseModule):
    NAME = "CSRF"

    def run(self):
        self.ui.section("CSRF — Cross-Site Request Forgery Detection")
        if not requests:
            return

        forms = self.ctx.get("forms", [])
        if not forms:
            self.ui.info("No forms discovered. Run recon module first.")
            return

        # Classic CSRF relies on the browser auto-attaching an ambient
        # credential (a cookie) to a cross-site request. If the only auth
        # signal this target uses is a custom header (e.g. an API token from
        # an OpenAPI spec) and no session cookie was ever supplied/observed,
        # a cross-site page cannot forge that header at all — flagging
        # "missing CSRF token" there would be a structural false positive.
        token_auth_only = bool(self.ctx.get("auth_headers")) and not self.ctx.get("session_cookie")
        if token_auth_only:
            self.ui.info(
                "Target uses header-based auth with no session cookie observed — "
                "CSRF doesn't apply to cross-site requests here (a browser can't forge "
                "the auth header), skipping form-based CSRF checks."
            )
            return

        found = 0
        csrf_indicators = ["csrf", "token", "_token", "authenticity_token", "requestverificationtoken", "xsrf", "nonce"]

        for form in forms:
            # recon.py stores the form's action URL under "action", not "url",
            # and "inputs" as a {name: value} dict, not a list of {name, type}
            # dicts — iterating it as the latter throws AttributeError on the
            # first field and crashes the whole module before it flags anything.
            url = form.get("action", self.base_url)
            method = form.get("method", "GET").upper()

            # CSRF generally applies to state-changing requests (POST, PUT, DELETE)
            if method not in ("POST", "PUT", "DELETE"):
                continue

            inputs = form.get("inputs", {})
            input_names = inputs.keys() if isinstance(inputs, dict) else inputs
            has_csrf_token = any(
                any(ind in str(name).lower() for ind in csrf_indicators)
                for name in input_names
            )

            if not has_csrf_token:
                # A hidden token field is only ONE way to protect a form.
                # Before flagging, check for a framework CSRF token delivered
                # via <meta>+header or a double-submit cookie — otherwise every
                # Rails/Discourse/Django/Angular form is a false positive.
                if self._framework_csrf_present(url):
                    continue

                # Login forms: classic session-riding CSRF does not apply (no
                # authenticated session exists yet); only low-severity
                # login-CSRF does, and these flows are usually header/meta- or
                # SameSite-protected. Don't raise a HIGH finding on them.
                if self._is_login_form(input_names):
                    severity, score = "low", 35
                    desc = (
                        f"The login form on {url} ({method}) has no hidden anti-CSRF token field. "
                        "Only login-CSRF applies here (an attacker could log a victim into an "
                        "attacker-controlled account) — the classic session-riding impact does not, "
                        "since no authenticated session exists at login. Confirm the flow isn't "
                        "already protected by a header/meta CSRF token or SameSite cookies."
                    )
                else:
                    severity, score = "medium", 60
                    desc = (
                        f"The form on {url} using {method} method does not contain a discernible "
                        "Anti-CSRF token (no hidden field, no <meta>/header token, no CSRF cookie "
                        "observed). If the action is state-changing and relies on session cookies, "
                        "it may be vulnerable to Cross-Site Request Forgery."
                    )

                self.db.add(
                    title="CSRF — Missing Anti-CSRF Token in Form",
                    severity=severity, url=url, module=self.NAME,
                    description=desc,
                    remediation="Implement Anti-CSRF tokens for all state-changing forms or use SameSite=Lax/Strict for session cookies.",
                    cvss="6.5",
                    confidence="MEDIUM", # We didn't exploit it, just analyzed the form
                    confidence_score=score,
                    validation_steps=["form_analyzed", "csrf_token_missing", "no_framework_csrf_detected"],
                    evidence=[f"Fields on form: {', '.join(input_names) or '(none)'}"],
                )
                self.ui.find(severity, "Missing Anti-CSRF Token", url)
                found += 1

        if found == 0:
            self.ui.info("No CSRF vulnerabilities detected in discovered forms.")

    @staticmethod
    def _is_login_form(input_names):
        return any("pass" in str(n).lower() for n in input_names)

    def _framework_csrf_present(self, url):
        """Best-effort detection of a non-form-field CSRF defense: a <meta>
        CSRF token (read into an X-CSRF-Token request header by the app's JS)
        or a double-submit CSRF cookie. Returns False on any error so a failed
        probe never suppresses a genuine finding incorrectly — it just falls
        through to the normal (now severity-tiered) report."""
        try:
            resp = self._session().get(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return False
        if _CSRF_META_RE.search(resp.text or ""):
            return True
        try:
            for c in resp.cookies:
                if "csrf" in c.name.lower() or "xsrf" in c.name.lower():
                    return True
        except Exception:
            pass
        return any("csrf" in k.lower() or "xsrf" in k.lower() for k in resp.headers)
