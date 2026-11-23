"""
AuthFlowModule — password-reset / OTP flow weaknesses.

Account-recovery flows are a rich bug-bounty surface, but most of it is
app-specific logic that can't be asserted without false positives. This
module tests the one failure mode that is both common and provable without
guessing semantics or causing side effects: **the recovery secret is handed
straight back in the HTTP response.**

When a "forgot password" / "send OTP" / "magic link" endpoint returns the
reset token, OTP code, or reset URL in its body (or a redirect/JSON), anyone
can take over an account without ever accessing the victim's inbox/phone. The
module submits only benign, non-existent `@example.com` identifiers (so it
never emails or texts a real person and causes no state an operator would
care about) and reports ONLY when a structured secret — a field literally
named otp/code/token/reset_token/pin, a reset link carrying a token
parameter, or a short numeric code adjacent to an OTP keyword — comes back.

It deliberately does NOT try to brute force codes or rate-limit endpoints
(that overlaps rate_limit.py and risks lockouts) or do reset host-header
poisoning (host_header.py already does), staying narrow and high-signal.
"""
import re
import math
import urllib.parse
from collections import Counter

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule
from recon.core import cancellation


def _shannon(s):
    """Shannon entropy (bits/char) — used to tell a real short token
    ('A3f9Kd') from a dictionary/UI word ('Angetal', 'error')."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _is_secretish(value):
    """A recovery secret is a numeric OTP, a long opaque token, or a
    mixed-class high-entropy string — never a short dictionary/UI word.

    This is the gate that rejects matches like `"postalCode":"Ange…"`,
    `"statusCode":"error"`, or `"code":"email"` that the field pattern would
    otherwise hand back as a leaked account-recovery secret (the exact source
    of the 'Ange' critical-severity false positives on localized marketing
    pages)."""
    v = (value or "").strip()
    if len(v) < 4:
        return False
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    # Long opaque strings are token-like regardless of composition.
    if len(v) >= 16:
        return True
    # OTP-style: all/mostly digits, no letters.
    if has_digit and not has_alpha:
        return True
    # Short mixed token (letters+digits) only if it carries real entropy.
    if has_digit and has_alpha and _shannon(v) >= 2.5:
        return True
    # Pure-alphabetic short value (UI words, field names, 'Ange', 'error',
    # 'email', 'false') → not a secret.
    return False

RESET_HINTS = ["forgot", "reset", "recover", "otp", "one-time", "onetime",
               "verify", "verification", "resend", "magic", "passwordless",
               "send-code", "sendcode", "request-reset", "forgot-password"]

IDENTIFIER_FIELDS = ["email", "username", "user", "login", "phone", "mobile",
                     "account", "identifier", "e-mail", "mail"]

# A benign, guaranteed-undeliverable probe identity (RFC 2606 reserved domain).
PROBE_EMAIL = "yata-recon-probe@example.com"
PROBE_PHONE = "+10000000000"

# Structured secret signals in a recovery response. The leading
# (?<![A-Za-z0-9]) is critical: without it, `code` matched inside
# postalCode / statusCode / languageCode / qrCode / barcode (and `token`
# inside csrfToken), turning ordinary page/JSON fields into "leaked secrets".
_SECRET_FIELD_RE = re.compile(
    r'(?<![A-Za-z0-9])(otp|code|pin|token|reset[_-]?token|reset[_-]?code|verification[_-]?code|'
    r'magic[_-]?link|reset[_-]?link|reset[_-]?url|activation[_-]?code)["\']?\s*[:=]\s*'
    r'["\']?([A-Za-z0-9._\-/:%]{4,})', re.IGNORECASE)
_RESET_LINK_RE = re.compile(r'https?://[^\s"\'<>]+[?&](token|reset[_-]?token|reset[_-]?code)=([A-Za-z0-9._\-%]{8,})', re.IGNORECASE)
# Numeric OTP must be in a real key:value structure (`"code":"483920"`),
# not loose prose like "zip code 90210", which the old [^0-9]{0,20} allowed.
_NUMERIC_CODE_RE = re.compile(r'(?<![A-Za-z])(?:otp|code|pin|verification)["\']?\s*[:=]\s*["\']?(\d{4,8})\b', re.IGNORECASE)


class AuthFlowModule(BaseModule):
    NAME = "Auth Recovery Flow"
    MODULE_ID = "otp"
    MODULE_LABEL = "OTP / Password-Reset Flow"

    MAX_ENDPOINTS = 10

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=6, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self._found = 0

    def run(self):
        self.ui.section("Auth Recovery — OTP / Password-Reset Secret Leakage")
        if not requests:
            return
        endpoints = self._collect()
        if not endpoints:
            self.ui.info("No password-reset / OTP endpoints discovered — skipping.")
            return
        self.ui.info(f"Probing {len(endpoints)} recovery endpoint(s) with a benign example.com identity.")
        for ep in endpoints:
            if cancellation.is_cancelled():
                break
            try:
                self._test(ep)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"auth-flow error: {e}")
        if self._found == 0:
            self.ui.info("No recovery-secret leakage detected.")
        else:
            self.ui.ok(f"Auth-recovery scan complete — {self._found} finding(s).")

    def _collect(self):
        eps, seen = [], set()

        def add(url, method, fields):
            key = (url.split("#", 1)[0], method)
            if key in seen or len(eps) >= self.MAX_ENDPOINTS:
                return
            seen.add(key)
            eps.append({"url": url, "method": method.upper(), "fields": fields})

        for form in self.ctx.get("forms", []):
            url = form.get("action") or self.base_url
            inputs = form.get("inputs", {})
            if any(h in url.lower() for h in RESET_HINTS) or \
               any(h in " ".join(inputs.keys()).lower() for h in RESET_HINTS) or \
               (any(f in " ".join(inputs.keys()).lower() for f in IDENTIFIER_FIELDS)
                    and any(h in url.lower() for h in RESET_HINTS)):
                add(url, form.get("method", "POST"), list(inputs.keys()))

        for api in self.ctx.get("api_endpoints", []):
            url = api.get("url", "")
            if any(h in url.lower() for h in RESET_HINTS) and "{" not in url:
                add(url, api.get("method", "POST"), api.get("json_props", []) or ["email"])

        for ep in self.ctx.get("endpoints", []):
            if any(h in ep.lower() for h in RESET_HINTS) and "{" not in ep:
                add(ep, "POST", ["email"])
        return eps

    def _build_body(self, fields):
        body = {}
        for f in fields or ["email"]:
            fl = f.lower()
            if "phone" in fl or "mobile" in fl:
                body[f] = PROBE_PHONE
            elif any(idf in fl for idf in IDENTIFIER_FIELDS):
                body[f] = PROBE_EMAIL
            else:
                body[f] = PROBE_EMAIL if "mail" in fl else "yata-recon"
        if not any(k.lower() in ("email", "mail", "e-mail") for k in body):
            body.setdefault("email", PROBE_EMAIL)
        return body

    def _test(self, ep):
        body = self._build_body(ep["fields"])
        headers = self.auth_headers()
        cookies = self.auth_cookies()
        self._throttle()
        resp = None
        try:
            # Try form-encoded and JSON — many APIs only accept one.
            resp = self.session.request(ep["method"], ep["url"], data=body,
                                        timeout=self.timeout, headers=headers, cookies=cookies,
                                        allow_redirects=True)
            if resp is not None and resp.status_code >= 400:
                self._throttle()
                j = self.session.request(ep["method"], ep["url"], json=body,
                                         timeout=self.timeout, headers=headers, cookies=cookies,
                                         allow_redirects=True)
                if j is not None and j.status_code < 400:
                    resp = j
        except RequestException:
            return
        if resp is None:
            return

        # A recovery secret returned "in the response" is an API/JSON
        # behavior. Scraping a full HTML page for code:/token: substrings is
        # what produced the critical-severity false positives on localized
        # marketing pages (postalCode/UI text/build hashes), so only trust a
        # structured JSON response here. Reset links delivered via a redirect
        # Location are still covered — resp.history is scanned below.
        if self._is_json_response(resp):
            leak = self._find_secret(resp.text or "")
            if leak:
                self._report(ep, leak, resp)
                return

        # Reset link leaked via a redirect target (Location header), e.g.
        # 302 → /reset?token=… — specific enough to trust without a JSON body.
        for r in list(getattr(resp, "history", [])) + [resp]:
            loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
            m = _RESET_LINK_RE.search(loc)
            if m:
                self._report(ep, ("reset link with token (redirect)", m.group(0)[:120]), resp)
                return

    @staticmethod
    def _is_json_response(resp):
        """True only for a genuinely structured (JSON) response — the only
        place a returned OTP/token is a real finding rather than incidental
        page content."""
        ct = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" in ct or "+json" in ct or "text/json" in ct:
            return True
        head = (resp.text or "")[:512].lstrip()
        return head[:1] in ("{", "[")

    def _find_secret(self, body):
        if not body:
            return None
        # Ignore obvious non-secret echoes (the probe identity we sent, empty
        # nulls) so a field like "email": "...@example.com" can't trip it.
        m = _RESET_LINK_RE.search(body)
        if m:
            return ("reset link with token", m.group(0)[:120])
        for m in _SECRET_FIELD_RE.finditer(body):
            field, value = m.group(1), m.group(2)
            if value.lower() in ("null", "true", "false", "none", "") or "@example.com" in value:
                continue
            if PROBE_EMAIL in value:
                continue
            # Must actually look like a secret, not a dictionary/UI word
            # (postalCode:"Ange…", statusCode:"error", code:"email").
            if not _is_secretish(value):
                continue
            return (f"'{field}' field in response", value[:60])
        m = _NUMERIC_CODE_RE.search(body)
        if m:
            return ("numeric code adjacent to OTP keyword", m.group(1))
        return None

    def _report(self, ep, leak, resp):
        kind, value = leak
        redacted = (value[:3] + "…" + value[-2:]) if len(value) > 6 else value
        added = self.db.add(
            title="Account-Recovery Secret Returned in Response (OTP/Reset Token Leak)",
            severity="critical", url=ep["url"], module=self.NAME,
            description=(
                f"The recovery endpoint {ep['url']} returned the account-recovery secret directly in "
                f"its HTTP response ({kind}). Submitting only a benign, non-existent example.com "
                "identity, the response contained a value that functions as the reset token / OTP / "
                "magic link. Because the secret never has to be read from the victim's email or phone, "
                "anyone who can trigger recovery for an account can immediately complete it — a direct "
                "account-takeover primitive."
            ),
            remediation=(
                "Never return the OTP, reset token, or reset link in the API/HTTP response. Deliver it "
                "only out-of-band (email/SMS/authenticator), return a generic 'if the account exists, a "
                "message was sent' acknowledgement, and make tokens single-use, short-lived, and "
                "high-entropy."
            ),
            cvss="9.1", confidence="CONFIRMED", confidence_score=95,
            validation_steps=["benign_identity_submitted", "structured_recovery_secret_in_response"],
            evidence=[f"Signal: {kind}", f"Leaked value (redacted): {redacted}",
                      f"Status: {resp.status_code}"],
            references=[
                "https://owasp.org/www-community/attacks/Credential_stuffing",
                "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("critical", "Recovery secret leaked in response", ep["url"])
            self.ui.bullet(kind, indent=12)
