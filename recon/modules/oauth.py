"""
OAuthModule — YATA RECON module.
Detects OAuth 2.0 configuration flaws, plus two LIVE probes:

  - redirect_uri validation: an unauthenticated GET to the authorization
    endpoint with a manipulated redirect_uri reveals whether the server
    does exact allow-list matching or something weaker (substring/suffix/
    prefix), via a differential canary comparison — no login needed.

  - PKCE verifier enforcement: when the scan already has an authenticated
    session (--cookie/--header), a real headless browser (playwright —
    optional dependency, see core/screenshot.py) reuses those cookies to
    drive the ACTUAL authorization redirect and capture a genuine
    authorization code — no manual login flow to script, since the
    existing session already carries whatever the IdP needs to
    auto-approve. That code is then exchanged at the token endpoint with a
    DELIBERATELY WRONG code_verifier; if the exchange still succeeds,
    PKCE isn't actually being enforced server-side — a live-confirmed
    finding, not a static guess. Falls back to a no-op (with a clear
    reason) when no session/playwright is available, same degrade pattern
    as every other optional-dependency feature in this codebase.
"""
import base64
import hashlib
import secrets as _secrets
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule

try:
    from recon.core.screenshot import available as _playwright_available
except Exception:
    def _playwright_available():
        return False


class OAuthModule(BaseModule):
    NAME = "OAuth Security"

    def run(self):
        self.ui.section("OAuth — Security Misconfiguration Detection")
        if not requests:
            return

        endpoints = self.ctx.get("endpoints", [])
        oauth_endpoints = []
        
        # Identify OAuth endpoints
        for ep in endpoints:
            if any(x in ep.lower() for x in ["oauth", "authorize", "callback", "client_id", "redirect_uri"]):
                oauth_endpoints.append(ep)

        if not oauth_endpoints:
            self.ui.info("No OAuth endpoints discovered.")
            return

        found = 0
        s = self._session()

        for ep in oauth_endpoints:
            parsed = urllib.parse.urlparse(ep)
            params = urllib.parse.parse_qs(parsed.query)
            is_auth_request = "client_id" in params and "redirect_uri" in params
            if not is_auth_request:
                continue

            # Live redirect_uri validation probe — see module docstring.
            if self._test_redirect_uri_validation(ep, params, s):
                found += 1

            # Live PKCE verifier-enforcement probe — see module docstring.
            if self._test_pkce_live(ep, params, s):
                found += 1

            # Check for missing state parameter
            if "state" not in params:
                self.db.add(
                    title="OAuth — Missing 'state' Parameter",
                    severity="high", url=ep, module=self.NAME,
                    description=(
                        "The OAuth authorization request is missing the 'state' parameter. "
                        "This makes the OAuth flow vulnerable to Cross-Site Request Forgery (CSRF)."
                    ),
                    remediation="Always use a cryptographically strong, unguessable 'state' parameter to prevent CSRF.",
                    cvss="7.4",
                    confidence="HIGH",
                    confidence_score=85,
                    validation_steps=["oauth_endpoint_identified", "state_param_missing"]
                )
                self.ui.find("high", "OAuth Missing 'state' Parameter", ep)
                found += 1

            response_type = (params.get("response_type", [""])[0]).lower()

            # Implicit flow (response_type=token) returns the access token
            # directly in the URL fragment — leaks via browser history,
            # Referer headers, and any embedded/proxy JS. Deprecated by
            # OAuth 2.1 in favor of Authorization Code + PKCE.
            if response_type == "token":
                self.db.add(
                    title="OAuth — Deprecated Implicit Grant Flow",
                    severity="medium", url=ep, module=self.NAME,
                    description=(
                        "This authorization request uses response_type=token (the OAuth 2.0 "
                        "implicit grant). The access token is returned directly in the URL "
                        "fragment, exposing it to browser history, Referer leakage, and any "
                        "script with DOM access. OAuth 2.1 removes this grant entirely."
                    ),
                    remediation="Migrate to the Authorization Code flow with PKCE (response_type=code + code_challenge).",
                    cvss="5.4",
                    confidence="HIGH",
                    confidence_score=90,
                    validation_steps=["oauth_endpoint_identified", "implicit_flow_detected"],
                )
                self.ui.find("medium", "OAuth Implicit Grant Flow (deprecated)", ep)
                found += 1

            # Missing PKCE on an authorization-code request for a client that
            # looks public (no client_secret in this URL — a confidential
            # server-side client wouldn't leak its secret in the browser URL
            # either way, so absence here isn't conclusive on its own, hence
            # MEDIUM confidence rather than HIGH).
            elif response_type in ("code", "") and "code_challenge" not in params:
                self.db.add(
                    title="OAuth — Authorization Code Flow Without PKCE",
                    severity="medium", url=ep, module=self.NAME,
                    description=(
                        "The authorization request does not include a 'code_challenge' "
                        "(PKCE). Without PKCE, an attacker who intercepts the authorization "
                        "code (e.g. via a malicious app registering the same custom URI "
                        "scheme on mobile, or an open redirect) can exchange it for an "
                        "access token themselves."
                    ),
                    remediation="Implement PKCE (RFC 7636) for all public/native/SPA clients — send code_challenge and verify code_verifier on token exchange.",
                    cvss="6.5",
                    confidence="MEDIUM",
                    confidence_score=60,
                    validation_steps=["oauth_endpoint_identified", "pkce_param_missing"],
                )
                self.ui.find("medium", "OAuth Missing PKCE", ep)
                found += 1

        if found == 0:
             self.ui.info("No OAuth vulnerabilities detected.")

    @staticmethod
    def _loc_host(request_url, location):
        """Resolved destination host of a (possibly relative) Location, with
        backslashes normalized the way a browser would. Used so redirect_uri
        acceptance is judged by the real target host, not substring presence."""
        if not location:
            return ""
        try:
            dest = urllib.parse.urljoin(request_url, location.strip().replace("\\", "/"))
            return (urllib.parse.urlparse(dest).hostname or "").lower()
        except Exception:
            return ""

    # ─────────────────────────────────────────────────────────────────────────
    def _test_redirect_uri_validation(self, ep, params, s):
        """
        Live redirect_uri validation probe — doesn't require completing the
        consent flow. We first send a canary redirect_uri that was
        DEFINITELY never registered for this client, to establish how a
        clean rejection actually looks on this server. Then a set of
        bypass-shaped variants of the real redirect_uri are sent the same
        way. If a bypass gets treated like an accepted request while the
        plain-invalid canary was rejected, the redirect_uri check is doing
        weak (substring/suffix/prefix) matching instead of exact
        allow-listing — a live-confirmed finding, not a static guess.
        """
        found = 0
        original_redirect = params.get("redirect_uri", [""])[0]
        if not original_redirect:
            return 0
        parsed_r = urllib.parse.urlparse(original_redirect)
        legit_host = parsed_r.netloc
        if not legit_host:
            return 0

        def probe(redirect_uri):
            new_params = dict(params)
            new_params["redirect_uri"] = [redirect_uri]
            flat = {k: v[0] for k, v in new_params.items()}
            base = urllib.parse.urlparse(ep)
            url = f"{base.scheme}://{base.netloc}{base.path}?{urllib.parse.urlencode(flat)}"
            try:
                return s.get(url, timeout=self.timeout, allow_redirects=False)
            except Exception:
                return None

        canary = "https://yata-recon-invalid-canary.example/"
        canary_resp = probe(canary)
        if canary_resp is None:
            return 0
        time.sleep(self.delay)

        canary_location = canary_resp.headers.get("Location", "")
        # Confirm the server actually redirected TO the canary host — not that
        # the canary URL merely appears as a substring of the Location (an
        # error page echoing `?redirect_uri=https://…canary…` on a same-origin
        # redirect would match a substring test and fabricate a CRITICAL).
        canary_host = (urllib.parse.urlparse(canary).hostname or "").lower()
        canary_loc_host = self._loc_host(ep, canary_location)
        canary_redirected_to_attacker = bool(canary_host) and (
            canary_loc_host == canary_host or canary_loc_host.endswith("." + canary_host)
        )
        rejection_kw = ["invalid redirect", "redirect_uri", "unregistered", "mismatch", "invalid_request"]
        canary_rejected = (
            canary_resp.status_code in (400, 401, 403, 422)
            or any(kw in canary_resp.text.lower() for kw in rejection_kw)
        )

        if canary_redirected_to_attacker:
            self.db.add(
                title="OAuth — redirect_uri Accepts Arbitrary Unregistered Value",
                severity="critical", url=ep, module=self.NAME,
                description=(
                    "The authorization endpoint redirected straight to a completely "
                    "unrelated, never-registered redirect_uri with no validation at all. "
                    "Any attacker can steal authorization codes/tokens by supplying their "
                    "own redirect_uri and phishing a victim into the flow."
                ),
                remediation="Enforce exact-match allow-listing of pre-registered redirect_uri values server-side — never trust the client-supplied value directly.",
                cvss="9.6", confidence="CONFIRMED", confidence_score=95,
                validation_steps=["canary_redirect_uri_probed", "server_redirected_to_unregistered_domain"],
                evidence=[f"Canary redirect_uri: {canary}", f"Location header: {canary_location}"],
            )
            self.ui.find("critical", "OAuth redirect_uri — no validation at all", ep)
            return 1

        if not canary_rejected:
            # Can't establish a reliable rejected-baseline on this server
            # (e.g. it always 200s a generic error page regardless of
            # redirect_uri) — the differential bypass tests below would be
            # too noisy to trust, so skip them rather than guess.
            return 0

        bypasses = [
            (f"{original_redirect.rstrip('/')}.attacker.com/", "suffix-append bypass"),
            (f"https://attacker.com/?{legit_host}", "query-embedding bypass"),
            (f"https://{legit_host}.attacker.com/", "subdomain-confusion bypass"),
            (f"https://attacker.com\\@{legit_host}/", "backslash/userinfo confusion bypass"),
            (f"{parsed_r.scheme}://attacker.com#{legit_host}/", "fragment-confusion bypass"),
        ]

        for bypass_uri, name in bypasses:
            resp = probe(bypass_uri)
            time.sleep(self.delay)
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            attacker_host = "attacker.com"
            dest_host = self._loc_host(ep, location)
            looks_accepted = (
                resp.status_code in (200, 302, 303)
                and (dest_host == attacker_host or dest_host.endswith("." + attacker_host))
            ) or (
                # SPA/JS-redirect fallback: attacker host reflected in a 2xx/3xx
                # body that is NOT itself a redirect_uri-rejection error page.
                resp.status_code == canary_resp.status_code
                and resp.status_code not in (400, 401, 403, 422)
                and attacker_host in resp.text
                and not any(kw in resp.text.lower() for kw in rejection_kw)
            )
            if looks_accepted:
                self.db.add(
                    title=f"OAuth — redirect_uri Validation Bypass ({name})",
                    severity="high", url=ep, module=self.NAME,
                    description=(
                        f"A clean canary redirect_uri ({canary}) was correctly rejected, but a "
                        f"{name} variant of the legitimate redirect_uri was accepted/redirected "
                        "to. This indicates weak (substring/suffix/prefix) redirect_uri matching "
                        "instead of exact allow-listing, letting an attacker redirect the "
                        "authorization code or token to an attacker-controlled endpoint."
                    ),
                    remediation="Validate redirect_uri with exact string equality against a pre-registered allow-list — never substring, prefix, or suffix matching.",
                    cvss="8.1", confidence="HIGH", confidence_score=80,
                    validation_steps=["canary_rejected", f"{name.replace(' ', '_').replace('/', '_')}_probed",
                                       "bypass_accepted_while_canary_rejected"],
                    evidence=[f"Bypass redirect_uri: {bypass_uri}", f"Location header: {location}"],
                )
                self.ui.find("high", f"OAuth redirect_uri bypass — {name}", ep)
                found += 1

        return found

    # ─────────────────────────────────────────────────────────────────────────
    def _generate_pkce_pair(self):
        """RFC 7636 PKCE pair: code_verifier is 43-128 chars from
        [A-Za-z0-9-._~]; code_challenge is base64url(SHA256(verifier)),
        unpadded. base64.urlsafe already only emits [A-Za-z0-9-_], a
        subset of the allowed charset, so no further filtering is needed."""
        verifier = base64.urlsafe_b64encode(_secrets.token_bytes(64)).decode().rstrip('=')[:128]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        return verifier, challenge

    def _discover_token_endpoint(self, s, origin):
        """Try OIDC discovery first (authoritative when present), then
        fall back to the handful of near-universal conventional paths."""
        try:
            resp = s.get(urllib.parse.urljoin(origin, "/.well-known/openid-configuration"), timeout=self.timeout)
            data = resp.json()
            if data.get("token_endpoint"):
                return data["token_endpoint"]
        except Exception:
            pass
        for path in ("/oauth/token", "/oauth2/token", "/token", "/auth/token", "/api/oauth/token"):
            url = urllib.parse.urljoin(origin, path)
            try:
                # A HEAD/GET here just tells us whether *something* answers
                # at this path (a real token endpoint usually rejects a
                # bare GET with 400/405, not 404) — good enough to pick the
                # most plausible candidate without guessing blindly.
                resp = s.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code != 404:
                    return url
            except Exception:
                continue
        return urllib.parse.urljoin(origin, "/oauth/token")

    def _drive_browser_to_code(self, authorize_url, redirect_uri):
        """
        Drives a real headless-browser navigation to `authorize_url` (with
        the scan's existing auth_cookies injected, so an IdP that
        recognizes the session can auto-approve without a manual consent
        click) and captures the 'code' query param from whichever request
        the browser makes to redirect_uri. Returns the code, or None if
        playwright isn't available, there's no session to drive it with,
        or the flow never reached redirect_uri (e.g. a real manual consent
        screen genuinely requiring a click — a known, honest limitation).
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return None

        parsed_redirect = urllib.parse.urlparse(redirect_uri)
        redirect_origin_path = f"{parsed_redirect.scheme}://{parsed_redirect.netloc}{parsed_redirect.path}"
        captured = {"code": None}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
                try:
                    context = browser.new_context(ignore_https_errors=True)
                    cookies = self.auth_cookies()
                    if cookies:
                        domain = urllib.parse.urlparse(self.base_url).netloc.split(":")[0]
                        context.add_cookies([
                            {"name": k, "value": v, "domain": domain, "path": "/"}
                            for k, v in cookies.items()
                        ])
                    page = context.new_page()

                    def on_request(request):
                        if request.url.startswith(redirect_origin_path):
                            qs = urllib.parse.parse_qs(urllib.parse.urlparse(request.url).query)
                            if "code" in qs and not captured["code"]:
                                captured["code"] = qs["code"][0]

                    page.on("request", on_request)
                    try:
                        page.goto(authorize_url, timeout=12000, wait_until="domcontentloaded")
                        page.wait_for_timeout(2000)
                    except Exception:
                        pass  # navigating INTO redirect_uri (often not a renderable page) failing is expected
                    context.close()
                finally:
                    browser.close()
        except Exception:
            return None

        return captured["code"]

    def _test_pkce_live(self, ep, params, s):
        """
        Live PKCE-verifier-enforcement probe — see module docstring for
        the full rationale. No-ops cleanly (returns 0) whenever a
        prerequisite is missing: no session to drive the browser with, no
        playwright installed, or the flow didn't yield a real code.
        """
        if not _playwright_available():
            return 0
        if not self.auth_cookies() and not self.auth_headers():
            return 0  # nothing to auto-approve with — would need a real manual login

        client_id = params.get("client_id", [""])[0]
        redirect_uri = params.get("redirect_uri", [""])[0]
        scope = params.get("scope", ["openid"])[0]
        if not client_id or not redirect_uri:
            return 0

        verifier, challenge = self._generate_pkce_pair()
        base = urllib.parse.urlparse(ep)
        authorize_params = {
            "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
            "scope": scope, "code_challenge": challenge, "code_challenge_method": "S256",
            "state": _secrets.token_hex(8),
        }
        authorize_url = f"{base.scheme}://{base.netloc}{base.path}?{urllib.parse.urlencode(authorize_params)}"

        code = self._drive_browser_to_code(authorize_url, redirect_uri)
        if not code:
            return 0

        origin = f"{base.scheme}://{base.netloc}"
        token_endpoint = self._discover_token_endpoint(s, origin)
        wrong_verifier = _secrets.token_urlsafe(64)[:64]

        try:
            resp = s.post(token_endpoint, data={
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": redirect_uri, "client_id": client_id,
                "code_verifier": wrong_verifier,
            }, timeout=self.timeout)
        except Exception:
            return 0

        try:
            body = resp.json()
        except Exception:
            body = {}
        accepted = resp.status_code == 200 and isinstance(body, dict) and "access_token" in body

        if not accepted:
            return 0

        self.db.add(
            title="OAuth — PKCE Code Verifier Not Enforced",
            severity="critical", url=token_endpoint, module=self.NAME,
            description=(
                "A real authorization code was obtained via a live-driven browser session "
                "(reusing the scan's existing authenticated session) with a correctly-generated "
                "PKCE code_challenge, then exchanged at the token endpoint using a DELIBERATELY "
                "WRONG code_verifier — and the exchange SUCCEEDED. PKCE exists specifically to "
                "prevent this: an attacker who intercepts the authorization code (open "
                "redirect, a malicious app on the same device, a network capture) can exchange "
                "it for an access token without ever knowing the original code_verifier."
            ),
            remediation="Verify code_verifier against the code_challenge captured at authorization time on every token exchange — reject the exchange unless SHA256(code_verifier) == code_challenge.",
            cvss="9.1", confidence="CONFIRMED", confidence_score=97,
            validation_steps=["real_authorization_code_captured_via_live_browser",
                               "wrong_code_verifier_used", "token_endpoint_accepted_mismatched_verifier"],
            evidence=[f"Authorize URL: {authorize_url}", f"Token endpoint: {token_endpoint}"],
        )
        self.ui.find("critical", "OAuth PKCE code_verifier not enforced", token_endpoint)
        if body.get("access_token"):
            self.capture_credential("bearer", body["access_token"], source=f"{self.NAME} (PKCE bypass)")
        return 1
