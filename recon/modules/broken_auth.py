"""
BrokenAuthModule — YATA RECON module.
Checks for session management flaws and authentication weaknesses.
"""
import time

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule

SESSION_COOKIE_NAMES = ("session", "sess", "sid", "phpsessid", "jsessionid", "connect.sid", "auth")


class BrokenAuthModule(BaseModule):
    NAME = "Broken Auth"

    def run(self):
        self.ui.section("Broken Authentication — Session Security")
        if not requests:
            return

        s = self._session()
        found = 0

        # Session indicators
        session_names = ["session", "sess", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid", "connect.sid"]
        tracking_names = ["_ga", "_gid", "_fbp", "__utm", "_hj"]

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:10]
        seen_cookie_names = set()  # avoid re-flagging the same cookie at every endpoint

        for endpoint in endpoints:
            try:
                resp = s.get(endpoint, timeout=self.timeout)

                # Only inspect cookies THIS response actually set. `s.cookies`
                # is the session-wide jar — it keeps accumulating every cookie
                # ever seen, so checking it on every iteration re-flags the
                # same cookie (set once on the first request) at every
                # subsequent endpoint's URL, producing near-duplicate findings.
                for cookie in resp.cookies:
                    name_lower = cookie.name.lower()

                    # Skip known tracking cookies
                    if any(name_lower.startswith(t) for t in tracking_names):
                        continue

                    # Check if it looks like a session cookie
                    if any(s_name in name_lower for s_name in session_names):
                        if cookie.name in seen_cookie_names:
                            continue
                        seen_cookie_names.add(cookie.name)

                        issues = []

                        # Double-submit CSRF/XSRF cookies are intentionally
                        # readable by JavaScript — "missing HttpOnly" on them is
                        # by design (Angular XSRF-TOKEN, Django csrftoken), not a
                        # flaw, so don't raise it for those.
                        is_csrf_cookie = "csrf" in name_lower or "xsrf" in name_lower
                        if not cookie.has_nonstandard_attr('HttpOnly') and not is_csrf_cookie:
                            issues.append("Missing HttpOnly")

                        if not cookie.secure and endpoint.startswith('https'):
                            issues.append("Missing Secure")

                        samesite = cookie.get_nonstandard_attr('SameSite')
                        if not samesite:
                            issues.append("Missing SameSite")

                        if issues:
                            # Redact the actual token value — it's a live
                            # credential and shouldn't be persisted verbatim
                            # into JSON/Markdown report output.
                            value = cookie.value or ""
                            redacted = (value[:4] + "…" + value[-4:]) if len(value) > 10 else "(short value)"
                            self.db.add(
                                title=f"Broken Auth — Insecure Session Cookie ({cookie.name})",
                                severity="high", url=endpoint, module=self.NAME,
                                description=(
                                    f"The session cookie '{cookie.name}' has security flaws: {', '.join(issues)}. "
                                    "This increases the risk of XSS-based theft and CSRF."
                                ),
                                remediation="Set HttpOnly, Secure, and SameSite=Lax (or Strict) attributes on all session cookies.",
                                cvss="5.3",
                                confidence="HIGH",
                                confidence_score=85,
                                validation_steps=["cookie_analyzed", "flags_missing"],
                                evidence=[f"Cookie: {cookie.name}={redacted}", f"Missing: {', '.join(issues)}"]
                            )
                            self.ui.find("high", f"Insecure Session Cookie: {cookie.name}", endpoint)
                            found += 1
            except Exception:
                pass

        # Session token quality — a check that's entirely NEW information,
        # not overlapping with the flag-presence checks above (HttpOnly/
        # Secure/SameSite say nothing about whether the token VALUE itself
        # is any good; a perfectly-flagged cookie holding a 6-digit
        # sequential counter is still trivially guessable).
        if self._test_token_quality(s):
            found += 1

        if found == 0:
            self.ui.info("No session security issues detected.")

    def _test_token_quality(self, _unused_session) -> bool:
        """
        Fetch base_url with N fully independent (fresh cookie jar) sessions
        and compare the session-cookie VALUES issued each time — catches a
        static/shared token (zero session isolation between different
        clients) or a low-entropy/predictable one (short, purely numeric,
        or sequential across samples). Deliberately uses a brand-new
        session per sample rather than reusing one — a persistent session
        only gets a fresh Set-Cookie on its first request in general, so
        sampling through one shared jar would just see the SAME token
        reused, telling us nothing about how the server generates them for
        genuinely different clients.
        """
        samples = []
        for _ in range(3):
            fresh = self._session()
            try:
                resp = fresh.get(self.base_url, timeout=self.timeout)
            except Exception:
                continue
            for cookie in resp.cookies:
                if any(sn in cookie.name.lower() for sn in SESSION_COOKIE_NAMES) and cookie.value:
                    samples.append((cookie.name, cookie.value))
                    break  # one session-shaped cookie per fresh client is enough
            time.sleep(self.delay)

        if len(samples) < 2:
            return False

        name = samples[0][0]
        values = [v for _, v in samples]

        if len(set(values)) == 1:
            self.db.add(
                title=f"Broken Auth — Static/Shared Session Token ({name})",
                severity="critical", url=self.base_url, module=self.NAME,
                description=(
                    f"{len(samples)} independent, unauthenticated clients (separate cookie jars, "
                    f"no shared state) all received the IDENTICAL session cookie value for "
                    f"'{name}'. Sessions aren't being isolated per-client at all — anyone can "
                    "hijack any other user's session simply by using this same static token, "
                    "no theft required."
                ),
                remediation="Generate a fresh, cryptographically random session identifier for every new session — never issue the same token to different clients.",
                cvss="9.8", confidence="CONFIRMED", confidence_score=95,
                validation_steps=["multiple_independent_clients_sampled", "identical_token_issued_to_all"],
                evidence=[f"Sample values: {values}"],
            )
            self.ui.find("critical", f"Static/shared session token: {name}", self.base_url)
            return True

        shortest = min(len(v) for v in values)
        all_numeric = all(v.isdigit() for v in values)
        looks_sequential = False
        if all_numeric:
            try:
                nums = sorted(int(v) for v in values)
                diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
                looks_sequential = bool(diffs) and all(0 < d <= 1000 for d in diffs)
            except (ValueError, OverflowError):
                pass

        if shortest < 16 or all_numeric or looks_sequential:
            reasons = []
            if shortest < 16:
                reasons.append(f"short length ({shortest} chars — recommend 128+ bits of entropy, "
                                "e.g. 22+ base64 chars or 32+ hex chars)")
            if all_numeric:
                reasons.append("purely numeric (a tiny fraction of the character-set entropy a "
                                "random alphanumeric/base64 token would have)")
            if looks_sequential:
                reasons.append("values increase sequentially/near-sequentially across independent "
                                "samples — highly predictable")

            self.db.add(
                title=f"Broken Auth — Weak/Predictable Session Token ({name})",
                severity="high", url=self.base_url, module=self.NAME,
                description=(
                    f"Session token '{name}' shows signs of weak entropy across "
                    f"{len(samples)} independent samples: {'; '.join(reasons)}. A predictable "
                    "or low-entropy token can be brute-forced or guessed outright, enabling "
                    "session hijacking without ever needing to steal a real token."
                ),
                remediation="Generate session tokens with a CSPRNG and at least 128 bits of entropy (32+ random bytes, base64/hex encoded) — never sequential counters or short/numeric values.",
                cvss="8.1", confidence="MEDIUM", confidence_score=65,
                validation_steps=["multiple_independent_clients_sampled", "entropy_heuristics_failed"],
                evidence=[f"Sample values: {values}"],
            )
            self.ui.find("high", f"Weak/predictable session token: {name}", self.base_url)
            return True

        return False
