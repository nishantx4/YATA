"""
RateLimitModule — YATA RECON module.
Detects missing rate limits on sensitive endpoints.
"""
import re
import time

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


# Matched with non-letter boundaries so `auth` does NOT fire inside `author`
# / `authority` (the /pt/author/<name> blog pages were being tested as auth
# endpoints), `reset` not inside `preset`, `otp` not inside unrelated words.
# oauth / authenticate / authentication are listed explicitly since the
# boundary rules them out as substrings of each other.
_SENSITIVE_RE = re.compile(
    r'(?<![a-z])(login|log-in|signin|sign-in|oauth|auth|authenticate|authentication|'
    r'reset|forgot|otp|verify|verification|2fa|mfa|sso|password|passwd|credential)(?![a-z])',
    re.I,
)


def _is_sensitive(url: str) -> bool:
    return bool(_SENSITIVE_RE.search(url or ""))


class RateLimitModule(BaseModule):
    NAME = "Rate Limit"

    def run(self):
        self.ui.section("Rate Limit / Brute Force Protection Detection")
        if not requests:
            return

        s = self._session()
        found = 0

        # Prefer the real credential-check POST action when we have one —
        # rate limiting is almost universally applied to the endpoint that
        # actually CHECKS a password/OTP, not the GET that merely renders
        # the login page. Testing only the GET page load (the previous
        # behavior) could report "missing rate limiting" on a target whose
        # POST /login IS properly protected, purely because the page load
        # itself was never meant to be rate-limited — a false positive in
        # the "no protection found" direction.
        post_targets = []
        for form in self.ctx.get("forms", []):
            action = form.get("action", "")
            if form.get("method", "GET").upper() == "POST" and _is_sensitive(action):
                post_targets.append((action, dict(form.get("inputs", {}))))

        get_targets = [ep for ep in self.ctx.get("endpoints", []) if _is_sensitive(ep)]

        if not post_targets and not get_targets:
            self.ui.info("No clearly sensitive authentication endpoints found.")
            return

        for action, fields in post_targets[:2]:
            if self._test_endpoint(s, action, method="POST", body=fields):
                found += 1

        for endpoint in get_targets[:3]:
            if self._test_endpoint(s, endpoint, method="GET", body=None):
                found += 1

        if found == 0:
            self.ui.info("No rate limit vulnerabilities detected.")

    def _fire(self, s, url, method, body, headers, count) -> tuple:
        """Send `count` rapid requests. Returns (completed, hit_429)."""
        completed = 0
        hit_429 = False
        for _ in range(count):
            try:
                if method == "POST":
                    resp = s.post(url, data=body, headers=headers, timeout=5)
                else:
                    resp = s.get(url, headers=headers, timeout=5)
                completed += 1
                if resp.status_code == 429:
                    hit_429 = True
                    break
                time.sleep(0.01)  # rapid fire — deliberately not throttled, that's the point of the test
            except Exception:
                continue
        return completed, hit_429

    def _test_endpoint(self, s, url, method, body) -> bool:
        # Phase 1: CLEAN baseline — no spoofed headers at all. This is the
        # only phase that can legitimately conclude "no rate limiting
        # exists" — mixing in an IP-spoofing bypass attempt here (the
        # previous behavior) meant a server that rate-limits correctly by
        # real client IP, but ALSO happens to trust X-Forwarded-For for an
        # unrelated reason, would have every single one of its 30 requests
        # sent under a rotating fake IP, silently defeating its own
        # protection and reporting a false "missing rate limit" finding —
        # the exact opposite of what actually happened.
        completed, hit_429 = self._fire(s, url, method, body, headers={}, count=30)
        # completed is naturally low when hit_429 is True — _fire() breaks
        # out the moment it sees a 429, so a fast, correct positive result
        # (e.g. blocked after 6 requests) must never be rejected by a
        # threshold that assumes "low completed count" means "too many
        # failures." The threshold only matters for judging whether a
        # NEGATIVE result (no 429 at all) is trustworthy.
        if not hit_429 and completed < 20:
            return False  # too many failures to trust a "no rate limit" conclusion

        if not hit_429:
            # Only the POST credential-check surface can conclude "missing rate
            # limiting." A GET that accepts 30 rapid requests is just a page
            # load (a login PAGE renders unlimited times by design) — it is not
            # the brute-force surface, so reporting it is a false positive.
            if method != "POST":
                return False
            self.db.add(
                title="Missing Rate Limiting on Authentication Endpoint",
                severity="high", url=url, module=self.NAME,
                description=(
                    f"The endpoint ({method}) accepted 30 rapid sequential requests, from a "
                    "single unmodified client identity, without ever returning HTTP 429 (Too "
                    "Many Requests) or otherwise blocking. This leaves the application "
                    "vulnerable to brute-force and credential stuffing attacks."
                ),
                remediation="Implement strict rate limiting and account lockout policies for authentication endpoints.",
                cvss="7.5",
                confidence="HIGH",
                confidence_score=85,
                validation_steps=["rapid_requests_accepted_clean", "no_429_returned"],
            )
            self.ui.find("high", f"Missing Rate Limit ({method})", url)
            return True

        # Phase 2: rate limiting clearly exists (Phase 1 hit a 429) — now
        # check whether it can be trivially bypassed by rotating a
        # client-supplied header some proxies/apps mistakenly trust as the
        # real client identity. This is a SEPARATE, more specific finding
        # from "no rate limiting at all," and only makes sense to test once
        # we've confirmed protection is actually there to bypass.
        time.sleep(1)  # let any short rate-limit window reset before the bypass attempt
        bypass_completed = 0
        bypass_hit_429 = False
        for i in range(30):
            headers = {"X-Forwarded-For": f"127.0.0.{i + 1}"}
            try:
                if method == "POST":
                    resp = s.post(url, data=body, headers=headers, timeout=5)
                else:
                    resp = s.get(url, headers=headers, timeout=5)
                bypass_completed += 1
                if resp.status_code == 429:
                    bypass_hit_429 = True
                    break
                time.sleep(0.01)
            except Exception:
                continue

        if bypass_completed >= 20 and not bypass_hit_429:
            self.db.add(
                title="Rate Limiting Bypassable via X-Forwarded-For Spoofing",
                severity="high", url=url, module=self.NAME,
                description=(
                    f"The endpoint ({method}) DOES rate-limit a single client identity (confirmed: "
                    "a clean burst of requests triggered HTTP 429), but rotating the "
                    "X-Forwarded-For header on every request let 30 more requests through with "
                    "no 429 at all. The rate limiter is keying off a client-supplied header "
                    "instead of the actual connection source — trivially bypassable by anyone "
                    "who can set an arbitrary header."
                ),
                remediation="Rate-limit by the real connection-level source IP (or an authenticated session/account identifier), never by a client-controllable header like X-Forwarded-For, unless it's cryptographically set by a trusted, directly-connected proxy.",
                cvss="7.5",
                confidence="HIGH",
                confidence_score=85,
                validation_steps=["clean_burst_triggered_429", "xff_rotated_burst_bypassed_limit"],
            )
            self.ui.find("high", f"Rate limit bypass via X-Forwarded-For ({method})", url)
            return True

        return False
