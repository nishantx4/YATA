"""
HPPModule — HTTP Parameter Pollution.

Sending the same parameter twice (`?p=a&p=b`) is resolved differently by
different stacks — first wins (PHP/Apache), last wins (ASP.NET/Express),
both concatenated (some frameworks), or array. On its own that's a quirk, not
a vulnerability, so this module is careful about what it claims:

  * PARSING BEHAVIOR (low-signal) — reported only when BOTH polluted values
    are provably observable in the response, so the stack's duplicate-handling
    is a fact, not a guess. Low confidence by design; it's reconnaissance
    context that surfaces only when you lower --confidence.
  * FILTER BYPASS VIA POLLUTION (the real bug) — when a canary value is
    rejected/sanitized on its own but reaches the response intact once smuggled
    alongside a benign duplicate, an input filter/WAF keys on the wrong
    occurrence. That's security-relevant, so it's reported at MEDIUM — and only
    after the bypass reproduces on a second request.

No payloads beyond an inert reflection canary are used, so the module can
never itself cause injection side effects.
"""
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule
from recon.core import markers, cancellation

# An inert canary: angle brackets + quote are what naive input filters strip
# or block, but it executes nothing.
def _canary():
    m = markers.marker("hpp")
    return f"<{m}>'\""


class HPPModule(BaseModule):
    NAME = "HTTP Parameter Pollution"
    MODULE_ID = "hpp"
    MODULE_LABEL = "HTTP Parameter Pollution"

    MAX_POINTS = 20

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=6, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self._found = 0

    def run(self):
        self.ui.section("HTTP Parameter Pollution — Duplicate-Parameter Handling & Filter Bypass")
        if not requests:
            return
        points = self._collect()
        if not points:
            self.ui.info("No parameterized endpoints to test for HPP — skipping.")
            return
        self.ui.info(f"Testing {len(points)} parameter(s) for pollution behavior and filter bypass.")
        for pt in points:
            if cancellation.is_cancelled():
                break
            try:
                self._test(pt)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"hpp error: {e}")
        if self._found == 0:
            self.ui.info("No notable parameter-pollution behavior confirmed.")
        else:
            self.ui.ok(f"HPP scan complete — {self._found} finding(s).")

    def _collect(self):
        points, seen = [], set()
        for ep in self.ctx.get("endpoints", []):
            try:
                parsed = urllib.parse.urlparse(ep)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue
            if not qs:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in qs:
                key = (base, param)
                if key in seen or len(points) >= self.MAX_POINTS:
                    continue
                seen.add(key)
                others = {k: v[0] for k, v in qs.items() if k != param}
                points.append({"base": base, "param": param, "others": others})
        return points

    def _raw_get(self, base, query_pairs, headers=None):
        """GET with an explicitly ordered/duplicated query string (requests'
        dict params can't express duplicate keys, so build it by hand)."""
        qs = urllib.parse.urlencode(query_pairs)
        url = base + ("?" + qs if qs else "")
        try:
            self._throttle()
            return self.session.get(url, timeout=self.timeout, headers=headers or self.auth_headers(),
                                    cookies=self.auth_cookies(), allow_redirects=False)
        except RequestException:
            return None

    def _test(self, pt):
        base, param = pt["base"], pt["param"]
        others = list(pt["others"].items())
        va, vb = markers.marker("hppa"), markers.marker("hppb")

        # Baseline single-value responses to learn reflection.
        r_a = self._raw_get(base, others + [(param, va)])
        r_b = self._raw_get(base, others + [(param, vb)])
        if r_a is None or r_b is None:
            return
        a_reflects = va in (r_a.text or "")
        b_reflects = vb in (r_b.text or "")

        # Polluted request p=va&p=vb.
        r_dup = self._raw_get(base, others + [(param, va), (param, vb)])
        if r_dup is None:
            return
        dup_body = r_dup.text or ""
        dup_a, dup_b = va in dup_body, vb in dup_body

        # ── Parsing behavior (only when something reflects → provable) ──
        if a_reflects or b_reflects:
            behavior = None
            if dup_a and dup_b:
                behavior = "both values (concatenated/array)"
            elif dup_a and not dup_b:
                behavior = "first value wins"
            elif dup_b and not dup_a:
                behavior = "last value wins"
            if behavior:
                self._report_behavior(base, param, behavior, va, vb)

        # ── Filter bypass via pollution ──
        self._test_filter_bypass(base, param, others)

    def _test_filter_bypass(self, base, param, others):
        canary = _canary()
        single = self._raw_get(base, others + [(param, canary)])
        if single is None:
            return
        single_reflects_raw = canary in (single.text or "")
        single_blocked = single.status_code in (403, 406, 419, 429) or single.status_code >= 500
        # Only interesting if the canary alone is NOT passed through cleanly
        # (blocked or stripped/encoded).
        if single_reflects_raw and not single_blocked:
            return

        polluted = self._raw_get(base, others + [(param, "safe"), (param, canary)])
        if polluted is None:
            return
        if canary in (polluted.text or "") and polluted.status_code < 400:
            # Reproduce before reporting.
            confirm = self._raw_get(base, others + [(param, "safe"), (param, canary)])
            if confirm is not None and canary in (confirm.text or "") and confirm.status_code < 400:
                self._report_bypass(base, param, single, polluted)

    def _report_behavior(self, base, param, behavior, va, vb):
        added = self.db.add(
            title=f"HTTP Parameter Pollution — '{param}' parsed as {behavior.split(' (')[0]}",
            severity="low", url=f"{base}?{param}=...", module=self.NAME,
            description=(
                f"When '{param}' is supplied twice, this stack resolves it as: {behavior} "
                f"(confirmed by reflecting unique markers). On its own this is informational, but it "
                "matters wherever one tier validates a different occurrence of the parameter than the "
                "tier that uses it (filter/WAF bypass, cache-key confusion, inconsistent "
                "authorization)."
            ),
            remediation=("Canonicalize duplicate parameters consistently across every tier (proxy, "
                         "framework, application) and reject unexpected duplicates on security-relevant "
                         "parameters."),
            cvss="3.1", confidence="MEDIUM", confidence_score=40,
            validation_steps=["both_markers_injected", "duplicate_handling_observed_in_response"],
            evidence=[f"Parameter: {param}", f"Resolution: {behavior}"],
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"],
        )
        if added:
            self._found += 1
            self.ui.find("low", f"HPP ({behavior.split(' (')[0]}) on '{param}'", base)

    def _report_bypass(self, base, param, single, polluted):
        added = self.db.add(
            title=f"Input-Filter Bypass via Parameter Pollution on '{param}'",
            severity="medium", url=f"{base}?{param}=...", module=self.NAME,
            description=(
                f"An inert canary containing filter-triggering characters is blocked/stripped when sent "
                f"as '{param}' alone (status {single.status_code}), but reaches the response intact when "
                f"smuggled as a second occurrence (`{param}=safe&{param}=canary`) — reproduced on a "
                "second request. An input filter or WAF is inspecting a different occurrence of the "
                "parameter than the one the application consumes, so the protection can be bypassed. "
                "Combined with an injection sink this converts directly into XSS/SQLi/etc."
            ),
            remediation=("Normalize duplicate parameters before filtering, and ensure the WAF/filter and "
                         "the application agree on which occurrence is authoritative."),
            cvss="5.3", confidence="HIGH", confidence_score=72,
            validation_steps=["canary_blocked_when_single", "canary_passed_when_polluted", "reproduced"],
            evidence=[f"Parameter: {param}", f"Single-value status: {single.status_code}",
                      f"Polluted status: {polluted.status_code} (canary reflected)"],
            references=["https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution"],
        )
        if added:
            self._found += 1
            self.ui.find("medium", f"Filter bypass via HPP on '{param}'", base)
