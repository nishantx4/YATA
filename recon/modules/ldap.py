"""
LDAPInjectionModule — LDAP filter injection.

Login forms and directory-search features that build an LDAP filter from user
input (`(uid=<input>)`) are vulnerable when the input isn't escaped. Proving
it the near-zero-false-positive way means never relying on a reflected string:

  1. ERROR SIGNATURE — inject filter-breaking metacharacters and confirm an
     LDAP-engine error surfaces that is NOT present in the clean baseline
     (e.g. `javax.naming.directory`, `Bad search filter`, `Invalid DN
     syntax`, `ldap_search`). The directory server's own parser complaining
     about our broken filter is direct proof the input reaches it.
  2. BOOLEAN DIFFERENTIAL — an always-true filter wildcard (`*`) vs an
     always-false one yields two structurally different, reproducible
     responses, the same differential discipline the SQLi/NoSQL modules use.

Nothing is reported unless the signal reproduces on a re-probe.
"""
import re
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.core.validator import Validator
from recon.modules import BaseModule
from recon.core import cancellation

# LDAP engine / library error fingerprints (absent from a normal page).
LDAP_ERRORS = [
    "javax.naming.directory", "javax.naming.namingexception", "com.sun.jndi.ldap",
    "ldapexception", "invalid dn syntax", "bad search filter", "ldap_search",
    "supplied argument is not a valid ldap", "ldap: error code", "protocol error",
    "invalid attribute syntax", "unbalanced parenthesis", "sizelimit exceeded",
    "distinguishedname", "ldap_bind", "ldap_modify", "search filter",
]

# Filter-breaking probes. The first few are designed to raise a parser error;
# the TRUE/FALSE pair drives a boolean differential.
ERROR_PROBES = ["*)(", ")(cn=*", "*()|%26'", "*)(uid=*))(|(uid=*", "admin)(&)",
                "\\", "*))%00"]
TRUE_PROBE = "*"
FALSE_PROBE = ")(!(objectclass=*))"

PARAM_HINTS = ["user", "username", "uid", "login", "name", "cn", "search", "q",
               "query", "email", "mail", "account", "dn", "group", "filter", "id"]


class LDAPInjectionModule(BaseModule):
    NAME = "LDAP Injection"
    MODULE_ID = "ldap"
    MODULE_LABEL = "LDAP Injection"

    MAX_POINTS = 25

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=6, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self.validator = Validator(baseline=self.ctx.get("baseline_profile"), ai=self.ai, ui=self.ui)
        self._found = 0

    def run(self):
        self.ui.section("LDAP Injection — Directory Filter Injection")
        if not requests:
            return
        points = self._collect()
        if not points:
            self.ui.info("No candidate directory/search parameters found — skipping.")
            return
        self.ui.info(f"Testing {len(points)} parameter(s) for LDAP filter injection.")
        for pt in points:
            if cancellation.is_cancelled():
                break
            try:
                self._test(pt)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"ldap error: {e}")
        if self._found == 0:
            self.ui.info("No LDAP injection detected.")
        else:
            self.ui.ok(f"LDAP injection scan complete — {self._found} finding(s).")

    def _collect(self):
        points, seen = [], set()

        def add(url, method, param, ptype, others):
            key = (url.split("#", 1)[0], param, ptype)
            if key in seen or len(points) >= self.MAX_POINTS:
                return
            seen.add(key)
            points.append({"url": url, "method": method, "param": param,
                           "ptype": ptype, "others": others})

        for ep in self.ctx.get("endpoints", []):
            try:
                parsed = urllib.parse.urlparse(ep)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in qs:
                if any(h in param.lower() for h in PARAM_HINTS):
                    add(base, "GET", param, "query", {k: v[0] for k, v in qs.items() if k != param})

        for form in self.ctx.get("forms", []):
            url = form.get("action") or self.base_url
            method = (form.get("method") or "POST").upper()
            inputs = form.get("inputs", {})
            for name in inputs:
                if any(h in name.lower() for h in PARAM_HINTS):
                    add(url, method, name, "form", {k: (v or "x") for k, v in inputs.items() if k != name})
        return points

    def _send(self, pt, value):
        self._throttle()
        headers, cookies = self.auth_headers(), self.auth_cookies()
        try:
            if pt["ptype"] == "query":
                params = {**pt["others"], pt["param"]: value}
                return self.session.get(pt["url"], params=params, timeout=self.timeout,
                                        headers=headers, cookies=cookies)
            data = {**pt["others"], pt["param"]: value}
            return self.session.request(pt["method"], pt["url"], data=data, timeout=self.timeout,
                                        headers=headers, cookies=cookies)
        except RequestException:
            return None

    @staticmethod
    def _errors_in(body):
        low = (body or "").lower()
        return [e for e in LDAP_ERRORS if e in low]

    def _test(self, pt):
        base_resp = self._send(pt, "yata-recon")
        if base_resp is None:
            return
        base_body = base_resp.text or ""
        base_errs = set(self._errors_in(base_body))

        # 1) Error-signature probes.
        for probe in ERROR_PROBES:
            if cancellation.is_cancelled():
                return
            r = self._send(pt, probe)
            if r is None:
                continue
            new_errs = set(self._errors_in(r.text or "")) - base_errs
            if new_errs:
                confirm = self._send(pt, probe)
                if confirm is not None and (set(self._errors_in(confirm.text or "")) - base_errs):
                    self._report(pt, probe, "LDAP engine error", list(new_errs), 93)
                    return

        # 2) Boolean differential (true wildcard vs always-false filter).
        r_true = self._send(pt, TRUE_PROBE)
        r_false = self._send(pt, FALSE_PROBE)
        if r_true is None or r_false is None:
            return
        if r_true.status_code != r_false.status_code:
            diff_signal = True
        else:
            h_true = self.validator._structural_hash(r_true.text or "")
            h_false = self.validator._structural_hash(r_false.text or "")
            h_base = self.validator._structural_hash(base_body)
            # True (*) should look like the baseline-ish "matches"; false should differ.
            diff_signal = (h_true != h_false) and (abs(len(r_true.text or "") - len(r_false.text or "")) > 40)
        if diff_signal:
            # Reproduce.
            r_true2 = self._send(pt, TRUE_PROBE)
            r_false2 = self._send(pt, FALSE_PROBE)
            if r_true2 is None or r_false2 is None:
                return
            same_dir = (r_true2.status_code != r_false2.status_code) or \
                       (self.validator._structural_hash(r_true2.text or "") !=
                        self.validator._structural_hash(r_false2.text or ""))
            if same_dir:
                self._report(pt, f"{TRUE_PROBE} vs {FALSE_PROBE}", "boolean filter differential", [], 85)

    def _report(self, pt, payload, technique, errs, score):
        url = pt["url"]
        loc = "GET parameter" if pt["ptype"] == "query" else "form field"
        conf = "CONFIRMED" if score >= 90 else "HIGH"
        added = self.db.add(
            title=f"LDAP Injection ({technique}) in '{pt['param']}' {loc}",
            severity="high", url=url, module=self.NAME,
            description=(
                f"The '{pt['param']}' {loc} on {url} is vulnerable to LDAP filter injection "
                f"({technique}). " +
                (f"Filter-breaking input produced LDAP-engine errors ({', '.join(errs)}) absent from "
                 "the baseline, " if errs else
                 "An always-true filter wildcard and an always-false filter produced reproducibly "
                 "different responses, ") +
                "proving user input is concatenated into an LDAP search filter without escaping. An "
                "attacker can bypass authentication, enumerate directory entries, or read attributes "
                "they should not see."
            ),
            remediation=(
                "Escape all user input used in LDAP filters/DNs per RFC 4515 (encode * ( ) \\ NUL), "
                "prefer a vetted LDAP library's parameterized filter builder, and validate inputs "
                "against a strict allow-list."
            ),
            cvss="8.6", confidence=conf, confidence_score=score,
            validation_steps=(["ldap_error_signature", "reproduced"] if errs
                              else ["boolean_filter_differential", "reproduced"]),
            evidence=[f"Technique: {technique}", f"Payload: {payload}"] +
                     ([f"Errors: {', '.join(errs)}"] if errs else []),
            references=[
                "https://owasp.org/www-community/attacks/LDAP_Injection",
                "https://portswigger.net/web-security/ldap-injection",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("high", f"LDAP injection via '{pt['param']}'", url)
            self.ui.bullet(f"{loc}: {pt['param']}  |  {technique}", indent=12)
