"""
XPathInjectionModule — XPath / XQuery injection.

Apps that query an XML document or database with an XPath expression built
from user input (`//user[name='<input>']`) are injectable when input isn't
escaped. Same near-zero-false-positive discipline as the LDAP module —
never a reflected string, only proof the expression engine processed broken
input:

  1. ERROR SIGNATURE — a quote/bracket-breaking payload elicits an XPath
     engine error absent from the baseline (`XPathException`, `Invalid XPath`,
     `unterminated string`, `System.Xml.XPath`, `xmlXPathEval`, …).
  2. BOOLEAN DIFFERENTIAL — `' or '1'='1` (always true) vs `' and '1'='2`
     (always false) produce two reproducibly different responses.

Both must reproduce on a re-probe before anything is reported.
"""
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.core.validator import Validator
from recon.modules import BaseModule
from recon.core import cancellation

XPATH_ERRORS = [
    "xpathexception", "org.apache.xpath", "javax.xml.xpath", "system.xml.xpath",
    "ms.internal.xml", "xmlxpatheval", "invalid xpath", "invalid expression",
    "unterminated string", "expression must evaluate to a node-set",
    "xpath_eval", "simplexpathengine", "xpath error", "sablotron",
    "libxml2", "warning: xpath", "a closing quotation", "nodeset expected",
]

ERROR_PROBES = ["'", "\"", "']", "')", "' or ", "1' or '1'='1", "|//*", "') or ('1'='1"]
TRUE_PROBE = "' or '1'='1"
FALSE_PROBE = "' and '1'='2"

PARAM_HINTS = ["user", "username", "name", "search", "q", "query", "id", "item",
               "node", "path", "xml", "doc", "file", "lang", "category", "filter",
               "role", "key", "value", "login", "email"]


class XPathInjectionModule(BaseModule):
    NAME = "XPath Injection"
    MODULE_ID = "xpath"
    MODULE_LABEL = "XPath / XQuery Injection"

    MAX_POINTS = 25

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=6, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self.validator = Validator(baseline=self.ctx.get("baseline_profile"), ai=self.ai, ui=self.ui)
        self._found = 0

    def run(self):
        self.ui.section("XPath Injection — XML Query Injection")
        if not requests:
            return
        points = self._collect()
        if not points:
            self.ui.info("No candidate parameters for XPath injection — skipping.")
            return
        self.ui.info(f"Testing {len(points)} parameter(s) for XPath injection.")
        for pt in points:
            if cancellation.is_cancelled():
                break
            try:
                self._test(pt)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"xpath error: {e}")
        if self._found == 0:
            self.ui.info("No XPath injection detected.")
        else:
            self.ui.ok(f"XPath injection scan complete — {self._found} finding(s).")

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
        return [e for e in XPATH_ERRORS if e in low]

    def _test(self, pt):
        base_resp = self._send(pt, "yata-recon")
        if base_resp is None:
            return
        base_body = base_resp.text or ""
        base_errs = set(self._errors_in(base_body))

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
                    self._report(pt, probe, "XPath engine error", list(new_errs), 93)
                    return

        r_true = self._send(pt, TRUE_PROBE)
        r_false = self._send(pt, FALSE_PROBE)
        if r_true is None or r_false is None:
            return
        if r_true.status_code != r_false.status_code:
            diff = True
        else:
            h_true = self.validator._structural_hash(r_true.text or "")
            h_false = self.validator._structural_hash(r_false.text or "")
            diff = (h_true != h_false) and (abs(len(r_true.text or "") - len(r_false.text or "")) > 40)
        if diff:
            r_true2 = self._send(pt, TRUE_PROBE)
            r_false2 = self._send(pt, FALSE_PROBE)
            if r_true2 is None or r_false2 is None:
                return
            repro = (r_true2.status_code != r_false2.status_code) or \
                    (self.validator._structural_hash(r_true2.text or "") !=
                     self.validator._structural_hash(r_false2.text or ""))
            if repro:
                self._report(pt, f"{TRUE_PROBE} vs {FALSE_PROBE}", "boolean differential", [], 85)

    def _report(self, pt, payload, technique, errs, score):
        url = pt["url"]
        loc = "GET parameter" if pt["ptype"] == "query" else "form field"
        conf = "CONFIRMED" if score >= 90 else "HIGH"
        added = self.db.add(
            title=f"XPath Injection ({technique}) in '{pt['param']}' {loc}",
            severity="high", url=url, module=self.NAME,
            description=(
                f"The '{pt['param']}' {loc} on {url} is vulnerable to XPath injection ({technique}). " +
                (f"A quote/bracket-breaking payload produced XPath-engine errors ({', '.join(errs)}) "
                 "absent from the baseline, " if errs else
                 "An always-true and an always-false XPath condition produced reproducibly different "
                 "responses, ") +
                "proving user input is concatenated into an XPath/XQuery expression without escaping. "
                "An attacker can bypass authentication checks or extract the entire backing XML "
                "document (which often holds credentials or other users' records)."
            ),
            remediation=(
                "Use parameterized/precompiled XPath with variable binding (e.g. XPathExpression with "
                "an XPathVariableResolver, or XQuery external variables) instead of string "
                "concatenation, and validate/escape input against a strict allow-list."
            ),
            cvss="8.2", confidence=conf, confidence_score=score,
            validation_steps=(["xpath_error_signature", "reproduced"] if errs
                              else ["boolean_differential", "reproduced"]),
            evidence=[f"Technique: {technique}", f"Payload: {payload}"] +
                     ([f"Errors: {', '.join(errs)}"] if errs else []),
            references=[
                "https://owasp.org/www-community/attacks/XPATH_Injection",
                "https://portswigger.net/web-security/xpath-injection",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("high", f"XPath injection via '{pt['param']}'", url)
            self.ui.bullet(f"{loc}: {pt['param']}  |  {technique}", indent=12)
