"""
OpenRedirectModule — YATA RECON module.
Detects unvalidated redirect/forward vulnerabilities.
"""
import re
import time
import uuid
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


def _with_param(endpoint: str, param: str, value: str) -> str:
    """Return `endpoint` with `param` set to `value`, REPLACING any existing
    occurrence and preserving the other query params (value is URL-encoded).

    Two bugs this fixes versus the old `f"{endpoint}?{param}=..."`:
      * endpoints that already carry a query string (/go?url=/home — exactly
        what recon seeds from a page's own redirect links) became malformed
        double-'?' URLs; and
      * naively appending `&url=<payload>` leaves the ORIGINAL url=/home in
        place, so on a server that honours the first occurrence the payload
        never takes effect and a real open redirect is missed. Replacing the
        param is correct regardless of first-wins/last-wins precedence."""
    parsed = urllib.parse.urlparse(endpoint)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_q = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_q))


class OpenRedirectModule(BaseModule):
    NAME = "Open Redirect"

    REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "goto", "dest",
        "redirect_uri", "return_to", "continue", "target", "rurl",
        "returnUrl", "forward", "follow", "redirect_url", "return_url",
        "checkout_url", "login_url", "image_url", "success_url",
    ]

    CANARY_URLS = [
        "//yata-recon-redirect-test.example.com",
        "https://yata-recon-redirect-test.example.com",
        "/\\yata-recon-redirect-test.example.com",
        "//yata-recon-redirect-test.example.com%2f%2f",
        # {target} as fake userinfo, canary as the real authority — a naive
        # "starts with / contains our domain" whitelist check passes this,
        # but the browser navigates to the canary. (Previously had this
        # backwards — canary-as-userinfo/target-as-host — which resolves to
        # the *legitimate* target and can never trigger a canary match.)
        "https://{target}@yata-recon-redirect-test.example.com",
        "////yata-recon-redirect-test.example.com",
        "https:yata-recon-redirect-test.example.com",
    ]

    canary_domain = "yata-recon-redirect-test.example.com"

    def _redirects_to_canary(self, request_url, location):
        """True only if following `location` from `request_url` actually lands
        the browser on the canary HOST — not merely that the canary string
        appears somewhere in the Location value.

        The old `canary_domain in location` substring test fired on the
        extremely common case of a server that redirects to ITSELF while
        echoing the untouched (often URL-encoded) parameter in the new query
        string, e.g.
            Location: https://site/path?next=%2F%2Fyata-recon-...example.com
        The user ends up on `site`, not the canary — that is not an open
        redirect. Resolving the Location (relative Locations included) and
        comparing the resulting host is what distinguishes a real redirect to
        the attacker domain from a self-redirect that carries the payload."""
        if not location:
            return False
        # Browsers treat backslashes in the authority as forward slashes;
        # normalize so `/\canary` and friends resolve the way a browser would.
        loc = location.strip().replace("\\", "/")
        try:
            dest = urllib.parse.urljoin(request_url, loc)
            host = (urllib.parse.urlparse(dest).hostname or "").lower()
        except Exception:
            return False
        cd = self.canary_domain.lower()
        return host == cd or host.endswith("." + cd)

    def run(self):
        self.ui.section("Open Redirect — Unvalidated Redirect Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        self._found_lock = threading.Lock()
        self._found = 0

        # Deduplicated (endpoint, param) worklist — real params already in a
        # URL's query string plus the common redirect-param name list, keyed
        # by (path, param) so the same pair isn't tested twice via two seeds.
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]
        seen, worklist = set(), []
        for endpoint in endpoints:
            path_key = endpoint.split("#", 1)[0].split("?", 1)[0]
            try:
                url_params = list(urllib.parse.parse_qs(urllib.parse.urlparse(endpoint).query).keys())
            except Exception:
                url_params = []
            for param in url_params + self.REDIRECT_PARAMS:
                key = (path_key, param)
                if key in seen:
                    continue
                seen.add(key)
                worklist.append((endpoint, param))

        self.ui.info(
            f"Testing {len(worklist)} (endpoint, param) pair(s) for open redirect "
            f"(liveness-filtered, {self.threads} workers)"
        )

        # Parallelized: the previous version was a strictly serial
        # endpoints x params x payloads matrix (~4000 requests, each paced by
        # time.sleep(delay)), which alone could take half an hour. A per-pair
        # liveness pre-filter (one probe; skip params that don't influence the
        # redirect/response at all) plus a worker pool over the global
        # adaptive throttle collapses that dramatically without losing recall.
        with ThreadPoolExecutor(max_workers=max(1, self.threads)) as ex:
            futures = [ex.submit(self._test_param, s, ep, param) for ep, param in worklist]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"Open-redirect thread error: {e}")

        self._found += self._test_json_bodies(s, self.canary_domain, self._found)

        if self._found == 0:
            self.ui.info("No open redirect vulnerabilities detected.")

    def _test_param(self, s, endpoint, param):
        """Liveness-gate one (endpoint, param), then run the bypass canary set
        only if the param actually influences the redirect/response."""
        # Liveness probe: a benign token. If it isn't reflected in the body,
        # doesn't appear in a Location header, and the response isn't itself a
        # redirect, this param has no bearing on where the app sends the user —
        # testing the bypass payloads against it is wasted work. (We DON'T
        # require the token to be validated-and-accepted — that would skip
        # exactly the flawed-validator case open-redirect testing exists to
        # catch; mere influence on the response is enough to proceed.)
        token = "yata-reconlive" + uuid.uuid4().hex[:8]
        self._throttle()
        try:
            probe = s.get(_with_param(endpoint, param, token), timeout=self.timeout, allow_redirects=False)
        except Exception:
            return
        loc = probe.headers.get("Location", "")
        live = (token in loc) or (token in (probe.text or "")) or (300 <= probe.status_code < 400)
        if not live:
            return

        for canary_url in self.CANARY_URLS:
            test_url = canary_url.replace("{target}", self.target)
            full_url = _with_param(endpoint, param, test_url)
            self._throttle()
            try:
                resp = s.get(full_url, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            location = resp.headers.get("Location", "")

            # Server-side redirect straight to our canary authority.
            if self._redirects_to_canary(full_url, location):
                self._report(
                    endpoint, f"Open Redirect via '{param}' Parameter", "medium", "CONFIRMED", 95,
                    f"Parameter '{param}' allows unvalidated redirects. Injected URL '{test_url}' "
                    f"caused redirect to: {location}. This enables phishing, OAuth token theft, and "
                    "SSO bypass attacks.",
                    ["canary_in_location_header"], [f"Location: {location}", f"Payload: {test_url}"],
                    f"Open Redirect via '{param}'",
                )
                return

            # SPA/JS-driven redirect: no Location header, but the exact canary
            # is reflected right next to a client-side redirect sink.
            if not location and resp.status_code == 200 and test_url in (resp.text or ""):
                sink = self._check_js_redirect_sink(resp.text, test_url)
                if sink:
                    self._report(
                        endpoint, f"Open Redirect (Client-Side) via '{param}' Parameter", "medium", "MEDIUM", 65,
                        f"Parameter '{param}' is reflected directly next to a client-side redirect sink "
                        f"({sink}) in the page's own JavaScript. The browser never sees this in a network "
                        "response — it's assigned to location/window.location by the page's own script — "
                        "but the phishing/SSO-bypass impact is the same.",
                        ["canary_reflected_in_body", "js_redirect_sink_nearby"],
                        [f"Sink: {sink}", f"Payload: {test_url}"],
                        f"Open Redirect (client-side) via '{param}'",
                    )
                    return

    def _report(self, url, title, severity, confidence, score, description, steps, evidence, find_label):
        added = self.db.add(
            title=title, severity=severity, url=url, module=self.NAME,
            description=description,
            remediation=(
                "Validate redirect targets against a whitelist of allowed domains. "
                "Use relative paths only, or maintain a mapping of allowed redirect keys."
            ),
            cvss="6.1", confidence=confidence, confidence_score=score,
            validation_steps=steps, evidence=evidence,
        )
        if added:
            with self._found_lock:
                self._found += 1
            self.ui.find(severity, find_label, url)

    def _test_json_bodies(self, s, canary_domain, already_found):
        """
        OAuth-style redirect_uri / callback params are commonly delivered as
        JSON body properties on API-first targets, not query strings — check
        those too using ctx['api_endpoints'] from an OpenAPI/Swagger spec.
        """
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})
        redirect_hints = [p.lower() for p in self.REDIRECT_PARAMS]

        for ep in self.ctx.get("api_endpoints", []):
            method = ep.get("method", "POST")
            if method not in ("POST", "PUT", "PATCH"):
                continue
            json_props = ep.get("json_props", [])
            candidates = [p for p in json_props if any(h in p.lower() for h in redirect_hints)]
            if not candidates:
                continue

            headers = dict(auth_headers)
            for name, example in ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            for prop in candidates:
                for canary_url in self.CANARY_URLS:
                    test_url = canary_url.replace("{target}", self.target)
                    body = {p: "test" for p in json_props if p != prop}
                    body[prop] = test_url
                    try:
                        resp = s.request(method, ep["url"], json=body, timeout=self.timeout,
                                          headers=headers, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if self._redirects_to_canary(ep["url"], location):
                            self.db.add(
                                title=f"Open Redirect via '{prop}' JSON Body Property",
                                severity="medium", url=ep["url"], module=self.NAME,
                                description=(
                                    f"JSON body property '{prop}' allows unvalidated redirects. "
                                    f"Injected URL '{test_url}' caused redirect to: {location}. "
                                    "This enables phishing, OAuth token theft, and SSO bypass attacks."
                                ),
                                remediation=(
                                    "Validate redirect targets against a whitelist of allowed domains."
                                ),
                                cvss="6.1", confidence="CONFIRMED", confidence_score=95,
                                validation_steps=["canary_in_location_header"],
                                evidence=[f"Location: {location}", f"Payload: {test_url}"],
                            )
                            self.ui.find("medium", f"Open Redirect via '{prop}' (JSON)", ep["url"])
                            found += 1
                            break
                        time.sleep(self.delay)
                    except Exception:
                        continue
                if found + already_found > 10:
                    return found
        return found

    def _check_js_redirect_sink(self, body, test_url):
        """Return a short description if `test_url` appears within a few
        characters of a common client-side redirect sink, else None. A
        proximity check (not just 'both exist somewhere on the page') is
        what distinguishes 'this value feeds a redirect' from 'this value
        is reflected literally anywhere on an entire multi-KB page'."""
        idx = body.find(test_url)
        if idx == -1:
            return None
        window = body[max(0, idx - 150):idx + 150]
        # Only genuine navigation sinks. A bare `.assign(` matched the
        # ubiquitous `Object.assign(` in every bundled app and flooded the
        # report; scope it to `location.assign(`. `window.open()` opens a tab,
        # it isn't a redirect, so it's dropped from the redirect check.
        sinks = [
            (r'location\s*\.\s*href\s*=', "location.href assignment"),
            (r'location\s*\.\s*replace\s*\(', "location.replace()"),
            (r'(?:window|document|top|self)\s*\.\s*location\s*=', "window.location assignment"),
            (r'\blocation\s*\.\s*assign\s*\(', "location.assign()"),
            (r'\blocation\s*=\s*', "location assignment"),
        ]
        for pattern, label in sinks:
            if re.search(pattern, window, re.IGNORECASE):
                return label
        return None
