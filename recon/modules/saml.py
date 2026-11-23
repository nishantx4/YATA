"""
SAMLModule — SAML/SSO security testing.

OAuth and JWT are covered elsewhere; SAML is a distinct, still-common
enterprise SSO protocol with zero coverage before this. Static checks run
on any SAMLRequest/SAMLResponse actually observed during the crawl (query
strings, form fields, both HTTP-POST and HTTP-Redirect bindings). Two live
tests — that don't need a fresh login, just a previously-observed real
assertion — run when one was actually captured:
  - Assertion replay: resubmit the EXACT SAME (byte-identical) SAMLResponse
    a second time; a new session being granted proves there's no
    one-time-use/replay protection.
  - Signature stripping: resubmit the SAMLResponse with its <Signature>
    element removed entirely; acceptance proves the server isn't verifying
    signatures at all — the SAML equivalent of jwt.py's alg:none forgery.
Completing a fresh SSO login to mint a brand-new assertion isn't attempted
(would need real IdP credentials) — same honest scoping as oauth.py's
redirect_uri-only live testing.
"""
import base64
import re
import time
import urllib.parse
import zlib

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


SAML_ENDPOINT_PATHS = [
    "/saml/login", "/saml/sso", "/saml2/idp/SSOService.php", "/saml2/sp/acs",
    "/sso/saml", "/Shibboleth.sso/Login", "/simplesaml/saml2/idp/SSOService.php",
    "/adfs/ls", "/auth/saml/callback", "/login/saml", "/saml/acs",
]
SAML_METADATA_PATHS = [
    "/saml/metadata", "/simplesaml/saml2/idp/metadata.php",
    "/FederationMetadata/2007-06/FederationMetadata.xml", "/saml2/idp/metadata.php",
    "/auth/saml/metadata",
]


class SAMLModule(BaseModule):
    NAME = "SAML/SSO Security"

    def run(self):
        self.ui.section("SAML — SSO Security Testing")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        self._discover_endpoints(s)
        found += self._discover_metadata(s)

        captured = self._find_saml_response()
        if captured:
            xml_str, acs_url, param_name, binding = captured
            self.ui.info(f"Captured a real SAMLResponse/Request from recon — running active tests against {acs_url}")
            found += self._analyze_static(xml_str, acs_url)
            found += self._test_replay(s, acs_url, param_name, binding, xml_str)
            found += self._test_signature_strip(s, acs_url, param_name, binding, xml_str)
        else:
            self.ui.info("No SAMLResponse/Request observed during recon — active bypass tests "
                          "skipped (static endpoint/metadata checks above still ran).")

        if found == 0:
            self.ui.info("No SAML vulnerabilities detected.")

    # ── discovery ────────────────────────────────────────────────────────
    def _discover_endpoints(self, s):
        for path in SAML_ENDPOINT_PATHS:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.get(url, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            if resp.status_code not in (404, 410) and url not in self.ctx.setdefault("endpoints", []):
                self.ctx["endpoints"].append(url)
            time.sleep(self.delay)

    def _discover_metadata(self, s):
        found = 0
        for path in SAML_METADATA_PATHS:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.get(url, timeout=self.timeout)
            except Exception:
                continue
            if resp.status_code == 200 and "EntityDescriptor" in resp.text[:3000]:
                self.db.add(
                    title="SAML Metadata Publicly Accessible",
                    severity="info", url=url, module=self.NAME,
                    description=(
                        "SAML federation metadata is publicly accessible, revealing the "
                        "IdP/SP entity IDs, ACS endpoints, and signing certificate. Often "
                        "intentional (required for federation setup) — worth confirming it "
                        "doesn't expose more than the deployment intends."
                    ),
                    remediation="Confirm this is intentional; restrict access if the metadata is meant to be shared only with specific federation partners.",
                    cvss="0.0", confidence="CONFIRMED", confidence_score=90,
                    validation_steps=["status_200", "entity_descriptor_present"],
                )
                self.ui.find("info", "SAML metadata publicly accessible", url)
                found += 1
            time.sleep(self.delay)
        return found

    # ── capture a real SAMLResponse/Request from the crawl ─────────────────
    def _find_saml_response(self):
        """
        Scan already-crawled forms (HTTP-POST binding — base64 in a hidden
        field) and endpoints (HTTP-Redirect binding — base64+raw-deflate in
        a query param) for a genuine SAMLResponse/SAMLRequest. Returns
        (decoded_xml, acs_or_idp_url, param_name, binding) or None.
        """
        for form in self.ctx.get("forms", []):
            inputs = form.get("inputs", {})
            for pname in ("SAMLResponse", "SAMLRequest"):
                if inputs.get(pname):
                    xml_str = self._decode_saml(inputs[pname], deflated=False)
                    if xml_str:
                        return xml_str, form["action"], pname, "POST"

        for ep in self.ctx.get("endpoints", []):
            parsed = urllib.parse.urlparse(ep)
            qs = urllib.parse.parse_qs(parsed.query)
            for pname in ("SAMLResponse", "SAMLRequest"):
                if qs.get(pname):
                    xml_str = self._decode_saml(qs[pname][0], deflated=True)
                    if xml_str:
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        return xml_str, base, pname, "REDIRECT"
        return None

    def _decode_saml(self, value, deflated):
        try:
            raw = base64.b64decode(urllib.parse.unquote(value))
            if deflated:
                raw = zlib.decompress(raw, -15)  # raw DEFLATE, no zlib header — HTTP-Redirect binding
            text = raw.decode("utf-8", errors="ignore")
            if "<" in text and any(m in text for m in ("Response", "AuthnRequest", "Assertion")):
                return text
        except Exception:
            pass
        return None

    def _encode_saml(self, xml_str, deflated):
        raw = xml_str.encode("utf-8")
        if deflated:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            raw = co.compress(raw) + co.flush()
        return base64.b64encode(raw).decode()

    # ── static analysis ─────────────────────────────────────────────────
    def _analyze_static(self, xml_str, url):
        found = 0
        if "Response" not in xml_str[:800]:
            return 0  # an AuthnRequest, not a Response/Assertion — the checks below don't apply

        # A real element open tag, not just the substring "Signature"
        # anywhere in the document (which would false-negative on a
        # deliberately-mangled tag name and could equally false-positive on
        # an unrelated mention of the word elsewhere in the XML).
        has_signature = re.search(r'<(?:\w+:)?Signature\b', xml_str) is not None
        if not has_signature:
            self.db.add(
                title="SAML Response Not Signed",
                severity="critical", url=url, module=self.NAME,
                description=(
                    "A captured SAMLResponse carries no XML digital signature at all. Without "
                    "a signature, anyone who can intercept, replay, or simply forge a SAML "
                    "flow can impersonate any user."
                ),
                remediation="Require and verify XML digital signatures on every SAML assertion/response server-side — never accept an unsigned assertion.",
                cvss="9.8", confidence="HIGH", confidence_score=85,
                validation_steps=["saml_response_captured", "no_signature_element_present"],
            )
            self.ui.find("critical", "SAML Response Not Signed", url)
            found += 1

        if "NotOnOrAfter" not in xml_str:
            self.db.add(
                title="SAML Assertion Missing NotOnOrAfter (Unbounded Replay Window)",
                severity="high", url=url, module=self.NAME,
                description=(
                    "The captured SAML assertion has no NotOnOrAfter condition — there's no "
                    "time bound on how long it remains valid, so a captured assertion could "
                    "be replayed indefinitely."
                ),
                remediation="Set a short NotOnOrAfter window on every issued assertion, and enforce it server-side on every SAML consumer.",
                cvss="7.5", confidence="HIGH", confidence_score=80,
                validation_steps=["saml_response_captured", "notonorafter_missing"],
            )
            self.ui.find("high", "SAML assertion missing NotOnOrAfter", url)
            found += 1

        assertion_ids = re.findall(r'<(?:saml2?:)?Assertion[^>]*\bID="([^"]+)"', xml_str)
        signed_refs = re.findall(r'<(?:ds:)?Reference[^>]*URI="#([^"]+)"', xml_str)
        if len(assertion_ids) > 1:
            unsigned = [a for a in assertion_ids if a not in signed_refs]
            if unsigned:
                self.db.add(
                    title="SAML Response Contains Multiple Assertions — Signature Wrapping Risk",
                    severity="high", url=url, module=self.NAME,
                    description=(
                        f"The captured SAMLResponse contains {len(assertion_ids)} <Assertion> "
                        f"elements, but the XML signature's <Reference> covers only "
                        f"{len(signed_refs)} of them. A classic XML Signature Wrapping (XSW) "
                        "attack exploits exactly this gap: inject a second, attacker-controlled "
                        "assertion and hope the application processes the unsigned one while the "
                        "validator checks the original."
                    ),
                    remediation="Use a SAML library that validates the signature against the SAME assertion node that actually gets processed. Reject any response with more than one Assertion unless multi-assertion is explicitly required.",
                    cvss="8.1", confidence="MEDIUM", confidence_score=60,
                    validation_steps=["saml_response_captured", "multiple_assertion_ids_found",
                                       "signature_reference_does_not_cover_all"],
                    evidence=[f"Assertion IDs: {assertion_ids}", f"Signed reference IDs: {signed_refs}"],
                )
                self.ui.find("high", "SAML signature wrapping risk (multiple assertions)", url)
                found += 1
        return found

    # ── live tests ───────────────────────────────────────────────────────
    def _submit(self, s, url, param_name, value, binding):
        try:
            if binding == "POST":
                return s.post(url, data={param_name: value}, timeout=self.timeout, allow_redirects=False)
            qs = urllib.parse.urlencode({param_name: value})
            return s.get(f"{url}?{qs}", timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None

    def _test_replay(self, s, url, param_name, binding, xml_str):
        """Resubmit the EXACT captured value unmodified. A new session
        being granted on a second, later submission proves the server has
        no one-time-use/replay protection on this assertion."""
        deflated = binding == "REDIRECT"
        encoded = self._encode_saml(xml_str, deflated)

        first = self._submit(s, url, param_name, encoded, binding)
        if first is None:
            return 0
        time.sleep(self.delay)
        second = self._submit(s, url, param_name, encoded, binding)
        if second is None:
            return 0

        accepted_twice = (
            first.status_code in (200, 302, 303) and second.status_code in (200, 302, 303)
            and bool(getattr(second, "cookies", None))
        )
        if accepted_twice:
            self.db.add(
                title="SAML Assertion Replay Accepted",
                severity="critical", url=url, module=self.NAME,
                description=(
                    "The exact same (byte-identical) captured SAMLResponse was submitted to "
                    f"{url} twice, and BOTH submissions were accepted (a session cookie was "
                    "issued each time). A SAML assertion captured from a proxy log, browser "
                    "history, or network capture can be replayed to establish a new "
                    "authenticated session at any time within its validity window."
                ),
                remediation="Track and reject already-used assertion IDs (InResponseTo / Assertion ID) server-side — a SAML assertion must only ever be accepted once.",
                cvss="9.1", confidence="HIGH", confidence_score=80,
                validation_steps=["saml_response_captured", "resubmitted_unmodified_twice",
                                   "both_submissions_accepted"],
                evidence=[f"First submission status: {first.status_code}",
                          f"Second submission status: {second.status_code}"],
            )
            self.ui.find("critical", "SAML assertion replay accepted", url)
            return 1
        return 0

    def _test_signature_strip(self, s, url, param_name, binding, xml_str):
        """Remove the <Signature>...</Signature> block entirely and
        resubmit — acceptance proves the server doesn't actually verify
        signatures (same methodology as jwt.py's alg:none forgery test)."""
        stripped = re.sub(r'<(?:\w+:)?Signature\b.*?</(?:\w+:)?Signature>', '', xml_str, flags=re.S)
        if stripped == xml_str:
            return 0  # nothing to strip — already covered by the missing-signature check above

        deflated = binding == "REDIRECT"
        encoded = self._encode_saml(stripped, deflated)
        resp = self._submit(s, url, param_name, encoded, binding)
        if resp is None:
            return 0

        accepted = resp.status_code in (200, 302, 303) and bool(getattr(resp, "cookies", None))
        if accepted:
            self.db.add(
                title="SAML Signature Stripping Accepted — Signature Not Verified",
                severity="critical", url=url, module=self.NAME,
                description=(
                    "A captured SAMLResponse with its entire <Signature> element removed was "
                    f"still ACCEPTED by {url} (a session cookie was issued). The server isn't "
                    "actually verifying the XML signature — anyone can forge an assertion with "
                    "arbitrary claims (including an arbitrary NameID/username) and log in as "
                    "any user."
                ),
                remediation="Fix SAML response validation to reject any assertion without a valid, verified XML digital signature.",
                cvss="9.8", confidence="CONFIRMED", confidence_score=95,
                validation_steps=["saml_response_captured", "signature_element_stripped",
                                   "server_accepted_unsigned_assertion"],
                evidence=[f"Submission status: {resp.status_code}"],
            )
            self.ui.find("critical", "SAML signature stripping accepted", url)
            return 1
        return 0
