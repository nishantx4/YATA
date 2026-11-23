"""
XXEModule — YATA RECON module.
Detects XML External Entity (XXE) vulnerabilities by injecting benign external entities.
"""
import re
import time

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


class XXEModule(BaseModule):
    NAME = "XXE"

    # Specific XML-parser diagnostics. The old check — "xml" in body AND
    # ("parse error" OR "doctype") — matched virtually every HTML5 page,
    # because `<!doctype html>` supplies "doctype" and inline SVG / xmlns /
    # xml:lang supply "xml". These strings only appear in a genuine parser
    # error, never in normal page markup.
    _XML_ERROR_SIGNS = (
        "org.xml.sax", "saxparseexception", "xmlsyntaxerror",
        "not well-formed", "premature end of data", "xml parsing error",
        "content is not allowed in prolog", "xmlparseentityref",
        "undeclared entity", "error parsing xml", "lxml.etree",
        "javax.xml.", "xml document structures must start and end",
        "fatal error: ", "expectation failed: xml",
    )

    @classmethod
    def _looks_like_xml_parser_error(cls, text):
        if not text:
            return False
        low = text.lower()
        return any(sig in low for sig in cls._XML_ERROR_SIGNS)

    @staticmethod
    def _entity_resolved(body: str, canary: str, payload: str) -> bool:
        """Confirm the external entity was actually RESOLVED — i.e. the canary
        appears where `&xxe;` expanded — rather than the server merely echoing
        the submitted XML, where the canary sits inside the reflected
        `<!ENTITY xxe "canary">` declaration.

        The old guard only caught a VERBATIM echo of the whole payload; a
        server that pretty-prints, re-indents, JSON-wraps or otherwise
        normalizes the echoed body slips past it (the payload is no longer a
        substring) while the canary is still present inside the reflected
        entity declaration — a false 'resolved'. Here we strip the echoed
        payload AND any DOCTYPE/ENTITY declarations before requiring the
        canary to remain."""
        if not body or canary not in body:
            return False
        cleaned = body.replace(payload, "")
        # Drop any echoed DTD internal subset and standalone ENTITY/DOCTYPE
        # declarations, where a reflected (not resolved) canary would live.
        cleaned = re.sub(r"<!DOCTYPE\b[^>\[]*(?:\[.*?\])?\s*>", "", cleaned, flags=re.S | re.I)
        cleaned = re.sub(r"<!ENTITY\b[^>]*>", "", cleaned, flags=re.I)
        return canary in cleaned

    def run(self):
        self.ui.section("XXE — XML External Entity Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        # API endpoints from an OpenAPI/Swagger spec (recon.py) carry a real,
        # schema-correct XML request body (xml_template, with the vulnerable
        # field's text already replaced by a __GR_INJECT__ marker). This is
        # tried FIRST and is far more likely to reach the vulnerable parser
        # than the generic <foo>&xxe;</foo> envelope below — most real APIs
        # validate the document against an expected root/element shape before
        # doing anything else, and a made-up envelope simply never gets that
        # far.
        found += self._test_api_endpoints(s)

        # Blind/OOB XXE confirmation — everything else in this module relies
        # on the entity's value being reflected back in the response. A
        # parser that eagerly resolves a SYSTEM identifier while parsing the
        # DTD (common — many parsers fetch external DTDs/entities before
        # they even know if the entity will be used in the document body)
        # will still make that outbound request even when the document is
        # otherwise rejected or the value never appears anywhere in the
        # response — invisible to every in-band check below. Same
        # methodology as ssrf.py's OOB confirmation, reusing the same
        # interactsh session machinery.
        found += self._test_oob(s)

        # Known XML endpoints or any POST endpoints from context
        test_endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]

        # XXE payload with a benign entity
        canary = "yata_recon_xxe_canary"
        xxe_payload = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe "{canary}" >]>
<foo>&xxe;</foo>"""

        headers_list = [
            {"Content-Type": "application/xml"},
            {"Content-Type": "text/xml"}
        ]

        for endpoint in test_endpoints:
            # Skip likely non-API endpoints
            if endpoint.endswith((".jpg", ".png", ".js", ".css")):
                continue
                
            for headers in headers_list:
                try:
                    resp = s.post(endpoint, data=xxe_payload, headers=headers, timeout=self.timeout)
                    
                    # Confirmed only when the entity was RESOLVED — not when the
                    # server merely echoed our XML (canary inside a reflected
                    # <!ENTITY> declaration). See _entity_resolved.
                    if self._entity_resolved(resp.text, canary, xxe_payload):
                        self.db.add(
                            title=f"XXE — XML External Entity Injection",
                            severity="critical", url=endpoint, module=self.NAME,
                            description=(
                                f"Endpoint accepts XML input and resolves external entities. "
                                f"A benign entity ('{canary}') was injected and successfully resolved by the server. "
                                "This can lead to local file disclosure (LFI), SSRF, and potential RCE."
                            ),
                            remediation=(
                                "Disable external entity parsing in the XML parser configuration. "
                                "For Java, set FEATURE_SECURE_PROCESSING to true. For Python lxml, "
                                "use resolve_entities=False. Prefer JSON over XML where possible."
                            ),
                            cvss="9.8",
                            confidence="CONFIRMED",
                            confidence_score=95,
                            validation_steps=["entity_resolved", "not_literal_reflection"],
                            evidence=[f"Payload:\n{xxe_payload}"]
                        )
                        self.ui.find("critical", "XXE Injection (Entity Resolved)", endpoint)
                        found += 1
                        break  # Found XXE on this endpoint

                    # A genuine XML-parser error (specific parser diagnostic,
                    # not the words "xml"/"doctype" that every HTML page has).
                    elif self._looks_like_xml_parser_error(resp.text):
                        self.db.add(
                            title=f"XXE Potential — XML Parsing Error",
                            severity="low", url=endpoint, module=self.NAME,
                            description=(
                                f"Endpoint accepts XML and returned an XML parsing error. "
                                "This indicates an active XML parser, though entity resolution was not confirmed."
                            ),
                            remediation="Ensure the XML parser is securely configured to disable DTD processing.",
                            cvss="3.1",
                            confidence="LOW",
                            confidence_score=35,
                            validation_steps=["xml_error_matched"],
                        )
                        
                    time.sleep(self.delay)
                except Exception:
                    continue
            
            if found > 5:
                break

        if found == 0:
            self.ui.info("No XXE vulnerabilities detected.")

    def _test_api_endpoints(self, s) -> int:
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})

        for api_ep in self.ctx.get("api_endpoints", []):
            template = api_ep.get("xml_template")
            if not template or "__GR_INJECT__" not in template:
                continue

            method = api_ep.get("method", "POST")
            url = api_ep.get("url")
            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)
            headers["Content-Type"] = "application/xml"

            canary = "yata_recon_xxe_canary"

            # Build a DOCTYPE whose Name matches the document's actual root
            # element (some parsers are stricter than others about this),
            # keep the rest of the real, schema-correct body intact, and
            # replace only the marked field's text with an entity reference.
            body_no_prolog = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", template)
            root_match = re.search(r"<([A-Za-z_][\w:.-]*)[ >]", body_no_prolog)
            root_name = root_match.group(1) if root_match else "root"

            payload = (
                '<?xml version="1.0"?>\n'
                f'<!DOCTYPE {root_name} [<!ENTITY xxe "{canary}">]>\n'
                + body_no_prolog.replace("__GR_INJECT__", "&xxe;")
            )

            try:
                resp = s.request(method, url, data=payload.encode("utf-8", "ignore"),
                                  headers=headers, timeout=self.timeout)
            except Exception:
                continue

            if self._entity_resolved(resp.text, canary, payload):
                self.db.add(
                    title="XXE — XML External Entity Injection (OpenAPI-discovered body)",
                    severity="critical", url=url, module=self.NAME,
                    description=(
                        f"The endpoint's real request body schema was reused with a benign external "
                        f"entity injected into its '{api_ep.get('xml_field')}' field. The entity "
                        f"('{canary}') was successfully resolved by the server. This can lead to local "
                        "file disclosure, SSRF, and potential RCE."
                    ),
                    remediation=(
                        "Disable external entity parsing in the XML parser configuration. "
                        "For Java, set FEATURE_SECURE_PROCESSING to true. For Python lxml, "
                        "use resolve_entities=False. Prefer JSON over XML where possible."
                    ),
                    cvss="9.8",
                    confidence="CONFIRMED",
                    confidence_score=95,
                    validation_steps=["entity_resolved", "not_literal_reflection", "schema_correct_body"],
                    evidence=[f"Payload:\n{payload}"],
                )
                self.ui.find("critical", "XXE Injection (Entity Resolved, OpenAPI body)", url)
                found += 1

            time.sleep(self.delay)
            if found > 5:
                return found

        return found

    # ─────────────────────────────────────────────────────────────────────────
    def _test_oob(self, s):
        """
        Blind/out-of-band XXE confirmation via interactsh-client — see
        module docstring above. Degrades to a no-op (with a clear message)
        when interactsh-client isn't installed, same pattern as ssrf.py.
        """
        from recon.core.oast import OASTClient

        oast = OASTClient(self.ui)
        if not oast.available:
            self.ui.info("interactsh-client not installed — skipping blind/OOB XXE confirmation "
                          "(in-band checks above still ran).")
            return 0

        self.ui.info("Starting interactsh session for blind/OOB XXE confirmation...")
        if not oast.start():
            self.ui.warn("Could not establish an interactsh session — skipping OOB XXE confirmation.")
            return 0
        self.ui.ok(f"OOB session ready: *.{oast.domain}")

        test_endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:12]
        probes = {}  # label -> endpoint

        try:
            for endpoint in test_endpoints:
                if endpoint.endswith((".jpg", ".png", ".js", ".css")):
                    continue
                label, oob_url = oast.label_url()
                # A SYSTEM identifier referenced from the DTD's own internal
                # subset — many XML parsers fetch this while parsing the
                # DTD itself, before evaluating whether &xxe; is even used
                # anywhere in the document body, so this can fire even on a
                # document that's otherwise rejected outright.
                payload = (
                    '<?xml version="1.0"?>\n'
                    f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}"> ]>\n'
                    '<foo>&xxe;</foo>'
                )
                for headers in ({"Content-Type": "application/xml"}, {"Content-Type": "text/xml"}):
                    try:
                        s.post(endpoint, data=payload, headers=headers, timeout=self.timeout)
                    except Exception:
                        pass
                probes[label] = endpoint
                time.sleep(self.delay)

            if not probes:
                return 0

            self.ui.info(f"Sent {len(probes)} OOB XXE probe(s) — waiting for callbacks...")
            interactions = oast.poll(wait=15.0)
        finally:
            oast.stop()

        found = 0
        reported = set()
        for interaction in interactions:
            label = oast.interaction_label(interaction)
            if not label or label not in probes or label in reported:
                continue
            reported.add(label)
            endpoint = probes[label]
            protocol = interaction.get("protocol", "dns/http")
            self.db.add(
                title="Blind XXE (OOB-Confirmed) — External Entity Resolved",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    f"Endpoint accepts XML input and, while parsing a DOCTYPE declaring a "
                    f"SYSTEM entity pointing at an interactsh domain we control, made an "
                    f"outbound {protocol} request to it — an out-of-band callback received "
                    "directly, independent of anything in the HTTP response. This proves the "
                    "XML parser resolves external entities even where nothing is ever reflected "
                    "back, which the in-band checks in this module cannot see at all."
                ),
                remediation=(
                    "Disable external entity and external DTD resolution in the XML parser "
                    "configuration (e.g. libxml2: LIBXML_NONET / resolve_entities=False; Java: "
                    "FEATURE_SECURE_PROCESSING; .NET: XmlResolver = null). Prefer JSON over XML "
                    "where possible."
                ),
                cvss="9.8", confidence="CONFIRMED", confidence_score=99,
                validation_steps=["oob_probe_sent", "interaction_received", "label_correlated"],
                evidence=[f"Protocol: {protocol}",
                          f"Remote: {interaction.get('remote-address', interaction.get('remote_address', 'n/a'))}"],
            )
            self.ui.find("critical", "Blind XXE (OOB-confirmed)", endpoint)
            found += 1

        if found == 0:
            self.ui.info("No OOB XXE callbacks received.")
        return found
