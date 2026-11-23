"""
WebSocketModule — YATA RECON module.
Detects Cross-Site WebSocket Hijacking (CSWSH) vulnerabilities.

NOTE: A prior version of this module tried to detect a WebSocket upgrade by
checking `requests.Session.get(...).status_code == 101`. That can't work: an
HTTP/1.1 "101 Switching Protocols" response is handled at the raw connection
layer, not represented as a normal completed `requests.Response`. In
practice, urllib3 either raises on the malformed-looking response or the
call just times out waiting for HTTP-shaped bytes that never come — either
way the exception is swallowed by a bare `except Exception: pass`, so this
check could never actually fire against a real WebSocket server. This
version performs a real WebSocket handshake via the `websocket-client`
library so it observes genuine accept/reject behavior.
"""
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

try:
    import websocket as ws_client  # `websocket-client` package
except ImportError:
    ws_client = None

from recon.modules import BaseModule


class WebSocketModule(BaseModule):
    NAME = "WebSocket Security"

    EVIL_ORIGIN = "https://yata-recon-evil-origin.example.com"

    def run(self):
        self.ui.section("WebSocket — CSWSH Detection")
        if not requests:
            return
        if not ws_client:
            self.ui.warn(
                "websocket-client not installed — cannot perform a real WS handshake "
                "(pip install websocket-client). Skipping CSWSH detection."
            )
            return

        ws_endpoints = self._collect_ws_endpoints()
        if not ws_endpoints:
            self.ui.info("No WebSocket endpoints discovered.")
            return

        found = 0
        for endpoint in ws_endpoints[:5]:
            if self._test_endpoint(endpoint):
                found += 1

        if found == 0:
            self.ui.info("No WebSocket vulnerabilities detected.")

    def _collect_ws_endpoints(self):
        """Discover WebSocket endpoints from crawled URLs, common paths on the
        base host (since ws:// endpoints are rarely linked in HTML and won't
        show up from crawling alone), and any explicit ws(s):// URLs found in
        mined JS (recon.py stores raw endpoint strings, which may already be
        ws(s):// if JS referenced them directly)."""
        found = set()
        for ep in self.ctx.get("endpoints", []):
            low = ep.lower()
            if low.startswith(("ws://", "wss://")):
                found.add(ep)
            elif any(path in low for path in ["/ws", "/websocket", "/socket.io", "/signalr", "/cable"]):
                found.add(self._to_ws_url(ep))

        for path in ["/ws", "/websocket", "/socket", "/socket.io/?EIO=4&transport=websocket"]:
            found.add(self._to_ws_url(urllib.parse.urljoin(self.base_url, path)))

        return list(found)

    @staticmethod
    def _to_ws_url(url: str) -> str:
        if url.startswith("https://"):
            return "wss://" + url[len("https://"):]
        if url.startswith("http://"):
            return "ws://" + url[len("http://"):]
        return url

    def _handshake(self, url: str, origin: str):
        """Attempt a real WS handshake. Returns True if the server accepted
        the connection, False if it was rejected, None if unreachable/timed out."""
        try:
            conn = ws_client.create_connection(
                url, timeout=self.timeout, origin=origin,
                sslopt={"cert_reqs": 0},  # CERT_NONE — match other modules' verify=False
                enable_multithread=True,
            )
            conn.close()
            return True
        except ws_client.WebSocketBadStatusException:
            return False  # server actively rejected the handshake (e.g. 403)
        except ws_client.WebSocketTimeoutException:
            return None
        except Exception:
            return None

    def _origin_variants(self):
        """
        Multiple bypass-shaped origins, not just one unrelated domain —
        mirrors cors.py's origin matrix. A server that correctly rejects a
        totally unrelated origin might still fall for a same-app-looking
        subdomain-confusion variant (an attacker-controlled subdomain, or a
        naive substring check), which a single-origin test can never reveal.
        """
        target = self.target.split(':')[0]
        return [
            (self.EVIL_ORIGIN, "unrelated origin"),
            (f"https://evil.{target}", "attacker subdomain of target"),
            (f"https://{target}.evil.com", "target-as-substring-of-attacker-domain"),
            ("null", "null origin (sandboxed iframe / data: URI)"),
        ]

    def _test_endpoint(self, endpoint: str) -> bool:
        legit_origin = self.base_url.rstrip("/")
        accepted_variants = []

        for origin, label in self._origin_variants():
            result = self._handshake(endpoint, origin)
            if result is True:
                accepted_variants.append((origin, label))

        if not accepted_variants:
            return False  # couldn't reach it, or every bypass variant was correctly rejected

        # Confirm this endpoint is genuinely live (not a coincidental accept-anything
        # response) by also completing a handshake with the legitimate origin.
        legit_accepted = self._handshake(endpoint, legit_origin)
        if legit_accepted is not True:
            return False

        variant_list = ", ".join(f"'{o}' ({label})" for o, label in accepted_variants)
        self.db.add(
            title="Cross-Site WebSocket Hijacking (CSWSH)",
            severity="high", url=endpoint, module=self.NAME,
            description=(
                f"The WebSocket endpoint at {endpoint} completed a full handshake with "
                f"{len(accepted_variants)} attacker-controllable Origin value(s) — {variant_list} "
                "— the same as it does for the legitimate origin. If this WebSocket relies on "
                "ambient credentials (cookies, session state) for authentication rather than a "
                "per-connection token, a malicious page can open a cross-origin WebSocket "
                "connection as the victim and hijack their session."
            ),
            remediation=(
                "Validate the Origin header during the WebSocket handshake with an EXACT "
                "allow-list match — never substring/suffix matching, and explicitly reject "
                "'null'. Do not rely solely on cookies for WebSocket authentication — require a "
                "CSRF-style token in the handshake (e.g. a query param validated server-side)."
            ),
            cvss="7.4",
            confidence="HIGH",
            confidence_score=85,
            evidence=[f"Accepted Origin '{o}' ({label})" for o, label in accepted_variants]
                     + [f"Handshake with legitimate Origin '{legit_origin}': accepted"],
            validation_steps=["real_ws_handshake_completed", "bypass_origin_accepted", "legit_origin_control_accepted"],
        )
        self.ui.find("high", f"CSWSH — {len(accepted_variants)} bypass origin(s) accepted", endpoint)
        return True
