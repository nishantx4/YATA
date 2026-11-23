"""
Validator — Multi-stage false positive elimination engine.

Every module should call Validator methods before reporting findings.
Stages:
  1. Baseline comparison (soft-404, content-type, SPA filtering)
  2. Differential confirmation (canary → probe → control)
  3. Statistical timing verification (Z-score analysis)
  4. AI semantic verification (NVIDIA NIM structured evaluation)

Usage:
    validator = Validator(baseline_profile, ai_engine, ui)

    # Check if a file exposure is real
    if validator.validate_file_exposure(url, response, expected_type="text/plain"):
        db.add(finding)

    # Check if reflected input is exploitable XSS
    if validator.validate_reflection(url, param, payload, response, context="html_body"):
        db.add(finding)

    # Confidence scoring
    score = validator.compute_confidence(checks_passed, checks_total, verification_type)
"""

import re
import json
import hashlib
import time
import statistics
from typing import Any


def _json_shape_paths(data, prefix="$", depth=0):
    """
    Recursively describe a JSON value's *shape* (key paths + value types),
    not its values — so two structurally identical responses with different
    content (e.g. two successful logins for different users) still hash the
    same, while a genuinely different shape (a 401 error body vs. a 200
    success body) correctly diverges. Used by Validator._structural_hash to
    make differential comparison meaningful on JSON API responses, which
    otherwise contain no HTML tags for the tag-sequence hash to key off.
    """
    if depth > 6:
        return [f"{prefix}:{type(data).__name__}"]
    if isinstance(data, dict):
        if not data:
            return [f"{prefix}:empty_dict"]
        paths = []
        for k in sorted(data.keys(), key=str)[:50]:
            paths.extend(_json_shape_paths(data[k], f"{prefix}.{k}", depth + 1))
        return paths
    if isinstance(data, list):
        if not data:
            return [f"{prefix}:empty_list"]
        # Only the first element's shape + a length bucket — the hash
        # shouldn't depend on exactly how many items came back.
        return [f"{prefix}:list[{min(len(data), 50)}]"] + _json_shape_paths(data[0], f"{prefix}[]", depth + 1)
    return [f"{prefix}:{type(data).__name__}"]


class Validator:
    """Multi-stage false positive elimination engine."""

    def __init__(self, baseline=None, ai=None, ui=None, session_factory=None):
        """
        Args:
            baseline: BaselineProfile from baseline.py
            ai: AIEngine instance for semantic verification
            ui: UI instance for output
            session_factory: Callable that returns a requests.Session
        """
        self.baseline = baseline
        self.ai = ai
        self.ui = ui
        self._session_factory = session_factory

    def _session(self):
        if self._session_factory:
            return self._session_factory()
        try:
            import requests
            s = requests.Session()
            s.headers.update({"User-Agent": "Mozilla/5.0 YATA RECON/5.0"})
            s.verify = False
            try:
                from recon.core import net
                net.apply(s)   # scan-wide proxy + scope guard
            except Exception:
                pass
            return s
        except ImportError:
            return None

    def _get(self, url: str, timeout: int = 10, **kwargs):
        s = self._session()
        if not s:
            return None
        try:
            return s.get(url, timeout=timeout, **kwargs)
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 1: Baseline Comparison
    # ═══════════════════════════════════════════════════════════════════════════

    def is_soft_404(self, response_body: str, status_code: int = 200) -> bool:
        """Check if a response is a soft-404 (custom error page with 200 status)."""
        if not self.baseline:
            return False
        return self.baseline.matches_soft_404(response_body, status_code)

    def is_html_masquerading(self, content_type: str, body: str, expected_type: str) -> bool:
        """
        Check if a response claiming to be a file is actually an HTML page.
        Used for: secrets.py, nuclei_sim.py — prevents flagging SPA catch-all routes.
        """
        if not expected_type:
            return False
        # If Content-Type says HTML but we expected something else
        ct_lower = content_type.lower()
        if "text/html" in ct_lower or "application/xhtml" in ct_lower:
            return True
        # Body starts with HTML markers
        stripped = body.strip()[:100].lower()
        if stripped.startswith(("<!doctype", "<html", "<!doctype html")):
            return True
        return False

    def validate_file_exposure(
        self,
        url: str,
        response,
        expected_type: str = "text/plain",
        content_patterns: list[str] | None = None,
    ) -> dict:
        """
        Validate a suspected file exposure (/.env, /.git/HEAD, /backup.zip, etc.)

        Returns:
            {"valid": bool, "confidence": str, "confidence_score": int, "reason": str}
        """
        if response is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": "No response"}

        body = response.text if hasattr(response, "text") else str(response)
        status = response.status_code if hasattr(response, "status_code") else 200
        ct = ""
        if hasattr(response, "headers"):
            ct = response.headers.get("Content-Type", "")

        # Check 1: Must be 200
        if status != 200:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": f"Status {status}"}

        # Check 2: Not a soft-404
        if self.is_soft_404(body, status):
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": "Soft-404 match"}

        # Check 3: Not HTML masquerading as a file
        if self.is_html_masquerading(ct, body, expected_type):
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": "HTML response for non-HTML resource"}

        # Check 4: Content pattern validation
        if content_patterns:
            matches = sum(1 for p in content_patterns if p in body)
            if matches == 0:
                return {"valid": False, "confidence": "LOW", "confidence_score": 10, "reason": "No expected content patterns found"}
            confidence_score = min(95, 50 + (matches * 15))
            return {
                "valid": True,
                "confidence": "CONFIRMED" if confidence_score >= 95 else "HIGH" if confidence_score >= 75 else "MEDIUM",
                "confidence_score": confidence_score,
                "reason": f"Matched {matches}/{len(content_patterns)} content patterns",
            }

        # Check 5: Body must have non-trivial content
        if len(body.strip()) < 10:
            return {"valid": False, "confidence": "LOW", "confidence_score": 5, "reason": "Empty or trivial response"}

        return {
            "valid": True,
            "confidence": "MEDIUM",
            "confidence_score": 60,
            "reason": "200 OK with non-HTML content, no soft-404 match",
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 2: Differential Confirmation
    # ═══════════════════════════════════════════════════════════════════════════

    def differential_test(
        self,
        url: str,
        param: str,
        true_payload: str,
        false_payload: str,
        baseline_value: str = "",
        timeout: int = 10,
        send_fn=None,
    ) -> dict:
        """
        Three-probe differential test for boolean-based injection.

        1. Send true_payload → should match baseline behavior
        2. Send false_payload → should differ from baseline
        3. Send baseline_value again → should recover to baseline (control)

        Args:
            send_fn: optional callable(value: str) -> response. When given,
                it is used to deliver each probe value instead of the default
                GET-query-string injection — lets callers drive the same
                true/false/control logic through POST bodies, JSON, XML,
                headers, or path segments.

        Returns:
            {"valid": bool, "confidence": str, "confidence_score": int, "details": str}
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        def inject_param(target_url: str, p: str, value: str) -> str:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[p] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        if send_fn:
            probe = lambda value: send_fn(value)
        else:
            probe = lambda value: self._get(inject_param(url, param, value), timeout=timeout)

        # Baseline request. NOTE: requests.Response is falsy for ANY non-2xx
        # status (bool(resp) == resp.ok) — a 401/403/500 response is a
        # perfectly valid, meaningful probe result (often exactly where the
        # interesting behavior is), so every check here must be `is None`,
        # never plain truthiness, or auth-walled/error-returning endpoints
        # get silently treated as "request failed" and skipped entirely.
        baseline_resp = probe(baseline_value)
        if baseline_resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "details": "Baseline request failed"}

        baseline_hash = self._structural_hash(baseline_resp.text)
        baseline_len = len(baseline_resp.text)

        # True probe
        true_resp = probe(true_payload)
        if true_resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "details": "True probe failed"}

        true_hash = self._structural_hash(true_resp.text)
        true_len = len(true_resp.text)

        # False probe
        false_resp = probe(false_payload)
        if false_resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "details": "False probe failed"}

        false_hash = self._structural_hash(false_resp.text)
        false_len = len(false_resp.text)

        # Control probe (repeat baseline)
        control_resp = probe(baseline_value)
        control_hash = self._structural_hash(control_resp.text) if control_resp is not None else ""

        # Analysis. We do NOT assume the baseline_value represents the "true"
        # condition — that only holds for classic `?id=1` style params. For
        # something like a login endpoint, the baseline is deliberately
        # invalid credentials (a FALSE condition), so a true auth-bypass
        # payload is the one that DIFFERS from baseline, and the false payload
        # is the one that matches it (still rejected, same as baseline). Both
        # orientations are checked — only the divergence between true/false,
        # and one of them anchoring to the known-stable baseline, matters.
        def _matches_baseline(h, l):
            return (h == baseline_hash) or (abs(l - baseline_len) < max(50, baseline_len * 0.03))

        def _orientation(th, tl, fh, fl):
            t_match = _matches_baseline(th, tl)
            f_match = _matches_baseline(fh, fl)
            # Orientation A: baseline == true state (e.g. ?id=1)
            a = t_match and (not f_match)
            # Orientation B: baseline == false state (e.g. invalid login creds)
            b = f_match and (not t_match)
            return a, b

        orientation_a, orientation_b = _orientation(true_hash, true_len, false_hash, false_len)
        orientation = "true≈baseline, false diverges" if orientation_a else "false≈baseline, true diverges"
        # Control should match baseline (proves the endpoint is stable, not
        # just returning per-request-varying content that any two probes would
        # diverge on — the #1 boolean false-positive source).
        control_matches = control_hash == baseline_hash if control_hash else False

        if not (orientation_a or orientation_b):
            return {
                "valid": False,
                "confidence": "LOW",
                "confidence_score": 15,
                "details": "No differential: responses don't follow boolean logic pattern",
            }

        # Reject WAF/edge artifacts before spending a confirmation round. A
        # genuine boolean-blind differential is a CONTENT difference (a record
        # shown vs hidden) — not the diverging probe collapsing to a block or
        # error page. A payload that carries SQL metacharacters can trip a WAF
        # that then returns a tiny 403/"request blocked" body; that structurally
        # "diverges from baseline" and otherwise reads as flawless boolean logic
        # (the real asana.com false positive: false=42b against a 361 KB
        # baseline). The divergent side is the one that does NOT anchor to
        # baseline.
        divergent_resp = false_resp if orientation_a else true_resp
        divergent_len = false_len if orientation_a else true_len
        if self._looks_blocked(divergent_resp) or (baseline_len >= 1000 and divergent_len < 128):
            return {
                "valid": False, "confidence": "LOW", "confidence_score": 20,
                "details": (f"Divergent probe looks like a WAF/error block "
                            f"({divergent_len}b vs baseline {baseline_len}b), not boolean content logic"),
            }

        # Second confirmation round: re-send the true/false probes and require
        # the SAME orientation to reproduce. A one-off divergence from caching,
        # rotating content, A/B bucketing or network jitter will not survive
        # this — a real boolean-injection differential is deterministic and
        # repeats every time.
        true_resp2 = probe(true_payload)
        false_resp2 = probe(false_payload)
        if true_resp2 is None or false_resp2 is None:
            return {
                "valid": False, "confidence": "LOW", "confidence_score": 20,
                "details": "Differential seen once but confirmation round failed to complete",
            }
        a2, b2 = _orientation(
            self._structural_hash(true_resp2.text), len(true_resp2.text),
            self._structural_hash(false_resp2.text), len(false_resp2.text),
        )
        consistent = (orientation_a and a2) or (orientation_b and b2)
        if not consistent:
            return {
                "valid": False, "confidence": "LOW", "confidence_score": 25,
                "details": "Differential did not reproduce on a second round — likely dynamic content, not injection",
            }

        if control_matches:
            return {
                "valid": True,
                "confidence": "CONFIRMED",
                "confidence_score": 95,
                "details": f"Differential confirmed over 2 rounds ({orientation}): true={true_len}b, "
                           f"false={false_len}b, baseline={baseline_len}b, control recovered",
            }
        return {
            "valid": True,
            "confidence": "HIGH",
            "confidence_score": 80,
            "details": f"Differential reproduced over 2 rounds ({orientation}) but control probe "
                       f"did not fully recover to baseline — endpoint may have mild jitter",
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 3: Statistical Timing Verification
    # ═══════════════════════════════════════════════════════════════════════════

    def validate_time_based(
        self,
        url: str,
        param: str,
        delay_payload: str,
        expected_delay: float = 5.0,
        baseline_value: str = "",
        timeout: int = 15,
        z_threshold: float = 3.5,
        send_fn=None,
    ) -> dict:
        """
        Statistical timing verification for time-based blind injection.

        1. Measure 5 baseline response times → compute μ, σ
        2. Send delay payload → measure response time
        3. Compute Z-score: Z = (T_payload - μ) / σ
        4. Send control probe → must return to baseline
        5. Require Z ≥ z_threshold AND control recovery

        Args:
            send_fn: optional callable(value: str, timeout: float) -> response.
                When given, used to deliver every probe instead of the default
                GET-query-string injection (see differential_test).

        Returns:
            {"valid": bool, "confidence": str, "confidence_score": int, "z_score": float, "details": str}
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        def inject_param(target_url: str, p: str, value: str) -> str:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[p] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        if send_fn:
            probe = lambda value, t: send_fn(value, t)
        else:
            probe = lambda value, t: self._get(inject_param(url, param, value), timeout=t)

        # Use stored baseline if available, otherwise measure
        if self.baseline and self.baseline.baseline_mean > 0:
            mu = self.baseline.baseline_mean
            sigma = self.baseline.baseline_stdev
        else:
            # Measure baseline
            times = []
            for _ in range(5):
                start = time.time()
                resp = probe(baseline_value, timeout)
                elapsed = time.time() - start
                if resp is not None:
                    times.append(elapsed)

            if len(times) < 3:
                return {"valid": False, "confidence": "LOW", "confidence_score": 0, "z_score": 0, "details": "Insufficient baseline measurements"}

            mu = statistics.mean(times)
            sigma = statistics.stdev(times) if len(times) > 1 else 0.1

        # Avoid division by near-zero sigma
        if sigma < 0.05:
            sigma = 0.05

        # Send delay payload
        start = time.time()
        resp = probe(delay_payload, timeout + expected_delay + 5)
        payload_time = time.time() - start

        if resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "z_score": 0, "details": "Payload request failed or timed out"}

        # Calculate Z-score
        z_score = (payload_time - mu) / sigma

        # Control probe — must return to baseline
        start = time.time()
        control_resp = probe(baseline_value, timeout)
        control_time = time.time() - start

        control_z = (control_time - mu) / sigma if control_resp is not None else 999

        # Verdict
        payload_delayed = z_score >= z_threshold and payload_time >= (mu + expected_delay * 0.7)
        control_normal = control_z < 2.0  # Control should be within 2σ of baseline

        if not payload_delayed:
            return {
                "valid": False,
                "confidence": "LOW",
                "confidence_score": 10,
                "z_score": z_score,
                "details": f"No significant delay: payload={payload_time:.2f}s, Z={z_score:.1f} < {z_threshold}",
            }

        if not control_normal:
            return {
                "valid": False,
                "confidence": "LOW",
                "confidence_score": 20,
                "z_score": z_score,
                "details": f"Payload slow (Z={z_score:.1f}) but control probe was also slow ({control_time:.2f}s) — network jitter, not injection",
            }

        # Re-confirmation: a single slow sample (GC pause, cold cache, a
        # transient network blip landing exactly on the payload request) must
        # not confirm a time-based injection on its own. Replay the delay
        # payload once more and require it to be slow AGAIN — a real
        # SLEEP/WAITFOR is perfectly reproducible, a fluke is not.
        start = time.time()
        confirm_resp = probe(delay_payload, timeout + expected_delay + 5)
        confirm_time = time.time() - start
        if confirm_resp is None:
            return {
                "valid": False, "confidence": "LOW", "confidence_score": 25, "z_score": z_score,
                "details": f"Payload delayed once (Z={z_score:.1f}) but the confirmation replay failed to complete",
            }
        confirm_z = (confirm_time - mu) / sigma
        if confirm_z < z_threshold or confirm_time < (mu + expected_delay * 0.7):
            return {
                "valid": False, "confidence": "LOW", "confidence_score": 30, "z_score": z_score,
                "details": f"Delay did not reproduce: 1st={payload_time:.2f}s (Z={z_score:.1f}), "
                           f"2nd={confirm_time:.2f}s (Z={confirm_z:.1f}) — one-off slowdown, not injection",
            }

        return {
            "valid": True,
            "confidence": "CONFIRMED",
            "confidence_score": 95,
            "z_score": z_score,
            "details": f"Time-based confirmed over 2 payloads: {payload_time:.2f}s (Z={z_score:.1f}) & "
                       f"{confirm_time:.2f}s (Z={confirm_z:.1f}), control={control_time:.2f}s normal, "
                       f"mean={mu:.2f}s stdev={sigma:.2f}s",
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 4: Reflection & Context Validation
    # ═══════════════════════════════════════════════════════════════════════════

    # Script `type` values the browser never executes as JavaScript — data
    # blocks an app later JSON.parses / clones (Next.js __NEXT_DATA__, JSON-LD,
    # Angular/Vue inline state, <template> clones). Reflecting a raw payload
    # into one of these is inert, not XSS.
    NON_EXECUTABLE_SCRIPT_TYPES = (
        "application/json", "application/ld+json", "text/template",
        "text/x-template", "text/html", "application/xml", "text/plain",
        "speculationrules", "importmap",
    )
    # Elements whose text content the HTML parser treats as raw/escapable text,
    # NOT markup. A `<script>` payload sitting inside one of these does not
    # execute unless the payload first closes the element (breakout). Python's
    # html.parser does NOT model these as raw-text elements, so BeautifulSoup
    # would wrongly build child tags inside them — which is exactly why the
    # previous raw-regex path false-flagged reflections in <textarea>/<title>
    # as live script. We detect containment on the raw byte stream instead.
    RAW_TEXT_ELEMENTS = (
        "textarea", "title", "style", "xmp", "iframe", "noframes",
        "noscript", "plaintext", "template", "option",
    )

    @staticmethod
    def _ct_is_html(content_type: str) -> bool:
        """Only a response the browser parses as HTML can run reflected markup.
        A JSON / plain-text / octet-stream / image response that happens to
        echo `<script>` is inert — flagging it is a false positive. Empty /
        unknown Content-Type is treated as HTML (servers default to it)."""
        if not content_type:
            return True
        ct = content_type.split(";", 1)[0].strip().lower()
        if not ct:
            return True
        if ct in ("text/html", "application/xhtml+xml", "application/xml", "text/xml"):
            return True
        # Anything explicitly non-HTML (application/json, text/plain,
        # text/javascript, text/csv, image/*, application/octet-stream, …) is
        # not an HTML execution context.
        return False

    def validate_reflection(
        self,
        body: str,
        payload: str,
        context: str = "any",
        content_type: str | None = None,
    ) -> dict:
        """
        Validate that a reflected payload is actually EXECUTABLE in the DOM
        context it landed in — not merely present in the response.

        The guiding rule for a near-zero false-positive rate: a reflection is
        only exploitable when the payload introduces live markup/script that
        the browser will act on. Reflection as inert text (page body text,
        a <textarea>/<title> value, an HTML comment, a JSON <script> data
        block, a quoted attribute the payload can't break out of, or a
        non-HTML response) is explicitly NOT reported.

        Args:
            body: Response body
            payload: The injected payload string
            context: Caller's context hint (advisory only)
            content_type: Response Content-Type — a non-HTML type is inert

        Returns:
            {"exploitable": bool, "context": str, "confidence": str,
             "confidence_score": int, "reason": str}
        """
        def verdict(exploitable, ctx, score, reason):
            label = ("CONFIRMED" if score >= 95 else "HIGH" if score >= 75
                     else "MEDIUM" if score >= 50 else "LOW")
            return {"exploitable": bool(exploitable), "context": ctx,
                    "confidence": label, "confidence_score": score, "reason": reason}

        if not body or not payload or payload not in body:
            return verdict(False, "none", 0, "Payload not reflected")

        # A non-HTML response can't execute reflected markup, full stop.
        if content_type is not None and not self._ct_is_html(content_type):
            return verdict(False, "non_html", 0,
                           f"Reflected in a non-HTML response ({content_type.split(';')[0].strip()}) — inert")

        # Entity-encoded everywhere it appears → safe.
        import html as _html
        encoded = _html.escape(payload, quote=True)
        if encoded != payload and encoded in body and payload not in body.replace(encoded, ""):
            return verdict(False, "encoded", 5, "Payload is HTML-entity encoded")

        low_body = body.lower()
        low_pl = payload.lower()

        # Judge EVERY reflection site; report the first that is genuinely
        # executable. If none is, return the most specific "safe" reason seen.
        best_safe = None
        start = 0
        while True:
            idx = body.find(payload, start)
            if idx == -1:
                break
            start = idx + 1
            res = self._classify_reflection(body, low_body, payload, low_pl, idx)
            if res["exploitable"]:
                return res
            if best_safe is None or res["confidence_score"] > best_safe["confidence_score"]:
                best_safe = res
        return best_safe or verdict(False, "unknown", 25, "Payload reflected but context not executable")

    def _classify_reflection(self, body, low_body, payload, low_pl, idx):
        """Classify a single reflection site at `idx` and decide exploitability."""
        def verdict(exploitable, ctx, score, reason):
            label = ("CONFIRMED" if score >= 95 else "HIGH" if score >= 75
                     else "MEDIUM" if score >= 50 else "LOW")
            return {"exploitable": bool(exploitable), "context": ctx,
                    "confidence": label, "confidence_score": score, "reason": reason}

        # 1. Raw-text element containment (textarea/title/style/script/…).
        for tag in self.RAW_TEXT_ELEMENTS + ("script",):
            otag = "<" + tag
            open_pos = low_body.rfind(otag, 0, idx)
            if open_pos == -1:
                continue
            nxt = low_body[open_pos + len(otag): open_pos + len(otag) + 1]
            if nxt not in ("", ">", " ", "/", "\t", "\n", "\r"):
                continue  # e.g. "<title" matched inside "<titlebar"
            close_pos = low_body.rfind("</" + tag, 0, idx)
            if open_pos <= close_pos:
                continue  # the element already closed before the reflection
            # Reflection is inside this element's text content.
            if tag == "script":
                tag_end = low_body.find(">", open_pos)
                open_tag = low_body[open_pos:tag_end + 1] if tag_end != -1 else ""
                m = re.search(r'type\s*=\s*["\']?([^"\'>\s]+)', open_tag)
                stype = (m.group(1) if m else "").lower()
                if stype and stype in self.NON_EXECUTABLE_SCRIPT_TYPES:
                    return verdict(False, "script_data_block", 5,
                                   f"Reflected inside inert <script type=\"{stype}\"> data block")
                # Executable script: only exploitable on a real breakout.
                if "</script" in low_pl:
                    return verdict(True, "js_context_breakout", 90,
                                   "Payload closes the <script> block and injects new markup")
                content_start = tag_end + 1 if tag_end != -1 else open_pos + len(otag)
                if self._js_string_breakout(body, payload, idx, content_start):
                    return verdict(True, "js_context", 80,
                                   "Payload breaks out of the JS string literal it is reflected into")
                return verdict(False, "js_string_contained", 20,
                               "Reflected inside a JS string without an unescaped breakout")
            else:
                if ("</" + tag) in low_pl:
                    return verdict(True, "rawtext_breakout", 85,
                                   f"Payload closes <{tag}> and injects new markup")
                return verdict(False, "rawtext_contained", 15,
                               f"Reflected as inert text inside <{tag}>")

        # 2. HTML comment containment.
        c_open = low_body.rfind("<!--", 0, idx)
        c_close = low_body.rfind("-->", 0, idx)
        if c_open > c_close:
            if "-->" in payload:
                return verdict(True, "html_comment_breakout", 80,
                               "Payload closes the HTML comment and injects new markup")
            return verdict(False, "html_comment", 10, "Reflected inside an HTML comment, no breakout")

        # 3. Inside a tag (attribute region) vs. in element text.
        lt = body.rfind("<", 0, idx)
        gt = body.rfind(">", 0, idx)
        if lt > gt:
            return self._classify_attribute(body, payload, idx)

        # 4. Element text content — exploitable only if the payload introduces
        #    a live tag or event handler, unescaped.
        return self._classify_body_text(body, payload, idx)

    @staticmethod
    def _LIVE_TAG_RE():
        return re.compile(
            r'<\s*(script|img|svg|iframe|body|details|input|object|embed|video|'
            r'audio|marquee|form|style|base|link|meta|math|a|button|select|'
            r'textarea|isindex|frame|frameset)[\s/>]', re.I)

    def _classify_body_text(self, body, payload, idx):
        def verdict(exploitable, ctx, score, reason):
            label = ("CONFIRMED" if score >= 95 else "HIGH" if score >= 75
                     else "MEDIUM" if score >= 50 else "LOW")
            return {"exploitable": bool(exploitable), "context": ctx,
                    "confidence": label, "confidence_score": score, "reason": reason}

        live_tag = self._LIVE_TAG_RE()
        # The payload must itself contain a live tag, and that same tag text
        # must be present unescaped at the reflection site (payload matched
        # verbatim at idx, so `<`/`>` are real characters here).
        if live_tag.search(payload):
            seg = body[idx: idx + len(payload)]
            if live_tag.search(seg):
                return verdict(True, "html_body", 95,
                               "Payload injects a live HTML tag, unescaped, into page body")
        # Event handler introduced directly (e.g. onerror=/onload=).
        if re.search(r'\bon[a-z]{3,}\s*=', payload, re.I):
            seg = body[idx: idx + len(payload)]
            if re.search(r'<[^>]*\bon[a-z]{3,}\s*=', seg, re.I):
                return verdict(True, "html_body", 85,
                               "Payload injects an inline event handler, unescaped, into page body")
        return verdict(False, "html_body_text", 20,
                       "Reflected as inert text in page body (no live tag/handler introduced)")

    def _classify_attribute(self, body, payload, idx):
        def verdict(exploitable, ctx, score, reason):
            label = ("CONFIRMED" if score >= 95 else "HIGH" if score >= 75
                     else "MEDIUM" if score >= 50 else "LOW")
            return {"exploitable": bool(exploitable), "context": ctx,
                    "confidence": label, "confidence_score": score, "reason": reason}

        # Breakout to a brand-new tag: payload must contain `>` AND open a tag.
        if ">" in payload and re.search(r'<\s*\w+', payload):
            seg = body[idx: idx + len(payload)]
            if ">" in seg and re.search(r'<\s*\w+', seg):
                return verdict(True, "html_attr_tag_breakout", 90,
                               "Payload closes the tag and injects new markup from an attribute")
        # New event-handler attribute: needs a quote that terminates the
        # current attribute value AND an on*= handler, both unescaped.
        has_handler = re.search(r'\bon[a-z]{3,}\s*=', payload, re.I)
        quote = next((q for q in ('"', "'") if q in payload), None)
        if has_handler and quote and self._unescaped_occurrence(body, payload, idx):
            return verdict(True, "html_attr_handler_injection", 80,
                           "Payload breaks the attribute quote and injects an event handler")
        # javascript:/data: URI landing in an href/src-style attribute.
        if re.match(r'\s*(javascript|data)\s*:', payload, re.I):
            before = body[max(0, idx - 80):idx].lower()
            if re.search(r'(href|src|action|formaction|xlink:href|data)\s*=\s*["\']?\s*$', before):
                return verdict(True, "url_attr", 80,
                               "Scheme-bearing payload lands in a URL attribute (javascript:/data:)")
        return verdict(False, "html_attr_contained", 20,
                       "Reflected inside an attribute value without an unescaped breakout")

    @staticmethod
    def _looks_blocked(resp):
        """True if `resp` looks like a WAF/edge block or a server error page
        rather than an application response — used to stop a blocked probe
        from masquerading as a boolean-injection differential. 404 is
        deliberately NOT treated as a block: 'record not found' is a legitimate
        boolean-false signal."""
        if resp is None:
            return False
        if getattr(resp, "status_code", 200) in (401, 403, 406, 429, 500, 501, 503):
            return True
        low = (getattr(resp, "text", "") or "").lower()
        needles = (
            "access denied", "request blocked", "attention required",
            "web application firewall", "you have been blocked", "not acceptable",
            "cloudflare", "akamai", "incapsula", "request unsuccessful",
            "reference #", "support id:", "blocked by",
        )
        return any(n in low for n in needles)

    @staticmethod
    def _unescaped_occurrence(body, payload, near_idx):
        """True if the payload's first character is NOT backslash-escaped.
        `payload in body` is not enough: a server that emits `\\'` still
        contains the raw `';…` as a substring, so a naive membership test
        treats an escaped quote as a live breakout.

        When `near_idx` points at a real occurrence, judge THAT site (an
        odd run of preceding backslashes = escaped); otherwise fall back to
        scanning for any unescaped occurrence."""
        def _unescaped_at(p):
            bs, j = 0, p - 1
            while j >= 0 and body[j] == "\\":
                bs += 1
                j -= 1
            return bs % 2 == 0

        if (near_idx is not None and 0 <= near_idx
                and body[near_idx:near_idx + len(payload)] == payload):
            return _unescaped_at(near_idx)

        p = body.find(payload)
        while p != -1:
            if _unescaped_at(p):
                return True
            p = body.find(payload, p + 1)
        return False

    @staticmethod
    def _open_js_string_quote(prefix):
        """Return the delimiter ("'", '"', or '`') of the JS string literal
        that is still OPEN at the end of `prefix`, else None.

        Walks the script text tracking string state and skipping `//` line
        and `/* */` block comments, so a quote inside a comment or a closed
        string doesn't flip state. A comment left unterminated at the end
        means the reflection is commented out → None. Conservative: it does
        not parse regex literals, so on ambiguity it may return None and the
        caller declines (under-reports rather than false-positives)."""
        i, n = 0, len(prefix)
        quote = None
        while i < n:
            c = prefix[i]
            if quote:
                if c == "\\":
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in ("'", '"', "`"):
                quote = c
                i += 1
                continue
            if c == "/" and i + 1 < n:
                nxt = prefix[i + 1]
                if nxt == "/":
                    j = prefix.find("\n", i + 2)
                    if j == -1:
                        return None
                    i = j + 1
                    continue
                if nxt == "*":
                    j = prefix.find("*/", i + 2)
                    if j == -1:
                        return None
                    i = j + 2
                    continue
            i += 1
        return quote

    def _js_string_breakout(self, body, payload, idx, content_start=0):
        """Confirm a JS-context payload actually breaks out of the string
        literal it is reflected into AT THIS reflection site (`idx`), rather
        than sitting inertly inside it. This is the single biggest historical
        XSS false-positive source, so the bar is high:

          * the reflection must sit inside an OPEN JS string whose delimiter
            is the SAME quote the payload uses to break out — a `'` does
            nothing inside a "double-quoted" string (the exact FP that fires
            when a page echoes the request URL into a double-quoted analytics
            blob like `"page_location":"...utm_source=';alert(1)//"`), and
          * that breakout quote must not be backslash-escaped at the site.

        Conservative by design: if the enclosing string can't be resolved, or
        the reflection is inside a comment, or no string is open, we decline."""
        lead = payload.lstrip("\\")
        q = lead[0] if lead[:1] in ("'", '"', "`") else None
        # `'-alert(1)-'`, `';alert(1)//`, `";alert(1)//`, `\\';alert(1)//`
        if q is None and ("-alert" in payload or ";alert" in payload):
            q = next((c for c in ("'", '"', "`") if c in payload), None)

        if q is None:
            # Template-literal / expression injection that needs no quote —
            # only live inside a backtick template.
            if payload.strip().startswith("${") or payload.strip().startswith("}"):
                return self._open_js_string_quote(body[content_start:idx]) == "`"
            return False

        # Absolute position of the breakout quote within this reflection.
        qpos = payload.find(q)
        if qpos == -1:
            return False
        qabs = idx + qpos

        # The reflection must break out of a string opened by the SAME quote.
        if self._open_js_string_quote(body[content_start:qabs]) != q:
            return False

        # ...and that quote must not be escaped (odd run of backslashes) here.
        bs, j = 0, qabs - 1
        while j >= content_start and body[j] == "\\":
            bs += 1
            j -= 1
        return bs % 2 == 0

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 5: AI Semantic Verification
    # ═══════════════════════════════════════════════════════════════════════════

    def ai_verify(
        self,
        finding_type: str,
        url: str,
        baseline_response: str,
        payload_response: str,
        payload: str,
        extra_context: str = "",
    ) -> dict:
        """
        Use NVIDIA NIM AI to semantically evaluate whether a finding is genuine.

        Returns:
            {"is_vulnerable": bool, "confidence": float, "reasoning": str}
        """
        if not self.ai or not self.ai.enabled:
            return {"is_vulnerable": True, "confidence": 0.5, "reasoning": "AI unavailable — manual review recommended"}

        system = (
            "You are a senior penetration tester reviewing automated scanner output. "
            "Your job is to determine if a finding is a TRUE vulnerability or a FALSE POSITIVE. "
            "Consider: SPA routing, public data, generic error pages, CDN caching, parameter reflection "
            "without execution, and other common false positive causes. "
            "Respond with ONLY valid JSON: "
            '{"is_vulnerable": true/false, "confidence": 0.0-1.0, "reasoning": "one sentence"}'
        )

        user = (
            f"Finding type: {finding_type}\n"
            f"URL: {url}\n"
            f"Payload: {payload}\n"
            f"Baseline response (first 500 chars):\n{baseline_response[:500]}\n\n"
            f"Payload response (first 500 chars):\n{payload_response[:500]}\n\n"
            f"{extra_context}\n\n"
            "Is this a genuine vulnerability or a false positive?"
        )

        result = self.ai._call(system, user, max_tokens=200)
        if result:
            try:
                import json
                start = result.find("{")
                end = result.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(result[start:end])
            except Exception:
                pass

        return {"is_vulnerable": True, "confidence": 0.5, "reasoning": "AI response parse failed — flagging for manual review"}

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _structural_hash(self, body: str) -> str:
        """
        Hash of the response's structure for differential comparison.
        JSON bodies (the norm for REST APIs) are hashed by key-path shape,
        not raw HTML-tag sequence — the tag regex finds nothing in a JSON
        body, which previously made every JSON response hash identically
        (MD5 of an empty string) and silently turned the structural-equality
        check in differential_test()/validate_time_based() into a no-op for
        any JSON API. Falls back to HTML tag-sequence hashing otherwise.
        """
        stripped = body.strip()
        if stripped[:1] in ("{", "["):
            try:
                data = json.loads(stripped)
                paths = sorted(_json_shape_paths(data))
                return hashlib.md5("|".join(paths).encode()).hexdigest()
            except Exception:
                pass

        tags = re.findall(r'</?[a-zA-Z][a-zA-Z0-9]*[^>]*>', body)
        normalized = []
        for tag in tags[:200]:
            match = re.match(r'</?([a-zA-Z][a-zA-Z0-9]*)', tag)
            if match:
                normalized.append(match.group(0).lower())
        structure = "|".join(normalized)
        return hashlib.md5(structure.encode()).hexdigest()

    @staticmethod
    def compute_confidence(
        checks_passed: int,
        checks_total: int,
        verification_type: str = "heuristic",
    ) -> tuple[str, int]:
        """
        Compute confidence label and score from validation results.

        Args:
            checks_passed: Number of validation checks that passed
            checks_total: Total validation checks performed
            verification_type: "confirmed" (OAST/exec), "differential", "heuristic", "static"

        Returns:
            (confidence_label, confidence_score)
        """
        if checks_total == 0:
            return ("LOW", 25)

        ratio = checks_passed / checks_total

        # Type multiplier
        multipliers = {
            "confirmed": 1.0,      # OAST callback, code execution
            "differential": 0.9,   # Boolean/timing differential
            "heuristic": 0.7,      # Pattern matching with validation
            "static": 0.5,         # Static analysis only
        }
        mult = multipliers.get(verification_type, 0.7)

        score = int(ratio * 100 * mult)
        score = max(5, min(100, score))

        if score >= 95:
            return ("CONFIRMED", score)
        elif score >= 75:
            return ("HIGH", score)
        elif score >= 50:
            return ("MEDIUM", score)
        else:
            return ("LOW", score)

    def validate_cookie_is_session(self, cookie_name: str) -> bool:
        """
        Check if a cookie name is likely a session cookie (vs analytics/tracking).
        Used to fix false positives in headers.py.
        """
        session_indicators = [
            "session", "sess", "sid", "token", "auth", "jwt",
            "csrf", "xsrf", "login", "user", "identity",
            "phpsessid", "jsessionid", "asp.net_sessionid",
            "connect.sid", "laravel_session", "ci_session",
        ]
        tracking_cookies = [
            "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl",
            "__utma", "__utmb", "__utmc", "__utmz",
            "_hjid", "_hjFirstSeen", "mp_", "ajs_",
            "intercom-", "hubspot", "optimizely", "vwo_",
        ]

        name_lower = cookie_name.lower()

        # Known tracking cookies
        for tracker in tracking_cookies:
            if name_lower.startswith(tracker) or name_lower == tracker:
                return False

        # Known session indicators
        for indicator in session_indicators:
            if indicator in name_lower:
                return True

        # If not clearly tracking and not clearly session, treat as unknown
        return False

    def validate_ssrf_indicator(self, indicator: str, payload_url: str, response_body: str) -> bool:
        """
        Validate an SSRF indicator isn't just the payload URL being reflected.
        Fixes the critical bug where ssrf.py matched its own injected URL string.
        """
        # If the indicator string is a substring of the payload URL itself,
        # we need to check it's not just reflection
        if indicator.lower() in payload_url.lower():
            # The indicator is part of the payload — check if it appears
            # OUTSIDE the reflected payload URL in the response
            # Remove all occurrences of the payload URL from the body
            cleaned = response_body.replace(payload_url, "")
            return indicator in cleaned

        # Indicator is not in the payload — safe to check directly
        return indicator in response_body
