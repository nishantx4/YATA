"""
DOMXSSModule — client-side / DOM-based XSS detection via a real browser.

Everything else in this codebase tests server RESPONSES: inject a payload,
grep the HTTP response body for it. DOM-based XSS often never touches the
server response at all — a client-side sink (location.hash / location.search
read into innerHTML/document.write/outerHTML/eval without sanitization) is
completely invisible to response-based testing, since the payload is never
sent to the server in the first place when delivered via the URL fragment.

Uses playwright (optional dependency — see core/screenshot.py, already
added for visual evidence) to actually load pages in headless Chromium and
observe real execution, via one payload that proves it regardless of which
unsafe sink caught it: `<img src=x onerror=...>` fires even when inserted
through innerHTML (unlike a bare `<script>` tag, which browsers never
execute when inserted that way) and sets a distinctive window-level marker
we can read back after navigation.
"""
import time
import urllib.parse

from recon.modules import BaseModule

try:
    from recon.core.screenshot import available as _playwright_available
except Exception:
    def _playwright_available():
        return False


MAX_PAGES = 8
_MARKER_PROP = "__yata_recon_dom_xss_fired"
_PAYLOAD = f'"><img src=x onerror="window.{_MARKER_PROP}=(window.{_MARKER_PROP}||0)+1">'

_STATIC_EXTENSIONS = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                      ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip")


class DOMXSSModule(BaseModule):
    NAME = "DOM-Based XSS"

    def run(self):
        self.ui.section("DOM-Based XSS — Client-Side Sink Testing (Real Browser)")
        if not _playwright_available():
            self.ui.info(
                "playwright not installed/configured — skipping DOM XSS testing "
                "(pip install playwright && playwright install chromium)."
            )
            return

        pages = self._collect_pages()
        if not pages:
            self.ui.info("No HTML pages discovered to test.")
            return

        found = 0
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
                try:
                    for page_url in pages:
                        try:
                            found += self._test_page(browser, page_url)
                        except Exception:
                            pass
                        time.sleep(self.delay)
                finally:
                    browser.close()
        except Exception as e:
            self.ui.warn(f"DOM XSS testing could not run: {e}")
            return

        if found == 0:
            self.ui.info("No DOM-based XSS confirmed.")
        else:
            self.ui.ok(f"DOM XSS scan complete — {found} confirmed finding(s)")

    def _collect_pages(self):
        origin = self.base_url.split("://", 1)[-1].split("/", 1)[0]
        pages = {self.base_url}
        for ep in self.ctx.get("endpoints", []):
            path = ep.split("?")[0].split("#")[0]
            if path.lower().endswith(_STATIC_EXTENSIONS):
                continue
            if origin in ep:
                pages.add(ep)
        return list(pages)[:MAX_PAGES]

    def _navigate_and_check(self, browser, url):
        """Load `url` in a fresh, isolated browser context and read back
        whether our marker fired. A fresh context per navigation avoids
        state (localStorage/cookies/window globals) leaking between what
        should be independent probes."""
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        try:
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            page.wait_for_timeout(800)
            marker_value = page.evaluate(f"() => window.{_MARKER_PROP} || 0")
        except Exception:
            marker_value = 0
        finally:
            context.close()
        return marker_value, dialogs

    def _test_page(self, browser, page_url):
        found = 0
        parsed = urllib.parse.urlparse(page_url)
        origin_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Sink 1: URL fragment (location.hash) — never even sent to the
        # server, so a fire here can ONLY be a client-side sink.
        hash_url = f"{origin_path}#{urllib.parse.quote(_PAYLOAD, safe='')}"
        marker, dialogs = self._navigate_and_check(browser, hash_url)
        if marker or dialogs:
            self._report(page_url, "URL fragment (location.hash)", hash_url, dialogs)
            return 1  # one confirmed sink is enough for this page

        # Sink 2: query string (location.search) — reuse a param name
        # already known for this page if we have one, else a handful of
        # common generic guesses.
        qs = urllib.parse.parse_qs(parsed.query)
        param_names = list(qs.keys()) or ["q", "search", "name", "redirect", "callback"]
        for pname in param_names[:3]:
            new_qs = dict(qs)
            new_qs[pname] = [_PAYLOAD]
            query_url = f"{origin_path}?{urllib.parse.urlencode(new_qs, doseq=True)}"
            marker2, dialogs2 = self._navigate_and_check(browser, query_url)
            if marker2 or dialogs2:
                self._report(page_url, f"URL query parameter '{pname}' (location.search)", query_url, dialogs2)
                found += 1
                break

        return found

    def _report(self, page_url, sink, poc_url, dialogs):
        proof = "a JS dialog firing" if dialogs else "a window-level marker being set after our <img onerror> payload rendered"
        self.db.add(
            title=f"DOM-Based XSS — {sink}",
            severity="high", url=page_url, module=self.NAME,
            description=(
                f"Loading {poc_url} in a real headless-browser session caused an injected "
                f"payload to EXECUTE client-side via {sink}, confirmed by {proof}. The page's "
                "own JavaScript reads this client-side value and inserts it into the DOM (or "
                "evaluates it) without sanitization. This never touches the server response "
                "at all — invisible to every response-based XSS check."
            ),
            remediation=(
                "Never insert location.hash/location.search values into the DOM via "
                "innerHTML/outerHTML/document.write/eval without sanitization. Use "
                "textContent for plain text, or a sanitization library (e.g. DOMPurify) when "
                "HTML genuinely needs to be inserted."
            ),
            cvss="6.1", confidence="CONFIRMED", confidence_score=95,
            validation_steps=["real_browser_navigation", "payload_executed_client_side"],
            evidence=[f"PoC URL: {poc_url}"] +
                     ([f"Dialog message: {dialogs[0][:200]}"] if dialogs else ["window-level execution marker observed"]),
        )
        self.ui.find("high", f"DOM-Based XSS — {sink}", page_url)
