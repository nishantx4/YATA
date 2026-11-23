"""
IDORModule — Insecure Direct Object Reference detection.

Two complementary techniques:

1. Object-ID harvesting + swap: instead of always guessing literal 1/2,
   real object IDs seen elsewhere in the scan (recon.py's crawl/JS-mining
   harvester — ctx['harvested_object_ids']) are swapped into the same
   endpoint template. This is what makes UUID-keyed APIs testable at all —
   a literal-1/2 guesser can never touch them, since a random guessed UUID
   will always 404.

2. Two-role differential access control: when a second, separately
   authenticated identity is supplied (--header2/--cookie2 — see
   yata recon), the SAME object is fetched under both identities and
   compared. This is the real IDOR/broken-access-control test: does a
   *different, genuinely distinct* authenticated user get into an object,
   not just "does removing auth entirely still work."

Both fall back gracefully: single-ID probing still runs without a second
identity, exactly as before.
"""
import re
import time
import difflib
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


ID_PATTERN   = re.compile(r'(.*/)(\d{1,10})(/?(?:\?.*)?)$')
UUID_PATTERN = re.compile(
    r'(.*/)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/?(?:\?.*)?)$'
)
DATA_INDICATORS = ["email", "username", "user_id", "account", "password",
                   "phone", "address", "token", "ssn", "firstname", "lastname",
                   "order", "invoice", "balance"]


class IDORModule(BaseModule):
    NAME = "IDOR Detector"

    def run(self):
        self.ui.section("IDOR — Insecure Direct Object Reference Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        self.session = self._session()
        cookie = self.ctx.get("session_cookie")
        if cookie:
            self.session.headers.update({"Cookie": cookie})
            self.ui.info("Using provided session cookie for authenticated IDOR testing")

        auth_headers = self.ctx.get("auth_headers")
        if auth_headers:
            self.session.headers.update(auth_headers)
            self.ui.info("Using discovered auth header(s) for authenticated IDOR testing")

        # Second identity, if supplied (--header2/--cookie2) — enables the
        # real cross-user differential test in addition to single-ID probing.
        self.session_b = None
        auth_headers_b = self.ctx.get("auth_headers_b")
        auth_cookies_b = self.ctx.get("auth_cookies_b")
        if auth_headers_b or auth_cookies_b:
            self.session_b = self._session()
            if auth_headers_b:
                self.session_b.headers.update(auth_headers_b)
            if auth_cookies_b:
                self.session_b.cookies.update(auth_cookies_b)
            self.ui.info("Second identity supplied — cross-role differential IDOR testing enabled")

        templates = self._collect_id_templates()
        if not templates:
            self.ui.info("No numeric/UUID-ID endpoints found — run recon first or supply ID URLs.")
            return

        harvested = self.ctx.get("harvested_object_ids", set())
        self.ui.info(f"Comparing object access across {len(templates)} ID endpoint(s) "
                      f"({len(harvested)} harvested real ID(s) available)...")
        found = 0

        for prefix, suffix, kind, seen_ids in templates[:30]:
            try:
                if self._test_template(prefix, suffix, kind, seen_ids):
                    found += 1
                if self.session_b and self._test_two_role(prefix, suffix, kind, seen_ids):
                    found += 1
                time.sleep(self.delay)
            except Exception:
                continue

        if found == 0:
            self.ui.info("No IDOR confirmed — manual testing with two accounts still recommended.")
        else:
            self.ui.ok(f"IDOR scan complete — {found} likely finding(s)")

    # ─────────────────────────────────────────────────────────────────────────
    def _collect_id_templates(self):
        """
        Return unique (prefix, suffix, kind, seen_ids) tuples — kind is
        'numeric' or 'uuid', and seen_ids is every literal ID value actually
        observed at that exact template across the whole crawl (not just the
        first one found), so genuinely different real objects can be
        compared instead of only ever guessing 1 vs 2.
        """
        templates = {}  # (prefix, suffix, kind) -> set of literal ids seen

        def add(prefix, suffix, kind, id_val=None):
            key = (prefix, suffix, kind)
            templates.setdefault(key, set())
            if id_val:
                templates[key].add(id_val)

        for ep in self.ctx.get("endpoints", []):
            m = UUID_PATTERN.match(ep)
            if m:
                add(m.group(1), m.group(3), "uuid", m.group(2).lower())
                continue
            m = ID_PATTERN.match(ep)
            if m:
                add(m.group(1), m.group(3), "numeric", m.group(2))

        # Common API object patterns as fallbacks (numeric only — we can't
        # usefully guess a UUID fallback path).
        for pattern in ["/api/v1/users/", "/api/v1/user/", "/api/users/",
                        "/api/v1/document/", "/api/v1/account/", "/api/orders/",
                        "/user/", "/profile/", "/account/", "/document/", "/invoice/"]:
            add(f"{self.base_url}{pattern}", "", "numeric")

        # Path-segment object identifiers from an OpenAPI/Swagger spec.
        for api_ep in self.ctx.get("api_endpoints", []):
            url_template = api_ep.get("url", "")
            path_params = api_ep.get("path_params", [])
            for pname, _ in path_params:
                placeholder = "{" + pname + "}"
                if placeholder not in url_template:
                    continue
                resolved = url_template
                for other_name, other_example in path_params:
                    if other_name == pname:
                        continue
                    default = str(other_example) if other_example else "1"
                    resolved = resolved.replace("{" + other_name + "}", default)
                prefix, _, suffix = resolved.partition(placeholder)
                add(prefix, suffix, "numeric")

        return [(prefix, suffix, kind, ids) for (prefix, suffix, kind), ids in templates.items()]

    def _candidate_ids(self, kind, seen_ids):
        """
        Build a pool of at least 2 distinct real-looking IDs to test with,
        preferring actually-observed ones over guesses:
          1. IDs seen at this exact template during the crawl
          2. Globally harvested IDs of the matching shape (recon.py)
          3. For numeric templates only, "1"/"2" as a last-resort guess —
             there is no safe equivalent guess for a UUID template, so a
             UUID template with nothing harvested is simply skipped.
        """
        harvested = self.ctx.get("harvested_object_ids", set())
        pool = list(seen_ids)

        if kind == "uuid":
            uuid_shaped = [i for i in harvested if UUID_PATTERN.match(f"/{i}")
                           or re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', i)]
            for i in uuid_shaped:
                if i not in pool:
                    pool.append(i)
        else:
            numeric_shaped = [i for i in harvested if re.match(r'^\d{1,12}$', i)]
            for i in numeric_shaped:
                if i not in pool:
                    pool.append(i)
            if len(pool) < 2:
                for fallback in ("1", "2"):
                    if fallback not in pool:
                        pool.append(fallback)

        return pool[:6]  # cap — we only ever compare 2 at a time

    def _fetch(self, prefix, obj_id, suffix, session=None):
        url = f"{prefix}{obj_id}{suffix}"
        sess = session or self.session
        try:
            return url, sess.get(url, timeout=self.timeout)
        except Exception:
            return url, None

    def _looks_like_distinct_data(self, resp_a, resp_b):
        if resp_a is None or resp_b is None:
            return None
        if resp_a.status_code != 200 or resp_b.status_code != 200:
            return None
        body_a, body_b = resp_a.text, resp_b.text
        if len(body_a) < 50 or len(body_b) < 50:
            return None
        looks_like_data = any(ind in body_a.lower() for ind in DATA_INDICATORS)
        ratio = difflib.SequenceMatcher(None, body_a, body_b).quick_ratio()
        distinct = ratio < 0.95 and body_a != body_b
        if not (looks_like_data and distinct):
            return None
        return ratio

    def _test_template(self, prefix, suffix, kind, seen_ids):
        ids = self._candidate_ids(kind, seen_ids)
        if len(ids) < 2:
            return False  # e.g. a UUID template with nothing real harvested — can't guess

        id_a, id_b = ids[0], ids[1]
        url_a, resp_a = self._fetch(prefix, id_a, suffix)
        url_b, resp_b = self._fetch(prefix, id_b, suffix)

        ratio = self._looks_like_distinct_data(resp_a, resp_b)
        if ratio is None:
            return False

        # Optional AI second opinion to cut false positives.
        reason = (f"Two {kind} object IDs returned distinct data-like records "
                  f"(similarity {ratio:.2f}) with no apparent ownership check.")
        confidence = "medium"
        if self.ai and self.ai.enabled:
            try:
                verdict = self.ai.analyze_idor_response(url_a, resp_a.text, id_a)
                if verdict:
                    if not verdict.get("is_idor", True):
                        return False
                    confidence = verdict.get("confidence", confidence)
                    reason = verdict.get("reason", reason)
            except Exception:
                pass

        source_note = " (real harvested IDs, not guessed)" if id_a not in ("1", "2") or id_b not in ("1", "2") else ""
        self.db.add(
            title="Insecure Direct Object Reference (IDOR)",
            severity="high", url=f"{prefix}{{id}}{suffix}", module=self.NAME,
            description=(
                f"Swapping the object ID at {prefix}<id>{suffix} returns different "
                f"per-object records without an authorization check{source_note}. {reason} Confirm by "
                "requesting another user's object ID while authenticated as a low-privilege user."
            ),
            remediation=(
                "Enforce server-side authorization: verify the requesting user owns or may "
                "access the object. Prefer non-sequential identifiers (UUIDs) and per-object "
                "access-control checks."
            ),
            cvss="8.1", confidence=confidence,
            evidence=[f"Object 1: {url_a}", f"Object 2: {url_b}",
                      f"Body similarity: {ratio:.2f}", f"ID type: {kind}"],
            references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
        )
        self.ui.find("high", "IDOR — unprotected object access", f"{prefix}{{id}}{suffix}")
        return True

    # ─────────────────────────────────────────────────────────────────────────
    def _test_two_role(self, prefix, suffix, kind, seen_ids):
        """
        Cross-role differential access-control test. Fetches the SAME
        object URL under two separately-authenticated identities (Session A
        — the scan's primary auth; Session B — --header2/--cookie2) and
        compares. This is the real broken-access-control test the roadmap
        called for: proving a *different, genuinely distinct* authenticated
        user reaches an object, not just that removing auth changes nothing.

        Object *ownership* between A and B is unknown to us — we can't
        prove "this specific object belongs to A" without deeper app
        knowledge — so this is reported at MEDIUM confidence by default,
        stepping up to HIGH only when an unauthenticated canary request to
        the same URL is rejected (proving auth genuinely gates the
        endpoint) while Session B still gets in.
        """
        ids = self._candidate_ids(kind, seen_ids)
        if not ids:
            return False
        obj_id = ids[0]
        url = f"{prefix}{obj_id}{suffix}"

        try:
            resp_a = self.session.get(url, timeout=self.timeout)
        except Exception:
            resp_a = None
        try:
            resp_b = self.session_b.get(url, timeout=self.timeout)
        except Exception:
            resp_b = None

        if resp_a is None or resp_b is None:
            return False
        if resp_a.status_code != 200 or resp_b.status_code != 200:
            return False
        if len(resp_b.text) < 50 or not any(ind in resp_b.text.lower() for ind in DATA_INDICATORS):
            return False

        # Sessions must actually be different credentials for this to mean
        # anything — otherwise we're just comparing a session to itself.
        creds_a = (frozenset(self.ctx.get("auth_headers", {}).items()),
                   frozenset(self.ctx.get("auth_cookies", {}).items()))
        creds_b = (frozenset(self.ctx.get("auth_headers_b", {}).items()),
                   frozenset(self.ctx.get("auth_cookies_b", {}).items()))
        if creds_a == creds_b:
            return False

        confidence, confidence_score = "MEDIUM", 55
        canary_note = ""
        try:
            canary_resp = requests.get(url, timeout=self.timeout, verify=False)
            if canary_resp.status_code in (401, 403):
                confidence, confidence_score = "HIGH", 78
                canary_note = (
                    f" An unauthenticated request to the same URL was rejected ({canary_resp.status_code}), "
                    "confirming this endpoint genuinely gates on identity — yet Session B still got in."
                )
        except Exception:
            pass

        self.db.add(
            title="Cross-Role IDOR — Second Identity Can Access Object",
            severity="high", url=url, module=self.NAME,
            description=(
                f"Object {url} was fetched successfully under TWO separately-authenticated "
                f"identities (different credentials for Session A and Session B).{canary_note} "
                "Manually verify object ownership to confirm this is a genuine cross-tenant/"
                "cross-user exposure rather than a shared/public resource."
            ),
            remediation=(
                "Enforce per-object, per-user authorization checks server-side — verify the "
                "authenticated identity actually owns or is explicitly granted access to the "
                "requested object ID, independent of whether the request is merely authenticated."
            ),
            cvss="8.1", confidence=confidence, confidence_score=confidence_score,
            validation_steps=["two_distinct_identities_used", "both_returned_200_with_data",
                               "credentials_confirmed_different"] + (["unauth_canary_rejected"] if canary_note else []),
            evidence=[f"URL: {url}", f"Object ID: {obj_id}", f"ID type: {kind}"],
            references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
        )
        self.ui.find("high", "Cross-role IDOR — second identity accessed object", url)
        return True


# --- GraphQL Module ---------------------------------------------------------
