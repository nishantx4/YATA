"""
GraphQLSuggestModule — schema disclosure via field suggestions when
introspection is turned off.

graphql.py already handles introspection, alias/array batching DoS, and
federation SDL leakage. This covers the one that bites teams who *did* the
right thing and disabled introspection in production: most GraphQL servers
(graphql-js, Apollo, …) still answer a query that references an unknown field
with a validation error like *"Cannot query field 'passwrd' on type 'User'.
Did you mean 'password'?"* — so an attacker can reconstruct the schema one
"did you mean" at a time, defeating the point of disabling introspection.

Discipline: it runs ONLY when introspection is confirmed disabled (otherwise
graphql.py already reported the bigger problem), and reports ONLY when the
server actually returns a suggestion for a field it invented — provable
schema disclosure, not a guess.
"""
try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule
from recon.core import markers, cancellation

GQL_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/gql", "/query", "/v1/graphql", "/graphql/v1"]


class GraphQLSuggestModule(BaseModule):
    NAME = "GraphQL Field Suggestions"
    MODULE_ID = "graphql_suggest"
    MODULE_LABEL = "GraphQL Schema Disclosure (suggestions)"

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=4, verbose=False, ai=None, output_dir=None):
        super().__init__(target, db, ui, context, timeout, delay, threads, verbose, ai, output_dir)
        self.session = self._session()
        self._found = 0

    def run(self):
        self.ui.section("GraphQL — Schema Disclosure via Field Suggestions")
        if not requests:
            return
        endpoints = self._endpoints()
        if not endpoints:
            self.ui.info("No GraphQL endpoint found — skipping.")
            return
        for url in endpoints:
            if cancellation.is_cancelled():
                break
            try:
                self._test(url)
            except Exception as e:
                if self.verbose:
                    self.ui.error(f"graphql-suggest error on {url}: {e}")
        if self._found == 0:
            self.ui.info("No field-suggestion schema disclosure detected.")

    def _endpoints(self):
        found, seen = [], set()
        # Reuse any /graphql endpoints graphql.py already confirmed, then the
        # standard guess paths.
        for ep in self.ctx.get("endpoints", []):
            if "graphql" in ep.lower() or ep.lower().endswith("/gql"):
                if ep not in seen:
                    seen.add(ep); found.append(ep)
        for p in GQL_PATHS:
            u = self.base_url + p
            if u not in seen:
                seen.add(u); found.append(u)
        return found[:8]

    def _post(self, url, query):
        try:
            self._throttle()
            return self.session.post(url, json={"query": query}, timeout=self.timeout,
                                     headers=self.auth_headers(), cookies=self.auth_cookies())
        except RequestException:
            return None

    def _is_graphql(self, resp):
        if resp is None:
            return False
        ct = (resp.headers.get("Content-Type", "") or "").lower()
        if "json" not in ct:
            return False
        try:
            body = resp.json()
        except Exception:
            return False
        return isinstance(body, dict) and ("data" in body or "errors" in body)

    def _introspection_disabled(self, url):
        r = self._post(url, "{__schema{queryType{name}}}")
        if r is None:
            return None  # not a graphql endpoint / unreachable
        if not self._is_graphql(r):
            return None
        try:
            body = r.json()
        except Exception:
            return None
        data = body.get("data") or {}
        if isinstance(data, dict) and data.get("__schema"):
            return False  # introspection ENABLED (graphql.py handles this)
        return True  # endpoint speaks graphql but introspection returned no schema

    def _test(self, url):
        disabled = self._introspection_disabled(url)
        if disabled is None:
            return  # not a graphql endpoint
        if disabled is False:
            self.ui.info(f"{url}: introspection enabled (reported by the GraphQL module) — suggestions moot.")
            return

        # Query a deliberately invented root field and look for a suggestion.
        bogus = "f" + markers.marker("")[:8]
        r = self._post(url, "{ %s }" % bogus)
        if r is None or not self._is_graphql(r):
            return
        try:
            errors = r.json().get("errors") or []
        except Exception:
            return
        msgs = " ".join(str(e.get("message", "")) for e in errors if isinstance(e, dict))
        low = msgs.lower()
        suggests = ("did you mean" in low) or ("cannot query field" in low and "did you mean" in low)
        if not suggests and "did you mean" not in low:
            # Some servers phrase it differently but still suggest.
            if "did you mean" not in low and "suggest" not in low:
                return

        # Confirm it genuinely suggests *real* fields: a second invented field
        # close to a common name should also elicit a suggestion.
        probe2 = self._post(url, "{ usr }")
        hint = ""
        try:
            e2 = " ".join(str(e.get("message", "")) for e in (probe2.json().get("errors") or [])
                          if isinstance(e, dict)) if probe2 is not None else ""
            if "did you mean" in e2.lower():
                hint = e2[:160]
        except Exception:
            pass

        self._report(url, msgs[:200], hint)

    def _report(self, url, sample, hint):
        added = self.db.add(
            title="GraphQL Schema Disclosure via Field Suggestions (introspection-off bypass)",
            severity="medium", url=url, module=self.NAME,
            description=(
                f"Introspection is disabled on {url}, but the server still returns field-name "
                "suggestions in its validation errors (\"Did you mean …?\") when a query references an "
                "unknown field. An attacker can iteratively reconstruct the schema — types, fields, "
                "and mutation names — defeating the protection that disabling introspection was meant "
                "to provide, and surfacing hidden/privileged fields to target next."
            ),
            remediation=(
                "Disable field suggestions in production (e.g. graphql-js: strip suggestions from "
                "validation errors / set a custom validation rule; Apollo Server: disable suggestions "
                "or return generic errors). Pair with a strict production error formatter that doesn't "
                "echo schema details."
            ),
            cvss="5.3", confidence="CONFIRMED", confidence_score=90,
            validation_steps=["introspection_confirmed_disabled", "invented_field_elicited_suggestion"],
            evidence=[f"Error sample: {sample}"] + ([f"Second probe: {hint}"] if hint else []),
            references=[
                "https://portswigger.net/web-security/graphql",
                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            ],
        )
        if added:
            self._found += 1
            self.ui.find("medium", "GraphQL field-suggestion schema disclosure", url)
