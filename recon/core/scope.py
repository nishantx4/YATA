"""
Scope engine — hard in/out-of-scope enforcement for authorized testing.

A bug-bounty / pentest engagement always has a scope: the hosts you are
allowed to touch and, just as important, the ones you must not. Until now
`--scope` was accepted on the CLI, stored in the report meta, and otherwise
ignored — nothing ever stopped a module (or a synthesized host from
cloud_storage / subdomain_takeover / an open-redirect follow) from firing a
request at something out of scope. For a tool whose whole premise is
*authorized* testing, that's the one guardrail that actually matters.

Rules are host patterns, one per entry:
  * exact host            api.example.com
  * wildcard subtree      *.example.com      (matches foo.example.com AND example.com)
  * bare domain           example.com        (treated as *.example.com + the apex)
  * scheme/port stripped  https://x.com:8443 -> x.com
Out-of-scope rules always win over in-scope rules (a classic "*.example.com
in scope, admin.example.com explicitly out" exclusion).

If no in-scope rules are given, the engine defaults to "the scan target and
its subdomains are in scope" so it never silently blocks the scan it was
launched for.
"""
from __future__ import annotations

import urllib.parse


def _host_of(value: str) -> str:
    """Pull a bare lowercase host out of a URL, host:port, or bare host."""
    if not value:
        return ""
    v = value.strip().lower()
    if "://" in v:
        try:
            v = urllib.parse.urlparse(v).netloc or v.split("://", 1)[1]
        except Exception:
            v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]       # drop any path
    v = v.split("@", 1)[-1]      # drop userinfo
    v = v.split(":", 1)[0]       # drop port
    return v.strip(". ")


class ScopeRule:
    __slots__ = ("host", "wildcard")

    def __init__(self, pattern: str):
        p = (pattern or "").strip().lower()
        self.wildcard = False
        if p.startswith("*."):
            self.wildcard = True
            p = p[2:]
        self.host = _host_of(p)

    def matches(self, host: str) -> bool:
        if not self.host or not host:
            return False
        if host == self.host:
            return True
        # A bare domain and an explicit *.domain both cover subdomains; an
        # exact-host rule only matches that exact host.
        if self.wildcard or _is_registrable_parent(self.host):
            return host.endswith("." + self.host)
        return False


# Treat a 2+-label rule host as a domain whose subdomains are in scope (the
# common bug-bounty reading of "example.com"). A single-label host (rare —
# e.g. "localhost") only matches exactly.
def _is_registrable_parent(host: str) -> bool:
    return host.count(".") >= 1


class ScopeEngine:
    def __init__(self, include=None, exclude=None, target: str | None = None):
        self.include = [ScopeRule(p) for p in (include or []) if p and p.strip()]
        self.exclude = [ScopeRule(p) for p in (exclude or []) if p and p.strip()]
        self.target_host = _host_of(target) if target else ""
        # Default inclusion: the target itself (+ its subdomains), so an
        # engine built with only exclusions, or none at all, never blocks
        # the very target the user asked us to scan.
        if not self.include and self.target_host:
            self.include = [ScopeRule(self.target_host)]
        self.enforcing = bool(self.include or self.exclude)

    @property
    def active(self) -> bool:
        """Whether any explicit rule was supplied (as opposed to the implicit
        target-only default). Used only for messaging."""
        return self.enforcing

    def is_in_scope(self, url_or_host: str) -> bool:
        host = _host_of(url_or_host)
        if not host:
            return False
        for rule in self.exclude:            # exclusions always win
            if rule.matches(host):
                return False
        if not self.include:
            return True
        return any(rule.matches(host) for rule in self.include)

    @staticmethod
    def _fmt(rule) -> str:
        return ("*." + rule.host) if rule.wildcard else rule.host

    def describe(self) -> str:
        inc = ", ".join(self._fmt(r) for r in self.include) or "(none)"
        exc = ", ".join(self._fmt(r) for r in self.exclude) or "(none)"
        return f"in: {inc}  |  out: {exc}"

    # ── construction helpers ────────────────────────────────────────────────
    @classmethod
    def from_args(cls, scope: str | None, scope_file: str | None,
                  out_of_scope, target: str | None):
        include, exclude = [], []
        if scope:
            include += _split_rules(scope)
        if out_of_scope:
            for item in out_of_scope:
                exclude += _split_rules(item)
        if scope_file:
            inc, exc = _read_scope_file(scope_file)
            include += inc
            exclude += exc
        return cls(include=include, exclude=exclude, target=target)


def _split_rules(value: str) -> list[str]:
    out = []
    for chunk in (value or "").replace(";", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            out.append(chunk)
    return out


def _read_scope_file(path: str) -> tuple[list[str], list[str]]:
    """Parse a scope file. Lines beginning with '!' or '-' are exclusions;
    blank lines and '#' comments are ignored. Also accepts a HackerOne/
    Bugcrowd-style JSON export with in_scope/out_of_scope asset lists."""
    include, exclude = [], []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception:
        return include, exclude

    stripped = raw.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            import json
            data = json.loads(raw)
            return _parse_scope_json(data)
        except Exception:
            pass  # fall through to line parsing

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in ("!", "-"):
            exclude.append(line[1:].strip())
        else:
            include.append(line)
    return include, exclude


def _parse_scope_json(data) -> tuple[list[str], list[str]]:
    """Best-effort reader for platform scope exports. Handles both a flat
    {"in_scope": [...], "out_of_scope": [...]} and HackerOne's
    structured_scopes list with asset_identifier + eligible_for_submission."""
    include, exclude = [], []

    def asset_str(item):
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            return (item.get("asset_identifier") or item.get("identifier")
                    or item.get("host") or item.get("target") or item.get("name") or "")
        return ""

    if isinstance(data, dict) and "structured_scopes" in data:
        for s in data["structured_scopes"]:
            ident = asset_str(s)
            if not ident:
                continue
            eligible = s.get("eligible_for_submission", True) if isinstance(s, dict) else True
            (include if eligible else exclude).append(ident)
        return include, exclude

    if isinstance(data, dict):
        for key in ("in_scope", "inScope", "include", "targets"):
            for item in data.get(key, []) or []:
                a = asset_str(item)
                if a:
                    include.append(a)
        for key in ("out_of_scope", "outOfScope", "exclude", "excludes"):
            for item in data.get(key, []) or []:
                a = asset_str(item)
                if a:
                    exclude.append(a)
    elif isinstance(data, list):
        for item in data:
            a = asset_str(item)
            if a:
                include.append(a)
    return include, exclude
