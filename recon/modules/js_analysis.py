"""
JSModule — YATA RECON module.
"""
import re
import math
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


class JSModule(BaseModule):
    NAME = "JS Analysis"

    SECRET_PATTERNS = [
        (r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
        (r'secret[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
        (r'aws_access_key_id\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', "AWS Access Key"),
        (r'(AKIA[A-Z0-9]{16})', "AWS Access Key"),
        (r'password\s*[=:]\s*["\']([^"\']{6,})["\']', "Hardcoded Password"),
        (r'token\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Token"),
        (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "JWT Token"),
        (r'mongodb\+srv://[^\s"\'<>]+', "MongoDB Connection String"),
        (r'mysql://[^\s"\'<>]+', "MySQL Connection String"),
        (r'postgres://[^\s"\'<>]+', "PostgreSQL Connection String"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
        (r'sk-[A-Za-z0-9]{32,}', "OpenAI/Anthropic API Key"),
        (r'xox[baprs]-[A-Za-z0-9\-]+', "Slack Token"),
        (r'https?://[^/\s"\']+\.internal[^"\'<>\s]*', "Internal URL"),
        (r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^"\'<>\s]*', "Internal IP URL"),
    ]

    def run(self):
        self.ui.section("JavaScript Analysis — Secret & Endpoint Extraction")
        if not requests:
            return

        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        endpoints = self.ctx.get("endpoints", [self.base_url])
        js_files  = [ep for ep in endpoints if ep.endswith(".js")]

        # Also try common JS file paths
        common_js = ["/static/js/main.js", "/js/app.js", "/assets/app.js",
                     "/static/app.js", "/js/bundle.js", "/dist/main.js"]
        for path in common_js:
            js_files.append(urllib.parse.urljoin(self.base_url, path))

        self.ui.info(f"Analyzing {len(js_files)} JavaScript files...")
        found_secrets = []
        new_endpoints = set()
        
        # LinkFinder Regex for extracting endpoints
        link_regex = re.compile(
            r"""
            (?:"|')                               # Start newline delimiter
            (
                ((?:[a-zA-Z]{1,10}://|//)         # Match a scheme [a-Z]*1-10 or //
                [^"'/]{1,}\.                      # Match a domainname (any character + dot)
                [a-zA-Z]{2,}[^"']{0,})            # The domainextension and/or path
                |
                ((?:/|\.\./|\./)                  # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]        # Next character can't be...
                [^"'><,;|()]{1,})                 # Rest of the characters can't be
                |
                ([a-zA-Z0-9_\-/]{1,}/             # Relative endpoint with /
                [a-zA-Z0-9_\-/]{1,}               # Resource name
                \.(?:[a-zA-Z]{1,4}|action)        # Rest + extension (length 1-4 or action)
                (?:[\?|#][^"|']{0,}|))            # ? or # mark with parameters
                |
                ([a-zA-Z0-9_\-/]{1,}/             # REST API (no extension)
                [a-zA-Z0-9_\-/]{3,}               # Proper REST endpoints usually have 3+ chars
                (?:[\?|#][^"|']{0,}|))            # ? or # mark with parameters
                |
                ([a-zA-Z0-9_\-]{1,}               # filename
                \.(?:php|asp|aspx|jsp|json|       # . + extension
                     action|html|js|txt|xml)
                (?:[\?|#][^"|']{0,}|))            # ? or # mark with parameters
            )
            (?:"|')                               # End newline delimiter
            """, re.VERBOSE
        )

        seen_js = set()
        for js_url in js_files[:30]:  # Cap at 30 files
            if js_url in seen_js:
                continue
            seen_js.add(js_url)
            resp = self._get(js_url)
            if not resp or resp.status_code != 200:
                continue
            content = resp.text

            # Secret Extraction
            for pattern, secret_type in self.SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.I):
                    val = match.group(1) if len(match.groups()) > 0 else match.group(0)
                    # Skip obvious test/placeholder values
                    skip = {"your_key", "your_secret", "example", "placeholder",
                            "changeme", "xxxxxxxx", "aaaa", "1234", "test"}
                    if any(s in val.lower() for s in skip):
                        continue
                    found_secrets.append((js_url, secret_type, val[:40]))

            # ── Source map discovery ──────────────────────────────────
            # A deployed .js.map file leaks the ORIGINAL, unminified source
            # (via sourcesContent) — often with comments, full variable
            # names, and secrets that were stripped/renamed out of the
            # minified bundle itself. This is a distinct, high-value
            # surface the minified-content scan above can never see.
            found_secrets.extend(self._check_source_map(js_url, content))

            # Endpoint Extraction (LinkFinder)
            for match in re.finditer(link_regex, content):
                ep = match.group(1).strip()
                if ep and not ep.startswith(('text/html', 'application/')):
                    # Reconstruct full URL if relative
                    if not ep.startswith('http'):
                        ep = urllib.parse.urljoin(self.base_url, ep)
                    new_endpoints.add(ep)

            # ── AI deep analysis of this JS file ────────────────────
            if self.ai and self.ai.enabled and len(content) > 200:
                ai_note = self.ai.analyze_js_content(js_url, content)
                if ai_note:
                    self.ui.subsection(f"AI JS Insight: {js_url.split('/')[-1]}")
                    for line in ai_note.split("\n"):
                        self.ui.raw(f"    {line}")
                    self.ui.blank()

        # Update global endpoints with JS discovered ones
        if new_endpoints:
            self.ui.info(f"LinkFinder regex extracted {len(new_endpoints)} endpoints from JS")
            existing = self.ctx.setdefault("endpoints", [])
            for ep in new_endpoints:
                if ep not in existing:
                    existing.append(ep)

        self.ctx["js_secrets"] = found_secrets
        if found_secrets:
            for url, stype, val in found_secrets:

                # Check FP: low-entropy strings ("aaaaaaaa", "111111", repeated
                # runs) are very unlikely to be a real key/token even if they
                # matched a secret pattern.
                if self._shannon_entropy(val) < 2.5:
                    continue

                # Generic name=value patterns (api_key/secret_key/password/
                # token) match minified bundles CONSTANTLY — i18n strings, form
                # field defaults, cache-busting hashes, class-name chains,
                # validation messages — and are the single biggest secret-scan
                # false-positive source. A generic match is only kept when its
                # captured value genuinely looks like a credential (long,
                # high-entropy, mixed character classes, no whitespace, not a
                # dictionary word/sentence). Provider-specific patterns
                # (AWS/Google/GitHub/Slack/JWT/connection strings) carry their
                # own structure and are trusted directly.
                if stype in self._GENERIC_SECRET_TYPES and not self._looks_like_real_secret(val):
                    continue

                severity, score, extra, cvss = self._classify_secret(stype)
                self.db.add(
                    title=f"Secret Exposed in JavaScript: {stype}",
                    severity=severity,
                    url=url,
                    module=self.NAME,
                    description=f"A {stype} was found in client-side JavaScript: {val}...{extra}",
                    remediation="Remove genuine secrets from client-side code and use server-side "
                                "environment variables. For keys that must ship to the browser "
                                "(e.g. Google Maps / analytics), restrict them by HTTP referrer, "
                                "API, and IP in the provider console.",
                    cvss=cvss,
                    confidence="HIGH" if severity in ("high", "critical") else "MEDIUM",
                    confidence_score=score,
                    validation_steps=["regex_match", "entropy_check"]
                )
                self.ui.find(severity, f"JS Secret: {stype}", url)
        else:
            self.ui.info("No secrets found in JavaScript files.")

    # Secret types that are public-by-design or merely informational when they
    # appear in CLIENT-SIDE JS. A Google browser key is MEANT to be embedded
    # (protected by referrer/API restrictions, not secrecy); an internal URL is
    # info disclosure, not a credential. Reporting these as HIGH "secret
    # exposed / account takeover" is a false positive.
    _LOW_SIGNAL_SECRETS = {
        "Google API Key": ("low", 40,
            " — note: Google browser/Maps/Analytics keys are designed to be embedded in client code "
            "and are protected by HTTP-referrer/API restrictions, not by secrecy. Only a risk if "
            "unrestricted; verify the key's restrictions in the Google Cloud console.", "3.7"),
        "Internal URL": ("info", 30,
            " — internal hostname disclosed in client-side JS (information disclosure, not a credential).", "0.0"),
        "Internal IP URL": ("info", 30,
            " — internal IP/host disclosed in client-side JS (information disclosure, not a credential).", "0.0"),
    }

    # Secret types matched by a GENERIC `name = "value"` regex rather than a
    # provider-specific structure. These require the stricter shape test in
    # _looks_like_real_secret() before being reported, and — even when they
    # pass it — are capped at MEDIUM, because a random-looking value next to
    # the word "token"/"password" in client JS is frequently a nonce, salt,
    # CSRF token or build hash, not a live credential.
    _GENERIC_SECRET_TYPES = {"API Key", "Secret Key", "Hardcoded Password", "Token"}

    # Substrings that mark a captured value as a placeholder/label/example even
    # when it is long and mixed-case enough to clear the entropy bar.
    _NON_SECRET_SUBSTRINGS = (
        "your_", "example", "placeholder", "changeme", "xxxx", "dummy",
        "sample", "redacted", "value", "password", "secret", "token",
        "enter", "please", "invalid", "required", "undefined", "null",
        "function", "object", "default", "123456",
    )

    def _looks_like_real_secret(self, val: str) -> bool:
        """Stricter gate for values captured by a GENERIC secret regex. A real
        leaked key/token is long, high-entropy, mixes letters and digits, and
        contains no whitespace or human-readable label text. This rejects the
        dominant JS false positives — quoted UI strings, field defaults,
        sentences and dictionary words that merely sit next to `password:`/
        `token:` in a bundle — while keeping genuinely random-looking secrets."""
        v = (val or "").strip()
        if len(v) < 16:
            return False
        if any(c.isspace() for c in v):
            return False
        if self._shannon_entropy(v) < 3.5:
            return False
        if not (any(c.isalpha() for c in v) and any(c.isdigit() for c in v)):
            return False
        low = v.lower()
        if any(w in low for w in self._NON_SECRET_SUBSTRINGS):
            return False
        return True

    def _classify_secret(self, stype):
        """Return (severity, confidence_score, description_suffix, cvss) for a
        secret type — public-by-design keys and info-only disclosures are not
        HIGH 'secret exposed' findings, and generic name=value matches that
        cleared the shape test are capped at MEDIUM rather than HIGH."""
        if stype in self._LOW_SIGNAL_SECRETS:
            return self._LOW_SIGNAL_SECRETS[stype]
        if stype in self._GENERIC_SECRET_TYPES:
            return ("medium", 65,
                    " — the value is high-entropy and credential-shaped, but a value next to a "
                    "generic 'key/token/password' name in client JS can also be a nonce, CSRF "
                    "token, salt or build hash. Verify it is a live secret before acting.", "5.3")
        return ("high", 85,
                ". This can enable account compromise, data access, or service abuse.", "7.5")

    def _check_source_map(self, js_url, js_content):
        """
        Probe for a source map for this JS file — the standard convention
        is `{file}.map`, and minifiers also usually emit a
        `//# sourceMappingURL=...` comment naming the exact path (which can
        differ from the convention, e.g. a hashed build filename). If found
        and it carries `sourcesContent` (the original, pre-minification
        source embedded inline — common with webpack/esbuild "inline
        sources" mode), the SAME secret-pattern scan runs against the real
        source instead of the minified bundle.
        """
        found = []
        candidates = [js_url + ".map"]

        m = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', js_content)
        if m:
            mapped = m.group(1).strip()
            if not mapped.startswith("data:"):  # inline data-URI maps aren't worth a second fetch
                candidates.append(urllib.parse.urljoin(js_url, mapped))

        for map_url in dict.fromkeys(candidates):  # de-dupe, preserve order
            try:
                resp = self._get(map_url)
            except Exception:
                continue
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if not isinstance(data, dict) or "sources" not in data:
                continue

            self.ui.ok(f"Source map found: {map_url} ({len(data.get('sources', []))} source file(s))")
            sources_content = data.get("sourcesContent") or []
            sources = data.get("sources") or []

            for i, src_text in enumerate(sources_content):
                if not isinstance(src_text, str) or len(src_text) < 20:
                    continue
                src_name = sources[i] if i < len(sources) else f"source[{i}]"
                for pattern, secret_type in self.SECRET_PATTERNS:
                    for match in re.finditer(pattern, src_text, re.I):
                        val = match.group(1) if len(match.groups()) > 0 else match.group(0)
                        skip = {"your_key", "your_secret", "example", "placeholder",
                                "changeme", "xxxxxxxx", "aaaa", "1234", "test"}
                        if any(s in val.lower() for s in skip):
                            continue
                        found.append((f"{map_url} (source: {src_name})", secret_type, val[:40]))

            if not sources_content and sources:
                # No inline sourcesContent, but the map still names real
                # original file paths — lower-value than a secret, but
                # still genuine internal-structure disclosure worth a look.
                self.ui.info(f"  Source map lists {len(sources)} original file path(s) "
                              f"(no inline source content): {', '.join(sources[:5])}"
                              + ("..." if len(sources) > 5 else ""))
            break  # one working map per JS file is enough
        return found

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Bits of entropy per character — low values mean 'aaaaaa' / '111111'
        style placeholders rather than a real random-looking key/token."""
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ─── Params Module ─────────────────────────────────────────────────────────────