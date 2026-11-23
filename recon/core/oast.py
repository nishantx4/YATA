"""
OASTClient — thin wrapper around ProjectDiscovery's interactsh-client for
out-of-band (blind) SSRF/XXE/SSTI confirmation.

Why this exists: in-band detection (grep the HTTP response body for a
leaked indicator string) can only ever prove SSRF into a sink whose
response is reflected back. A "fire-and-forget" webhook validator, an async
worker that fetches a URL and never returns its body, or a metadata request
whose result gets swallowed server-side, are all completely invisible to
that approach — the response looks identical whether the server made the
request or not. OOB confirmation fixes this: we hand the target a URL
under a domain WE control, and if our interaction server later receives a
DNS lookup or HTTP hit correlated to that exact probe, the target
definitely made that outbound request — full stop, no ambiguity.

interactsh-client (already registered in tool_installer.py, but never
wired to anything until now) is a thin CLI over ProjectDiscovery's public
(or self-hosted) interactsh server. `-json` streams one NDJSON line per
interaction as it arrives; the session banner also contains our unique
correlation domain, printed once at startup.
"""
import json as _json
import re
import secrets
import subprocess
import threading
import time

from recon.core.tool_installer import ToolInstaller

# interactsh domains look like <22-char-id>.oast.fun / .oast.live / etc,
# or the hosted interact.sh / interactsh.com — match broadly so a
# self-hosted server with a custom domain still parses (fenced to something
# vaguely domain-shaped rather than tied to a fixed suffix list).
_DOMAIN_RE = re.compile(
    r'\b([a-z0-9]{15,40}\.(?:oast\.(?:fun|live|site|online|pro|me)|interact\.sh|interactsh\.com))\b',
    re.I,
)


class OASTClient:
    """
    Manages one interactsh-client subprocess for the duration of a module's
    OOB probing phase. Usage:

        oast = OASTClient(ui)
        if oast.start():
            label, url = oast.label_url()   # -> ("a1b2c3", "http://a1b2c3.<domain>/")
            ... send `url` as a payload, remembering which (param, url) the
                label belongs to ...
            for interaction in oast.poll(wait=15):
                ... correlate interaction back to a label, report CONFIRMED ...
        oast.stop()
    """

    def __init__(self, ui=None):
        self.ui = ui
        self.proc = None
        self.domain = None
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._reader_thread = None
        self._binary = None

    @property
    def available(self) -> bool:
        if self._binary:
            return True
        try:
            installer = ToolInstaller(self.ui)
            self._binary = installer.get_tool_path("interactsh-client")
        except Exception:
            self._binary = None
        return self._binary is not None

    def start(self, wait_for_domain: float = 12.0) -> bool:
        """Launch interactsh-client -json and block until a session domain
        is parsed from its banner (or the timeout elapses). Returns True on
        success — callers should treat False/exception as "OOB unavailable,
        fall back to in-band only" rather than a hard failure."""
        if not self.available:
            return False
        try:
            self.proc = subprocess.Popen(
                [self._binary, "-json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as e:
            if self.ui:
                self.ui.warn(f"interactsh-client failed to start: {e}")
            return False

        def _read():
            try:
                if not self.proc or not self.proc.stdout:
                    return
                for line in self.proc.stdout:
                    with self._lock:
                        self._lines.append(line.rstrip("\n"))
            except Exception:
                pass

        self._reader_thread = threading.Thread(target=_read, daemon=True)
        self._reader_thread.start()

        deadline = time.time() + wait_for_domain
        while time.time() < deadline:
            with self._lock:
                for line in self._lines:
                    m = _DOMAIN_RE.search(line)
                    if m:
                        self.domain = m.group(1)
                        break
            if self.domain:
                return True
            time.sleep(0.3)
        return self.domain is not None

    def label_url(self, scheme: str = "http", path: str = "/") -> tuple[str, str]:
        """Return (label, url) — url points at a fresh random subdomain
        under our session's correlation domain. The label is what we later
        grep for in returned interaction records to know WHICH probe fired."""
        label = secrets.token_hex(5)
        host = f"{label}.{self.domain}"
        return label, f"{scheme}://{host}{path}"

    def poll(self, wait: float = 12.0) -> list[dict]:
        """Sleep `wait` seconds to give the interactsh server time to poll
        the target's resolvers/deliver callbacks, then return every parsed
        JSON interaction line collected so far (cumulative across the whole
        session, safe to call more than once)."""
        if not self.proc:
            return []
        time.sleep(wait)
        interactions = []
        with self._lock:
            for line in self._lines:
                stripped = line.strip()
                if not stripped.startswith("{"):
                    continue
                try:
                    interactions.append(_json.loads(stripped))
                except Exception:
                    continue
        return interactions

    @staticmethod
    def interaction_label(interaction: dict) -> str:
        """Best-effort extraction of the subdomain label that was hit, from
        whichever field this interactsh version populates."""
        for key in ("full-id", "unique-id", "full_id", "unique_id"):
            val = interaction.get(key)
            if val:
                return str(val).split(".")[0]
        return ""

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
