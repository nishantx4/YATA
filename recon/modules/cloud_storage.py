"""
CloudStorageModule — public cloud storage misconfiguration detection.

SSRF already probes cloud METADATA endpoints (169.254.169.254 etc.) from
inside a vulnerable server; this is the complementary, externally-facing
check: does this target have an S3 bucket / GCS bucket / Azure Blob
container sitting out there, publicly LISTABLE, under a plausibly-guessable
name derived from the domain? A public listing is a direct, serious
information-disclosure finding on its own (object keys often reveal far
more than they should) — this module never attempts to read individual
object contents, only detects whether the bucket-level listing itself is
public.
"""
import re
import time
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from recon.modules import BaseModule


# XML markers that distinguish "bucket exists and is PUBLICLY LISTABLE"
# from "bucket exists but access denied" / "no such bucket" — S3 and GCS
# both speak the same S3-compatible XML listing API.
_PUBLIC_LISTING_MARKERS = ("<ListBucketResult", "<Contents>", "<Key>")
_EXISTS_BUT_DENIED_MARKERS = ("AccessDenied", "<Code>AccessDenied</Code>")
_NOT_FOUND_MARKERS = ("NoSuchBucket", "BucketNotFound", "ContainerNotFound")

# Common container/subpath name guesses for Azure Blob, where the bucket
# equivalent (a "container") sits one level below the account name.
_AZURE_CONTAINER_GUESSES = ["data", "files", "public", "backup", "images",
                             "uploads", "documents", "static", "media", "assets"]


class CloudStorageModule(BaseModule):
    NAME = "Cloud Storage Exposure"

    def run(self):
        self.ui.section("Cloud Storage — Public Bucket/Container Exposure")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        candidates = self._candidate_names()
        candidates += self._names_from_endpoints()
        candidates = sorted(set(c for c in candidates if c))[:25]

        if not candidates:
            self.ui.info("No plausible bucket/container name candidates derived — skipping.")
            return

        self.ui.info(f"Testing {len(candidates)} candidate name(s) across S3/GCS/Azure Blob...")
        found = 0
        for name in candidates:
            found += self._test_s3(s, name)
            time.sleep(self.delay)
            found += self._test_gcs(s, name)
            time.sleep(self.delay)
            found += self._test_azure(s, name)
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No publicly-listable cloud storage buckets/containers found.")
        else:
            self.ui.ok(f"Cloud storage scan complete — {found} exposed bucket(s)/container(s)")

    # ─────────────────────────────────────────────────────────────────────────
    def _candidate_names(self):
        domain = self.target.split(':')[0].lower()
        parts = domain.split('.')
        skip_prefixes = {"www", "app", "api", "cdn", "static", "assets", "media", "img"}
        company = parts[0] if parts and parts[0] not in skip_prefixes else (parts[1] if len(parts) > 1 else (parts[0] if parts else domain))

        variants = {
            domain, domain.replace('.', '-'), domain.replace('.', ''), company,
            f"{company}-backup", f"{company}-data", f"{company}-files", f"{company}-assets",
            f"{company}-static", f"{company}-prod", f"{company}-dev", f"{company}-staging",
            f"{company}-uploads", f"{company}-media", f"www-{company}", f"{company}-www",
            f"{company}-storage", f"{company}-images", f"{company}-public",
        }
        return [v for v in variants if v]

    def _names_from_endpoints(self):
        """Pull any bucket-shaped hostnames already sitting in crawled
        endpoints/subdomains — a page that already links directly to its
        own bucket is the strongest possible candidate."""
        names = []
        bucket_re = re.compile(
            r'([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.(?:s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|'
            r'blob\.core\.windows\.net)|storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61})',
            re.I,
        )
        for ep in list(self.ctx.get("endpoints", []))[:200] + list(self.ctx.get("subdomains", []))[:50]:
            for m in bucket_re.finditer(ep):
                names.append((m.group(1) or m.group(2) or "").lower())
        return names

    def _classify(self, resp):
        """Returns 'public', 'exists_private', 'not_found', or 'unknown'."""
        if resp is None:
            return "unknown"
        body = resp.text[:2000] if hasattr(resp, "text") else ""
        if resp.status_code == 200 and any(m in body for m in _PUBLIC_LISTING_MARKERS):
            return "public"
        if any(m in body for m in _NOT_FOUND_MARKERS) or resp.status_code == 404:
            return "not_found"
        if resp.status_code in (403, 401) or any(m in body for m in _EXISTS_BUT_DENIED_MARKERS):
            return "exists_private"
        return "unknown"

    def _report(self, provider, name, url, sample_keys):
        self.db.add(
            title=f"Public {provider} Bucket — Listing Enabled ({name})",
            severity="high", url=url, module=self.NAME,
            description=(
                f"The {provider} bucket/container '{name}' is publicly listable — anyone can "
                f"enumerate every object it contains without authentication. "
                + (f"Sample object key(s) observed: {', '.join(sample_keys[:5])}." if sample_keys else "")
            ),
            remediation=(
                f"Disable public listing on this {provider} bucket/container (block public "
                "access at the bucket policy / IAM level). Review whether any objects inside "
                "it are themselves individually publicly readable, which would be a separate, "
                "likely more severe, finding."
            ),
            cvss="7.5", confidence="CONFIRMED", confidence_score=95,
            validation_steps=["bucket_name_guessed_or_discovered", "public_listing_xml_returned"],
            evidence=[f"URL: {url}"] + [f"Key: {k}" for k in sample_keys[:5]],
        )
        self.ui.find("high", f"Public {provider} bucket listing — {name}", url)

    def _extract_keys(self, body):
        return re.findall(r'<Key>([^<]+)</Key>', body)[:10]

    # ─────────────────────────────────────────────────────────────────────────
    def _test_s3(self, s, name):
        for url in (f"https://{name}.s3.amazonaws.com/",
                    f"https://s3.amazonaws.com/{urllib.parse.quote(name)}/"):
            try:
                resp = s.get(url, timeout=self.timeout)
            except Exception:
                continue
            if self._classify(resp) == "public":
                self._report("AWS S3", name, url, self._extract_keys(resp.text))
                return 1
        return 0

    def _test_gcs(self, s, name):
        url = f"https://storage.googleapis.com/{urllib.parse.quote(name)}/"
        try:
            resp = s.get(url, timeout=self.timeout)
        except Exception:
            return 0
        if self._classify(resp) == "public":
            self._report("Google Cloud Storage", name, url, self._extract_keys(resp.text))
            return 1
        return 0

    def _test_azure(self, s, name):
        # Azure Blob needs an account + a container; try the handful of
        # most common container names under this account-name guess.
        for container in _AZURE_CONTAINER_GUESSES[:6]:
            url = f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                resp = s.get(url, timeout=self.timeout)
            except Exception:
                continue
            if resp.status_code == 200 and "<EnumerationResults" in resp.text[:500]:
                names = re.findall(r'<Name>([^<]+)</Name>', resp.text)[:10]
                self._report("Azure Blob", f"{name}/{container}", url, names)
                return 1
            time.sleep(self.delay * 0.5)
        return 0
