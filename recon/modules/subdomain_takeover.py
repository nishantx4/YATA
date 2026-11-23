"""
SubdomainTakeoverModule — YATA RECON module.
Detects dangling CNAME records pointing to deprovisioned services.
"""
import time

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from recon.modules import BaseModule


# Service fingerprints: CNAME pattern → (service_name, response_signature)
TAKEOVER_SIGNATURES = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "no-such-app"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "s3-website": ("AWS S3 Website", "NoSuchBucket"),
    "cloudfront.net": ("AWS CloudFront", "Bad request"),
    # Empty signature = no reliable body fingerprint exists for this service;
    # it can only be confirmed via NXDOMAIN, so it deliberately never
    # auto-confirms on a resolving-but-unclaimed CNAME (avoids false positives
    # on a documented edge case — see the community can-i-take-over-xyz list).
    "azurewebsites.net": ("Azure App Service", "404 web site not found"),
    "cloudapp.azure.com": ("Azure Cloud Service", "404 web site not found"),
    "trafficmanager.net": ("Azure Traffic Manager", ""),
    "blob.core.windows.net": ("Azure Blob", "BlobNotFound"),
    "shopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "pantheonsite.io": ("Pantheon", "404 error unknown site"),
    "tumblr.com": ("Tumblr", "There's nothing here"),
    "wordpress.com": ("WordPress.com", "Do you want to register"),
    "zendesk.com": ("Zendesk", "Help Center Closed"),
    "teamwork.com": ("Teamwork", "Oops"),
    "unbounce.com": ("Unbounce", "The requested URL was not found"),
    "surge.sh": ("Surge.sh", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "readthedocs.io": ("ReadTheDocs", "unknown to Read the Docs"),
    "statuspage.io": ("StatusPage", "page not found"),
    "uservoice.com": ("UserVoice", "This UserVoice subdomain"),
    "helpjuice.com": ("HelpJuice", "We could not find what you're looking for"),
    "helpscout.net": ("HelpScout", "No settings were found"),
    "cargo.site": ("Cargo", "404 Not Found"),
    "feedpress.me": ("FeedPress", "The feed has not been found"),
    "freshdesk.com": ("Freshdesk", "There is no helpdesk here"),
    "ngrok.io": ("Ngrok", "Tunnel not found"),
    "canny.io": ("Canny", "Company Not Found"),
    "tilda.ws": ("Tilda", "Domain is not configured"),
    "wixsite.com": ("Wix", "Error ConnectYourDomain"),
}


class SubdomainTakeoverModule(BaseModule):
    NAME = "Subdomain Takeover"

    def run(self):
        self.ui.section("Subdomain Takeover — Dangling CNAME Detection")

        subdomains = self.ctx.get("subdomains", [])
        if not subdomains:
            self.ui.info("No subdomains discovered — skipping takeover detection.")
            self.ui.info("Tip: Run the recon module first, or use subfinder for subdomain discovery.")
            return

        if not HAS_DNS:
            self.ui.warn("dnspython not installed — using HTTP-only detection.")

        self.ui.info(f"Checking {len(subdomains)} subdomains for takeover potential...")

        found = 0
        for subdomain in subdomains[:100]:  # Cap at 100
            try:
                result = self._check_subdomain(subdomain)
                if result:
                    found += 1
            except Exception:
                continue
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No subdomain takeover vulnerabilities detected.")

    def _check_subdomain(self, subdomain: str) -> bool:
        """Check a single subdomain for takeover potential.

        BUG FIX: the previous version set `is_nxdomain` from resolving the
        SUBDOMAIN's own CNAME record failing — but that means `cname_target`
        is None in exactly that case, so the `if cname_target:` guard below
        it skipped the whole signature-matching block entirely, making the
        `elif is_nxdomain: confirmed = True` branch unreachable dead code.
        It could never fire for ANY of the signature-less services
        (trafficmanager.net etc. — the exact case that branch exists for).
        Dangling-CNAME confirmation actually requires a SEPARATE lookup: get
        the CNAME (which resolves fine — CNAME records don't require their
        target to resolve), THEN separately try to resolve that TARGET's own
        A record; if THAT fails with NXDOMAIN, the target is dangling.
        """
        cname_target = None

        # Step 1: Resolve the subdomain's CNAME (unrelated to whether the
        # target it points to is itself alive).
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(subdomain, "CNAME")
                for rdata in answers:
                    cname_target = str(rdata.target).rstrip(".")
                    break
            except Exception:
                pass  # no CNAME / doesn't resolve / timeout — nothing to check further

        if not cname_target:
            return False

        # Step 2: Check CNAME against known vulnerable services
        for service_domain, (service_name, signature) in TAKEOVER_SIGNATURES.items():
            if service_domain not in cname_target.lower():
                continue

            # Step 3: Verify the service is actually deprovisioned
            if signature and requests:
                confirmed = self._verify_signature(subdomain, signature)
            else:
                # No reliable body fingerprint for this service — the only
                # way to confirm is checking whether the CNAME TARGET
                # itself is dangling (its own A record fails to resolve).
                confirmed = self._target_is_dangling(cname_target)

            if confirmed:
                self.db.add(
                    title=f"Subdomain Takeover — {subdomain} ({service_name})",
                    severity="high", url=f"https://{subdomain}", module=self.NAME,
                    description=(
                        f"Subdomain '{subdomain}' has a dangling CNAME record pointing to "
                        f"'{cname_target}' ({service_name}). The service appears deprovisioned. "
                        "An attacker can claim this service and serve malicious content under your domain."
                    ),
                    remediation=(
                        f"Either reclaim the {service_name} resource or remove the DNS CNAME record "
                        f"for {subdomain}."
                    ),
                    cvss="8.2",
                    confidence="CONFIRMED" if signature else "HIGH",
                    confidence_score=95 if signature else 80,
                    validation_steps=["cname_resolved", "service_identified", "signature_verified"],
                    evidence=[f"CNAME: {cname_target}", f"Service: {service_name}"],
                )
                self.ui.find("high", f"Subdomain Takeover: {subdomain}", f"CNAME → {cname_target}")
                return True

            break  # matched a service_domain but couldn't confirm — no point checking the rest

        return False

    def _target_is_dangling(self, cname_target: str) -> bool:
        """True if the CNAME TARGET's own A record fails to resolve
        (NXDOMAIN) — the correct signal for a dangling CNAME on a service
        with no reliable body fingerprint. Any other outcome (resolves
        fine, timeout, no DNS available) is NOT treated as dangling —
        inconclusive should never become a false "confirmed"."""
        if not HAS_DNS:
            return False
        try:
            dns.resolver.resolve(cname_target, "A")
            return False  # resolves fine — not dangling
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False  # inconclusive (timeout, no answer, etc.) — don't guess

    def _verify_signature(self, subdomain: str, signature: str) -> bool:
        """HTTP request to verify the takeover signature is present."""
        if not requests:
            return False
        try:
            s = self._session()
            for scheme in ("https", "http"):
                try:
                    resp = s.get(f"{scheme}://{subdomain}", timeout=self.timeout)
                    if signature.lower() in resp.text.lower():
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False
