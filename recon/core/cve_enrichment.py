"""
CVE enrichment — cross-references fingerprinted software versions (from
Server/X-Powered-By response headers) against the public NVD CVE feed for
free "known-vuln-version" findings, with no local CVE database to maintain.

This is deliberately a heuristic, not a precise CPE version-range match:
NVD's keywordSearch is free-text search, so a result here is a starting
point for manual triage ("this version is mentioned by a real CVE") rather
than a guaranteed-affected verdict — reported at MEDIUM confidence
accordingly, same spirit as every other best-effort signal in this codebase.
"""
import json
import re

try:
    import requests
except ImportError:
    requests = None

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# "nginx/1.31.6", "Apache/2.4.41 (Ubuntu)", "PHP/8.1.2", "Microsoft-IIS/10.0", ...
VERSION_RE = re.compile(r'([A-Za-z][A-Za-z0-9._-]*)/(\d+(?:\.\d+){1,3})')

# (product.lower(), version) -> results, so re-scanning the same fingerprint
# within one process never re-queries NVD.
_CACHE: dict[tuple[str, str], list[dict]] = {}


def parse_product_version(header_value: str) -> list[tuple[str, str]]:
    """Extract (product, version) pairs from a Server/X-Powered-By header
    value — a single header can list several, e.g. 'Apache/2.4.41 (Unix) PHP/7.4.3'."""
    return VERSION_RE.findall(header_value or "")


def _mentions_version(cve: dict, version: str) -> bool:
    if version in json.dumps(cve.get("descriptions", [])):
        return True
    configs = cve.get("configurations", [])
    return version in json.dumps(configs)


# ── Precise CPE version-range matching ──────────────────────────────────────
# The free-text check above (does the version string appear anywhere in the
# CVE JSON?) is a coarse heuristic — plenty of false matches (a version
# number that happens to appear in an unrelated field) and false negatives
# (a CVE whose CPE range covers our version but never spells it out
# literally, e.g. "affects 1.18.0 through 1.24.x"). NVD's `configurations`
# block gives real CPE 2.3 match criteria with structured version-range
# bounds (versionStartIncluding/Excluding, versionEndIncluding/Excluding) —
# parsing those properly is what actually answers "is THIS version affected."

def _version_tuple(v: str) -> tuple:
    """Parse a dotted version string into a tuple of ints for ordered
    comparison. Stops at the first non-numeric/non-dot run, so
    '2.4.41-beta' and '2.4.41 (Ubuntu)' both parse as (2, 4, 41)."""
    m = re.match(r'^[\d.]+', v or "")
    if not m:
        return ()
    result = []
    for p in m.group(0).rstrip('.').split('.'):
        if not p:
            continue
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def _version_in_range(v: tuple, start_inc=None, start_exc=None, end_inc=None, end_exc=None) -> bool:
    if not v:
        return False
    if start_inc and v < _version_tuple(start_inc):
        return False
    if start_exc and v <= _version_tuple(start_exc):
        return False
    if end_inc and v > _version_tuple(end_inc):
        return False
    if end_exc and v >= _version_tuple(end_exc):
        return False
    return True


def _parse_cpe(criteria: str) -> dict | None:
    """Parse a CPE 2.3 formatted string
    ('cpe:2.3:a:vendor:product:version:update:edition:...') into its
    vendor/product/version components."""
    parts = criteria.split(':')
    if len(parts) < 6 or parts[0] != 'cpe':
        return None
    return {"vendor": parts[3], "product": parts[4], "version": parts[5]}


def _cpe_product_matches(cpe_product: str, product: str) -> bool:
    p1 = cpe_product.lower().replace('_', ' ').replace('-', ' ')
    p2 = product.lower().replace('_', ' ').replace('-', ' ')
    return p1 in p2 or p2 in p1


def _cve_affects_version(cve: dict, product: str, version: str) -> tuple[bool, str]:
    """
    Returns (matched, method):
      'cpe-range' — a CPE match for this product declares an explicit
                    version range and our version falls inside it (the
                    precise, high-confidence case)
      'cpe-exact' — a CPE match's own version field equals (or is a
                    dotted-prefix of) our version, with no range given
      'text'      — no structured configuration data matched; fell back to
                    the free-text heuristic (kept for CVEs NVD hasn't fully
                    structured yet, at lower confidence)
      'none'      — nothing matched at all
    """
    v_tuple = _version_tuple(version)
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue
                parsed = _parse_cpe(cpe_match.get("criteria", ""))
                if not parsed or not _cpe_product_matches(parsed["product"], product):
                    continue

                start_inc = cpe_match.get("versionStartIncluding")
                start_exc = cpe_match.get("versionStartExcluding")
                end_inc = cpe_match.get("versionEndIncluding")
                end_exc = cpe_match.get("versionEndExcluding")

                if start_inc or start_exc or end_inc or end_exc:
                    if _version_in_range(v_tuple, start_inc, start_exc, end_inc, end_exc):
                        return True, "cpe-range"
                    continue  # this CPE match's range explicitly excludes us — don't fall through

                cpe_version = parsed["version"]
                if cpe_version in ("*", "-", ""):
                    continue  # unbounded wildcard with no range — too imprecise to claim a match
                if cpe_version == version or version.startswith(cpe_version + "."):
                    return True, "cpe-exact"

    if _mentions_version(cve, version):
        return True, "text"
    return False, "none"


def lookup_cves(product: str, version: str, max_results: int = 5, timeout: int = 15) -> list[dict]:
    """Query NVD for CVEs whose description/CPE configuration mentions both
    the product name and this exact version string. Returns [] on any
    failure (offline, rate-limited, malformed response) — this is an
    enrichment, never something that should break a scan."""
    if not requests:
        return []
    key = (product.lower(), version)
    if key in _CACHE:
        return _CACHE[key]

    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 20}
    try:
        resp = requests.get(NVD_API, params=params, timeout=timeout,
                             headers={"User-Agent": "YATA RECON/5.0 (security research)"})
        if resp.status_code != 200:
            _CACHE[key] = []
            return []
        data = resp.json()
    except Exception:
        _CACHE[key] = []
        return []

    results = []
    for item in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        matched, method = _cve_affects_version(cve, product, version)
        if not matched:
            continue
        descriptions = cve.get("descriptions", [])
        desc_text = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

        cvss = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key)
            if entries:
                cvss = entries[0].get("cvssData", {}).get("baseScore")
                break

        results.append({
            "id": cve_id,
            "summary": desc_text[:300],
            "cvss": cvss,
            "match_method": method,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    results.sort(key=lambda c: c["cvss"] or 0, reverse=True)
    results = results[:max_results]
    _CACHE[key] = results
    return results
