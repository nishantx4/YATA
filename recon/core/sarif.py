"""
SARIF 2.1.0 export — turns YATA RECON findings into the Static Analysis
Results Interchange Format consumed by GitHub Advanced Security code
scanning, Azure DevOps, and most CI security dashboards.

Pairs with the existing CI story (--fail-on): a pipeline can run YATA RECON,
upload the .sarif, and have findings show up inline as code-scanning alerts
sortable by `security-severity` (the CVSS-derived property GitHub sorts on).

Kept dependency-free (stdlib only) and defensive — a malformed finding must
never break report generation.
"""
import hashlib
import re

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# YATA RECON severity -> SARIF result level.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}

# Fallback security-severity (0-10, GitHub's sort key) when a finding has no
# CVSS of its own.
_SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5",
                 "low": "3.0", "info": "2.0"}


def _slug(text: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:maxlen] or "finding"


def _normalize_title(title: str) -> str:
    """Collapse the variable bits of a title (param names, ids, versions,
    quoted specifics) so repeated scans map to a STABLE ruleId instead of a
    brand-new rule per parameter."""
    t = title or ""
    t = re.sub(r"\([^)]*\)", "", t)        # drop parenthetical specifics
    t = re.sub(r"'[^']*'", "", t)          # drop quoted specifics
    t = re.sub(r"\b[0-9a-fA-F-]{6,}\b", "", t)  # drop ids/hashes/versions
    t = re.sub(r"\d+", "", t)               # drop remaining digits
    return re.sub(r"\s+", " ", t).strip()


def _security_severity(f: dict) -> str:
    cvss = f.get("cvss")
    try:
        if cvss is not None and str(cvss).strip() not in ("", "N/A"):
            return str(float(str(cvss).strip()))
    except (TypeError, ValueError):
        pass
    return _SEC_SEVERITY.get(f.get("severity", "info"), "2.0")


def _rule_id(f: dict) -> str:
    return f"{_slug(f.get('module', 'yata-recon'), 32)}/{_slug(_normalize_title(f.get('title', '')), 60)}"


def _fingerprint(f: dict) -> str:
    """Stable per-finding fingerprint so a scanner/UI can track the same
    alert across runs (GitHub uses partialFingerprints to dedupe)."""
    basis = _normalize_title(f.get("title", "")) + "|" + re.sub(r"\d+", "", f.get("url", ""))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:20]


def build_sarif(target: str, findings: list, tool_version: str = "5.0") -> dict:
    rules, rule_index = {}, {}
    results = []

    for f in findings:
        try:
            sev = (f.get("severity") or "info").lower()
            level = _LEVEL.get(sev, "note")
            rid = _rule_id(f)
            if rid not in rules:
                rule = {
                    "id": rid,
                    "name": "".join(w.capitalize() for w in _slug(_normalize_title(f.get("title", ""))).split("-")) or "Finding",
                    "shortDescription": {"text": (f.get("title") or "Finding")[:200]},
                    "fullDescription": {"text": (f.get("description") or f.get("title") or "")[:1000]},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": [t for t in (f.get("module"), sev) if t],
                        "security-severity": _security_severity(f),
                    },
                }
                remediation = f.get("remediation")
                if remediation:
                    rule["help"] = {"text": remediation[:1500]}
                refs = f.get("references") or []
                if refs and isinstance(refs[0], str) and refs[0].startswith(("http://", "https://")):
                    rule["helpUri"] = refs[0]
                rule_index[rid] = len(rules)
                rules[rid] = rule

            msg = f.get("title") or "Finding"
            if f.get("description"):
                msg += " — " + f["description"][:400]
            result = {
                "ruleId": rid,
                "ruleIndex": rule_index[rid],
                "level": level,
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": f.get("url") or target}},
                    "logicalLocations": [{"fullyQualifiedName": f.get("url") or target, "kind": "namespace"}],
                }],
                "partialFingerprints": {"yata-recon/v1": _fingerprint(f)},
                "properties": {
                    "security-severity": _security_severity(f),
                    "confidence": f.get("confidence"),
                    "confidence_score": f.get("confidence_score"),
                    "cvss": f.get("cvss"),
                    "module": f.get("module"),
                },
            }
            results.append(result)
        except Exception:
            continue  # one malformed finding must never sink the whole report

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "YATA RECON",
                "version": str(tool_version),
                "informationUri": "https://build.nvidia.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": target},
        }],
    }


def write_sarif(path: str, target: str, findings: list, tool_version: str = "5.0") -> str:
    import json
    doc = build_sarif(target, findings, tool_version)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    return path
