"""
Finding -> reproducible request exporters.

A report tells you *what* was found; an operator's very next move is to
reproduce it by hand (in curl, or by dropping a raw request into Burp
Repeater). This turns each finding into a ready-to-run `curl` command and a
raw `.http` request block, so "confirm this myself" is copy-paste instead of
reverse-engineering the finding text.

Best-effort by design: YATA RECON findings record the target URL, the
technique, and (in evidence) the payload/method, not a full captured HTTP
transaction. The exporter reconstructs the most faithful request it can from
those fields and annotates anything it had to infer, rather than pretending
to a precision the data doesn't have.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import urllib.parse

_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b")
_PAYLOAD_RE = re.compile(r"payload\s*:\s*(.+)", re.IGNORECASE)


def _extract(evidence, pattern):
    for line in evidence or []:
        m = pattern.search(str(line))
        if m:
            return m.group(1).strip() if m.groups() else m.group(0).strip()
    return None


def _infer(finding: dict) -> dict:
    ev = finding.get("evidence", []) or []
    method = _extract(ev, _METHOD_RE) or "GET"
    payload = _extract(ev, _PAYLOAD_RE)
    return {"method": method.upper(), "payload": payload}


def finding_to_curl(finding: dict, auth_headers: dict | None = None,
                    auth_cookies: dict | None = None) -> str:
    info = _infer(finding)
    url = finding.get("url", "")
    parts = ["curl", "-sk"]                      # -s quiet, -k: self-signed is common on test hosts
    if info["method"] != "GET":
        parts += ["-X", info["method"]]
    for k, v in (auth_headers or {}).items():
        parts += ["-H", f"{k}: {v}"]
    if auth_cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())
        parts += ["-b", cookie]
    if info["method"] in ("POST", "PUT", "PATCH") and info["payload"]:
        parts += ["--data", info["payload"]]
    parts.append(url)
    cmd = " ".join(shlex.quote(p) for p in parts)
    note = ""
    if info["payload"] and info["method"] == "GET":
        note = f"\n# payload used: {info['payload']}"
    return f"# [{finding.get('severity','').upper()}] {finding.get('title','')}{note}\n{cmd}"


def finding_to_http(finding: dict, auth_headers: dict | None = None,
                    auth_cookies: dict | None = None) -> str:
    info = _infer(finding)
    url = finding.get("url", "")
    try:
        p = urllib.parse.urlparse(url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        host = p.netloc
    except Exception:
        path, host = url, ""
    lines = [f"### [{finding.get('severity','').upper()}] {finding.get('title','')}",
             f"{info['method']} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    lines.append("User-Agent: YATA RECON/5.0")
    for k, v in (auth_headers or {}).items():
        lines.append(f"{k}: {v}")
    if auth_cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in auth_cookies.items()))
    if info["method"] in ("POST", "PUT", "PATCH") and info["payload"]:
        lines += ["Content-Type: application/x-www-form-urlencoded", "", info["payload"]]
    else:
        lines.append("")
    return "\n".join(lines)


def export_report(json_path: str, out_dir: str | None = None) -> dict:
    """Read a saved yata_recon_*.json report and write a .http file and a
    curl .sh runbook beside it (or in out_dir). Returns {'http':..,'sh':..,
    'count':n} or {'error':..}."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"error": f"could not read report: {e}"}

    findings = data.get("findings", []) if isinstance(data, dict) else []
    meta = data.get("meta", {}) if isinstance(data, dict) else {}
    target = meta.get("target", "target")
    if not findings:
        return {"error": "no findings in report"}

    out_dir = out_dir or os.path.dirname(os.path.abspath(json_path))
    base = os.path.splitext(os.path.basename(json_path))[0]
    http_path = os.path.join(out_dir, f"{base}_requests.http")
    sh_path = os.path.join(out_dir, f"{base}_requests.sh")

    # Only export findings worth hand-verifying — high-signal first.
    findings = sorted(findings, key=lambda f: f.get("confidence_score", 0), reverse=True)

    with open(http_path, "w", encoding="utf-8") as f:
        f.write(f"# YATA RECON reproducible requests — {target}\n")
        f.write(f"# {len(findings)} finding(s). Open in VS Code REST Client / JetBrains HTTP client,\n")
        f.write("# or paste a block into Burp Repeater.\n\n")
        f.write("\n\n".join(finding_to_http(x) for x in findings))

    with open(sh_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# YATA RECON curl runbook — {target}\n")
        f.write("# Each command reproduces one finding. Review before running against a live host.\n\n")
        f.write("\n\n".join(finding_to_curl(x) for x in findings))

    return {"http": http_path, "sh": sh_path, "count": len(findings)}
