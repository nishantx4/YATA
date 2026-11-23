from __future__ import annotations

import re
from pathlib import Path

from red_agent import VulnerabilityDetector, VulnerabilityFinding

# ---------------------------------------------------------------------------
# Shared JS/TS taint-tracking helpers.
#
# There is no AST here -- these detectors work directly on source text using
# regex + bracket-depth scanning, the same way HardcodedSecretDetector already
# uses regex within the Python/AST detectors. This is intentionally lighter
# than a real parser: it is enough to find `req.query`/`req.body`/`req.params`
# flowing into a handful of well-known Express/Node sinks, which is the
# pattern every fixture below (and most real vulnerable code) actually uses.
#
# js_patches.py (the JS-side PatchStrategy implementations) imports the
# private helpers below directly -- they are shared, not duplicated.
# ---------------------------------------------------------------------------


def js_string_literal(value: str) -> str:
    """Render `value` as a double-quoted JS string literal."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'

_JS_REQUEST_SOURCE_RE = re.compile(r"\breq\.(?:query|body|params|headers|cookies)\b")

_TS_TYPE_ANNOTATION = r"(?:\s*:\s*[^=]+?)?"

_JS_SIMPLE_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)" + _TS_TYPE_ANNOTATION + r"\s*=\s*req\.(?:query|body|params|headers|cookies)\b"
)

_JS_DESTRUCTURE_RE = re.compile(
    r"(?:const|let|var)\s*\{\s*([^}]+?)\s*\}" + _TS_TYPE_ANNOTATION + r"\s*=\s*req\.(?:query|body|params|headers|cookies)\b"
)

_JS_ESCAPE_HINT_RE = re.compile(
    r"\b(?:escapeHtml|escapeHTML|encodeHTML|sanitizeHtml|sanitize|he\.encode|_\.escape)\s*\("
)

# Names of the helper functions YATA's own JS patches insert. Once a value is
# wrapped by one of these, it's mitigated -- re-scanning patched code must not
# flag it as still tainted just because the original variable name is still
# textually present inside the wrapper call.
_JS_MITIGATION_HINT_RE = re.compile(
    r"\b(?:_yataShellQuote|escapeHtml|escapeHTML|encodeHTML|sanitizeHtml|sanitize|he\.encode|_\.escape)\s*\("
)


def _js_collect_tainted_vars(source_text: str) -> set[str]:
    """Collect variable names that are directly assigned from a
    req.query/body/params/headers/cookies source, via a plain assignment or
    object destructuring."""
    tainted: set[str] = set()
    for match in _JS_SIMPLE_ASSIGN_RE.finditer(source_text):
        tainted.add(match.group(1))
    for match in _JS_DESTRUCTURE_RE.finditer(source_text):
        for piece in match.group(1).split(","):
            piece = piece.strip()
            if not piece:
                continue
            # `{ host }`, `{ host: hostName }`, `{ host = "default" }`
            name = piece.split(":")[-1].split("=")[0].strip()
            if name:
                tainted.add(name)
    return tainted


def _js_expr_is_tainted(expr_text: str, tainted_vars: set[str]) -> bool:
    """Is this expression text (a call argument, typically a template
    literal or string concatenation) built from request-derived data that
    has not already been wrapped by one of YATA's own mitigation helpers?"""
    if _JS_MITIGATION_HINT_RE.search(expr_text):
        return False
    if _JS_REQUEST_SOURCE_RE.search(expr_text):
        return True
    for var in tainted_vars:
        if re.search(rf"\b{re.escape(var)}\b", expr_text):
            return True
    return False


_JS_VAR_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*"
    r"(`(?:[^`\\]|\\.)*`|\"(?:[^\"\\]|\\.)*\"(?:\s*\+\s*[^;\n]+)?|'(?:[^'\\]|\\.)*'(?:\s*\+\s*[^;\n]+)?)\s*;"
)


def _js_collect_string_assignments(source_text: str) -> dict[str, dict]:
    """Map variable name -> {"text": <RHS source>, "line": .., "end_line": ..}
    for simple single-statement template-literal or string(+concat)
    assignments, e.g. `const sql = \\`SELECT ... ${x}\\`;`. Used to resolve a
    query built into an intermediate variable before being passed to a sink."""
    assignments: dict[str, dict] = {}
    for match in _JS_VAR_ASSIGN_RE.finditer(source_text):
        assignments[match.group(1)] = {
            "text": match.group(2),
            "line": source_text.count("\n", 0, match.start()) + 1,
            "end_line": source_text.count("\n", 0, match.end()) + 1,
        }
    return assignments


def _js_has_bare_interpolation(text: str, var_names: set[str]) -> str | None:
    """Return the first variable name that appears as a *bare* `${var}`
    template interpolation inside `text` -- i.e. not wrapped by an escaping
    call such as `${escapeHtml(var)}`. Returns None if every reference is
    already wrapped, or none are referenced via template interpolation."""
    for var in var_names:
        if re.search(rf"\$\{{\s*{re.escape(var)}\s*\}}", text):
            return var
    return None


def _js_has_preceding_guard(source_text: str, line_number: int, guard_markers: tuple[str, ...]) -> bool:
    """Coarse mitigation check for guard-style patches (SSRF, Open Redirect):
    does a known validator-function name already appear earlier in the file,
    before this sink's line?"""
    prefix = "\n".join(source_text.splitlines()[: max(line_number - 1, 0)])
    return any(marker in prefix for marker in guard_markers)


def _js_split_top_level_args(args_text: str) -> list[str]:
    """Split raw call-argument text into top-level comma-separated argument
    strings, without splitting inside nested (), [], {}, or string/template
    literals."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    in_string: str | None = None
    i = 0
    n = len(args_text)
    while i < n:
        ch = args_text[i]
        if in_string:
            current.append(ch)
            if ch == "\\" and i + 1 < n:
                current.append(args_text[i + 1])
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in "'\"`":
            in_string = ch
            current.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
            current.append(ch)
            i += 1
            continue
        if ch in ")]}":
            depth -= 1
            current.append(ch)
            i += 1
            continue
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def _js_find_call_sites(source_text: str, func_names: set[str]) -> list[dict]:
    """Find call sites like `name(...)` or `obj.name(...)` for any name in
    func_names. Returns line numbers, the matched call text, the call's
    (optional) object prefix, and its top-level argument strings. One call
    per statement is matched; this is adequate for sink detection on typical
    one-liner Express handlers, which is all these detectors target."""
    results: list[dict] = []
    alt = "|".join(re.escape(name) for name in func_names)
    pattern = re.compile(r"((?:[\w.]+\.)?)(" + alt + r")\s*\(")

    for match in pattern.finditer(source_text):
        open_paren = match.end() - 1
        depth = 0
        in_string: str | None = None
        i = open_paren
        n = len(source_text)
        close_paren = None
        while i < n:
            ch = source_text[i]
            if in_string:
                if ch == "\\" and i + 1 < n:
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
                i += 1
                continue
            if ch in "'\"`":
                in_string = ch
                i += 1
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_paren = i
                    break
            i += 1
        if close_paren is None:
            continue

        args_text = source_text[open_paren + 1 : close_paren]
        results.append(
            {
                "prefix": match.group(1),
                "func_name": match.group(2),
                "call_start": match.start(),
                "call_end": close_paren + 1,
                "line_number": source_text.count("\n", 0, match.start()) + 1,
                "end_line_number": source_text.count("\n", 0, close_paren) + 1,
                "call_src": source_text[match.start() : close_paren + 1],
                "args": _js_split_top_level_args(args_text),
            }
        )
    return results


def _js_line_evidence(lines: list[str], line_number: int) -> str:
    return lines[line_number - 1].strip() if 0 <= line_number - 1 < len(lines) else ""


class JSCommandInjectionDetector(VulnerabilityDetector):
    vulnerability_type = "Command Injection"
    detector_id = "js.cmd_injection.taint-exec"
    language = "javascript"

    _SINK_NAMES = {"exec", "execSync"}

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
        except Exception:
            return []

        tainted_vars = _js_collect_tainted_vars(source_text)
        lines = source_text.splitlines()
        findings: list[VulnerabilityFinding] = []

        for call in _js_find_call_sites(source_text, self._SINK_NAMES):
            if not call["args"]:
                continue
            first_arg = call["args"][0]
            if not _js_expr_is_tainted(first_arg, tainted_vars):
                continue

            line_number = call["line_number"]
            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="CRITICAL",
                    affected_file=str(source_file),
                    line_number=line_number,
                    exploit_payload="; echo YATA_SUCCESS",
                    evidence=_js_line_evidence(lines, line_number),
                    detector_id=self.detector_id,
                    metadata={
                        "execute_line": line_number,
                        "end_execute_line": call["end_line_number"],
                        "func_name": call["func_name"],
                        "call_src": call["call_src"],
                        "first_arg_src": first_arg,
                    },
                )
            )
        return findings


class JSPathTraversalDetector(VulnerabilityDetector):
    vulnerability_type = "Path Traversal"
    detector_id = "js.path_traversal.taint-fs-read"
    language = "javascript"

    _SINK_NAMES = {"readFile", "readFileSync", "createReadStream", "sendFile"}

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
        except Exception:
            return []

        tainted_vars = _js_collect_tainted_vars(source_text)
        lines = source_text.splitlines()
        findings: list[VulnerabilityFinding] = []

        for call in _js_find_call_sites(source_text, self._SINK_NAMES):
            func_name = call["func_name"]
            prefix = call["prefix"]
            if func_name == "sendFile" and "res." not in prefix:
                continue
            if func_name != "sendFile" and "fs" not in prefix:
                continue
            if not call["args"]:
                continue

            first_arg = call["args"][0]
            if not _js_expr_is_tainted(first_arg, tainted_vars):
                continue

            line_number = call["line_number"]
            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="HIGH",
                    affected_file=str(source_file),
                    line_number=line_number,
                    exploit_payload="../secret_admin.txt",
                    evidence=_js_line_evidence(lines, line_number),
                    detector_id=self.detector_id,
                    metadata={
                        "execute_line": line_number,
                        "end_execute_line": call["end_line_number"],
                        "func_name": func_name,
                        "call_src": call["call_src"],
                        "first_arg_src": first_arg,
                    },
                )
            )
        return findings


class JSSQLInjectionDetector(VulnerabilityDetector):
    vulnerability_type = "SQL Injection"
    detector_id = "js.sqli.taint-query-string"
    language = "javascript"

    _SINK_NAMES = {"query", "execute"}
    _SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
        except Exception:
            return []

        tainted_vars = _js_collect_tainted_vars(source_text)
        assignments = _js_collect_string_assignments(source_text)
        lines = source_text.splitlines()
        findings: list[VulnerabilityFinding] = []

        for call in _js_find_call_sites(source_text, self._SINK_NAMES):
            if not call["args"]:
                continue
            first_arg = call["args"][0]

            query_text = first_arg
            query_var = None
            assign_info = None
            if re.fullmatch(r"\w+", first_arg) and first_arg in assignments:
                query_var = first_arg
                assign_info = assignments[first_arg]
                query_text = assign_info["text"]

            if not self._SQL_KEYWORD_RE.search(query_text):
                continue
            if "${" not in query_text and "+" not in query_text:
                continue  # statically built / already parameterized
            if not _js_expr_is_tainted(query_text, tainted_vars):
                continue

            line_number = call["line_number"]
            metadata: dict[str, object] = {
                "execute_line": line_number,
                "end_execute_line": call["end_line_number"],
                "func_name": call["func_name"],
                "call_src": call["call_src"],
                "first_arg_src": first_arg,
                "query_text": query_text,
            }
            if query_var and assign_info:
                metadata["query_var"] = query_var
                metadata["assign_line"] = assign_info["line"]
                metadata["end_assign_line"] = assign_info["end_line"]

            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="CRITICAL",
                    affected_file=str(source_file),
                    line_number=line_number,
                    exploit_payload="' OR '1'='1' -- ",
                    evidence=_js_line_evidence(lines, line_number),
                    detector_id=self.detector_id,
                    metadata=metadata,
                )
            )
        return findings


class JSCrossSiteScriptingDetector(VulnerabilityDetector):
    vulnerability_type = "Cross-Site Scripting"
    detector_id = "js.xss.taint-res-send"
    language = "javascript"

    _SINK_NAMES = {"send", "end"}

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
        except Exception:
            return []

        tainted_vars = _js_collect_tainted_vars(source_text)
        lines = source_text.splitlines()
        findings: list[VulnerabilityFinding] = []

        for call in _js_find_call_sites(source_text, self._SINK_NAMES):
            if "res." not in call["prefix"]:
                continue
            if not call["args"]:
                continue
            first_arg = call["args"][0]
            if "<" not in first_arg:
                continue  # doesn't look like it is building an HTML response
            if _JS_ESCAPE_HINT_RE.search(first_arg):
                continue

            bare_var = _js_has_bare_interpolation(first_arg, tainted_vars)
            if bare_var is None:
                continue

            line_number = call["line_number"]
            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="MEDIUM",
                    affected_file=str(source_file),
                    line_number=line_number,
                    exploit_payload="<script>alert('YATA_XSS')</script>",
                    evidence=_js_line_evidence(lines, line_number),
                    detector_id=self.detector_id,
                    metadata={
                        "execute_line": line_number,
                        "end_execute_line": call["end_line_number"],
                        "func_name": call["func_name"],
                        "call_src": call["call_src"],
                        "first_arg_src": first_arg,
                        "tainted_var": bare_var,
                    },
                )
            )
        return findings


class JSSSRFDetector(VulnerabilityDetector):
    vulnerability_type = "SSRF"
    detector_id = "js.ssrf.taint-outbound-request"
    language = "javascript"

    _SINK_NAMES = {"get", "post", "request", "fetch"}
    _GUARD_MARKERS = ("_yataIsSafeUrl(",)

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
        except Exception:
            return []

        tainted_vars = _js_collect_tainted_vars(source_text)
        lines = source_text.splitlines()
        findings: list[VulnerabilityFinding] = []

        for call in _js_find_call_sites(source_text, self._SINK_NAMES):
            func_name = call["func_name"]
            prefix = call["prefix"]
            if func_name in ("get", "post", "request") and "axios" not in prefix and "http" not in prefix:
                continue
            if func_name == "fetch" and prefix not in ("", "global."):
                continue
            if not call["args"]:
                continue

            first_arg = call["args"][0]
            if not _js_expr_is_tainted(first_arg, tainted_vars):
                continue

            line_number = call["line_number"]
            if _js_has_preceding_guard(source_text, line_number, self._GUARD_MARKERS):
                continue

            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="CRITICAL",
                    affected_file=str(source_file),
                    line_number=line_number,
                    exploit_payload="http://127.0.0.1/internal/secret",
                    evidence=_js_line_evidence(lines, line_number),
                    detector_id=self.detector_id,
                    metadata={
                        "execute_line": line_number,
                        "end_execute_line": call["end_line_number"],
                        "func_name": func_name,
                        "call_src": call["call_src"],
                        "first_arg_src": first_arg,
                    },
                )
            )
        return findings


class JSOpenRedirectDetector(VulnerabilityDetector):
    vulnerability_type = "Open Redirect"
    detector_id = "js.open_redirect.taint-res-redirect"
    language = "javascript"

    _SINK_NAMES = {"redirect"}
    _GUARD_MARKERS = ("_yataIsSafeRedirect(",)

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
        except Exception:
            return []

        tainted_vars = _js_collect_tainted_vars(source_text)
        lines = source_text.splitlines()
        findings: list[VulnerabilityFinding] = []

        for call in _js_find_call_sites(source_text, self._SINK_NAMES):
            if "res." not in call["prefix"]:
                continue
            if not call["args"]:
                continue

            first_arg = call["args"][-1]  # res.redirect([status,] url)
            if not _js_expr_is_tainted(first_arg, tainted_vars):
                continue

            line_number = call["line_number"]
            if _js_has_preceding_guard(source_text, line_number, self._GUARD_MARKERS):
                continue

            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="MEDIUM",
                    affected_file=str(source_file),
                    line_number=line_number,
                    exploit_payload="http://evil-yata-test.example/phish",
                    evidence=_js_line_evidence(lines, line_number),
                    detector_id=self.detector_id,
                    metadata={
                        "execute_line": line_number,
                        "end_execute_line": call["end_line_number"],
                        "func_name": call["func_name"],
                        "call_src": call["call_src"],
                        "first_arg_src": first_arg,
                    },
                )
            )
        return findings


ALL_JS_DETECTORS: list[type[VulnerabilityDetector]] = [
    JSCommandInjectionDetector,
    JSPathTraversalDetector,
    JSSQLInjectionDetector,
    JSCrossSiteScriptingDetector,
    JSSSRFDetector,
    JSOpenRedirectDetector,
]
