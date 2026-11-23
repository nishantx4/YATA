from __future__ import annotations

import re

from blue_agent import PatchStrategy
from js_detectors import _js_split_top_level_args, js_string_literal
from red_agent import VulnerabilityFinding


def _line_indent(lines: list[str], line_number: int) -> str:
    if not (0 <= line_number - 1 < len(lines)):
        return ""
    line = lines[line_number - 1]
    return line[: len(line) - len(line.lstrip())]


def _insert_lines(lines: list[str], line_number: int, end_line_number: int, new_lines: list[str]) -> None:
    lines[line_number - 1 : end_line_number] = new_lines


class JSCommandInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "Command Injection"
    language = "javascript"

    _HELPER_MARKER = "function _yataShellQuote("
    _HELPER_SOURCE = (
        "function _yataShellQuote(value) {\n"
        '  var str = String(value);\n'
        '  if (process.platform === "win32") {\n'
        '    return \'"\' + str.replace(/"/g, \'""\') + \'"\';\n'
        "  }\n"
        '  return "\'" + str.replace(/\'/g, "\'\\\\\'\'") + "\'";\n'
        "}\n"
    )

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        new_first_arg_src = re.sub(
            r"\$\{\s*([^}]*?)\s*\}",
            lambda m: f"${{_yataShellQuote({m.group(1)})}}",
            first_arg_src,
        )

        lines = source.splitlines()
        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        new_call_src = call_src
        if first_arg_src and first_arg_src in call_src:
            new_call_src = call_src.replace(first_arg_src, new_first_arg_src, 1)
        new_segment = segment.replace(call_src, new_call_src, 1) if call_src in segment else segment
        lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_helper(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        return self._HELPER_MARKER in source and "_yataShellQuote(" in source

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the command already appeared safely constructed."
        return (
            "Wrapped every request-derived value interpolated into the shell command with a "
            "shell-quoting helper, neutralizing injected shell metacharacters as literal text."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Quote every user-controlled value passed to exec()/execSync() so shell metacharacters cannot break out of the argument, or switch to execFile() with an explicit argument array.",
            "Defense Strategy: Prefer execFile()/spawn() with array arguments (no shell) over exec(); when a shell is unavoidable, quote every interpolated value.",
        )

    def _ensure_helper(self, source: str) -> str:
        if self._HELPER_MARKER in source:
            return source
        prefix = source if source.endswith("\n") else source + "\n"
        return prefix + "\n" + self._HELPER_SOURCE


class JSPathTraversalPatchStrategy(PatchStrategy):
    vulnerability_type = "Path Traversal"
    language = "javascript"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        base_expr, filename_expr = self._parse_path_join(first_arg_src)

        lines = source.splitlines()
        indent = _line_indent(lines, execute_line)

        guard_block = [
            f"{indent}const _yataSafePath = require('path').join({base_expr}, require('path').basename({filename_expr}));",
        ]

        new_call_src = call_src
        if first_arg_src and first_arg_src in call_src:
            new_call_src = call_src.replace(first_arg_src, "_yataSafePath", 1)

        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        new_segment = segment.replace(call_src, new_call_src, 1) if call_src in segment else segment
        lines[execute_line - 1 : end_execute_line] = guard_block + new_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _parse_path_join(self, expr_src: str) -> tuple[str, str]:
        match = re.match(r"^\s*(?:path\.)?join\((.*)\)\s*$", expr_src, re.DOTALL)
        if not match:
            return "__dirname", expr_src
        args = _js_split_top_level_args(match.group(1))
        if len(args) < 2:
            return "__dirname", expr_src
        base = ", ".join(args[:-1])
        filename = args[-1]
        return f"require('path').join({base})", filename

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source
        return "_yataSafePath" in normalized and "path.basename(" in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the file path already appeared safely resolved."
        return (
            "Stripped any directory-traversal components from the request-derived filename with "
            "path.basename() before joining it back onto the restricted base directory."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Reduce the user-supplied filename to its basename with path.basename() before joining it onto the intended base directory.",
            "Defense Strategy: Never let request-derived path segments reach fs.* or res.sendFile() unsanitized; always confine them to a known base directory.",
        )


class JSSQLInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "SQL Injection"
    language = "javascript"

    _QUOTED_INTERPOLATION_RE = re.compile(r"'\$\{\s*([^}]*?)\s*\}'")
    _REMAINING_INTERPOLATION_RE = re.compile(r"\$\{[^}]*\}")

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))
        query_text = str(metadata.get("query_text", first_arg_src))
        query_var = metadata.get("query_var")
        assign_line = metadata.get("assign_line")
        end_assign_line = metadata.get("end_assign_line")

        parameterized_inner, param_exprs = self._parameterize(query_text)
        if parameterized_inner is None:
            return source

        lines = source.splitlines()

        if query_var and assign_line is not None and end_assign_line is not None and int(assign_line) == int(end_assign_line):
            indent = _line_indent(lines, int(assign_line))
            lines[int(assign_line) - 1] = f"{indent}const {query_var} = {js_string_literal(parameterized_inner)};"
            new_call_src = self._insert_params(call_src, first_arg_src, param_exprs)
        else:
            new_call_src = self._insert_params(
                call_src.replace(first_arg_src, js_string_literal(parameterized_inner), 1)
                if first_arg_src in call_src
                else call_src,
                js_string_literal(parameterized_inner),
                param_exprs,
            )

        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        new_segment = segment.replace(call_src, new_call_src, 1) if call_src in segment else segment
        lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _parameterize(self, query_text: str) -> tuple[str | None, list[str]]:
        if not (query_text.startswith("`") and query_text.endswith("`")):
            return None, []
        inner = query_text[1:-1]
        param_exprs: list[str] = []

        def _sub(match: re.Match) -> str:
            param_exprs.append(match.group(1))
            return "?"

        parameterized = self._QUOTED_INTERPOLATION_RE.sub(_sub, inner)
        if not param_exprs or self._REMAINING_INTERPOLATION_RE.search(parameterized):
            return None, []
        return parameterized, param_exprs

    def _insert_params(self, call_src: str, first_arg_marker: str, param_exprs: list[str]) -> str:
        params_array = f"[{', '.join(param_exprs)}]"
        pattern = re.escape(first_arg_marker) + r"\s*,"
        new_call_src, count = re.subn(pattern, f"{first_arg_marker}, {params_array},", call_src, count=1)
        return new_call_src if count else call_src

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        query_var = finding.metadata.get("query_var")
        if query_var:
            match = re.search(rf"const\s+{re.escape(str(query_var))}\s*=\s*\"[^\"]*\"", source)
            if match and "${" in match.group(0):
                return False
        return "?" in source and "${" not in str(finding.metadata.get("query_text", ""))

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the query already appeared parameterized."
        return (
            "Replaced the string-interpolated SQL query with a parameterized query using ? "
            "placeholders and passed the request-derived values as bound parameters."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Replace template-literal SQL with a parameterized query, passing user input through the driver's params array instead of string interpolation.",
            "Defense Strategy: Never build SQL from string concatenation or template literals; route every query through bound parameters.",
        )


class JSCrossSiteScriptingPatchStrategy(PatchStrategy):
    vulnerability_type = "Cross-Site Scripting"
    language = "javascript"

    _HELPER_MARKER = "function escapeHtml("
    _HELPER_SOURCE = (
        "function escapeHtml(value) {\n"
        "  return String(value)\n"
        '    .replace(/&/g, "&amp;")\n'
        '    .replace(/</g, "&lt;")\n'
        '    .replace(/>/g, "&gt;")\n'
        '    .replace(/"/g, "&quot;")\n'
        "    .replace(/'/g, \"&#39;\");\n"
        "}\n"
    )

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))
        tainted_var = str(metadata.get("tainted_var", ""))

        new_first_arg_src = re.sub(
            r"\$\{\s*" + re.escape(tainted_var) + r"\s*\}",
            f"${{escapeHtml({tainted_var})}}",
            first_arg_src,
        )

        lines = source.splitlines()
        new_call_src = call_src
        if first_arg_src and first_arg_src in call_src:
            new_call_src = call_src.replace(first_arg_src, new_first_arg_src, 1)

        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        new_segment = segment.replace(call_src, new_call_src, 1) if call_src in segment else segment
        lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_helper(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        tainted_var = str(finding.metadata.get("tainted_var", ""))
        return self._HELPER_MARKER in source and f"escapeHtml({tainted_var})" in source

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the response value already appeared escaped."
        return "Wrapped the request-derived value with an HTML-escaping helper before interpolating it into the response."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Escape user-controlled values (encode &, <, >, \", ') before embedding them in an HTML response.",
            "Defense Strategy: Never hand-build HTML from template literals with raw user input; prefer a templating engine with autoescaping, or escape any remaining raw string output.",
        )

    def _ensure_helper(self, source: str) -> str:
        if self._HELPER_MARKER in source:
            return source
        prefix = source if source.endswith("\n") else source + "\n"
        return prefix + "\n" + self._HELPER_SOURCE


class JSSSRFPatchStrategy(PatchStrategy):
    vulnerability_type = "SSRF"
    language = "javascript"

    _HELPER_MARKER = "function _yataIsSafeUrl("
    _HELPER_SOURCE = (
        "function _yataResolveNumericIp(hostname) {\n"
        "  if (!/^[0-9.]+$/.test(hostname)) return null;\n"
        '  var parts = hostname.split(".").filter(function (p) { return p.length > 0; });\n'
        "  if (parts.length === 0 || parts.length > 4) return null;\n"
        "  var nums = parts.map(function (p) {\n"
        "    return /^0[0-7]+$/.test(p) ? parseInt(p, 8) : parseInt(p, 10);\n"
        "  });\n"
        "  if (nums.some(function (n) { return Number.isNaN(n) || n < 0; })) return null;\n"
        "  if (nums.length === 1) {\n"
        "    var v = nums[0];\n"
        "    return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(\".\");\n"
        "  }\n"
        "  if (nums.length === 4) {\n"
        "    if (nums.some(function (n) { return n > 255; })) return null;\n"
        "    return nums.join(\".\");\n"
        "  }\n"
        "  var last = nums[nums.length - 1];\n"
        "  var head = nums.slice(0, -1);\n"
        "  if (head.some(function (n) { return n > 255; })) return null;\n"
        "  var remBytes = 4 - head.length;\n"
        "  var lastBytes = [];\n"
        "  var v2 = last;\n"
        "  for (var i = 0; i < remBytes; i++) {\n"
        "    lastBytes.unshift(v2 & 255);\n"
        "    v2 = Math.floor(v2 / 256);\n"
        "  }\n"
        "  if (v2 !== 0) return null;\n"
        "  return head.concat(lastBytes).join(\".\");\n"
        "}\n"
        "\n"
        "function _yataIsPrivateOrLoopbackIp(ip) {\n"
        "  var octets = ip.split(\".\").map(Number);\n"
        "  if (octets.length !== 4) return true;\n"
        "  var a = octets[0], b = octets[1];\n"
        "  if (a === 127 || a === 10 || a === 0) return true;\n"
        "  if (a === 172 && b >= 16 && b <= 31) return true;\n"
        "  if (a === 192 && b === 168) return true;\n"
        "  if (a === 169 && b === 254) return true;\n"
        "  return false;\n"
        "}\n"
        "\n"
        "function _yataIsSafeUrl(url) {\n"
        "  var parsed;\n"
        "  try {\n"
        "    parsed = new URL(url);\n"
        "  } catch (e) {\n"
        "    return false;\n"
        "  }\n"
        '  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;\n'
        "  var hostname = parsed.hostname;\n"
        '  if (hostname === "localhost" || hostname === "::1") return false;\n'
        '  if (hostname.indexOf(":") !== -1) return false;\n'
        "  var numericIp = _yataResolveNumericIp(hostname);\n"
        "  if (numericIp) return !_yataIsPrivateOrLoopbackIp(numericIp);\n"
        '  if (/^[0-9.]+$/.test(hostname)) return false;\n'
        "  return true;\n"
        "}\n"
    )

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        lines = source.splitlines()
        indent = _line_indent(lines, execute_line)

        guard_block = [
            f"{indent}if (!_yataIsSafeUrl({first_arg_src})) {{",
            f"{indent}  return res.status(403).send(\"blocked\");",
            f"{indent}}}",
        ]

        segment_lines = lines[execute_line - 1 : end_execute_line]
        lines[execute_line - 1 : end_execute_line] = guard_block + segment_lines

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_helper(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        return self._HELPER_MARKER in source and "_yataIsSafeUrl(" in source

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; outbound requests already appeared validated."
        return (
            "Added a URL validation guard that decodes numeric-IP obfuscation tricks and rejects "
            "loopback, private, and link-local targets before making the outbound request."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Resolve and validate the target hostname, rejecting loopback/private/link-local ranges (including numeric-IP-encoded forms), before making the outbound call.",
            "Defense Strategy: Enforce an egress allowlist for server-side HTTP calls and block requests to internal/metadata address ranges by default.",
        )

    def _ensure_helper(self, source: str) -> str:
        if self._HELPER_MARKER in source:
            return source
        prefix = source if source.endswith("\n") else source + "\n"
        return prefix + "\n" + self._HELPER_SOURCE


class JSOpenRedirectPatchStrategy(PatchStrategy):
    vulnerability_type = "Open Redirect"
    language = "javascript"

    _HELPER_MARKER = "function _yataIsSafeRedirect("
    _HELPER_SOURCE = (
        "function _yataIsSafeRedirect(url) {\n"
        "  if (!url) return false;\n"
        '  var normalized = url.replace(/\\\\/g, "/");\n'
        '  if (normalized.indexOf("//") === 0) return false;\n'
        "  try {\n"
        '    var base = "http://_yata_base_.invalid";\n'
        "    var parsed = new URL(normalized, base);\n"
        "    return parsed.origin === base;\n"
        "  } catch (e) {\n"
        "    return false;\n"
        "  }\n"
        "}\n"
    )

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        first_arg_src = str(metadata.get("first_arg_src", ""))
        call_src = str(metadata.get("call_src", ""))

        lines = source.splitlines()
        indent = _line_indent(lines, execute_line)

        # Guard with an early return rather than reassigning the tainted
        # variable -- the original binding may be `const`, which a plain
        # reassignment would throw on at runtime.
        safe_call_src = call_src.replace(first_arg_src, '"/"', 1) if first_arg_src and first_arg_src in call_src else 'res.redirect("/")'
        guard_block = [
            f"{indent}if (!_yataIsSafeRedirect({first_arg_src})) {{",
            f"{indent}  return {safe_call_src};",
            f"{indent}}}",
        ]

        segment_lines = lines[execute_line - 1 : end_execute_line]
        lines[execute_line - 1 : end_execute_line] = guard_block + segment_lines

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_helper(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        return self._HELPER_MARKER in source and "_yataIsSafeRedirect(" in source

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the redirect target already appeared validated."
        return (
            "Added a redirect-target validation guard that rejects absolute URLs, protocol-relative "
            "(//) targets, and backslash-normalization bypasses, falling back to a safe same-origin default."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Reject redirect targets that are not a same-origin relative path before calling res.redirect(); fall back to a safe default such as \"/\".",
            "Defense Strategy: Never redirect to a raw user-supplied URL -- validate against an allowlist of known-safe relative paths or internal route names.",
        )

    def _ensure_helper(self, source: str) -> str:
        if self._HELPER_MARKER in source:
            return source
        prefix = source if source.endswith("\n") else source + "\n"
        return prefix + "\n" + self._HELPER_SOURCE


ALL_JS_PATCH_STRATEGIES: list[type[PatchStrategy]] = [
    JSCommandInjectionPatchStrategy,
    JSPathTraversalPatchStrategy,
    JSSQLInjectionPatchStrategy,
    JSCrossSiteScriptingPatchStrategy,
    JSSSRFPatchStrategy,
    JSOpenRedirectPatchStrategy,
]
