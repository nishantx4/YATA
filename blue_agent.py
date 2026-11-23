from __future__ import annotations

import ast
import importlib
import importlib.util
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from llm_client import LLMClient
from red_agent import VulnerabilityFinding


def python_source_is_loadable(source: str) -> bool:
    """True if `source` parses and every import of an *installed* module asks
    for names that module really provides (e.g. flask 3 has no `escape`).
    Modules that are not installed (the project's own files) are not judged."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
            names: list[str] = []
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules = [node.module]
            names = [alias.name for alias in node.names if alias.name != "*"]
        else:
            continue

        for module_name in modules:
            try:
                if importlib.util.find_spec(module_name) is None:
                    continue
                module = importlib.import_module(module_name)
            except Exception:
                continue
            for name in names:
                if hasattr(module, name):
                    continue
                try:
                    importlib.import_module(f"{module_name}.{name}")
                except Exception:
                    return False
    return True


@dataclass(slots=True)
class PatchResult:
    patched_root: Path
    patched_file: Path
    changed_files: list[str]
    patch_text: str
    used_llm: bool
    mitigation_explanation: str
    defense_strategy: str


class PatchStrategy:
    vulnerability_type = "Generic"
    language = "python"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        raise NotImplementedError

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        raise NotImplementedError

    def apply_auxiliary_updates(self, patched_root: Path, finding: VulnerabilityFinding) -> list[str]:
        return []

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No source changes were required because the file already matched the expected safe pattern."
        return "Applied a safe patch."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Apply a targeted defensive change that neutralizes the exploit path while preserving behavior.",
            "Defense Strategy: Standardize secure coding patterns for this vulnerability class and re-verify them continuously.",
        )


class SQLInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "SQL Injection"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        parameterized_query = str(metadata.get("parameterized_query", "")).strip()
        parameter_names = [str(name) for name in metadata.get("parameter_names", [])]
        query_var_name = str(metadata.get("query_var_name", "query"))
        execute_receiver = str(metadata.get("execute_receiver", "cursor"))
        query_line = int(metadata.get("query_line", finding.line_number))
        execute_line = int(metadata.get("execute_line", finding.line_number))

        lines = source.splitlines()
        query_indent = str(metadata.get("query_indent", self._line_indent(lines, query_line)))
        execute_indent = str(metadata.get("execute_indent", self._line_indent(lines, execute_line)))
        escaped_query = parameterized_query.replace("\\", "\\\\").replace('"', '\\"')
        query_replacement = f'{query_indent}{query_var_name} = "{escaped_query}"'
        execute_replacement = f"{execute_indent}{execute_receiver}.execute({query_var_name}, {self._tuple_literal(parameter_names)})"

        if 0 <= query_line - 1 < len(lines):
            lines[query_line - 1] = query_replacement

        if 0 <= execute_line - 1 < len(lines):
            if execute_line == query_line:
                lines[execute_line - 1] = f"{query_replacement}\n{execute_replacement}"
            else:
                lines[execute_line - 1] = execute_replacement

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        parameterized_query = str(finding.metadata.get("parameterized_query", "")).strip()
        query_var_name = str(finding.metadata.get("query_var_name", "query"))
        normalized = source.replace("\t", "    ")
        return parameterized_query in normalized and f".execute({query_var_name}," in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the SQL statement already appeared parameterized."
        return (
            "Replaced string-built SQL with a parameterized query and passed user input as bound parameters "
            "to block SQL injection payloads."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Replace dynamic SQL string construction with a parameterized query so user input cannot alter SQL syntax.",
            "Defense Strategy: Route every database access path through bound parameters and continuously retest exploitable request flows.",
        )

    def _tuple_literal(self, parameter_names: list[str]) -> str:
        if not parameter_names:
            return "()"
        if len(parameter_names) == 1:
            return f"({parameter_names[0]},)"
        return f"({', '.join(parameter_names)})"

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class HardcodedSecretPatchStrategy(PatchStrategy):
    vulnerability_type = "Hardcoded Secret"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        variable_name = str(finding.metadata.get("variable_name", "SECRET_VALUE"))
        env_var_name = str(finding.metadata.get("env_var_name", variable_name.upper()))
        line_number = finding.line_number
        lines = source.splitlines()
        indent = self._line_indent(lines, line_number)

        if 0 <= line_number - 1 < len(lines):
            lines[line_number - 1] = f'{indent}{variable_name} = os.getenv("{env_var_name}", "")'

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_os_import(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        variable_name = str(finding.metadata.get("variable_name", "SECRET_VALUE"))
        env_var_name = str(finding.metadata.get("env_var_name", variable_name.upper()))
        literal_pattern = re.compile(rf"\b{re.escape(variable_name)}\b\s*=\s*['\"]")
        env_usage = f'os.getenv("{env_var_name}", "")' in source or f"os.getenv('{env_var_name}', '')" in source
        return env_usage and literal_pattern.search(source) is None

    def apply_auxiliary_updates(self, patched_root: Path, finding: VulnerabilityFinding) -> list[str]:
        env_var_name = str(finding.metadata.get("env_var_name", "SECRET_VALUE"))
        env_example_path = patched_root / ".env.example"
        existing_lines: list[str] = []
        if env_example_path.exists():
            existing_lines = env_example_path.read_text(encoding="utf-8").splitlines()

        if not any(line.strip().startswith(f"{env_var_name}=") for line in existing_lines):
            existing_lines.append(f"{env_var_name}=change_me")
            env_example_path.write_text("\n".join(existing_lines).rstrip() + "\n", encoding="utf-8")
            return [".env.example"]
        return []

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the secret already appeared to be sourced from the environment."
        return "Moved a hardcoded credential out of source code and replaced it with an environment-variable lookup."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Remove the credential literal from source code and load it from an environment variable instead.",
            "Defense Strategy: Keep secrets out of repositories, document required variables in .env.example, and continuously re-verify for literals.",
        )

    def _ensure_os_import(self, source: str) -> str:
        if re.search(r"^\s*import os\b", source, re.MULTILINE) or re.search(r"^\s*from os import\b", source, re.MULTILINE):
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, "import os")
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class CommandInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "Command Injection"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        safe_args = metadata.get("safe_args")
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        func_name = str(metadata.get("func_name", "os.system"))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        lines = source.splitlines()
        indent = self._line_indent(lines, execute_line)

        # Build replacement call
        if safe_args:
            args_str = ", ".join(safe_args)
        else:
            param = metadata.get("parameter_names", ["cmd"])
            param_name = param[0] if param else "cmd"
            args_str = param_name

        if func_name.startswith("subprocess.") or func_name in ("run", "Popen", "check_output", "call"):
            # Subprocess call. We replace the call source in the line.
            if call_src and first_arg_src:
                new_call_src = call_src.replace(first_arg_src, f"[{args_str}]", 1)
                new_call_src = re.sub(r"\bshell\s*=\s*True\b", "shell=False", new_call_src)
                
                segment = "\n".join(lines[execute_line - 1 : end_execute_line])
                if call_src in segment:
                    new_segment = segment.replace(call_src, new_call_src, 1)
                else:
                    new_segment = f"{indent}{new_call_src}"
                lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()
            else:
                lines[execute_line - 1 : end_execute_line] = [f"{indent}subprocess.run([{args_str}], shell=False)"]
        elif func_name in ("os.popen", "popen"):
            # stream = subprocess.Popen(["ping", host], shell=False, stdout=subprocess.PIPE, text=True)
            lines[execute_line - 1 : end_execute_line] = [f"{indent}import subprocess; stream = subprocess.Popen([{args_str}], shell=False, stdout=subprocess.PIPE, text=True)"]
        else:
            # os.system(cmd) -> subprocess.run(["ping", host], shell=False)
            lines[execute_line - 1 : end_execute_line] = [f"{indent}subprocess.run([{args_str}], shell=False)"]

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"

        return self._ensure_subprocess_import(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        return "shell=False" in normalized or "subprocess.run" in normalized or "subprocess.Popen" in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the execution path already appeared safe."
        return "Replaced unsafe shell execution with secure subprocess.run/Popen call (shell=False)."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Replace unsafe shell execution (shell=True, os.system, os.popen) with secure subprocess.run calls using shell=False and argument lists.",
            "Defense Strategy: Standardize on subprocess.run with shell=False, passing command and arguments as a list to prevent shell command injection.",
        )

    def _ensure_subprocess_import(self, source: str) -> str:
        if re.search(r"^\s*import subprocess\b", source, re.MULTILINE) or re.search(r"^\s*from subprocess import\b", source, re.MULTILINE):
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, "import subprocess")
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class PathTraversalPatchStrategy(PatchStrategy):
    vulnerability_type = "Path Traversal"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        lines = source.splitlines()
        indent = self._line_indent(lines, execute_line)

        # Parse base and filename from first_arg_src
        base_src, filename_src = self._parse_path_expression(first_arg_src)

        # Build sanitization code block
        sanitization_block = [
            f"{indent}from pathlib import Path",
            f"{indent}base = Path({base_src}).resolve()",
            f"{indent}target = (base / {filename_src}).resolve()",
            f"{indent}if not str(target).startswith(str(base)):",
            f"{indent}    from flask import abort",
            f"{indent}    abort(403)",
        ]

        if first_arg_src:
            new_call_src = call_src.replace(first_arg_src, "target", 1)
        else:
            new_call_src = call_src

        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        if call_src in segment:
            new_segment = segment.replace(call_src, new_call_src, 1)
        else:
            new_segment = segment

        lines_replacement = sanitization_block + new_segment.splitlines()
        lines[execute_line - 1 : end_execute_line] = lines_replacement

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"

        return self._ensure_imports(patched)

    def _parse_path_expression(self, expr_src: str) -> tuple[str, str]:
        if not expr_src:
            return '"."', '""'
        try:
            tree = ast.parse(expr_src.strip())
            if not tree.body or not isinstance(tree.body[0], ast.Expr):
                return '"."', expr_src
            expr = tree.body[0].value
            if isinstance(expr, ast.Call):
                func_name = self._get_func_name(expr.func)
                if func_name in ("os.path.join", "join", "safe_join") and len(expr.args) >= 2:
                    base_src = ast.get_source_segment(expr_src, expr.args[0])
                    filename_parts = [ast.get_source_segment(expr_src, arg) for arg in expr.args[1:]]
                    filename_src = " / ".join(filename_parts)
                    return base_src, filename_src
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                left_src = ast.get_source_segment(expr_src, expr.left)
                right_src = ast.get_source_segment(expr_src, expr.right)
                return left_src, right_src
        except Exception:
            pass
        return '"."', expr_src

    def _get_func_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            val_name = self._get_func_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
            return node.attr
        return None

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]

    def _ensure_imports(self, source: str) -> str:
        patched = source
        if "from pathlib import Path" not in patched and "import pathlib" not in patched:
            patched = self._insert_import(patched, "from pathlib import Path")
        if "from flask import abort" not in patched and "import flask" not in patched:
            patched = self._insert_import(patched, "from flask import abort")
        return patched

    def _insert_import(self, source: str, import_stmt: str) -> str:
        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, import_stmt)
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        has_path = "Path(" in normalized
        has_resolve = ".resolve()" in normalized
        has_startswith = "startswith(" in normalized
        has_abort = "abort(" in normalized or "raise " in normalized
        return has_path and has_resolve and has_startswith and has_abort

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the path resolution already appeared safe."
        return "Resolved path dynamically and validated that it starts with the restricted base directory."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Resolve and normalize the file path using pathlib.Path, then check if the target starts with the base uploads directory prefix.",
            "Defense Strategy: Standardize on resolving relative paths and checking startswith boundary validation before opening any filesystem resources.",
        )


class CrossSiteScriptingPatchStrategy(PatchStrategy):
    vulnerability_type = "Cross-Site Scripting"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        return_src = str(metadata.get("return_src", ""))
        tainted_names = [str(name) for name in metadata.get("tainted_names", [])]

        lines = source.splitlines()
        new_return_src = return_src
        for name in tainted_names:
            pattern = re.compile(r"\{\s*" + re.escape(name) + r"\s*\}")
            new_return_src = pattern.sub(f"{{markupsafe.escape({name})}}", new_return_src)

        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        if return_src and return_src in segment:
            new_segment = segment.replace(return_src, new_return_src, 1)
        else:
            new_segment = segment
        lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_import(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        tainted_names = [str(name) for name in finding.metadata.get("tainted_names", [])]
        if not tainted_names:
            return False
        return all(
            f"markupsafe.escape({name})" in normalized or f"escape({name})" in normalized
            for name in tainted_names
        )

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the response value already appeared escaped."
        return (
            "Wrapped request-derived values with markupsafe.escape() before interpolating them into the "
            "HTML response, neutralizing injected markup."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Escape user-controlled values with markupsafe.escape() before embedding them in HTML responses.",
            "Defense Strategy: Never hand-build HTML from raw string interpolation; prefer templates with autoescaping enabled, and escape any remaining raw string output.",
        )

    def _ensure_import(self, source: str) -> str:
        if re.search(r"^\s*import markupsafe\b", source, re.MULTILINE):
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, "import markupsafe")
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched


class SSRFPatchStrategy(PatchStrategy):
    vulnerability_type = "SSRF"

    _HELPER_MARKER = "def _yata_is_safe_url("
    _HELPER_SOURCE = (
        "import ipaddress\n"
        "import socket\n"
        "from urllib.parse import urlparse\n\n\n"
        "def _yata_is_safe_url(url: str) -> bool:\n"
        "    try:\n"
        "        parsed = urlparse(url)\n"
        "    except Exception:\n"
        "        return False\n"
        "    if parsed.scheme not in (\"http\", \"https\"):\n"
        "        return False\n"
        "    hostname = parsed.hostname\n"
        "    if not hostname:\n"
        "        return False\n"
        "    try:\n"
        "        infos = socket.getaddrinfo(hostname, None)\n"
        "    except Exception:\n"
        "        return False\n"
        "    for info in infos:\n"
        "        ip = ipaddress.ip_address(info[4][0])\n"
        "        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:\n"
        "            return False\n"
        "    return True\n"
    )

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        lines = source.splitlines()
        indent = self._line_indent(lines, execute_line)

        guard_block = [
            f"{indent}if not _yata_is_safe_url({first_arg_src}):",
            f"{indent}    from flask import abort",
            f"{indent}    abort(403)",
        ]

        segment_lines = lines[execute_line - 1 : end_execute_line]
        lines[execute_line - 1 : end_execute_line] = guard_block + segment_lines

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_helper(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        return "_yata_is_safe_url(" in normalized and self._HELPER_MARKER in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; outbound requests already appeared validated."
        return (
            "Added a URL validation guard that resolves the target hostname and blocks private, loopback, "
            "link-local, reserved, and multicast IP ranges before making the outbound request."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Resolve the target hostname and reject requests whose IP falls in a private, loopback, link-local, or reserved range before making the outbound call.",
            "Defense Strategy: Enforce an egress allowlist for server-side HTTP calls and block requests to internal/metadata address ranges by default.",
        )

    def _ensure_helper(self, source: str) -> str:
        if self._HELPER_MARKER in source:
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines[insert_at:insert_at] = ["", *self._HELPER_SOURCE.splitlines(), ""]
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class ServerSideTemplateInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "Server-Side Template Injection"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        call_line = int(metadata.get("call_line", finding.line_number))
        end_call_line = int(metadata.get("end_call_line", call_line))
        call_src = str(metadata.get("call_src", ""))
        template_expr_src = str(metadata.get("template_expr_src", ""))
        tainted_names = [str(name) for name in metadata.get("tainted_names", [])]
        jinja_literal = str(metadata.get("jinja_literal", ""))
        is_direct_arg = bool(metadata.get("is_direct_arg", False))
        template_var = metadata.get("template_var")
        assign_line = metadata.get("assign_line")
        end_assign_line = metadata.get("end_assign_line")

        lines = source.splitlines()

        # Case A: the template text lives in a separate variable assignment
        # (the common case) -- rewrite that single-line assignment from an
        # f-string into a plain, non-interpolated Jinja-safe literal.
        if (
            not is_direct_arg
            and template_var
            and assign_line is not None
            and end_assign_line is not None
            and int(assign_line) == int(end_assign_line)
        ):
            assign_indent = self._line_indent(lines, int(assign_line))
            lines[int(assign_line) - 1] = f"{assign_indent}{template_var} = {jinja_literal!r}"

        # Always: append the tainted values as render_template_string()
        # keyword context args (Jinja auto-escapes these; they are never
        # evaluated as template source), and for the direct-arg case,
        # replace the f-string argument itself with the safe literal.
        new_call_src = call_src
        if is_direct_arg and template_expr_src and template_expr_src in new_call_src:
            new_call_src = new_call_src.replace(template_expr_src, repr(jinja_literal), 1)

        kwargs_str = ", ".join(f"{name}={name}" for name in tainted_names)
        if kwargs_str:
            stripped = new_call_src.rstrip()
            if stripped.endswith(")"):
                body = stripped[:-1].rstrip()
                separator = "" if body.endswith("(") else ", "
                new_call_src = f"{body}{separator}{kwargs_str})"

        call_indent = self._line_indent(lines, call_line)
        call_segment = "\n".join(lines[call_line - 1 : end_call_line])
        if call_src and call_src in call_segment:
            new_call_segment = call_segment.replace(call_src, new_call_src, 1)
        else:
            new_call_segment = f"{call_indent}{new_call_src}"
        lines[call_line - 1 : end_call_line] = new_call_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        tainted_names = [str(name) for name in finding.metadata.get("tainted_names", [])]
        if not tainted_names or "{{" not in normalized:
            return False
        return all(f"{name}={name}" in normalized for name in tainted_names)

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the template source already appeared free of raw user interpolation."
        return (
            "Moved request-derived values out of the template source and into the Jinja render context, so "
            "they are auto-escaped as data instead of being compiled and evaluated as template code."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Never build the template string itself from user input; pass user values as render_template_string() context variables instead, where Jinja auto-escapes them.",
            "Defense Strategy: Treat template source as code, not data -- keep it fully static in source control and only ever interpolate user input through the render context.",
        )

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class OpenRedirectPatchStrategy(PatchStrategy):
    vulnerability_type = "Open Redirect"

    _HELPER_MARKER = "def _yata_is_safe_redirect("
    _HELPER_SOURCE = (
        "from urllib.parse import urlparse\n\n\n"
        "def _yata_is_safe_redirect(url: str) -> bool:\n"
        "    if not url:\n"
        "        return False\n"
        "    normalized = url.replace(\"\\\\\", \"/\")\n"
        "    if normalized.startswith(\"//\"):\n"
        "        return False\n"
        "    try:\n"
        "        parsed = urlparse(normalized)\n"
        "    except Exception:\n"
        "        return False\n"
        "    if parsed.scheme or parsed.netloc:\n"
        "        return False\n"
        "    return normalized.startswith(\"/\")\n"
    )

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        lines = source.splitlines()
        indent = self._line_indent(lines, execute_line)

        guard_block = [
            f"{indent}if not _yata_is_safe_redirect({first_arg_src}):",
            f"{indent}    {first_arg_src} = \"/\"",
        ]

        segment_lines = lines[execute_line - 1 : end_execute_line]
        lines[execute_line - 1 : end_execute_line] = guard_block + segment_lines

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_helper(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        return "_yata_is_safe_redirect(" in normalized and self._HELPER_MARKER in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the redirect target already appeared validated."
        return (
            "Added a redirect-target validation guard that rejects absolute URLs, protocol-relative (//) "
            "targets, and backslash-normalization bypasses, falling back to a safe same-origin default."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Reject redirect targets that are not a same-origin relative path before calling redirect(); fall back to a safe default such as \"/\".",
            "Defense Strategy: Never redirect to a raw user-supplied URL -- validate against an allowlist of known-safe relative paths or internal route names.",
        )

    def _ensure_helper(self, source: str) -> str:
        if self._HELPER_MARKER in source:
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines[insert_at:insert_at] = ["", *self._HELPER_SOURCE.splitlines(), ""]
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class InsecureDeserializationPatchStrategy(PatchStrategy):
    vulnerability_type = "Insecure Deserialization"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        func_name = str(metadata.get("func_name", "pickle.loads"))
        call_src = str(metadata.get("call_src", ""))
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))

        replacement_func = "json.loads" if func_name.endswith("loads") else "json.load"
        new_call_src = re.sub(r"\bpickle\.(loads|load)\b", replacement_func, call_src, count=1)

        lines = source.splitlines()
        indent = self._line_indent(lines, execute_line)
        segment = "\n".join(lines[execute_line - 1 : end_execute_line])
        if call_src and call_src in segment:
            new_segment = segment.replace(call_src, new_call_src, 1)
        else:
            new_segment = f"{indent}{new_call_src}"
        lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_import(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        return "pickle.loads(" not in normalized and "pickle.load(" not in normalized and "json.load" in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; untrusted input was not being deserialized with pickle."
        return (
            "Replaced pickle.loads()/pickle.load() on untrusted input with json.loads()/json.load(), which can "
            "only produce plain data structures and can never trigger arbitrary code execution during "
            "deserialization."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Never call pickle.loads()/pickle.load() on data an attacker can influence; use a safe, data-only format like json instead.",
            "Defense Strategy: Treat deserialization of untrusted input as code execution by default -- restrict it to formats that cannot embed executable objects.",
        )

    def _ensure_import(self, source: str) -> str:
        if re.search(r"^\s*import json\b", source, re.MULTILINE):
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, "import json")
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class BlueAgent:
    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        strategies: dict[tuple[str, str], PatchStrategy] | None = None,
    ) -> None:
        self.llm = llm_client or LLMClient()
        if strategies is None:
            from js_patches import ALL_JS_PATCH_STRATEGIES

            python_strategies: list[PatchStrategy] = [
                SQLInjectionPatchStrategy(),
                HardcodedSecretPatchStrategy(),
                CommandInjectionPatchStrategy(),
                PathTraversalPatchStrategy(),
                CrossSiteScriptingPatchStrategy(),
                SSRFPatchStrategy(),
                ServerSideTemplateInjectionPatchStrategy(),
                OpenRedirectPatchStrategy(),
                InsecureDeserializationPatchStrategy(),
            ]
            js_strategies = [strategy_cls() for strategy_cls in ALL_JS_PATCH_STRATEGIES]
            strategies = {
                (strategy.vulnerability_type, strategy.language): strategy
                for strategy in (*python_strategies, *js_strategies)
            }
        self.strategies = strategies
        self.verbose = False

    def generate_patch(self, target_root: Path, finding: VulnerabilityFinding) -> PatchResult:
        if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
            if self.verbose:
                print("[HEALER]")
                print("Using deterministic remediation strategy.")
            import fallback_patches
            return fallback_patches.generate_patch(target_root, finding)

        strategy = self.strategies.get((finding.vulnerability_type, getattr(finding, "language", "python")))
        if strategy is None:
            raise ValueError(f"No patch strategy registered for {finding.vulnerability_type}")

        target_root = target_root.resolve()
        temp_root = Path(tempfile.mkdtemp(prefix="yata_patched_"))
        patched_root = temp_root / target_root.name
        shutil.copytree(
            target_root,
            patched_root,
            ignore=shutil.ignore_patterns(".yata", ".git", ".venv", "__pycache__")
        )

        relative_file = Path(str(finding.metadata.get("relative_file", Path(finding.affected_file).name)))
        patched_copy_file = patched_root / relative_file
        original_source = patched_copy_file.read_text(encoding="utf-8")
        patched_source = strategy.apply_source(original_source, finding)

        patch_llm_response = self.llm.generate(
            system_prompt=(
                "You are HEALER in YATA. Patch the provided file without changing unrelated behavior. "
                "Return only the full patched file contents."
            ),
            user_prompt=self._build_patch_prompt(original_source, finding),
            fallback_text="LLM patch suggestion unavailable; using deterministic local patch strategy.",
            max_tokens=1600,
            request_type="healer",
        )

        llm_source = self._extract_code_candidate(patch_llm_response.content)
        if (
            llm_source
            and strategy.is_safe(llm_source, finding)
            and (strategy.language != "python" or python_source_is_loadable(llm_source))
        ):
            patched_source = llm_source

        patched_copy_file.write_text(patched_source, encoding="utf-8")
        changed_files = [str(relative_file)]
        changed_files.extend(strategy.apply_auxiliary_updates(patched_root, finding))

        mitigation_response = self.llm.generate(
            system_prompt=(
                "You are HEALER in YATA. Explain how a patch reduces exploitability and how defenders "
                "should harden the affected workflow."
            ),
            user_prompt=(
                f"Vulnerability Type: {finding.vulnerability_type}\n"
                f"Affected File: {finding.affected_file}\n"
                f"Evidence: {finding.evidence}\n\n"
                "Return exactly two lines:\n"
                "Mitigation: <one concise sentence>\n"
                "Defense Strategy: <one concise sentence>"
            ),
            fallback_text=self._fallback_guidance_text(strategy),
            max_tokens=220,
        )
        mitigation_explanation, defense_strategy = self._parse_mitigation_details(
            mitigation_response.content,
            strategy,
        )
        patch_text = strategy.build_summary(original_source, patched_source)

        return PatchResult(
            patched_root=patched_root,
            patched_file=patched_copy_file,
            changed_files=changed_files,
            patch_text=patch_text,
            used_llm=bool(llm_source and strategy.is_safe(llm_source, finding)),
            mitigation_explanation=mitigation_explanation,
            defense_strategy=defense_strategy,
        )

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented",
            "Hardcoded Secrets": "implemented",
            "Cross-Site Scripting": "implemented",
            "Command Injection": "implemented",
            "Path Traversal": "implemented",
            "SSRF": "implemented",
            "Server-Side Template Injection": "implemented",
            "Open Redirect": "implemented",
            "Insecure Deserialization": "implemented",
        }

    def _build_patch_prompt(self, source: str, finding: VulnerabilityFinding) -> str:
        return (
            f"File: {finding.affected_file}\n"
            f"Line: {finding.line_number}\n"
            f"Vulnerability: {finding.vulnerability_type}\n"
            f"Evidence: {finding.evidence}\n\n"
            f"Source:\n{source}"
        )

    def _extract_code_candidate(self, content: str) -> str | None:
        stripped = content.strip()
        if not stripped:
            return None
        if stripped.startswith("```") and "```" in stripped[3:]:
            parts = stripped.split("```")
            if len(parts) >= 3:
                code = parts[1]
                if code.startswith("python\n"):
                    code = code[len("python\n") :]
                return code.strip()
        if "def " in stripped and "import " in stripped:
            return stripped
        return None

    def _fallback_guidance_text(self, strategy: PatchStrategy) -> str:
        mitigation, defense_strategy = strategy.fallback_guidance()
        return f"Mitigation: {mitigation}\nDefense Strategy: {defense_strategy}"

    def _parse_mitigation_details(self, content: str, strategy: PatchStrategy) -> tuple[str, str]:
        default_mitigation, default_defense_strategy = strategy.fallback_guidance()
        mitigation = default_mitigation
        defense_strategy = default_defense_strategy
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if line.lower().startswith("mitigation:"):
                mitigation = line.split(":", 1)[1].strip() or mitigation
            elif line.lower().startswith("defense strategy:"):
                defense_strategy = line.split(":", 1)[1].strip() or defense_strategy
        return mitigation, defense_strategy
