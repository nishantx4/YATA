from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from llm_client import LLMClient

_TOOL_CALL_RE = re.compile(
    r'^\s*TOOL:\s*(rescan)\(\)\s*$|^\s*TOOL:\s*(read_file)\(\s*["\'](.+?)["\']\s*\)\s*$'
)
_READ_FILE_MAX_BYTES = 20_000
_MAX_TOOL_CALLS_PER_TURN = 3


@dataclass(slots=True)
class ChatContext:
    """Everything the chat's system prompt is grounded in. Built once from a
    live MissionState (TUI) or a quick read-only scan (CLI) -- see
    build_context_from_mission_state() / build_context_from_scan() below.

    There are no tools yet: this snapshot is the chat's entire view of the
    world for the lifetime of the session. It does not update if the
    repository changes underneath it.
    """

    target_name: str
    target_path: str
    scope_summary: str
    mode: str
    findings: list[dict[str, object]] = field(default_factory=list)
    initial_score: int | None = None
    final_score: int | None = None
    verification_outcome: str | None = None
    reports: dict[str, str] = field(default_factory=dict)
    note: str = ""


SYSTEM_PROMPT_PREAMBLE = (
    "You are YATA's assistant, answering questions about one specific security assessment. "
    "YATA is an autonomous tool that discovers vulnerabilities (HUNTER), generates patches "
    "(HEALER), re-attacks the patch (VALIDATOR), and tries mutated payloads against it "
    "(MUTATOR). Ground every answer in the target, mode, and findings listed below -- do not "
    "invent vulnerabilities, files, or line numbers that aren't there.\n\n"
    "You have exactly two tools, both read-only:\n"
    "  - rescan(): re-runs HUNTER's discovery scan against the target repository right now, "
    "replacing the findings list below with current results. Use this if asked whether "
    "something has changed since the assessment ran.\n"
    "  - read_file(\"relative/path\"): reads a file from the target repository (capped at "
    "20KB, path must stay inside the repository). Use this to answer questions about code "
    "that isn't already summarized in the findings below.\n\n"
    "To use a tool, reply with EXACTLY one line and nothing else: TOOL: rescan() or "
    "TOOL: read_file(\"relative/path\"). You will get the result back and can then answer "
    "normally, or call another tool (up to a few times). Do not narrate that you are about to "
    "call a tool -- just emit the TOOL: line by itself. For anything else, answer normally in "
    "plain text. You cannot modify files, run exploits, or apply patches -- only discover and "
    "read."
)


def build_system_prompt(context: ChatContext) -> str:
    lines = [
        SYSTEM_PROMPT_PREAMBLE,
        "",
        f"Target repository: {context.target_name} ({context.target_path})",
        f"Scope: {context.scope_summary}",
        f"Mode: {context.mode}",
    ]
    if context.initial_score is not None and context.final_score is not None:
        lines.append(f"Security score: {context.initial_score} -> {context.final_score}")
    if context.verification_outcome:
        lines.append(f"Validation outcome: {context.verification_outcome}")
    if context.reports:
        report_list = ", ".join(f"{fmt}: {path}" for fmt, path in context.reports.items())
        lines.append(f"Reports written to: {report_list}")
    if context.note:
        lines.append(context.note)

    lines.append("")
    if context.findings:
        lines.append(f"Findings ({len(context.findings)}):")
        for idx, finding in enumerate(context.findings, 1):
            vuln_type = finding.get("vulnerability_type", "Unknown")
            file_path = finding.get("file", "?")
            line_number = finding.get("line_number", "?")
            severity = finding.get("severity", "?")
            status = finding.get("status", "unknown")
            lines.append(f"  {idx}. {vuln_type} in {file_path}:{line_number} [{severity}] -- status: {status}")
    else:
        lines.append("No findings recorded for this repository in this session.")

    return "\n".join(lines)


class ChatSession:
    """A standing multi-turn conversation grounded in a ChatContext snapshot.
    Shared by the TUI ChatScreen and the `yata chat` CLI command -- neither
    surface talks to LLMClient directly."""

    MAX_TURNS_KEPT = 20  # user+assistant pairs; oldest turns drop first

    def __init__(self, context: ChatContext, llm_client: LLMClient | None = None) -> None:
        self.context = context
        self.llm = llm_client or LLMClient()
        self.system_prompt = build_system_prompt(context)
        self.messages: list[dict[str, str]] = []

    @property
    def is_available(self) -> bool:
        return bool(self.llm.api_key)

    def unavailable_reason(self) -> str:
        return (
            "Chat needs a configured NVIDIA_API_KEY (set it in .env). Unlike HUNTER/HEALER, "
            "there's no offline fallback for open-ended conversation -- it either talks to the "
            "real model or it doesn't run."
        )

    def send(self, user_text: str) -> str:
        if not self.is_available:
            return self.unavailable_reason()

        self.messages.append({"role": "user", "content": user_text})
        self._trim_history()

        tool_calls_used = 0
        while True:
            payload = [{"role": "system", "content": self.system_prompt}, *self.messages]
            # Empty fallback_text here on purpose: a key IS configured at this
            # point, so if the call still fails, that's a real error (bad model,
            # rate limit, network) -- not the "no key" case, and hiding it behind
            # the same canned message would mislead someone who just fixed their
            # .env into thinking they hadn't.
            response = self.llm.chat(messages=payload, fallback_text="")
            if not response.success:
                reply = self._format_error_reply(response.error)
                self.messages.append({"role": "assistant", "content": reply})
                return reply

            reply = response.content
            tool_match = _TOOL_CALL_RE.match(reply.strip())
            if tool_match is None or tool_calls_used >= _MAX_TOOL_CALLS_PER_TURN:
                self.messages.append({"role": "assistant", "content": reply})
                return reply

            # The model's own TOOL: line is kept in history so it can see what
            # it already tried, followed by the tool's result as a user turn
            # (this LLM/provider has no dedicated "tool" role in the chat API).
            self.messages.append({"role": "assistant", "content": reply})
            tool_calls_used += 1
            tool_result = self._run_tool_call(tool_match, tool_call_id=f"call_{tool_calls_used}")
            self.messages.append({"role": "user", "content": f"[Tool result]\n{tool_result}"})
            self._trim_history()

    def _run_tool_call(self, match: re.Match, *, tool_call_id: str) -> str:
        tool_name = match.group(1) or match.group(2)
        try:
            if tool_name == "rescan":
                return self._tool_rescan()
            if tool_name == "read_file":
                return self._tool_read_file(match.group(3), tool_call_id=tool_call_id)
            return f"Unknown tool: {tool_name}"
        except Exception as exc:  # tool failures are data for the model, not crashes
            return f"Tool {tool_name} failed: {exc}"

    def _tool_rescan(self) -> str:
        from red_agent import RedAgent

        target_path = Path(self.context.target_path)
        raw_findings = RedAgent().scan(target_path)
        self.context.findings = [
            {
                "vulnerability_type": f.vulnerability_type,
                "file": f.metadata.get("relative_file", f.affected_file),
                "line_number": f.line_number,
                "severity": f.severity,
                "status": "active (rescanned live during chat)",
            }
            for f in raw_findings
        ]
        self.system_prompt = build_system_prompt(self.context)
        return f"Rescan complete: {len(self.context.findings)} finding(s) now recorded."

    def _tool_read_file(self, relative_path: str, *, tool_call_id: str) -> str:
        from tool_output import bound_and_store

        target_root = Path(self.context.target_path).resolve()
        candidate = (target_root / relative_path).resolve()
        try:
            candidate.relative_to(target_root)
        except ValueError:
            return f"Refused: {relative_path!r} resolves outside the target repository."

        if not candidate.is_file():
            return f"No such file: {relative_path}"

        raw_bytes = candidate.read_bytes()[:_READ_FILE_MAX_BYTES]
        text = raw_bytes.decode("utf-8", errors="replace")
        store_dir = target_root / ".yata" / "tool-output"
        display, _full_path = bound_and_store(text, tool_call_id, store_dir)
        suffix = "\n[... file truncated at 20KB ...]" if len(raw_bytes) >= _READ_FILE_MAX_BYTES else ""
        return f"Contents of {relative_path}:\n{display}{suffix}"

    def _format_error_reply(self, error: str | None) -> str:
        return (
            "The request to the LLM failed, so there's no real reply this turn.\n"
            f"Underlying error: {error or 'unknown error'}"
        )

    def _trim_history(self) -> None:
        max_messages = self.MAX_TURNS_KEPT * 2
        if len(self.messages) > max_messages:
            self.messages = self.messages[-max_messages:]


def build_context_from_mission_state(state) -> ChatContext:  # tui.state.MissionState, avoiding a tui import here
    scope_type = getattr(state.scope_type, "value", str(state.scope_type)).capitalize()
    scope_summary = scope_type
    if state.scope_path:
        scope_summary = f"{scope_type} ({state.scope_path.name})"

    return ChatContext(
        target_name=state.target_name or "unknown",
        target_path=str(state.target_path or ""),
        scope_summary=scope_summary,
        mode=getattr(state.mode, "value", str(state.mode)).upper(),
        findings=list(state.findings),
        initial_score=state.initial_score,
        final_score=state.final_score,
        verification_outcome=state.verification_outcome,
        reports=dict(state.reports),
    )


def build_context_from_scan(target_path) -> ChatContext:
    """CLI entrypoint (`yata chat <path>`) has no prior mission to ground on,
    so it runs a quick read-only HUNTER-only scan (discovery, no exploit
    attempts, no patching) to seed the conversation instead."""
    from pathlib import Path

    from red_agent import RedAgent

    target_path = Path(target_path).resolve()
    raw_findings = RedAgent().scan(target_path)
    findings = [
        {
            "vulnerability_type": f.vulnerability_type,
            "file": f.metadata.get("relative_file", f.affected_file),
            "line_number": f.line_number,
            "severity": f.severity,
            "status": "active (discovered only -- not yet exploited, patched, or validated)",
        }
        for f in raw_findings
    ]

    return ChatContext(
        target_name=target_path.name,
        target_path=str(target_path),
        scope_summary="Entire repository",
        mode="SCAN-ONLY (no HEALER/VALIDATOR run yet)",
        findings=findings,
        note=(
            "This is a discovery-only preview from `yata chat`, not a full assessment -- "
            "run `yata assess` for exploitation, patching, and validation."
        ),
    )
