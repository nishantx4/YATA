from __future__ import annotations

import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from sandbox import ConfinedProcess, spawn_confined


class NodeAppStartupError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.05)
    return False


@dataclass(slots=True)
class HTTPResult:
    status_code: int
    body: str
    headers: dict[str, str]


class NodeAppProcess:
    """Starts a Node/Express (or ts-node/TypeScript) app in `app_root` as a
    real subprocess bound to an ephemeral loopback port, so the verifier can
    send it real HTTP requests -- the same "prove it at runtime" philosophy
    as the Flask test_client() used for Python targets, just over a real
    socket instead of a WSGI test interface.
    """

    def __init__(self, app_root: Path, entry_file: str) -> None:
        self.app_root = app_root
        self.entry_file = entry_file
        self.port = _free_port()
        self.process: ConfinedProcess | None = None

    def __enter__(self) -> "NodeAppProcess":
        is_typescript = self.entry_file.endswith(".ts")
        if is_typescript:
            ts_node_bin = _find_project_bin("ts-node")
            # Patched copies live in a temp directory outside the project
            # tree, so ts-node's own tsconfig.json auto-discovery (walking up
            # from cwd) won't find ours -- point it there explicitly.
            project_tsconfig = Path(__file__).resolve().parent / "tsconfig.json"
            command = [ts_node_bin, "--transpile-only", "--project", str(project_tsconfig), self.entry_file]
        else:
            node_bin = shutil.which("node")
            if node_bin is None:
                raise NodeAppStartupError("node executable not found on PATH")
            command = [node_bin, self.entry_file]

        self.process = spawn_confined(command, self.app_root, env=_child_env(self.port))

        if not _wait_for_port(self.port):
            output = self.process.read_output()
            self.__exit__(None, None, None)
            raise NodeAppStartupError(
                f"Node app in {self.app_root} did not start listening on port {self.port}.\n{output}"
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.process is None:
            return
        self.process.stop()
        self.process = None

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        allow_redirects: bool = True,
        timeout: float = 5.0,
    ) -> HTTPResult:
        url = f"http://127.0.0.1:{self.port}{path}"
        response = requests.request(
            method.upper(),
            url,
            params=params if method.upper() == "GET" else None,
            data=data if method.upper() != "GET" else None,
            allow_redirects=allow_redirects,
            timeout=timeout,
        )
        return HTTPResult(
            status_code=response.status_code,
            body=response.text,
            headers=dict(response.headers),
        )


def _find_project_bin(name: str) -> str:
    """Resolve a locally-installed npm binary (node_modules/.bin/<name>)
    relative to the yata-fyp project root, without depending on a global
    npm install or PATH configuration."""
    project_root = Path(__file__).resolve().parent
    for candidate in (f"{name}.cmd", name):
        bin_path = project_root / "node_modules" / ".bin" / candidate
        if bin_path.exists():
            return str(bin_path)
    resolved = shutil.which(name)
    if resolved:
        return resolved
    raise NodeAppStartupError(
        f"Could not find '{name}'. Run `npm install` in the project root to set up the JS/TS runtime."
    )


def _child_env(port: int) -> dict[str, str]:
    import os

    env = dict(os.environ)
    for secret_name in ("NVIDIA_API_KEY", "NGC_API_KEY"):
        env.pop(secret_name, None)
    env["PORT"] = str(port)

    # Patched copies are written to a temp directory outside the project
    # tree (see BlueAgent.generate_patch / fallback_patches.generate_patch),
    # so plain `require("express")` can't walk up to find node_modules from
    # there. NODE_PATH gives Node a second place to look.
    project_node_modules = str(Path(__file__).resolve().parent / "node_modules")
    existing_node_path = env.get("NODE_PATH", "")
    env["NODE_PATH"] = (
        f"{project_node_modules}{os.pathsep}{existing_node_path}" if existing_node_path else project_node_modules
    )
    return env


def detect_entry_file(app_root: Path) -> str:
    """Pick the fixture's entry file: server.js/app.js (and .ts variants),
    falling back to any single top-level .js/.ts file."""
    for candidate in ("server.js", "app.js", "server.ts", "app.ts"):
        if (app_root / candidate).exists():
            return candidate
    top_level = [p.name for p in app_root.iterdir() if p.suffix in (".js", ".ts") and p.is_file()]
    if len(top_level) == 1:
        return top_level[0]
    raise NodeAppStartupError(f"Could not determine entry file for {app_root}")
