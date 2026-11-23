"""
`yata recon` — deployment-side RECON module.

This is a thin bridge from YATA's unified CLI into the RECON engine
(`recon.cli`). Everything after `yata recon` is forwarded verbatim to the
engine's own argument parser, so the full flag set (`-t`, `--preset`,
`--modules`, `--header/--cookie`, `--no-tui`, `--set-api`, `--save-profile`,
`--sarif`, scheduling, stats, …) is available under `yata recon …`.

One YATA-specific convenience is layered on top: `--serve-local <test_repo>`
boots one of the bundled vulnerable Flask fixtures locally and points RECON at
it over real HTTP, so the live-deployment path can be demonstrated end to end
without an external target. It never mutates the fixture in place (Golden
Rule 3) — it always serves a sandboxed copy.
"""
from __future__ import annotations

import os
import shutil
import sys
import threading
import time
import importlib.util
from pathlib import Path

from rich.console import Console

console = Console()


def run(args) -> int:
    """Dispatch entry point used by yata.py. `args.recon_argv` holds every
    token that followed `yata recon` on the command line."""
    argv = list(getattr(args, "recon_argv", []) or [])

    # --serve-local is handled here (YATA-side demo convenience), then the scan
    # itself is delegated to the engine against the local URL.
    serve_local, port, argv = _extract_serve_local(argv)
    if serve_local is not None:
        return _run_against_local_test_repo(serve_local, port, argv)

    return _invoke_engine(argv)


def _invoke_engine(argv: list[str]) -> int:
    """Call the RECON engine's main(). It may raise SystemExit (it is a CLI);
    translate that into a normal return code so the unified CLI stays in
    control of process exit."""
    from recon.cli import main as recon_main
    try:
        rc = recon_main(argv)
        return int(rc) if isinstance(rc, int) else 0
    except SystemExit as exc:  # engine gates/exits via sys.exit(...)
        code = exc.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1


def _extract_serve_local(argv: list[str]) -> tuple[str | None, int, list[str]]:
    """Pull --serve-local <path> and --port <n> out of argv (they are
    YATA-side only), returning (serve_local_path, port, remaining_argv)."""
    serve_local: str | None = None
    port = 8765
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--serve-local":
            serve_local = argv[i + 1] if i + 1 < len(argv) else None
            i += 2
            continue
        if tok.startswith("--serve-local="):
            serve_local = tok.split("=", 1)[1]
            i += 1
            continue
        if tok == "--port":
            if i + 1 < len(argv):
                try:
                    port = int(argv[i + 1])
                except ValueError:
                    pass
            i += 2
            continue
        if tok.startswith("--port="):
            try:
                port = int(tok.split("=", 1)[1])
            except ValueError:
                pass
            i += 1
            continue
        out.append(tok)
        i += 1
    return serve_local, port, out


def _run_against_local_test_repo(serve_local: str, port: int, argv: list[str]) -> int:
    repo_dir = Path(serve_local).resolve()
    if not repo_dir.exists():
        console.print(f"[red]Repository path does not exist: {repo_dir}[/red]")
        return 1

    # Never touch the fixture in place (Golden Rule 3): serve a sandboxed copy.
    project_root = Path(__file__).resolve().parent.parent
    sandbox_dir = project_root / ".yata" / "recon_sandbox" / repo_dir.name
    if sandbox_dir.exists():
        shutil.rmtree(sandbox_dir, ignore_errors=True)
    sandbox_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(repo_dir, sandbox_dir, ignore=shutil.ignore_patterns(".yata", ".git", "__pycache__"))

    # Some fixtures open relative paths against the process CWD; mirror
    # verifier.py's _verify_path_traversal by chdir-ing into the app root.
    old_cwd = os.getcwd()
    os.chdir(sandbox_dir)
    server = None
    thread = None
    try:
        unique_name = f"yata_recon_target_{abs(hash(str(sandbox_dir.resolve())))}"
        spec = importlib.util.spec_from_file_location(unique_name, sandbox_dir / "app.py")
        if spec is None or spec.loader is None:
            console.print(f"[red]Unable to load app module from {sandbox_dir / 'app.py'}[/red]")
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        app = module.create_app(str(sandbox_dir / "database.db"))

        # Quiet werkzeug's per-request access log — in a headless RECON demo it
        # floods the console and drowns out the scan's own output.
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        from werkzeug.serving import make_server

        # threaded=True is essential: RECON drives the target with a pool of
        # concurrent workers (keep-alive connections), and a single-threaded
        # dev server would serialize — and effectively stall — the scan.
        server = make_server("127.0.0.1", port, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{port}"
        console.print(f"[cyan]Serving {repo_dir.name} locally at {base_url} for RECON[/cyan]")

        # Force headless mode for the served demo (a background HTTP server +
        # the Textual TUI fighting over the terminal is not what we want), and
        # inject the target unless the caller already supplied one.
        engine_argv = list(argv)
        if not any(a in ("-t", "--target") or a.startswith("-t=") or a.startswith("--target=") for a in engine_argv):
            engine_argv = ["-t", base_url, *engine_argv]
        if "--no-tui" not in engine_argv:
            engine_argv.append("--no-tui")
        # We chdir into the sandbox so the served fixture can resolve its own
        # relative files, which means a relative --output-dir would write the
        # report *inside* the sandbox. Pin it to an absolute path under the
        # project root so reports are easy to find, unless the caller chose one.
        if not any(a == "--output-dir" or a.startswith("--output-dir=") for a in engine_argv):
            out_dir = str((project_root / "yata_recon_output").resolve())
            engine_argv += ["--output-dir", out_dir]

        return _invoke_engine(engine_argv)
    finally:
        if server is not None:
            server.shutdown()
        if thread is not None:
            thread.join(timeout=5)
        os.chdir(old_cwd)
