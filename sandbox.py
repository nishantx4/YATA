from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT_BYTES = 1_000_000

# Variables the child is allowed to inherit. Everything else (API keys, tokens,
# cloud credentials in the parent shell) is dropped.
_ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "NODE_PATH")


@dataclass(slots=True)
class SandboxResult:
    exit_code: int
    output: str
    timed_out: bool
    backend: str
    isolated: bool  # True only when the OS/container enforces the boundary, not just this module


class SandboxBackend:
    name = "base"
    isolated = False

    def available(self) -> bool:
        raise NotImplementedError

    def run(self, argv: list[str], workdir: Path, *, timeout: int = 30, network: bool = False) -> SandboxResult:
        raise NotImplementedError


def _scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {key: os.environ[key] for key in _ENV_ALLOWLIST if key in os.environ}
    if extra:
        env.update(extra)
    return env


def _kill_tree(process: subprocess.Popen) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.kill()


class LocalProcessBackend(SandboxBackend):
    """Runs the command as a child process of the caller. It bounds time, output
    size, working directory and environment, but it does NOT block network or
    filesystem access outside workdir -- results are marked isolated=False so
    reports never overstate the guarantee."""

    name = "local-process"
    isolated = False

    def available(self) -> bool:
        return True

    def run(self, argv: list[str], workdir: Path, *, timeout: int = 30, network: bool = False) -> SandboxResult:
        workdir = Path(workdir).resolve()
        if not workdir.is_dir():
            return SandboxResult(-1, f"workdir does not exist: {workdir}", False, self.name, self.isolated)

        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        process = subprocess.Popen(
            argv,
            cwd=workdir,
            env=_scrubbed_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )

        chunks: list[bytes] = []

        def _drain() -> None:
            total = 0
            assert process.stdout is not None
            for chunk in iter(lambda: process.stdout.read(4096), b""):
                if total < MAX_OUTPUT_BYTES:
                    chunks.append(chunk[: MAX_OUTPUT_BYTES - total])
                total += len(chunk)

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()

        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(process)
            process.wait()
        reader.join(timeout=2)

        output = b"".join(chunks).decode("utf-8", errors="replace")
        return SandboxResult(process.returncode, output, timed_out, self.name, self.isolated)


class DockerBackend(SandboxBackend):
    """Runs the command in a throwaway container: no network by default, no
    capabilities, read-only root, workdir mounted read-only, memory/CPU/pid caps."""

    name = "docker"
    isolated = True

    def __init__(self, image: str = "python:3.13-slim") -> None:
        self.image = image

    def available(self) -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            probe = subprocess.run(
                ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return probe.returncode == 0

    def run(self, argv: list[str], workdir: Path, *, timeout: int = 30, network: bool = False) -> SandboxResult:
        workdir = Path(workdir).resolve()
        command = [
            "docker", "run", "--rm",
            "--network", "bridge" if network else "none",
            "--cap-drop", "ALL",
            "--read-only",
            "--tmpfs", "/tmp",
            "--memory", "512m",
            "--cpus", "1",
            "--pids-limit", "128",
            "-v", f"{workdir}:/workspace:ro",
            "-w", "/workspace",
            self.image,
            *argv,
        ]
        try:
            completed = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout + 5, check=False
            )
        except subprocess.TimeoutExpired as exc:
            partial = (exc.stdout or b"")[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            return SandboxResult(-1, partial, True, self.name, self.isolated)
        output = completed.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        return SandboxResult(completed.returncode, output, False, self.name, self.isolated)


def _windows_job_with_limits(process: subprocess.Popen, memory_limit_mb: int):
    """Put `process` (and anything it later spawns) in a Job Object that kills
    the whole tree when closed and caps per-process memory. Returns the job
    handle, or None if the OS refuses -- callers still kill the tree by pid."""
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BASIC_LIMITS(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMITS(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMITS), ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None

    limits = EXTENDED_LIMITS()
    limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x100  # KILL_ON_JOB_CLOSE | PROCESS_MEMORY
    limits.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024
    ok = kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
    if not ok or not kernel32.AssignProcessToJobObject(job, int(process._handle)):
        kernel32.CloseHandle(job)
        return None
    return job


class ConfinedProcess:
    """A long-running child (e.g. a target web app) whose whole process tree is
    stopped together, whose output goes to a file (so a chatty app can never
    fill a pipe and freeze), and which cannot be orphaned."""

    def __init__(self, popen: subprocess.Popen, log_path: Path, job) -> None:
        self.popen = popen
        self.log_path = log_path
        self._job = job

    def poll(self) -> int | None:
        return self.popen.poll()

    def read_output(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")[-MAX_OUTPUT_BYTES:]
        except OSError:
            return ""

    def stop(self) -> None:
        if self.popen.poll() is None:
            _kill_tree(self.popen)
            try:
                self.popen.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if self._job is not None:
            import ctypes
            ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(self._job))
            self._job = None
        if sys.platform != "win32":
            try:
                os.killpg(self.popen.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            self.log_path.unlink()
        except OSError:
            pass


def spawn_confined(
    argv: list[str], cwd: Path, *, env: dict[str, str], memory_limit_mb: int = 1024
) -> ConfinedProcess:
    log_fd, log_name = tempfile.mkstemp(prefix="yata_proc_", suffix=".log")
    log_file = os.fdopen(log_fd, "wb")
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
        try:
            import resource

            limit = memory_limit_mb * 1024 * 1024

            def _limit_memory() -> None:
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

            kwargs["preexec_fn"] = _limit_memory
        except ImportError:
            pass
    try:
        popen = subprocess.Popen(
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT, **kwargs
        )
    finally:
        log_file.close()

    job = _windows_job_with_limits(popen, memory_limit_mb) if sys.platform == "win32" else None
    return ConfinedProcess(popen, Path(log_name), job)


def get_backend(prefer_isolated: bool = True) -> SandboxBackend:
    if prefer_isolated:
        docker = DockerBackend()
        if docker.available():
            return docker
    return LocalProcessBackend()
