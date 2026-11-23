"""
Cooperative cancellation — a single process-wide "stop now" signal.

Ctrl-C used to leave the module ThreadPoolExecutor and any in-flight
long-wait loops (OOB poll windows, time-based re-probes, race-condition
bursts) grinding on until they happened to finish, so the interrupt felt
unresponsive and partial results were slow to save. This gives the session a
flag to raise on KeyboardInterrupt and gives long-running loops a cheap thing
to check so they bail out promptly and cleanly.
"""
import threading

_STOP = threading.Event()


def request_stop():
    _STOP.set()


def reset():
    _STOP.clear()


def is_cancelled() -> bool:
    return _STOP.is_set()


def check():
    """Raise KeyboardInterrupt if cancellation was requested — lets a worker
    unwind through the same path a direct Ctrl-C would."""
    if _STOP.is_set():
        raise KeyboardInterrupt("scan cancelled")


def sleep(seconds: float, step: float = 0.25) -> bool:
    """Interruptible sleep: returns True if it slept the full duration, False
    if cancellation cut it short. Use in place of time.sleep() in long waits."""
    import time
    end = time.time() + max(0.0, seconds)
    while time.time() < end:
        if _STOP.is_set():
            return False
        time.sleep(min(step, max(0.0, end - time.time())))
    return True
