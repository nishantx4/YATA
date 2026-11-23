"""
SkipController — cooperative, per-module cancellation for a running scan.

The operator can decide mid-scan to abandon a module that's taking too long
(classically Nuclei, which can block for minutes on its own subprocess). This
gives every module one shared, thread-safe place to ask "has the operator
asked to skip me?":

  * HTTP-bound modules abort at their next request — BaseModule._throttle()
    raises ModuleSkipped when this says so, so the module stops issuing new
    requests almost immediately (and drains any remaining worklist for free).
  * Subprocess-bound tools (Nuclei, recon's katana/subfinder) pass the
    per-module threading.Event from event_for() into the tool runner, which
    kills the child process when it's set.

One Event per module id; setting it is the skip request. Nothing here blocks.
"""
import threading


class SkipController:
    def __init__(self):
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}

    def event_for(self, module_id: str) -> threading.Event:
        """The (lazily created) cancellation Event for a module id."""
        with self._lock:
            ev = self._events.get(module_id)
            if ev is None:
                ev = threading.Event()
                self._events[module_id] = ev
            return ev

    def request(self, module_id: str) -> None:
        """Operator asks to skip this module. Idempotent."""
        self.event_for(module_id).set()

    def is_requested(self, module_id: str) -> bool:
        with self._lock:
            ev = self._events.get(module_id)
        return bool(ev and ev.is_set())

    def reset(self, module_id: str) -> None:
        with self._lock:
            self._events.pop(module_id, None)
