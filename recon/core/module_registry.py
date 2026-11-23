"""
Module registry — plugin/module SDK.

Every new built-in module used to mean hand-editing core/session.py's
MODULE_MAP/MODULE_LABELS/PRESETS directly. This auto-discovers any
THIRD-PARTY module dropped into modules/ that opts in to the convention
below, so it becomes selectable via --modules <id>, shows up in the TUI
checklist, and joins the 'full' preset automatically — no core/session.py
edit required.

Convention for a new plugin module (modules/my_check.py):

    from recon.modules import BaseModule

    class MyCheckModule(BaseModule):
        MODULE_ID = "my_check"          # required — the --modules key
        MODULE_LABEL = "My Custom Check" # optional — defaults to NAME or a
                                          # title-cased MODULE_ID
        NAME = "My Custom Check"         # existing convention — UI display name

        def run(self):
            ...

That's it — YATA RECON finds it automatically on next run.

The 36 built-in modules are NOT part of this discovery (they're still
registered explicitly in core/session.py's MODULE_MAP, unchanged, so
existing --modules/--preset behavior/documentation stays exactly as
before) — this only ever ADDS modules that opt in with MODULE_ID, and
explicitly skips anything already present in the static map, so a
plugin can never accidentally shadow a built-in module id.
"""
import importlib
import inspect
import pkgutil

import recon.modules as _modules_pkg
from recon.modules import BaseModule


def discover_plugin_modules(existing_ids: set) -> dict:
    """
    Scan modules/*.py for BaseModule subclasses that declare a MODULE_ID
    class attribute not already present in `existing_ids`. Returns
    {module_id: ModuleClass}. Never raises — a broken/malformed plugin
    file is skipped, not fatal to the whole scan.
    """
    discovered = {}
    try:
        pkg_path = _modules_pkg.__path__
    except Exception:
        return discovered

    for _finder, name, ispkg in pkgutil.iter_modules(pkg_path):
        if ispkg or name.startswith('_'):
            continue
        try:
            mod = importlib.import_module(f"recon.modules.{name}")
        except Exception:
            continue

        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if not issubclass(obj, BaseModule) or obj is BaseModule:
                continue
            if obj.__module__ != mod.__name__:
                continue  # only classes DEFINED in this file, not re-exported/imported ones
            module_id = getattr(obj, "MODULE_ID", None)
            if not module_id or not isinstance(module_id, str):
                continue  # opt-in only — a module with no MODULE_ID is never auto-registered
            if module_id in existing_ids or module_id in discovered:
                continue  # never let a plugin shadow a built-in or another plugin
            discovered[module_id] = obj

    return discovered


def discover_plugin_labels(plugin_map: dict) -> dict:
    labels = {}
    for module_id, cls in plugin_map.items():
        label = getattr(cls, "MODULE_LABEL", None) or getattr(cls, "NAME", None) or module_id.replace('_', ' ').title()
        labels[module_id] = label
    return labels
