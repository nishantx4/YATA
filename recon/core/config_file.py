"""
Optional config-file support (--config FILE).

Lets an operator keep a reusable scan configuration in a JSON or YAML file
instead of a long command line or an opaque saved profile. Keys mirror the
CLI flag names (with - or _). CLI flags always win over the file, so the file
supplies defaults, never overrides an explicit choice.

YAML is supported only if PyYAML is installed; JSON always works. Unknown keys
are ignored with a warning rather than being fatal.
"""
import json

# argparse dest names we allow a config file to set (the safe, scan-shaping
# ones — never API keys or management commands).
_ALLOWED = {
    "target", "modules", "preset", "threads", "timeout", "delay", "confidence",
    "min_severity", "output", "output_dir", "scope", "scope_file", "out_of_scope",
    "proxy", "header", "cookie", "header2", "cookie2", "sarif", "sign_reports",
    "diff", "resume", "fresh_recon", "recon_cache_ttl", "no_parallel",
    "module_workers", "no_auto_install", "no_tui", "no_color", "verbose",
    "share_card", "fail_on",
}


def load_config_file(path: str):
    """Return a dict of {dest: value} parsed from the file, or raise on a hard
    parse error. Keys are normalized (dashes -> underscores)."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    data = None
    stripped = raw.lstrip()
    if stripped[:1] in ("{", "["):
        data = json.loads(raw)
    else:
        try:
            import yaml
            data = yaml.safe_load(raw)
        except ImportError:
            # Not JSON and no YAML available — try JSON anyway for a clear error.
            data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("config file must contain a top-level mapping of option -> value")
    return {str(k).replace("-", "_"): v for k, v in data.items()}


def apply_config_file(args, ui) -> None:
    """Fill any argparse value the user left at its default from the config
    file. Mutates `args` in place. Best-effort: a bad file warns and is
    skipped rather than killing the run."""
    path = getattr(args, "config", None)
    if not path:
        return
    try:
        cfg = load_config_file(path)
    except Exception as e:
        ui.error(f"--config: could not read '{path}': {e}")
        return

    applied, ignored = [], []
    for key, value in cfg.items():
        if key not in _ALLOWED:
            ignored.append(key)
            continue
        if not hasattr(args, key):
            ignored.append(key)
            continue
        current = getattr(args, key)
        # Only fill values the user didn't set on the CLI. argparse leaves
        # unset store_true flags False and unset options None/their default;
        # we treat None/False/"" as "unset" for file-fill purposes.
        if current in (None, False, "", []):
            setattr(args, key, value)
            applied.append(key)

    if applied:
        ui.info(f"--config: applied {len(applied)} option(s) from {path}: {', '.join(sorted(applied))}")
    if ignored:
        ui.warn(f"--config: ignored unknown/unsupported key(s): {', '.join(sorted(set(ignored)))}")
