"""
Named scan profiles — save a --header/--cookie/--modules/--threads/...
combo as a reusable named profile instead of retyping flags every time.
Stored at ~/.yata-recon/profiles.json.
"""
import json
import os

PROFILES_DIR = os.path.join(os.path.expanduser("~"), ".yata-recon")
PROFILES_FILE = os.path.join(PROFILES_DIR, "profiles.json")

SAVED_KEYS = ["header", "cookie", "header2", "cookie2", "modules", "preset",
              "threads", "timeout", "delay", "confidence", "output_dir"]

# Argparse defaults for the non-None-default flags — a profile value only
# gets applied for these if the current invocation left the flag at its
# default, so an explicit flag on THIS invocation always wins.
_ARG_DEFAULTS = {"threads": 10, "timeout": 10, "delay": 0.5, "confidence": 60,
                  "preset": "standard", "output_dir": "./yata_recon_output"}


def _load() -> dict:
    if not os.path.exists(PROFILES_FILE):
        return {}
    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    os.makedirs(PROFILES_DIR, exist_ok=True)
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def list_profiles() -> dict:
    return _load()


def get_profile(name: str) -> dict | None:
    return _load().get(name)


def save_profile(name: str, args_namespace) -> dict:
    """Persist the subset of this invocation's flags that are worth reusing."""
    data = _load()
    profile = {}
    for key in SAVED_KEYS:
        val = getattr(args_namespace, key, None)
        if val:
            profile[key] = val
    data[name] = profile
    _save(data)
    return profile


def delete_profile(name: str):
    data = _load()
    data.pop(name, None)
    _save(data)


def apply_profile(args, profile: dict):
    """Fill in any flag left at its default from a saved profile — an
    explicit flag on THIS invocation always overrides the profile."""
    for key, val in profile.items():
        if key in ("header", "cookie", "header2", "cookie2"):
            if not getattr(args, key, None):
                setattr(args, key, val)
        elif key == "modules":
            if not getattr(args, "modules", None):
                args.modules = val
        elif key in _ARG_DEFAULTS:
            if getattr(args, key, None) == _ARG_DEFAULTS[key]:
                setattr(args, key, val)
    return args
