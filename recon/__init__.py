"""
YATA RECON — the deployment-side module.

Where the development side of YATA (HUNTER / HEALER / VALIDATOR / MUTATOR /
LEARNER / REPORTER) scans *source code* and proves-then-patches vulnerabilities,
RECON does the equivalent job against a *live, deployed* web application it can
only reach over HTTP: reconnaissance, 35+ active scan modules with multi-stage
false-positive elimination, optional NVIDIA NIM AI assistance, and a Textual
TUI — all exposed through `yata recon`.

The engine lives under this package (`recon.core`, `recon.modules`,
`recon.tui`) and its command-line entry point is `recon.cli.main`.
"""

__all__ = ["main"]


def main(argv=None):
    """Entry point for the RECON engine (delegates to recon.cli.main)."""
    from recon.cli import main as _main
    return _main(argv)
