#!/usr/bin/env python3
"""
YATA RECON 1.0 — web application security scanner

Recon, scan, verify, and report. A console/CI mode and a live Textual TUI
share one engine and one look.

Usage:
  yata recon -t example.com [options]
  yata recon --set-api  nvapi-xxxx      (save your NVIDIA key)
  yata recon --set-model MODEL          (choose the NIM model)
  yata recon --api-test                 (verify the key works)
  yata recon --remove-api               (delete saved key)
  yata recon --interactive
"""

import argparse
import sys
import os

# Fix Windows terminal encoding so emoji/Unicode don't crash on cp1252
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


from recon.core.banner import print_banner
from recon.core.session import ScanSession
from recon.core.ui import UI
import recon.core.config as config


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='yata recon',
        description='YATA RECON 1.0 — web application security scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
API Key Management:
  yata recon --set-api nvapi-xxxx    Save your NVIDIA NIM API key
  yata recon --api-test              Test if saved key is working
  yata recon --remove-api            Remove the saved key

Scan Examples:
  yata recon -t example.com
  yata recon -t example.com --full
  yata recon -t example.com --modules recon,js,idor,xss
  yata recon --interactive

Get a free NVIDIA NIM API key at: https://build.nvidia.com/
        """
    )

    # ── API key management (no target needed) ──
    api_group = parser.add_argument_group('NVIDIA AI Key Management')
    api_group.add_argument('--set-api',    metavar='KEY',
                           help='Save your NVIDIA NIM API key persistently (~/.yata-recon/config.json)')
    api_group.add_argument('--remove-api', action='store_true',
                           help='Remove the saved NVIDIA API key')
    api_group.add_argument('--api-test',   action='store_true',
                           help='Test whether the saved (or provided) API key is working')
    api_group.add_argument('--set-model',  metavar='MODEL',
                           help='Set the NVIDIA NIM model id (default: meta/llama-3.1-70b-instruct)')
    api_group.add_argument('--show-model', action='store_true',
                           help='Show the currently configured NVIDIA NIM model')

    # ── Scan target ──
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-t', '--target',      help='Target domain (e.g. example.com)')
    scan_group.add_argument('--targets',           metavar='FILE',
                             help='File with one target per line — scan them all in sequence (forces headless mode). '
                                  'Lines starting with # are ignored.')
    scan_group.add_argument('--distributed',       type=int, metavar='N', default=1,
                             help='With --targets: run N target scans truly concurrently, each in its own worker '
                                  'process (default: 1 = sequential). Each worker process is fully isolated — a '
                                  'crashed/hung scan of one target cannot affect the others.')
    scan_group.add_argument('--api-key',           help='NVIDIA NIM API key for this session only (not saved)')
    scan_group.add_argument('--preset',            choices=['quick', 'standard', 'full'], default='standard', help='Scan profile preset')
    scan_group.add_argument('--modules',           help='Comma-separated modules to run (overrides preset)')
    scan_group.add_argument('--list-modules',      action='store_true',
                             help='List every available scan module (with the presets each belongs to) and exit')
    scan_group.add_argument('--scope',             help='In-scope hosts (comma-separated; supports *.example.com and bare domains). Enforced at the request layer.')
    scan_group.add_argument('--scope-file',        metavar='FILE',
                            help='Load scope from a file (one host/line; lines starting ! or - are exclusions) or a HackerOne/Bugcrowd JSON scope export.')
    scan_group.add_argument('--out-of-scope',      action='append', metavar='HOST',
                            help='Explicitly out-of-scope host/pattern (repeatable). Exclusions always win over in-scope rules.')
    scan_group.add_argument('--proxy',             metavar='URL',
                            help='Route all scan traffic through an upstream proxy, e.g. http://127.0.0.1:8080 (Burp/ZAP/mitmproxy).')
    scan_group.add_argument('--output',            help='Output report file')
    scan_group.add_argument('--output-dir',        default='./yata_recon_output', help='Output directory')
    scan_group.add_argument('--threads',           type=int, default=10, help='Threads (default: 10)')
    scan_group.add_argument('--timeout',           type=int, default=10, help='Request timeout (default: 10s)')
    scan_group.add_argument('--delay',             type=float, default=0.5, help='Delay between requests (default: 0.5s)')
    scan_group.add_argument('--confidence',        type=int, default=60, help='Minimum confidence score (0-100) to report')
    scan_group.add_argument('--min-severity',      choices=['critical', 'high', 'medium', 'low', 'info'], default=None,
                             help='Only report findings at or above this severity (e.g. --min-severity high keeps only critical+high)')
    scan_group.add_argument('--sarif',             action='store_true',
                             help='Also write a SARIF 2.1.0 report (.sarif) alongside the JSON/Markdown — for GitHub code-scanning / CI ingestion')
    scan_group.add_argument('--header',            action='append', metavar='"Name: Value"',
                             help='Extra header sent with every request (repeatable), e.g. --header "X-Auth-Token: abc123". '
                                  'Use this to scan authenticated areas — every module (and the API-spec parser) will use it.')
    scan_group.add_argument('--cookie',            action='append', metavar='name=value',
                             help='Extra cookie sent with every request (repeatable), e.g. --cookie "session=abc123"')
    scan_group.add_argument('--header2',           action='append', metavar='"Name: Value"',
                             help='Header for a SECOND, separately-authenticated identity (repeatable). '
                                  'Enables real two-role differential IDOR/broken-access-control testing: '
                                  'the IDOR module fetches the same object under both identities and compares.')
    scan_group.add_argument('--cookie2',           action='append', metavar='name=value',
                             help='Cookie for a SECOND, separately-authenticated identity (repeatable) — pairs with --header2.')
    scan_group.add_argument('--no-tui',            action='store_true', help='Disable Textual TUI (run headless)')
    scan_group.add_argument('--no-auto-install',   action='store_true', help='Do not auto-download external tools (nuclei/subfinder/katana/waybackurls)')
    scan_group.add_argument('--no-parallel',       action='store_true',
                             help='Run modules strictly sequentially instead of concurrently (slower; useful for debugging/deterministic ordering)')
    scan_group.add_argument('--module-workers',    type=int, default=None,
                             help='Max modules to run concurrently (default: auto, derived from --threads)')
    scan_group.add_argument('--fresh-recon',       action='store_true',
                             help='Skip the recon cache and force a full re-crawl/subdomain-enum/JS-mining pass')
    scan_group.add_argument('--recon-cache-ttl',   type=int, default=6 * 3600,
                             help='How long (seconds) cached recon data for a target stays valid (default: 21600 = 6h)')
    scan_group.add_argument('--diff',              action='store_true',
                             help='Continuous/diff mode — compare this scan against the most recent previous scan of the same target and report only what changed (new/fixed findings)')
    scan_group.add_argument('--resume',            action='store_true',
                             help='Resume an interrupted scan of this target — skips modules already attempted and restores their findings from the checkpoint left in --output-dir (a scan that ran to completion has none; a killed/crashed one does)')
    scan_group.add_argument('--sign-reports',      action='store_true',
                             help='Hash + Ed25519-sign the JSON/Markdown report output (.sig sidecar files) so they can be verified untampered later — requires the cryptography package')
    scan_group.add_argument('--verify-report',     metavar='PATH',
                             help='Verify a previously-signed report file against its .sig sidecar and exit — no scan runs')
    scan_group.add_argument('--fail-on',           choices=['critical', 'high', 'medium', 'low'], default=None,
                             help='CI/CD gating — exit with a non-zero code if any finding at or above this severity is found')
    scan_group.add_argument('--profile',           help='Load a named scan profile saved with --save-profile (see ~/.yata-recon/profiles.json)')
    scan_group.add_argument('--save-profile',      metavar='NAME',
                             help='Save this invocation\'s --header/--cookie/--modules/--threads/--timeout/--delay/--preset flags as a reusable named profile, then run normally')
    scan_group.add_argument('--list-profiles',     action='store_true', help='List saved scan profiles and exit')
    scan_group.add_argument('--generate-cron',     metavar='PROFILE',
                             help='Print ready-to-use cron/Task Scheduler snippets for continuous monitoring — running '
                                  'the named --profile on a schedule with --diff mode — and exit. Save a profile first with --save-profile.')
    scan_group.add_argument('--history',           nargs='?', const='__ALL__', metavar='TARGET', default=None,
                             help='Show scan history/trend for TARGET (or every scanned target if omitted) and exit — no scan runs')
    scan_group.add_argument('--mark-fp',           nargs=2, metavar=('TITLE', 'URL'),
                             help='Mark a finding (exact title + URL, as printed/reported) as a false positive — '
                                  'downweights matching findings (by a digit/UUID-normalized title+URL pattern) in future scans')
    scan_group.add_argument('--list-fp-feedback',  action='store_true', help='List all recorded false-positive feedback and exit')
    scan_group.add_argument('--dry-run',           action='store_true',
                            help='Show the scan plan (modules, scope, estimated request budget) and exit without sending any traffic.')
    scan_group.add_argument('--share-card',        action='store_true',
                            help='Print a compact, copy-paste-friendly result card at the end of the scan.')
    scan_group.add_argument('--export-requests',   metavar='REPORT.json',
                            help='Read a saved JSON report and write reproducible .http + curl files for every finding, then exit.')
    scan_group.add_argument('--stats',             nargs='?', const='__ALL__', metavar='TARGET', default=None,
                            help='Show personal scan statistics from local history (all targets, or one TARGET) and exit.')
    scan_group.add_argument('--config',            metavar='FILE',
                            help='Load default options from a JSON/YAML config file (CLI flags still override).')
    scan_group.add_argument('--no-color',          action='store_true', help='Disable colored output (headless only)')
    scan_group.add_argument('--verbose', '-v',     action='store_true', help='Verbose output (headless only)')
    scan_group.add_argument('--interactive', '-i', action='store_true', help='Legacy interactive mode')
    scan_group.add_argument('--version',           action='version', version='YATA RECON 1.0')

    args = parser.parse_args(argv)

    # --config: merge a JSON/YAML file UNDER the CLI. Loading the file into the
    # parser's defaults and re-parsing means an explicit CLI flag still wins,
    # while the file can override hard-coded defaults like --preset/--threads
    # (which a post-parse fill never could, since they're never "unset").
    if getattr(args, "config", None):
        try:
            from recon.core.config_file import load_config_file, _ALLOWED
            cfg = load_config_file(args.config)
            defaults = {k: v for k, v in cfg.items() if k in _ALLOWED and hasattr(args, k)}
            if defaults:
                parser.set_defaults(**defaults)
                args = parser.parse_args(argv)
                args._config_applied = sorted(defaults)
        except Exception as e:
            args._config_error = str(e)
    return args


def handle_api_commands(args, ui) -> bool:
    """
    Handle --set-api, --remove-api, --api-test.
    Returns True if a management command was handled (caller should exit).
    """
    handled = False

    if args.set_api:
        handled = True
        key = args.set_api.strip()
        ui.info("Testing key before saving...")
        from recon.core.ai_engine import AIEngine
        if AIEngine.test_key(key, ui):
            config.set_api_key(key)
            ui.ok("API key saved to ~/.yata-recon/config.json")
            ui.info("AI-assisted hunting is now active on all future scans.")
        else:
            ui.error("Key test failed — key NOT saved. Double-check your NVIDIA NIM key.")
            ui.info("Get a free key at: https://build.nvidia.com/")

    if args.set_model:
        handled = True
        config.set_model(args.set_model.strip())
        ui.ok(f"NVIDIA NIM model set to: {config.get_model()}")

    if args.show_model:
        handled = True
        ui.info(f"Configured NVIDIA NIM model: {config.get_model()}")

    if args.remove_api:
        handled = True
        config.remove_api_key()
        ui.ok("API key removed from ~/.yata-recon/config.json")

    if args.api_test:
        handled = True
        # Prefer CLI-provided key, fall back to saved one
        key = (args.api_key or "").strip() or config.get_api_key()
        if not key:
            ui.error("No API key found. Run: yata recon --set-api nvapi-xxxx")
        else:
            ui.info(f"Testing NVIDIA NIM API key: {key[:12]}...{key[-4:]}")
            from recon.core.ai_engine import AIEngine
            if AIEngine.test_key(key, ui):
                ui.ok("API key is valid and working.")
                ui.info(f"Model: {config.get_model()}  |  Endpoint: https://integrate.api.nvidia.com/v1")
            else:
                ui.error("API key test failed. Check the key and your internet connection.")

    return handled


def handle_profile_commands(args, ui) -> bool:
    """
    Handle --list-profiles, --profile (load), --save-profile (save).
    Returns True only for --list-profiles (a pure management command that
    exits without scanning) — --profile/--save-profile mutate `args` in
    place and let the scan continue normally afterward.
    """
    from recon.core.profiles import list_profiles, get_profile, apply_profile, save_profile

    if args.list_profiles:
        profiles = list_profiles()
        if not profiles:
            ui.info("No saved scan profiles. Create one with: yata recon -t <target> ... --save-profile NAME")
        else:
            ui.section("Saved Scan Profiles")
            for name, prof in profiles.items():
                ui.bullet(f"{name}: {prof}")
        return True

    if args.profile:
        prof = get_profile(args.profile)
        if not prof:
            ui.error(f"No saved profile named '{args.profile}'. Use --list-profiles to see what's available.")
            return True
        apply_profile(args, prof)
        ui.info(f"Loaded scan profile '{args.profile}'")

    if args.save_profile:
        save_profile(args.save_profile, args)
        ui.ok(f"Saved scan profile '{args.save_profile}' — reuse it with --profile {args.save_profile}")

    return False


def handle_history_command(args, ui) -> bool:
    """Handle --history. Returns True (always a pure read-only command that
    exits without scanning when the flag is present)."""
    if args.history is None:
        return False

    from recon.core.history_db import get_scan_history, get_all_targets
    from datetime import datetime

    targets = get_all_targets() if args.history == '__ALL__' else [args.history]
    if not targets:
        ui.info("No scan history recorded yet — run a scan first.")
        return True

    for target in targets:
        scans = get_scan_history(target)
        if not scans:
            ui.info(f"No history for '{target}'.")
            continue
        ui.section(f"Scan History — {target}")
        rows = []
        for s in scans:
            ts = datetime.fromtimestamp(s['timestamp']).strftime('%Y-%m-%d %H:%M')
            rows.append([ts, str(s['finding_count']), f"{s['risk_score']}/100",
                        str(s['critical']), str(s['high']), str(s['medium']), str(s['low'])])
        ui.table(["Date", "Findings", "Risk", "Crit", "High", "Med", "Low"], rows)
        if len(scans) >= 2:
            delta = scans[0]['risk_score'] - scans[-1]['risk_score']
            trend = "improving" if delta < 0 else "worsening" if delta > 0 else "stable"
            ui.info(f"Risk trend over {len(scans)} scan(s): {trend} ({delta:+d})")
        ui.blank()
    return True


def handle_fp_feedback_commands(args, ui) -> bool:
    """Handle --mark-fp and --list-fp-feedback. Returns True if a pure
    management command was handled (caller should exit without scanning)."""
    if args.mark_fp:
        from recon.core.fp_feedback import mark_false_positive
        title, url = args.mark_fp
        sig = mark_false_positive(title, url)
        ui.ok(f"Marked as false positive: \"{title}\" @ {url}")
        ui.info(f"Signature: {sig}")
        ui.info("Matching findings (digit/UUID-normalized title+URL) will have reduced confidence in future scans.")
        return True

    if args.list_fp_feedback:
        from recon.core.fp_feedback import list_feedback
        feedback = list_feedback()
        if not feedback:
            ui.info("No false-positive feedback recorded yet. Use --mark-fp \"TITLE\" \"URL\" after reviewing a report.")
        else:
            ui.section("False-Positive Feedback")
            for sig, entry in feedback.items():
                ui.bullet(f"[{entry.get('count', 1)}x] {entry.get('title', sig)}  —  {entry.get('url_example', '')}")
        return True

    return False


def handle_generate_cron_command(args, ui) -> bool:
    """
    Continuous monitoring workflow (--generate-cron PROFILE): ties named
    profiles (--save-profile/--profile) + diff mode (--diff) together into
    a ready-to-paste scheduled-task snippet, instead of each piece being
    independently usable but never wired into one documented workflow.
    """
    if not args.generate_cron:
        return False

    from recon.core.profiles import get_profile
    profile_name = args.generate_cron
    prof = get_profile(profile_name)
    if prof is None:
        ui.error(f"No saved profile named '{profile_name}'. Save one first with: "
                  f"yata recon -t <target> ... --save-profile {profile_name}")
        return True

    python_exe = sys.executable
    script_path = os.path.abspath(__file__)

    ui.section(f"Continuous Monitoring — Profile '{profile_name}'")
    ui.info("Combines named profiles + --diff mode: each scheduled run only reports what's "
            "NEW or FIXED since the last scan of that target, instead of the full finding set every time.")
    ui.info(f"Profile '{profile_name}' saves: {prof}")
    ui.blank()

    ui.subsection("Cron (Linux/macOS) — daily at 03:00")
    ui.cmd(f'0 3 * * * {python_exe} "{script_path}" -t <target> --profile {profile_name} '
           f'--diff --no-tui >> ~/yata_recon_cron.log 2>&1')
    ui.blank()

    ui.subsection("Windows Task Scheduler (run from an elevated PowerShell/cmd)")
    ui.cmd(f'schtasks /Create /SC DAILY /ST 03:00 /TN "YATA RECON-{profile_name}" '
           f'/TR "\\"{python_exe}\\" \\"{script_path}\\" -t <target> --profile {profile_name} --diff --no-tui"')
    ui.blank()

    ui.subsection("systemd timer (Linux — /etc/systemd/system/yata-recon-{}.timer)".format(profile_name))
    ui.raw(f"    [Unit]\n    Description=YATA RECON scheduled scan ({profile_name})\n\n"
           f"    [Timer]\n    OnCalendar=daily\n    Persistent=true\n\n    [Install]\n    WantedBy=timers.target")
    ui.blank()

    ui.info("Replace <target> with the actual domain — a profile saves flags "
            "(headers/modules/threads/...), not the target itself, so one profile can be "
            "reused across a whole scope list with --targets too.")
    return True


def handle_list_modules_command(args, ui) -> bool:
    """List every scan module with a human label and the presets it belongs
    to (q=quick, s=standard, f=full). A pure, read-only command that exits
    without scanning."""
    if not getattr(args, 'list_modules', False):
        return False

    from recon.core.session import MODULE_MAP, MODULE_LABELS, PRESETS

    ui.section("Available Scan Modules")
    rows = []
    for mid in MODULE_MAP:
        flags = (("q" if mid in PRESETS['quick'] else "·")
                 + ("s" if mid in PRESETS['standard'] else "·")
                 + ("f" if mid in PRESETS['full'] else "·"))
        rows.append([mid, MODULE_LABELS.get(mid, mid), flags])
    ui.table(["ID", "Module", "qsf"], rows)
    ui.info(f"{len(MODULE_MAP)} modules total. Presets: "
            f"quick ({len(PRESETS['quick'])}), standard ({len(PRESETS['standard'])}), "
            f"full ({len(PRESETS['full'])}).")
    ui.info("Run a subset with  --modules id1,id2,...  or a preset with  --preset quick|standard|full")
    return True


def handle_verify_report_command(args, ui) -> bool:
    if not args.verify_report:
        return False
    from recon.core.report_signing import verify_file
    result = verify_file(args.verify_report)
    if result["valid"]:
        ui.ok(f"VALID — {result['reason']}")
    else:
        ui.error(f"INVALID — {result['reason']}")
    return True


def get_preset_modules(preset: str):
    from recon.core.session import get_preset_modules as _get_preset_modules
    return _get_preset_modules(preset)


def parse_headers(header_args) -> dict:
    """Parse repeated --header "Name: Value" args into a dict."""
    headers = {}
    for h in (header_args or []):
        name, sep, value = h.partition(':')
        if not sep:
            continue
        headers[name.strip()] = value.strip()
    return headers


def parse_cookies(cookie_args) -> dict:
    """Parse repeated --cookie "name=value" args into a dict."""
    cookies = {}
    for c in (cookie_args or []):
        name, sep, value = c.partition('=')
        if not sep:
            continue
        cookies[name.strip()] = value.strip()
    return cookies


def run_headless(args, ui, api_key):
    """Run in legacy headless CLI mode. Returns the ScanSession on success
    (so callers can apply --fail-on gating), or None if no scan ran."""
    if args.interactive or not args.target:
        from recon.core.interactive import InteractiveMenu
        menu = InteractiveMenu(ui)
        target, modules = menu.run()
    else:
        target = args.target
        if args.modules:
            modules = [m.strip() for m in args.modules.split(',')]
        else:
            modules = get_preset_modules(args.preset)

    if not target:
        ui.error("No target specified. Exiting.")
        return None

    session = ScanSession(
        target=target,
        api_key=api_key,
        modules=modules,
        scope=args.scope,
        output_dir=args.output_dir,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
        ui=ui,
        auto_install_tools=not args.no_auto_install,
        auth_headers=parse_headers(args.header),
        auth_cookies=parse_cookies(args.cookie),
        auth_headers_b=parse_headers(args.header2),
        auth_cookies_b=parse_cookies(args.cookie2),
        parallel_modules=not args.no_parallel,
        module_workers=args.module_workers,
        fresh_recon=args.fresh_recon,
        recon_cache_ttl=args.recon_cache_ttl,
        diff_mode=args.diff,
        sign_reports=args.sign_reports,
        resume=args.resume,
        min_confidence=args.confidence,
        min_severity=args.min_severity,
        sarif=args.sarif,
        scope_file=args.scope_file,
        out_of_scope=args.out_of_scope,
        proxy=args.proxy,
        share_card=args.share_card,
    )

    try:
        session.run()
    except KeyboardInterrupt:
        from recon.core import cancellation
        cancellation.request_stop()   # tell in-flight module loops/waits to bail out promptly
        ui.error("\n\n[!] Scan interrupted by user. Saving partial results...")
        session.save_partial()
        sys.exit(0)

    return session


def check_severity_gate(args, session, ui) -> bool:
    """CI/CD severity gating (--fail-on): returns True if any finding at or
    above the given severity was found, so a pipeline step can fail the
    build on a bad scan result instead of always exiting 0. Caller decides
    when to actually sys.exit(1) — multi-target scans gate on the combined
    result across all targets, not the first one that trips it."""
    if not args.fail_on or session is None:
        return False
    order = ['critical', 'high', 'medium', 'low', 'info']
    threshold_idx = order.index(args.fail_on)
    gating = [f for f in session.db.findings if order.index(f['severity']) <= threshold_idx]
    if gating:
        ui.error(f"--fail-on {args.fail_on}: {len(gating)} finding(s) at or above '{args.fail_on}' severity for {session.target}.")
        return True
    ui.ok(f"--fail-on {args.fail_on}: no finding at or above '{args.fail_on}' severity for {session.target}.")
    return False


def _distributed_scan_worker(target_args) -> dict:
    """
    Distributed scanning worker — runs inside its OWN OS process (see
    --distributed), so a crashed/hung scan of one target can't affect any
    other. Everything it needs must be picklable to cross the process
    boundary: `target_args` is a plain argparse.Namespace (simple
    strings/ints/lists — picklable), but a UI instance (holds a
    threading.Lock) and a ScanSession can't cross that boundary, so both
    are constructed fresh HERE rather than received from the parent. The
    return value is a small, picklable summary dict instead of the full
    ScanSession object.
    """
    worker_ui = UI(no_color=target_args.no_color)
    api_key = (target_args.api_key or "").strip() or config.get_api_key()
    try:
        session = run_headless(target_args, worker_ui, api_key)
    except Exception as e:
        return {"target": target_args.target, "error": str(e), "gate_failed": False, "finding_count": 0}

    gate_failed = check_severity_gate(target_args, session, worker_ui) if session else False
    return {
        "target": target_args.target,
        "finding_count": len(session.db.findings) if session else 0,
        "gate_failed": gate_failed,
        "error": None,
    }


def run_multi_target(args, ui, api_key) -> bool:
    """
    Multi-target / scope-list scanning (--targets FILE): run the same scan
    configuration against every target in the file. Always headless — a
    TUI showing N independent scans at once doesn't make sense, and
    CI/scope-list usage is headless by nature anyway. With --distributed N
    (N>1), up to N target scans run truly concurrently in separate worker
    processes (see _distributed_scan_worker) instead of one target fully
    finishing before the next starts — real parallelism across full scans,
    not just within one. Returns True if the combined --fail-on gate
    across ALL targets was tripped.
    """
    try:
        with open(args.targets, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        ui.error(f"Could not read --targets file '{args.targets}': {e}")
        return True

    if not targets:
        ui.error(f"No targets found in '{args.targets}'.")
        return True

    print_banner(ui)
    ui.info(f"Multi-target scan: {len(targets)} target(s) from {args.targets}")
    ui.blank()

    per_target_args = []
    for target in targets:
        target_args = argparse.Namespace(**vars(args))
        target_args.target = target
        target_args.interactive = False
        per_target_args.append(target_args)

    gate_failed = False

    if args.distributed and args.distributed > 1 and len(targets) > 1:
        import concurrent.futures
        workers = min(args.distributed, len(targets))
        ui.info(f"Distributed mode: {workers} worker process(es) running concurrently — "
                f"per-target progress below may interleave.")
        ui.blank()
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_distributed_scan_worker, ta): ta.target for ta in per_target_args}
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    ui.error(f"Worker process for '{target}' crashed: {e}")
                    continue
                if result.get("error"):
                    ui.error(f"Scan of '{target}' failed: {result['error']}")
                    continue
                ui.ok(f"[{target}] complete — {result['finding_count']} finding(s)")
                if result.get("gate_failed"):
                    gate_failed = True
    else:
        for i, target_args in enumerate(per_target_args, 1):
            ui.section(f"Target {i}/{len(targets)}: {target_args.target}")
            try:
                session = run_headless(target_args, ui, api_key)
            except Exception as e:
                ui.error(f"Scan of '{target_args.target}' failed: {e}")
                continue
            if check_severity_gate(target_args, session, ui):
                gate_failed = True

    return gate_failed

def handle_export_requests(args, ui) -> bool:
    """--export-requests: turn a saved JSON report into reproducible .http +
    curl files for hand-verification. Pure, read-only, exits after."""
    if not args.export_requests:
        return False
    from recon.core.exporters import export_report
    result = export_report(args.export_requests)
    if result.get("error"):
        ui.error(f"--export-requests: {result['error']}")
        return True
    ui.ok(f"Exported {result['count']} reproducible request(s).")
    ui.info(f"Raw HTTP (REST Client / Burp Repeater): {result['http']}")
    ui.info(f"curl runbook:                            {result['sh']}")
    return True


def handle_stats_command(args, ui) -> bool:
    """--stats: personal scan statistics from the local history DB."""
    if args.stats is None:
        return False
    from recon.core.history_db import get_global_stats, get_all_targets
    from datetime import datetime

    target = None if args.stats == '__ALL__' else args.stats
    stats = get_global_stats(target)
    if not stats or not stats.get("scans"):
        ui.info("No scan history yet — run a scan first, then come back for your stats.")
        return True

    scope_label = target or "all targets"
    ui.section(f"YATA RECON Stats — {scope_label}")
    sev = stats.get("severity", {})
    ui.panel("Lifetime", [
        f"Scans run        : {stats['scans']}",
        f"Targets haunted  : {stats['targets']}",
        f"Findings total   : {stats['findings']}",
        f"Peak risk score  : {stats['max_risk']}/100   (avg {stats['avg_risk']})",
    ])
    ui.sev_bar({k: sev.get(k, 0) for k in ('critical', 'high', 'medium', 'low', 'info')})
    ui.blank()
    if stats.get("top_module"):
        ui.info(f"Most productive module : {stats['top_module'][0]} ({stats['top_module'][1]} findings)")
    if stats.get("top_finding"):
        ui.info(f"Most-found issue       : {stats['top_finding'][0]} (x{stats['top_finding'][1]})")
    if stats.get("first_scan"):
        first = datetime.fromtimestamp(stats['first_scan']).strftime('%Y-%m-%d')
        last = datetime.fromtimestamp(stats['last_scan']).strftime('%Y-%m-%d')
        ui.info(f"Active since {first} — last scan {last}")
    if not target:
        recent = get_all_targets(limit=8)
        if recent:
            ui.blank()
            ui.subsection("Recently Scanned")
            for t in recent:
                ui.bullet(t)
    return True


def handle_dry_run(args, ui, api_key) -> bool:
    """--dry-run: show exactly what a scan WOULD do — modules, scope, proxy,
    auth, output — and send zero packets. A safety/sanity preview."""
    if not getattr(args, "dry_run", False):
        return False
    from recon.core.session import MODULE_MAP, MODULE_LABELS
    from recon.core.scope import ScopeEngine

    target = args.target or "(none — interactive/menu)"
    mods = ([m.strip() for m in args.modules.split(',')] if args.modules
            else get_preset_modules(args.preset))
    mods = [m for m in mods if m in MODULE_MAP]

    print_banner(ui, info=[("target", target), ("preset", args.preset),
                           ("modules", str(len([m for m in mods if m != 'report'])))])
    ui.section("Dry Run — Scan Plan (no traffic will be sent)")

    scope = ScopeEngine.from_args(args.scope, args.scope_file, args.out_of_scope,
                                  args.target or "")
    ui.panel("Configuration", [
        f"Target        : {target}",
        f"Scope         : {scope.describe()}",
        f"Proxy         : {args.proxy or '(direct)'}",
        f"Threads       : {args.threads}   Timeout: {args.timeout}s   Delay floor: {args.delay}s",
        f"Auth headers  : {len(parse_headers(args.header))}   cookies: {len(parse_cookies(args.cookie))}",
        f"Second identity: {'yes' if (args.header2 or args.cookie2) else 'no'}",
        f"Min confidence: {args.confidence}   Min severity: {args.min_severity or 'any'}",
        f"Output dir    : {args.output_dir}",
    ])
    ui.subsection(f"Modules that would run ({len(mods)})")
    for m in mods:
        ui.bullet(f"{m:<16} {MODULE_LABELS.get(m, m)}")
    # Rough request-budget estimate: recon dominates; each active module is
    # bounded. This is intentionally a ballpark, not a promise.
    active = len([m for m in mods if m not in ('recon', 'report')])
    lo, hi = 150 + active * 20, 1500 + active * 120
    ui.blank()
    ui.info(f"Estimated request budget: ~{lo}–{hi} requests (bounded; adaptive throttle + --delay apply).")
    ui.info("Remove --dry-run to execute this plan.")
    return True


def main(argv=None):
    args = parse_args(argv)
    ui   = UI(no_color=args.no_color)

    # --config was merged into args in parse_args() (CLI still overrides it).
    if getattr(args, "_config_error", None):
        ui.error(f"--config: {args._config_error}")
    elif getattr(args, "_config_applied", None):
        ui.info(f"--config: loaded defaults from {args.config} ({', '.join(args._config_applied)})")

    # Handle scan-profile management first (no scan needed for --list-profiles)
    if handle_profile_commands(args, ui):
        return

    if handle_history_command(args, ui):
        return

    if handle_fp_feedback_commands(args, ui):
        return

    if handle_list_modules_command(args, ui):
        return

    if handle_verify_report_command(args, ui):
        return

    if handle_export_requests(args, ui):
        return

    if handle_stats_command(args, ui):
        return

    if handle_generate_cron_command(args, ui):
        return

    # Handle API management commands first (no scan needed)
    if handle_api_commands(args, ui):
        return

    # Resolve API key: CLI flag overrides saved key
    api_key = (args.api_key or "").strip() or config.get_api_key()

    # --dry-run: show the plan and exit without sending any traffic.
    if handle_dry_run(args, ui, api_key):
        return

    # Multi-target / scope-list scanning (--targets FILE) — always headless,
    # runs every target in the file in sequence and gates on the combined
    # result.
    if args.targets:
        gate_failed = run_multi_target(args, ui, api_key)
        sys.exit(1 if gate_failed else 0)

    # Determine if we should use TUI
    use_tui = not args.no_tui and sys.stdout.isatty() and not args.interactive

    if use_tui:
        try:
            from recon.tui.app import ReconApp
            
            # Prepare config to pass to TUI
            tui_config = {
                "target": args.target,
                "api_key": api_key,
                "preset": args.preset,
                "modules": [m.strip() for m in args.modules.split(',')] if args.modules else get_preset_modules(args.preset),
                "threads": args.threads,
                "timeout": args.timeout,
                "delay": args.delay,
                "output_dir": args.output_dir,
                "auto_install_tools": not args.no_auto_install,
                "auth_headers": parse_headers(args.header),
                "auth_cookies": parse_cookies(args.cookie),
                "auth_headers_b": parse_headers(args.header2),
                "auth_cookies_b": parse_cookies(args.cookie2),
                "parallel_modules": not args.no_parallel,
                "module_workers": args.module_workers,
                "fresh_recon": args.fresh_recon,
                "recon_cache_ttl": args.recon_cache_ttl,
                "sign_reports": args.sign_reports,
                "resume": args.resume,
                "min_confidence": args.confidence,
                "min_severity": args.min_severity,
                "sarif": args.sarif,
                "scope": args.scope,
                "scope_file": args.scope_file,
                "out_of_scope": args.out_of_scope,
                "proxy": args.proxy,
                "share_card": args.share_card,
            }

            app = ReconApp(config=tui_config)
            app.run()
            
        except ImportError as e:
            ui.error(f"Failed to load TUI: {e}")
            ui.info("Falling back to headless mode...")
            print_banner(ui)
            session = run_headless(args, ui, api_key)
            if check_severity_gate(args, session, ui):
                sys.exit(1)
    else:
        if args.target:
            mods = ([m.strip() for m in args.modules.split(',')]
                    if args.modules else get_preset_modules(args.preset))
            print_banner(ui, info=[
                ("target", args.target),
                ("modules", str(len([m for m in mods if m != 'report']))),
                ("threads", str(args.threads)),
                ("engine", "AI on" if api_key else "local-only"),
            ])
        else:
            print_banner(ui)
        if not api_key:
            ui.warn("No API key set — running in local-only mode.")
            ui.info("Set one with:  yata recon --set-api nvapi-xxxx   (free at build.nvidia.com)")
            ui.blank()

        session = run_headless(args, ui, api_key)
        if check_severity_gate(args, session, ui):
            sys.exit(1)


if __name__ == '__main__':
    main()