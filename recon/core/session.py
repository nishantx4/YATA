"""
ScanSession — orchestrates all scan modules, manages findings, triggers AI analysis
"""
import os
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import recon.core.config as config
from recon.core.ui import UI, Colors
from recon.core import net, markers, cancellation
from recon.core.scope import ScopeEngine
from recon.core.findings import FindingsDB
from recon.core.ai_engine import AIEngine
from recon.core.baseline import BaselineProfiler, BaselineProfile
from recon.core.tool_runner import ExternalToolRunner

# Phase 1: Recon
from recon.modules      import ModuleSkipped
from recon.modules.recon      import ReconModule
from recon.modules.cms_scanner import CMSScannerModule
# Phase 2: Configuration & Identity
from recon.modules.headers    import HeadersModule
from recon.modules.http_methods import HTTPMethodsModule
from recon.modules.subdomain_takeover import SubdomainTakeoverModule
from recon.modules.secrets    import SecretsModule
# Phase 3: Authentication & Authorization
from recon.modules.jwt        import JWTModule
from recon.modules.broken_auth import BrokenAuthModule
from recon.modules.oauth      import OAuthModule
from recon.modules.idor       import IDORModule
from recon.modules.second_order import SecondOrderModule
from recon.modules.cloud_storage import CloudStorageModule
from recon.modules.saml import SAMLModule
from recon.modules.dom_xss import DOMXSSModule
# Phase 4: Data & Input Validation
from recon.modules.params     import ParamModule
from recon.modules.js_analysis import JSModule
from recon.modules.file_upload import FileUploadModule
from recon.modules.mass_assignment import MassAssignmentModule
# Phase 5: Injection & Exploitation
from recon.modules.sqli       import SQLiModule
from recon.modules.cmdi       import CommandInjectionModule
from recon.modules.nosql      import NoSQLModule
from recon.modules.ssti       import SSTIModule
from recon.modules.xss        import XSSModule
from recon.modules.xxe        import XXEModule
from recon.modules.crlf       import CRLFModule
from recon.modules.ssrf       import SSRFModule
from recon.modules.lfi        import LFIModule
from recon.modules.deserialization import DeserializationModule
from recon.modules.prototype_pollution import PrototypePollutionModule
# Phase 6: Client-Side & Logic
from recon.modules.cors       import CORSModule
from recon.modules.csrf       import CSRFModule
from recon.modules.clickjacking import ClickjackingModule
from recon.modules.open_redirect import OpenRedirectModule
from recon.modules.host_header import HostHeaderModule
from recon.modules.websocket  import WebSocketModule
# Phase 7: Advanced
from recon.modules.cache_poisoning import CachePoisoningModule
from recon.modules.smuggling  import SmugglingModule
from recon.modules.rate_limit import RateLimitModule
from recon.modules.graphql    import GraphQLModule
from recon.modules.graphql_suggest import GraphQLSuggestModule
# Phase 8: Logic, supply-chain & access-control (v5.1)
from recon.modules.race_condition import RaceConditionModule
from recon.modules.web_cache_deception import WebCacheDeceptionModule
from recon.modules.auth_bypass import AuthBypassModule
from recon.modules.auth_flow import AuthFlowModule
from recon.modules.hpp import HPPModule
from recon.modules.ldap import LDAPInjectionModule
from recon.modules.xpath import XPathInjectionModule
from recon.modules.dependency_confusion import DependencyConfusionModule
# External Scanners
from recon.modules.nuclei_sim import NucleiModule
# Reporting
from recon.modules.reporter   import ReportModule


MODULE_MAP = {
    'recon':     ReconModule,
    'cms':       CMSScannerModule,
    'headers':   HeadersModule,
    'methods':   HTTPMethodsModule,
    'sub_take':  SubdomainTakeoverModule,
    'secrets':   SecretsModule,
    'jwt':       JWTModule,
    'broken_auth': BrokenAuthModule,
    'oauth':     OAuthModule,
    'saml':      SAMLModule,
    'idor':      IDORModule,
    'second_order': SecondOrderModule,
    'cloud':     CloudStorageModule,
    'params':    ParamModule,
    'js':        JSModule,
    'upload':    FileUploadModule,
    'mass_assign': MassAssignmentModule,
    'sqli':      SQLiModule,
    'cmdi':      CommandInjectionModule,
    'nosql':     NoSQLModule,
    'ssti':      SSTIModule,
    'xss':       XSSModule,
    'dom_xss':   DOMXSSModule,
    'xxe':       XXEModule,
    'crlf':      CRLFModule,
    'ssrf':      SSRFModule,
    'lfi':       LFIModule,
    'desync':    DeserializationModule,
    'proto_poll': PrototypePollutionModule,
    'cors':      CORSModule,
    'csrf':      CSRFModule,
    'clickjack': ClickjackingModule,
    'redirect':  OpenRedirectModule,
    'host_header': HostHeaderModule,
    'ws':        WebSocketModule,
    'cache':     CachePoisoningModule,
    'smuggling': SmugglingModule,
    'rate_limit': RateLimitModule,
    'graphql':   GraphQLModule,
    'graphql_suggest': GraphQLSuggestModule,
    'race':      RaceConditionModule,
    'wcd':       WebCacheDeceptionModule,
    'auth_bypass': AuthBypassModule,
    'otp':       AuthFlowModule,
    'hpp':       HPPModule,
    'ldap':      LDAPInjectionModule,
    'xpath':     XPathInjectionModule,
    'depconf':   DependencyConfusionModule,
    'nuclei':    NucleiModule,
    'report':    ReportModule,
}

# Human-readable labels for every selectable module (used by the TUI's
# module-selection checklist and anywhere else module IDs need a display name).
MODULE_LABELS = {
    'recon':      'Reconnaissance & Crawling',
    'cms':        'CMS Scanner',
    'headers':    'Security Headers',
    'methods':    'HTTP Methods & XST',
    'sub_take':   'Subdomain Takeover',
    'secrets':    'Secrets Exposure',
    'jwt':        'JWT Attacks',
    'broken_auth': 'Broken Authentication',
    'oauth':      'OAuth Misconfiguration',
    'saml':       'SAML/SSO Security',
    'idor':       'IDOR',
    'second_order': 'Second-Order / Stored Injection',
    'cloud':      'Cloud Storage Exposure',
    'params':     'Parameter Tampering',
    'js':         'JS Analysis',
    'upload':     'File Upload',
    'mass_assign': 'Mass Assignment',
    'sqli':       'SQL Injection',
    'cmdi':       'OS Command Injection',
    'nosql':      'NoSQL Injection',
    'ssti':       'Server-Side Template Injection',
    'xss':        'Cross-Site Scripting',
    'dom_xss':    'DOM-Based XSS',
    'xxe':        'XXE',
    'crlf':       'CRLF Injection',
    'ssrf':       'SSRF',
    'lfi':        'LFI / Path Traversal',
    'desync':     'Deserialization',
    'proto_poll': 'Prototype Pollution',
    'cors':       'CORS Misconfiguration',
    'csrf':       'CSRF',
    'clickjack':  'Clickjacking',
    'redirect':   'Open Redirect',
    'host_header': 'Host Header Injection',
    'ws':         'WebSocket Security',
    'cache':      'Cache Poisoning',
    'smuggling':  'HTTP Request Smuggling',
    'rate_limit': 'Rate Limiting',
    'graphql':    'GraphQL',
    'graphql_suggest': 'GraphQL Schema Disclosure (suggestions)',
    'race':       'Race Conditions (TOCTOU)',
    'wcd':        'Web Cache Deception',
    'auth_bypass': '401/403 Access-Control Bypass',
    'otp':        'OTP / Password-Reset Flow',
    'hpp':        'HTTP Parameter Pollution',
    'ldap':       'LDAP Injection',
    'xpath':      'XPath / XQuery Injection',
    'depconf':    'Dependency Confusion',
    'nuclei':     'Nuclei Scanner',
    'report':     'Report Generation',
}

# ── Plugin/module SDK ─────────────────────────────────────────────────────
# Auto-discover any third-party module dropped into modules/ that opts in
# via a MODULE_ID class attribute (see core/module_registry.py) — never
# touches/shadows the 36 built-in modules above, which stay exactly as
# hand-registered. A plugin becomes selectable via --modules <id> and joins
# the 'full' preset automatically the moment it's added to modules/.
try:
    from recon.core.module_registry import discover_plugin_modules, discover_plugin_labels
    _PLUGIN_MODULES = discover_plugin_modules(existing_ids=set(MODULE_MAP.keys()))
    MODULE_MAP.update(_PLUGIN_MODULES)
    MODULE_LABELS.update(discover_plugin_labels(_PLUGIN_MODULES))
except Exception:
    pass  # plugin discovery is best-effort — a broken plugin file must never block a scan

# Scan presets — single source of truth shared by the CLI (--preset) and the
# TUI's Quick/Standard/Full Profile buttons.
PRESETS = {
    'quick':    ['recon', 'cms', 'headers', 'secrets', 'cors', 'nuclei', 'report'],
    'standard': ['recon', 'cms', 'headers', 'methods', 'sub_take', 'secrets', 'idor', 'sqli',
                 'cmdi', 'xss', 'cors', 'ssrf', 'lfi', 'auth_bypass', 'race', 'depconf',
                 'nuclei', 'report'],
    'full':     list(MODULE_MAP.keys()),
}


def get_preset_modules(preset: str) -> list:
    """Return the module ID list for a named preset (defaults to 'standard')."""
    return list(PRESETS.get(preset, PRESETS['standard']))


class ScanSession:
    def __init__(self, target, api_key=None, modules=None, scope=None,
                 output_dir='./yata_recon_output', output_file=None,
                 threads=10, timeout=10, delay=0.5, verbose=False, ui=None,
                 event_callback=None, auto_install_tools=True,
                 auth_headers=None, auth_cookies=None,
                 auth_headers_b=None, auth_cookies_b=None,
                 parallel_modules=True, module_workers=None,
                 fresh_recon=False, recon_cache_ttl=6 * 3600,
                 diff_mode=False, sign_reports=False, resume=False,
                 min_confidence=0, min_severity=None, sarif=False,
                 scope_file=None, out_of_scope=None, proxy=None, share_card=False):
        self.target     = self._normalize_target(target)
        self.api_key    = api_key
        # Engagement scope + upstream proxy (see core/scope.py, core/net.py).
        self.scope_file = scope_file
        self.out_of_scope = out_of_scope or []
        self.proxy      = proxy
        self.share_card = share_card
        self._module_timings = {}
        self.auth_headers = dict(auth_headers or {})
        self.auth_cookies = dict(auth_cookies or {})
        # Second identity — a separately-authenticated user's credentials
        # (--header2/--cookie2). Enables real two-role differential IDOR/
        # broken-access-control testing (idor.py) instead of only ever
        # testing anonymous-vs-authenticated.
        self.auth_headers_b = dict(auth_headers_b or {})
        self.auth_cookies_b = dict(auth_cookies_b or {})
        # Default profile: full scan
        # `modules is None` means "not specified" -> default to everything.
        # An explicit `[]` must stay empty, not silently balloon into a full
        # 33-module scan — that's exactly what happened when the interactive
        # CLI's module parser produced an empty list on a typo.
        self.modules    = list(MODULE_MAP.keys()) if modules is None else modules
        self.scope      = scope
        self.output_dir = output_dir
        self.output_file = output_file
        self.threads    = threads
        self.timeout    = timeout
        self.delay      = delay
        self.verbose    = verbose
        # Modules run concurrently by default (independent modules mostly
        # only READ ctx after recon populates it) — cuts wall-clock scan
        # time significantly since a full-preset scan previously ran ~30
        # modules strictly one after another. --no-parallel / parallel_modules=False
        # restores the old strictly-sequential behavior when deterministic
        # module ordering matters more than speed (e.g. debugging).
        self.parallel_modules = parallel_modules
        self.module_workers = module_workers or max(2, min(8, threads))
        self.fresh_recon = fresh_recon
        self.recon_cache_ttl = recon_cache_ttl
        self.diff_mode = diff_mode
        self.sign_reports = sign_reports
        self.resume = resume
        self._last_risk_score = 0
        # Which modules this run has already attempted (succeeded OR
        # failed — a module that's broken against this target shouldn't be
        # retried forever on every --resume). Guards the checkpoint file
        # written to disk after each module so an interrupted scan (killed,
        # crashed, Ctrl+C) can pick back up instead of re-running all ~39
        # modules from scratch. See _checkpoint_path/_save_checkpoint/
        # _load_checkpoint/_clear_checkpoint below.
        self._completed_modules = set()
        self._checkpoint_lock = threading.Lock()
        self.ui         = ui or UI()
        self.start_time = None
        self.event_callback = event_callback # For TUI updates
        self.auto_install_tools = auto_install_tools
        self.min_confidence = min_confidence
        self.min_severity = min_severity
        self.sarif = sarif
        self.db         = FindingsDB(event_callback=self.event_callback,
                                     min_confidence=min_confidence,
                                     min_severity=min_severity)
        self.context    = {}  # shared data between modules (subdomains, endpoints, etc.)
        # Operator skip (TUI "skip module"): a module checks context
        # ['_skip_controller'] cooperatively (BaseModule._throttle) and
        # subprocess tools pass its per-module Event to the tool runner.
        from recon.core.skip import SkipController
        self.skip = SkipController()
        self.context['_skip_controller'] = self.skip
        self.ai         = AIEngine(api_key=api_key, ui=self.ui, event_callback=self.event_callback)
        self.tool_runner = ExternalToolRunner(self.ui)

    def _ensure_external_tools(self):
        """
        Auto-install the external Go tools the enabled modules actually rely
        on (subfinder/katana/waybackurls for recon, nuclei for the Nuclei
        module). ToolInstaller already implements this — it just was never
        called anywhere, so every scan silently used weak built-in fallbacks
        even when auto-install was documented as a feature.
        """
        if not self.auto_install_tools:
            return
        wanted = []
        if 'recon' in self.modules:
            wanted += ['subfinder', 'katana', 'waybackurls']
        if 'nuclei' in self.modules:
            wanted.append('nuclei')
        if 'ssrf' in self.modules or 'xxe' in self.modules:
            wanted.append('interactsh-client')
        wanted = sorted(set(wanted))
        if not wanted:
            return
        try:
            from recon.core.tool_installer import ToolInstaller
            installer = ToolInstaller(self.ui)
            missing = [t for t in wanted if not installer.is_installed(t)]
            if missing:
                self.ui.info(f"Auto-installing external tools: {', '.join(missing)} ...")
                self.ui.start_spinner(f"Installing {', '.join(missing)} (this can take a minute)...")
                try:
                    installer.ensure_tools(missing)
                finally:
                    self.ui.stop_spinner()
        except Exception as e:
            self.ui.warn(f"Tool auto-install skipped: {e}")

    def _normalize_target(self, t):
        t = t.strip().lower()
        for prefix in ('https://', 'http://'):
            if t.startswith(prefix):
                t = t[len(prefix):]
        return t.rstrip('/')
        
    def _emit(self, event_type, data):
        """Emit an event to the TUI if event_callback is provided."""
        if self.event_callback:
            try:
                self.event_callback(event_type, data)
            except Exception:
                pass

    # ── Scan checkpoint / resume ────────────────────────────────────────────
    # There was previously no way to continue an interrupted scan — killing
    # the process (or it crashing) partway through a 39-module run meant the
    # next scan of the same target always restarted at module 1, even though
    # findings from the earlier modules were already gone. This persists
    # which modules have been attempted (and their findings) to a small JSON
    # file next to the scan output after every module, so --resume (CLI) /
    # the TUI's "Resume" checkbox can skip what's already done.
    def _checkpoint_path(self):
        base = self.target
        for ch in (':', '/', '\\', '*', '?', '"', '<', '>', '|'):
            base = base.replace(ch, '_')
        return os.path.join(self.output_dir, f".yata-recon_checkpoint_{base}.json")

    def _load_checkpoint(self):
        path = self._checkpoint_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def _save_checkpoint(self):
        """Called after every module attempt (success or failure) — see
        _run_module. Written frequently rather than once at the end since
        the whole point is surviving a crash/kill mid-scan."""
        path = self._checkpoint_path()
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with self._checkpoint_lock:
                data = {
                    'target': self.target,
                    'modules': self.modules,
                    'completed': sorted(self._completed_modules),
                    'findings': list(self.db.findings),
                    'saved_at': datetime.now().isoformat(),
                }
            tmp_path = path + '.tmp'
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp_path, path)  # atomic — never leaves a half-written checkpoint
        except Exception:
            pass  # checkpointing is best-effort and must never break a scan

    def _clear_checkpoint(self):
        """Called once the scan reaches _save_results() — a fully completed
        scan has nothing left to resume."""
        path = self._checkpoint_path()
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def run(self):
        self.start_time = time.time()
        os.makedirs(self.output_dir, exist_ok=True)

        # ── Scan-wide network policy, markers, cancellation ──────────────────
        cancellation.reset()
        markers.seed_scan(self.target)
        if self.proxy:
            net.set_proxy(self.proxy)
        self._scope = ScopeEngine.from_args(
            scope=self.scope, scope_file=self.scope_file,
            out_of_scope=self.out_of_scope, target=self.target)
        self.context['scope_engine'] = self._scope
        # Only ENFORCE the guard at the request layer when the user supplied
        # explicit scope rules. The implicit "target + subdomains" default must
        # never block modules that legitimately reach off-target infrastructure
        # (cloud_storage -> S3/GCS, subdomain_takeover, CVE enrichment -> NVD) —
        # enforcing it by default would be a silent regression. net.set_scope(None)
        # also clears any guard left over from a previous target in a
        # multi-target/distributed run that shares this process.
        net.set_scope(self._scope if self._scope.active else None)

        self._emit("scan_started", {"target": self.target, "modules": self.modules})

        # ── Resume: pick up an interrupted earlier scan of this target ──────
        # Previously there was no way to continue a killed/crashed scan — the
        # next run always restarted all ~39 modules from scratch even though
        # the earlier run's findings were already gone. --resume (CLI) / the
        # TUI's "Resume" checkbox loads the checkpoint _save_checkpoint() left
        # behind after each module attempt (see _run_module), restores its
        # findings, and skips modules already attempted this time around.
        # 'recon' and 'report' always re-run regardless — recon is cheap on a
        # repeat run thanks to its own separate crawl cache (recon_cache_ttl),
        # and report needs to re-aggregate the restored + newly-found findings.
        if self.resume:
            ckpt = self._load_checkpoint()
            if ckpt and set(ckpt.get('modules', [])) == set(self.modules):
                done = set(ckpt.get('completed', []))
                restored = self.db.restore(ckpt.get('findings', []))
                self._completed_modules |= done
                self.ui.ok(f"Resuming previous scan — {len(done)}/{len(self.modules)} module(s) "
                           f"already attempted, {restored} finding(s) restored "
                           f"(checkpoint saved {ckpt.get('saved_at', 'unknown time')})")
                for m in done:
                    self._emit("module_completed", {"module": m})
            elif ckpt:
                self.ui.info("Found a checkpoint for this target, but it was for a different module "
                             "selection — ignoring it and starting fresh.")
            else:
                self.ui.info("--resume requested but no checkpoint found for this target — starting fresh.")

        # Seed any user-supplied auth (--header/--cookie) before anything
        # runs. Every module also checks/adds to this: recon.py adds static
        # OpenAPI example headers (without overwriting these), and modules
        # that find a live credential (e.g. sqli.py's auth-bypass capture)
        # add to it too — so a scan that starts authenticated stays
        # authenticated, and a scan that starts blind can become
        # authenticated mid-run.
        if self.auth_headers:
            self.context['auth_headers'] = dict(self.auth_headers)
        if self.auth_cookies:
            self.context['auth_cookies'] = dict(self.auth_cookies)
        if self.auth_headers_b:
            self.context['auth_headers_b'] = dict(self.auth_headers_b)
        if self.auth_cookies_b:
            self.context['auth_cookies_b'] = dict(self.auth_cookies_b)

        self.ui.section(f"Starting YATA RECON against: {self.target}")
        self.ui.info(f"Modules: {len(self.modules)} enabled")
        if self._scope.active:
            self.ui.info(f"Scope enforced — {self._scope.describe()} "
                         "(out-of-scope requests are blocked at the request layer)")
        if self.proxy:
            self.ui.info(f"Upstream proxy: {self.proxy} — all module traffic routed through it")
        self.ui.info(f"AI Analysis: {'Enabled — NVIDIA NIM (' + config.get_model() + ')' if self.api_key else 'Local engine (no API key set)'}")
        if self.auth_headers or self.auth_cookies:
            self.ui.info(f"Auth context: {len(self.auth_headers)} header(s), {len(self.auth_cookies)} cookie(s) supplied")
        if self.auth_headers_b or self.auth_cookies_b:
            self.ui.info(f"Second identity: {len(self.auth_headers_b)} header(s), {len(self.auth_cookies_b)} cookie(s) "
                          f"— two-role differential IDOR testing enabled")
        self.context['no_recon_cache'] = self.fresh_recon
        self.context['recon_cache_ttl'] = self.recon_cache_ttl
        # Let modules coordinate to avoid double-reporting the same underlying
        # issue from two angles (e.g. headers.py defers session-cookie flag
        # checks to the more thorough broken_auth.py when it's also enabled).
        self.context['enabled_modules'] = list(self.modules)
        self.ui.blank()

        # ── External tool auto-install (subfinder/katana/waybackurls/nuclei) ──
        self._ensure_external_tools()

        # ── Target Profiling (Baseline) ──
        self._emit("phase_started", {"name": "Target Profiling"})
        self.ui.section("Phase 0: Target Profiling & Fingerprinting")
        baseline = BaselineProfiler(self.target, timeout=self.timeout, ui=self.ui)
        self.ui.start_spinner("Fingerprinting target (probing endpoints, stack, WAF)...")
        try:
            profile = baseline.profile()
        finally:
            self.ui.stop_spinner()
        self.context['baseline_profile'] = profile
        self._emit("profiling_complete", profile)

        # ── Run modules ──
        # 'recon' (if selected) always runs first, alone: almost every other
        # module reads ctx['endpoints']/['forms']/['api_endpoints']/
        # ['harvested_object_ids'], which only recon populates. 'report' (if
        # explicitly listed here rather than run via _save_results) always
        # runs last, alone, since it summarizes everything else. Everything
        # in between is largely independent (each module mostly only READS
        # shared ctx once recon has run) and — unless --no-parallel was
        # passed — runs concurrently, which is what actually cuts wall-clock
        # time on a big preset instead of running ~30 modules strictly one
        # after another.
        ordered   = [m for m in self.modules if m in MODULE_MAP]
        for m in self.modules:
            if m not in MODULE_MAP:
                self.ui.warn(f"Unknown module '{m}' — skipping")

        recon_first = [m for m in ordered if m == 'recon']
        report_last = [m for m in ordered if m == 'report']
        rest        = [m for m in ordered if m not in ('recon', 'report')
                       and m not in self._completed_modules]
        # Smarter scheduling: a flat concurrent batch still bottlenecks on
        # its slowest member — if a module with a long, mostly-idle wait
        # (OOB SSRF's ~15s interactsh poll, raw-socket smuggling's ~2.5s/
        # probe sleeps, CVE enrichment's live NVD calls in headers.py) is
        # submitted LAST among N=module_workers threads, its wait doesn't
        # start overlapping with the others until everything ahead of it in
        # the queue has already been dispatched. Submitting known-slow
        # modules first means their idle time overlaps with the most other
        # work, instead of tacking their wait onto the end of the batch.
        _SLOW_FIRST = ('ssrf', 'cmdi', 'xxe', 'smuggling', 'headers', 'oauth', 'websocket')
        rest = sorted(rest, key=lambda m: 0 if m in _SLOW_FIRST else 1)

        for mod_name in recon_first:
            self._run_module(mod_name)

        # Trim recon's discoveries to in-scope assets before any other module
        # consumes them — only when explicit scope rules were supplied, so a
        # plain single-target scan behaves exactly as before.
        if getattr(self, "_scope", None) is not None and self._scope.active:
            self._enforce_scope_on_context()

        if rest:
            if self.parallel_modules and len(rest) > 1:
                workers = max(1, min(self.module_workers, len(rest)))
                self.ui.info(f"Running {len(rest)} module(s) concurrently (workers={workers})...")
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {pool.submit(self._run_module, m): m for m in rest}
                    for future in as_completed(futures):
                        future.result()  # exceptions are already caught/reported inside _run_module
            else:
                for mod_name in rest:
                    self._run_module(mod_name)

        for mod_name in report_last:
            self._run_module(mod_name)

        # ── AI Chain Analysis ──
        self._run_ai_chain_analysis()

        # ── Auto-verified exploit chains ──
        self._attempt_chain_verification()

        # ── Final summary ──
        self._print_summary()
        json_path = self._save_results()
        if self.diff_mode:
            self._print_diff_summary(json_path)
        self._record_history()
        if self.share_card:
            self._print_share_card()
        # Scan ran to completion — nothing left to resume. A scan killed
        # before reaching here leaves the checkpoint in place for next time.
        self._clear_checkpoint()
        self._emit("scan_completed", {
            "duration": time.time() - self.start_time,
            "findings": len(self.db.findings),
            "report_path": getattr(self, "_last_md_path", None),
            "risk_score": getattr(self, "_last_risk_score", None),
        })

    def _record_history(self):
        """Persist this scan + its findings to the local SQLite history
        database (core/history_db.py) for long-term trend tracking, beyond
        what diff mode's single-previous-scan comparison covers."""
        try:
            from recon.core.history_db import record_scan
            record_scan(self.target, self.db.findings, self.modules,
                        getattr(self, '_last_risk_score', 0))
        except Exception:
            pass  # history is a nice-to-have — never let it break a scan's completion

    def _attempt_chain_verification(self):
        """
        Auto-verified exploit chains. The AI chain analysis above writes a
        narrative about what COULD be chained — this actually attempts the
        highest-value chain LIVE when we have what it takes: a credential
        captured mid-scan (JWT forgery, SQLi auth-bypass, ...) plus a
        plausible sensitive endpoint. Fires the same request both without
        and with the captured credential; if the unauthenticated request is
        gated (401/403) and the credentialed one succeeds, that's a PROVEN
        end-to-end chain, not a theorized one.
        """
        captured = self.context.get('captured_credentials', [])
        if not captured:
            return

        try:
            import requests
        except ImportError:
            return

        self.ui.section("Auto-Verified Exploit Chain")
        self._emit("phase_started", {"name": "Chain Verification"})

        sensitive_hints = ["admin", "account", "profile", "settings", "user", "dashboard",
                            "manage", "config", "billing", "order", "api"]
        candidates = [e for e in self.context.get('endpoints', [])
                      if any(h in e.lower() for h in sensitive_hints)][:15]
        if not candidates:
            self.ui.info("No sensitive-looking endpoint discovered to verify a captured credential against.")
            return

        verified = 0
        for cred in captured[:3]:  # a confirmation step, not a full re-scan
            headers, cookies = {}, {}
            if cred['kind'] == 'header' and isinstance(cred['value'], dict):
                headers = dict(cred['value'])
            elif cred['kind'] == 'bearer' and isinstance(cred['value'], str):
                headers = {"Authorization": f"Bearer {cred['value']}"}
            elif cred['kind'] == 'cookie' and isinstance(cred['value'], dict):
                cookies = dict(cred['value'])
            else:
                continue

            for ep in candidates:
                try:
                    unauth_resp = requests.get(ep, timeout=self.timeout, verify=False)
                    auth_resp = requests.get(ep, timeout=self.timeout, headers=headers, cookies=cookies, verify=False)
                except Exception:
                    continue

                unauth_gated = unauth_resp.status_code in (401, 403)
                auth_succeeds = auth_resp.status_code == 200 and len(auth_resp.text) > 100

                if unauth_gated and auth_succeeds:
                    self.db.add(
                        title="PROVEN Exploit Chain — Captured Credential Grants Authenticated Access",
                        severity="critical", url=ep, module="Chain Verification",
                        description=(
                            f"A credential captured during this scan ({cred['source']}, via {cred['module']}) "
                            f"was used LIVE against {ep}, which rejects unauthenticated requests "
                            f"({unauth_resp.status_code}) but returned 200 with the captured credential. "
                            "This is a PROVEN end-to-end exploit chain, not a theoretical one — the "
                            "underlying vulnerability that produced this credential has real, "
                            "confirmed downstream impact."
                        ),
                        remediation="Fix the root-cause credential-disclosure/forgery vulnerability (see the originating finding) — this confirms it grants real authenticated access.",
                        cvss="9.8", confidence="CONFIRMED", confidence_score=99,
                        validation_steps=["credential_captured_mid_scan", "unauth_request_rejected",
                                           "credentialed_request_succeeded_live"],
                        evidence=[f"Credential source: {cred['source']}",
                                  f"Unauth status: {unauth_resp.status_code}", f"Auth status: {auth_resp.status_code}"],
                    )
                    self.ui.find("critical", f"PROVEN exploit chain → {ep}", ep)
                    verified += 1
                    time.sleep(self.delay)

        if verified == 0:
            self.ui.info("No live chain could be independently verified this run — chains in the AI analysis above remain theorized.")
        else:
            self.ui.ok(f"{verified} exploit chain(s) independently PROVEN live.")

    def _print_diff_summary(self, json_path):
        """Continuous/diff mode (--diff): compare this scan's findings
        against the most recent previous scan of the same target, so a
        target you monitor repeatedly shows only what's actually changed
        instead of the full finding set every single time."""
        from recon.core.diff import find_previous_report, diff_findings

        prev_path = find_previous_report(self.output_dir, self.target, exclude_path=json_path)
        if not prev_path:
            self.ui.info("Diff mode: no previous scan found for this target — this run is the new baseline.")
            return

        result = diff_findings(prev_path, self.db.findings)
        self.ui.section("Diff — Changes Since Last Scan")
        self.ui.info(f"Previous scan: {os.path.basename(prev_path)}"
                      + (f" ({result['previous_scan_time']})" if result.get('previous_scan_time') else ""))
        self.ui.panel("Diff Summary", [
            f"New findings   : {len(result['new'])}",
            f"Fixed findings : {len(result['fixed'])}",
            f"Unchanged      : {len(result['unchanged'])}",
        ])
        if result['new']:
            self.ui.subsection("New Since Last Scan")
            for f in result['new'][:20]:
                self.ui.find(f['severity'], f['title'], f.get('url', ''))
        if result['fixed']:
            self.ui.subsection("Fixed Since Last Scan")
            for f in result['fixed'][:20]:
                self.ui.bullet(f"[RESOLVED] [{f['severity'].upper()}] {f['title']} — {f.get('url', '')}")

        self._emit("diff_summary", {"new": len(result['new']), "fixed": len(result['fixed']),
                                     "unchanged": len(result['unchanged'])})

    def _enforce_scope_on_context(self):
        """Drop any recon-discovered asset that falls outside the engagement
        scope, so downstream modules never even consider testing it. Only
        invoked when explicit scope rules were supplied."""
        sc = self._scope
        before_ep = len(self.context.get('endpoints', []))
        before_sub = len(self.context.get('subdomains', []))

        if 'endpoints' in self.context:
            self.context['endpoints'] = [e for e in self.context['endpoints'] if sc.is_in_scope(e)]
        if 'subdomains' in self.context:
            self.context['subdomains'] = [s for s in self.context['subdomains'] if sc.is_in_scope(s)]
        if 'api_endpoints' in self.context:
            self.context['api_endpoints'] = [a for a in self.context['api_endpoints']
                                             if sc.is_in_scope(a.get('url', ''))]
        if 'forms' in self.context:
            self.context['forms'] = [f for f in self.context['forms']
                                     if sc.is_in_scope(f.get('action', self.base_url_for_scope()))]
        if 'probe_targets' in self.context:
            self.context['probe_targets'] = [p for p in self.context['probe_targets']
                                             if sc.is_in_scope(p if isinstance(p, str) else p.get('url', ''))]

        dropped_ep = before_ep - len(self.context.get('endpoints', []))
        dropped_sub = before_sub - len(self.context.get('subdomains', []))
        if dropped_ep or dropped_sub:
            self.ui.info(f"Scope filter: dropped {dropped_ep} out-of-scope endpoint(s) and "
                         f"{dropped_sub} out-of-scope subdomain(s) from the worklist.")

    def base_url_for_scope(self):
        return self.context.get('base_url') or f"https://{self.target}"

    def _run_module(self, mod_name):
        """Instantiate and run a single module. Safe to call from a worker
        thread — all exceptions (including KeyboardInterrupt propagation
        concerns) are handled here so a crashed/interrupted module can't
        take down the whole ThreadPoolExecutor batch."""
        self._emit("module_started", {"module": mod_name})
        # Tag every ui.* call made on this thread with the module that's
        # running on it, so parallel modules (each on their own thread)
        # don't get their output attributed to whichever other module's
        # section header happened to print most recently. See UI.set_module.
        self.ui.set_module(mod_name)
        _t0 = time.time()
        try:
            try:
                ModClass = MODULE_MAP[mod_name]
                mod = ModClass(
                    target=self.target,
                    db=self.db,
                    ui=self.ui,
                    context=self.context,
                    timeout=self.timeout,
                    delay=self.delay,
                    threads=self.threads,
                    verbose=self.verbose,
                    ai=self.ai,
                    output_dir=self.output_dir,
                )
                mod.module_id = mod_name  # lets the module honour an operator skip
                if hasattr(mod, 'event_callback'):
                    mod.event_callback = self.event_callback
                mod.run()
            except ModuleSkipped:
                pass  # cooperative abort — fall through to the skip emit below
            except Exception as e:
                self.ui.error(f"Module '{mod_name}' crashed: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                self._emit("module_failed", {"module": mod_name, "error": str(e)})
                return
            if self.skip.is_requested(mod_name):
                self.ui.warn(f"Module '{mod_name}' skipped by operator.")
                self._emit("module_skipped", {"module": mod_name})
            else:
                self._emit("module_completed", {"module": mod_name})
        finally:
            # Record this module as attempted (whether it succeeded, failed,
            # or crashed) and checkpoint immediately — see _checkpoint_path
            # and the --resume handling in run(). Checkpointing after every
            # module rather than once at the end is the whole point: it's
            # what survives a kill/crash partway through a big preset.
            self._completed_modules.add(mod_name)
            # Per-module wall-clock timing — surfaced in the summary (slowest
            # modules) and the report, so it's obvious where a scan spends its
            # time without guessing.
            elapsed = time.time() - _t0
            self._module_timings[mod_name] = elapsed
            self.context.setdefault('module_timings', {})[mod_name] = round(elapsed, 2)
            self._save_checkpoint()
            # Non-parallel modules ('report', and the first module when a
            # scan starts) run on the *main* thread. Leaving the tag set
            # would misattribute later main-thread-only output (the final
            # summary, AI chain analysis) to whichever module ran last.
            self.ui.set_module(None)

    def _run_ai_chain_analysis(self):
        if not self.db.findings:
            return
        self.ui.section("AI Vulnerability Chain Analysis")
        self._emit("phase_started", {"name": "AI Chain Analysis"})
        # BUG FIX: the return value (the full chain-analysis writeup — attack
        # paths, bounty estimates, PoC outlines) was being discarded here.
        # It printed to the terminal and then was gone forever — never
        # reached the saved JSON/Markdown report, so it didn't survive past
        # the current scroll buffer. Stashed into context so
        # reporter.py can include it as a real report section.
        result = self.ai.analyze_chains(self.target, self.db.findings)
        if result:
            self.context['chain_analysis'] = result

    def _print_summary(self):
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        self.ui.section("Scan Complete — Summary")
        self.ui.info(f"Target: {self.target}")
        self.ui.info(f"Duration: {mins}m {secs}s")
        self.ui.blank()

        counts = self.db.severity_counts()
        self.ui.sev_bar(counts)
        self.ui.blank()

        # Weighted risk score (0-100) to give an at-a-glance posture.
        weights = {'critical': 40, 'high': 20, 'medium': 8, 'low': 3, 'info': 0}
        raw = sum(weights.get(s, 0) * counts.get(s, 0) for s in weights)
        risk = min(100, raw)
        self._last_risk_score = risk  # stashed for _record_history()
        grade = ('CRITICAL' if risk >= 80 else 'HIGH' if risk >= 50 else
                 'MODERATE' if risk >= 20 else 'LOW' if risk > 0 else 'CLEAN')
        self.ui.panel("Risk Posture", [
            f"Risk score : {risk}/100  ({grade})",
            f"Findings   : {len(self.db.findings)} total",
        ])
        self.ui.blank()

        # Top findings
        critical = [f for f in self.db.findings if f['severity'] == 'critical']
        high     = [f for f in self.db.findings if f['severity'] == 'high']
        top = (critical + high)[:10]
        if top:
            self.ui.subsection("Top Findings")
            for i, f in enumerate(top, 1):
                self.ui.find(f['severity'], f['title'], f.get('url',''))

        self.ui.blank()
        self.ui.info(f"Total findings: {len(self.db.findings)}")
        if getattr(self.db, 'suppressed', 0):
            filt = []
            if self.min_confidence:
                filt.append(f"--confidence {self.min_confidence}")
            if self.min_severity:
                filt.append(f"--min-severity {self.min_severity}")
            self.ui.info(f"{self.db.suppressed} finding(s) suppressed by "
                         f"{' / '.join(filt) or 'active'} filter(s) "
                         f"(relax them to surface borderline/lower results).")
        subdomains = self.context.get('subdomains', [])
        endpoints  = self.context.get('endpoints', [])
        self.ui.info(f"Subdomains: {len(subdomains)}  |  Endpoints: {len(endpoints)}")

        blocked = net.blocked_count()
        if blocked:
            self.ui.info(f"Scope guard blocked {blocked} out-of-scope request(s).")

        # Slowest modules — show where the wall-clock actually went.
        if self._module_timings:
            slowest = sorted(self._module_timings.items(), key=lambda kv: kv[1], reverse=True)[:5]
            self.ui.subsection("Slowest Modules")
            for name, secs in slowest:
                label = MODULE_LABELS.get(name, name)
                self.ui.bullet(f"{label:<34} {secs:6.1f}s")

    def _print_share_card(self):
        """A compact, copy-paste-friendly result card (no ANSI) for pasting
        into a report, a chat, or a bounty submission note."""
        from recon.core.console import supports_unicode, ascii_fallback
        from recon.core import banner as _banner
        counts = self.db.severity_counts()
        elapsed = int(time.time() - self.start_time)
        risk = getattr(self, "_last_risk_score", 0)
        grade = ('CRITICAL' if risk >= 80 else 'HIGH' if risk >= 50 else
                 'MODERATE' if risk >= 20 else 'LOW' if risk > 0 else 'CLEAN')
        tl, tr, bl, br, h, v = "┌", "┐", "└", "┘", "─", "│"
        if not supports_unicode():
            tl = tr = bl = br = "+"; h = "-"; v = "|"
        width = 54
        def row(s):
            s = s[:width - 2]
            return f"{v} {s:<{width - 2}}{v}"
        lines = [
            tl + h * width + tr,
            row("yata-recon  ·  scan result"),
            row(""),
            row(f"target    {self.target}"),
            row(f"risk      {risk}/100  ({grade})"),
            row(f"findings  {len(self.db.findings)}  "
                f"(crit {counts.get('critical',0)}  high {counts.get('high',0)}  "
                f"med {counts.get('medium',0)}  low {counts.get('low',0)})"),
            row(f"modules   {len(self._completed_modules)} run  ·  {elapsed//60}m {elapsed%60}s"),
            bl + h * width + br,
        ]
        self.ui.blank()
        self.ui.subsection("Shareable Result Card")
        for ln in lines:
            self.ui.raw("  " + (ln if supports_unicode() else ascii_fallback(ln)))
        self.ui.blank()

    def _save_results(self):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Sanitize filename — Windows forbids : / \ * ? " < > | in filenames
        base = self.target
        for ch in (':', '/', '\\', '*', '?', '"', '<', '>', '|'):
            base = base.replace(ch, '_')

        # JSON raw data
        json_path = os.path.join(self.output_dir, f"yata_recon_{base}_{ts}.json")
        data = {
            'meta': {
                'target': self.target,
                'scan_time': datetime.now().isoformat(),
                'modules': self.modules,
                'scope': self.scope,
            },
            'subdomains': self.context.get('subdomains', []),
            'endpoints':  self.context.get('endpoints', []),
            'js_secrets': self.context.get('js_secrets', []),
            'commands':   self.context.get('commands', []),
            'findings':   self.db.findings,
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.ui.ok(f"JSON saved: {json_path}")

        # Markdown report
        md_path = self.output_file or os.path.join(self.output_dir, f"yata_recon_{base}_{ts}.md")
        self._last_md_path = md_path  # surfaced to the TUI report screen via scan_completed
        report_mod = ReportModule(
            target=self.target, db=self.db, ui=self.ui,
            context=self.context, timeout=self.timeout,
            delay=self.delay, threads=self.threads,
            verbose=self.verbose, ai=self.ai,
            output_dir=self.output_dir,
        )
        md = report_mod.build_report()
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md)
        self.ui.ok(f"Report saved: {md_path}")

        # SARIF 2.1.0 export (--sarif) for CI / GitHub code-scanning ingestion.
        if self.sarif:
            try:
                from recon.core.sarif import write_sarif
                sarif_path = os.path.join(self.output_dir, f"yata_recon_{base}_{ts}.sarif")
                write_sarif(sarif_path, self.target, self.db.findings, tool_version="5.0")
                self.ui.ok(f"SARIF saved: {sarif_path}")
            except Exception as e:
                self.ui.warn(f"SARIF export failed: {e}")

        # Signed/verifiable reports (--sign-reports): hash + Ed25519-sign
        # both output files so they can be verified untampered later —
        # `.sig` sidecars written next to each.
        if self.sign_reports:
            from recon.core.report_signing import sign_file, available as signing_available
            if signing_available():
                for path in (json_path, md_path):
                    sig_path = sign_file(path)
                    if sig_path:
                        self.ui.ok(f"Signed: {sig_path}")
            else:
                self.ui.warn("--sign-reports requested but the 'cryptography' package is not installed.")

        # Commands runbook
        cmds = self.context.get('commands', [])
        if cmds:
            cmd_path = os.path.join(self.output_dir, f"yata_recon_{base}_{ts}_commands.sh")
            with open(cmd_path, 'w', encoding='utf-8') as f:
                f.write(f"#!/bin/bash\n# YATA RECON Command Runbook — {self.target}\n# Generated: {datetime.now().isoformat()}\n\n")
                f.write('\n'.join(cmds))
            self.ui.ok(f"Command runbook saved: {cmd_path}")

        return json_path

    def save_partial(self):
        """Called on KeyboardInterrupt to preserve what we have"""
        self.ui.warn("Saving partial scan data...")
        self._save_results()