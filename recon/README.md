# YATA RECON — Deployment-Side Module (Architecture)

> RECON is the **deployment side** of YATA. Where the development side
> (HUNTER / HEALER / VALIDATOR / MUTATOR / LEARNER / REPORTER) proves and
> patches vulnerabilities in *source code*, RECON attacks a *live, deployed*
> web application over HTTP. It is driven by `yata recon` and its engine
> lives under `recon/` (`recon.core`, `recon.modules`, `recon.tui`).
> Persistent state (API key, scan history, auto-installed tool binaries)
> lives in `~/.yata-recon/`.

---

## 1. Project Overview & Purpose
**YATA RECON** is an advanced, AI-powered bug bounty hunting and vulnerability scanning framework. Unlike traditional scanners that simply run payloads and report blind results (often leading to false positives), YATA RECON integrates a multi-stage validation engine (Differential, Statistical Timing, JSON-shape-aware structural diffing, and AI Semantic Validation) that verifies findings *during* the scan, and discovers/tests OpenAPI-described REST APIs directly — not just crawlable HTML.

It is designed to be a personal, intelligent recon companion for bug bounty hunters, running both custom Python vulnerability checks (35 distinct modules) and orchestrating well-known external tools (Nuclei, Subfinder, Katana, etc.), all visualized through an asynchronous, highly interactive Textual Terminal UI (TUI).

## 2. Key Features & Capabilities
* **35 Scan Modules:** Covers OWASP Top 10 and advanced attack vectors (SQLi, NoSQLi, XSS, XXE, SSTI, LFI/Path Traversal, Command Injection, Prototype Pollution, Deserialization, IDOR, JWT, Broken Auth, OAuth, Mass Assignment, GraphQL, Smuggling, Cache Poisoning, Host Header Injection, etc.).
* **OpenAPI/Swagger-aware recon:** `ReconModule` actively probes common spec locations (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, ...) and parses discovered specs into `ctx['api_endpoints']` (method, path params, query params, header params, JSON body properties, and — when present — a real XML body template with the injection point already marked). This is what makes injection modules effective against pure JSON/XML REST APIs with zero HTML forms, which are otherwise invisible to crawl-based scanners.
* **Live credential propagation:** Any module can call `self.capture_credential(...)` (or the heuristic `self.try_capture_credential_from_response(resp, source)`, defined on `BaseModule` in `recon/modules/__init__.py`) to register a real token/cookie discovered mid-scan (e.g. an auth-bypass SQLi that returns a live session). It's merged into `ctx['auth_headers']`/`ctx['auth_cookies']` and every module's requests pick it up automatically from then on. Users can also seed this themselves via `--header`/`--cookie` (CLI) or the TUI setup screen's "Auth Header" field — this is the floor; live discovery only adds to it, never overwrites a real/user-supplied value with a weaker OpenAPI example placeholder (see `recon.py`'s `existing.setdefault(k, v)` precedence).
* **Multi-Stage False Positive Elimination (`Validator`):**
  * **Phase 0 Baseline:** Fingerprints WAFs, CMS, SPAs, calculates network jitter (μ, σ), and structural hashes for soft-404 error pages.
  * **Differential Tests:** Validates boolean-based injections (true payload matches baseline, false payload diverges, control recovers). Orientation-agnostic — it does not assume the baseline value represents the "true" condition (that only holds for `?id=1`-style params; for a login endpoint tested with intentionally-wrong credentials, the baseline *is* the false state, and it's the bypass payload that diverges). Accepts an optional `send_fn` callable so it can drive the probes through any injection point — GET query, POST body, JSON, XML, headers, path segments — not just URL query strings.
  * **Statistical Timing (Z-Score):** Validates time-based blind injections by comparing response times against the calculated baseline standard deviation. Also generalized via `send_fn`.
  * **JSON-shape-aware structural hashing:** `_structural_hash()` hashes JSON responses by key-path + value-type shape (not raw HTML tag sequence), so differential comparison is actually meaningful on JSON API responses. Two structurally-identical JSON bodies with different values (e.g. two successful logins for different users) still match; a genuinely different shape (a 401 error body vs. a 200 success body) correctly diverges.
  * **AI Semantic Validation:** Uses NVIDIA NIM to read DOMs, JS files, error messages, and 200-OK responses to determine if they are truly exploitable, and to distinguish a real secret from a placeholder/example value.
* **AI-Assisted Hunting (`AIEngine`):** Integrates directly with NVIDIA NIM (free tier, default model configurable via `--set-model`) using SSE streaming to generate context-aware payloads, inspect endpoint logic, deep-analyze JS files, and generate professional reports.
* **Active exploitation over static inspection:** e.g. `jwt.py` doesn't just flag "weak JWT config" — it forges an `alg:none` token and a weak-HMAC-secret-signed token and actually submits them to the live endpoint, only reporting CONFIRMED when the server actually accepts the forgery.
* **External Tool Pipeline (`ToolRunner` & `ToolInstaller`):** Asynchronously runs tools like `subfinder`, `katana`, `nuclei`, and `waybackurls`, parsing their NDJSON output streams on the fly. Auto-installs missing tools from GitHub releases locally into `~/.recon/tools/bin` without polluting the system path — wired into `ScanSession._ensure_external_tools()` at the start of every scan (disable with `--no-auto-install`).
* **Asynchronous Textual UI (TUI):** A 3×3-grid interactive dashboard (info bar, module progress, tool output, AI analysis, live findings) built with the `textual` framework, plus a setup screen with a live checklist of all 35 modules (driven by the same `PRESETS` the CLI's `--preset` flag uses) and an optional auth-header field. Includes a graceful fallback to a traditional headless CLI output using `rich`.
* **Actionable Output:** Every scan outputs raw JSON data, a beautifully formatted Markdown report (including per-finding evidence, confidence score, and validation steps) ready for HackerOne/Bugcrowd submission, and a Shell Runbook (`.sh`) to reproduce the attacks manually.

---

## 3. High-Level Architecture

The framework is decoupled into four main layers:

1. **CLI / Orchestration Layer (`recon/cli.py`, `recon/core/session.py`):**
   Parses arguments (including `--header`/`--cookie` for authenticated scanning), manages API keys, sets up the TUI/Headless mode, configures the session context, seeds any user-supplied auth into `ctx`, and loops through the selected scan modules.
2. **Core Engines (`recon/core/`):**
   The heavy lifting. Handles AI requests (`ai_engine.py`), intelligent validation (`validator.py`), network profiling (`baseline.py`), tool execution (`tool_runner.py`, `tool_installer.py`), and the findings database (`findings.py`).
3. **Vulnerability Modules (`recon/modules/`):**
   35 individual classes inheriting from `BaseModule`. They share a global rate limiter, HTTP session pooling, a `Validator` instance, and a context dictionary (`self.ctx`) that carries recon output, the OpenAPI-derived API surface, and the live/user-supplied auth state.
4. **Presentation Layer (`recon/tui/`, `recon/core/ui.py`):**
   The `textual` TUI (`app.py`) runs in the main thread while the scan session runs in a background thread. Events (`scan_started`, `finding_added`, `ai_call_completed`) are pushed via an event callback queue to update the UI without blocking.

---

## 4. Directory Structure

```text
recon/
├── recon/cli.py           # Main CLI entry point (--header/--cookie/--no-auto-install live here)
├── pyproject.toml          # Project metadata & dependencies
├── requirements.txt        # Pip dependencies (kept in sync with pyproject.toml)
├── core/                   # Core engine components
│   ├── ai_engine.py        # NVIDIA NIM API integration & streaming
│   ├── baseline.py         # Target profiling, WAF & Soft-404 detection
│   ├── config.py           # Config manager (~/.recon/config.json)
│   ├── findings.py         # In-memory findings database with deduplication
│   ├── interactive.py      # Legacy plain-text interactive wizard (--interactive flag)
│   ├── session.py          # ScanSession orchestrator, MODULE_MAP/MODULE_LABELS/PRESETS
│   ├── tool_installer.py   # Auto-installer for external Go binaries
│   ├── tool_runner.py      # Async subprocess pipeline runner
│   ├── ui.py                # Legacy headless Rich/Color UI wrapper
│   └── validator.py         # Differential/timing/reflection/JSON-shape validation engine
├── modules/                 # 35 scan modules + BaseModule
│   ├── __init__.py          # BaseModule: rate limiter, session helpers, credential capture/propagation
│   ├── recon.py              # Crawls, parses HTML/JS, discovers & parses OpenAPI/Swagger specs
│   ├── sqli.py               # SQL Injection — error/boolean/time/union-based, JSON/XML/path-aware
│   ├── xss.py                 # Cross-Site Scripting
│   ├── reporter.py            # Markdown/JSON/Shell output generator
│   └── ...                    # (31 other specific vulnerability modules)
├── tui/                       # Textual UI Application
│   ├── app.py                 # Main Textual App, threading/events, start_scan_from_setup()
│   ├── headless.py            # Rich-based headless fallback
│   ├── theme.py                # Shared color tokens
│   ├── screens/                # TUI Screens (TargetSetup, Dashboard, ReportView)
│   ├── widgets/                 # TUI Widgets (info bar, AI panel, findings, progress, tool output)
│   └── styles/
│       └── yata-recon.tcss     # Stylesheet for the Textual TUI
└── data/                        # Wordlists and static resources
    └── common.txt
```

---

## 5. Core Engine Components Breakdown

### 5.1 `ScanSession` (`recon/core/session.py`)
The orchestrator. It creates the `FindingsDB`, `AIEngine`, and `ExternalToolRunner`; auto-installs any external tools the selected modules need; seeds user-supplied auth headers/cookies into `self.context`; executes Phase 0 (`BaselineProfiler`); loops over the requested `MODULE_MAP`, and calls `module.run()`. It manages a shared `self.context` dictionary so Phase 1 (Recon) can pass discovered subdomains, endpoints, the OpenAPI-derived API surface, and (as the scan progresses) live-captured auth down to every later phase. Also defines `MODULE_LABELS` (human-readable names, used by the TUI) and `PRESETS`/`get_preset_modules()` (the single source of truth for `--preset quick|standard|full`, shared by the CLI and the TUI's profile buttons).

### 5.2 `BaselineProfiler` (`recon/core/baseline.py`)
Runs *before* any scan module. It issues initial requests to determine:
* **Default Response Fingerprint:** Generates a structural HTML hash to track page layout changes.
* **Soft-404s:** Hits 3 random non-existent paths. If they return 200 OK, it calculates the structural hash of the custom error page to filter false positives later.
* **Timing Jitter:** Issues 5 requests to calculate the mean (μ) and standard deviation (σ) of the target's response time, enabling accurate time-based blind injection checks.
* **Technology:** Identifies WAFs (Cloudflare, Akamai, etc.), CMS (WordPress, Joomla), and SPAs (React, Vue) via headers and regex patterns.

All response checks here use `is None`, not truthiness — `requests.Response.__bool__()` is `False` for any non-2xx status, so a WAF-blocked (403) or auth-walled (401) homepage would otherwise silently disable baseline profiling entirely.

### 5.3 `Validator` (`recon/core/validator.py`)
The brain behind false positive elimination. Modules pass their raw requests/responses here, or a `send_fn` closure so Validator can drive the probes itself through any injection point.
* **`validate_file_exposure`:** Ensures 200 OK, checks against the Soft-404 hash, and prevents HTML SPAs from masquerading as text/config files.
* **`differential_test`:** Boolean injection logic via true/false/control probes, checked in both orientations (baseline-as-true for classic `?id=1` params, baseline-as-false for e.g. a login endpoint tested with bad credentials).
* **`validate_time_based`:** Z-score statistical timing logic. Requires Z ≥ 3.5 and a subsequent control request to return to normal to prove time-based SQLi/NoSQLi/command injection.
* **`validate_reflection`:** Parses HTML with BeautifulSoup to determine if a payload is securely encoded or dangerously reflected inside `<script>` or attributes — used by `xss.py`.
* **`_structural_hash`:** JSON-shape-aware (key paths + value types) for JSON bodies, HTML tag-sequence based otherwise.
* **`validate_ssrf_indicator` / `validate_cookie_is_session`:** Small targeted helpers reused by `ssrf.py` and `broken_auth.py`/`idor.py`.

### 5.4 `AIEngine` (`recon/core/ai_engine.py`)
Powered by NVIDIA NIM (Streaming SSE POST requests). Generates structured insights mid-scan.
* Provides methods like `analyze_endpoint`, `suggest_payloads`, `analyze_js_content`, `analyze_sqli_error`, `analyze_idor_response`, `validate_secret`, `suggest_ssrf_payloads`/`analyze_ssrf_response`, `prioritize_endpoints`, and `analyze_chains`.
* It emits `ai_call_started` and `ai_call_completed` events with context hints to animate the AI panel in the TUI in real time.

### 5.5 `ExternalToolRunner` & `ToolInstaller` (`recon/core/tool_runner.py`, `recon/core/tool_installer.py`)
* **ToolRunner:** Async wrapper utilizing `asyncio.create_subprocess_exec` to run external binaries. It reads `stdout` line-by-line, parsing NDJSON (for ProjectDiscovery tools), and streaming it to the TUI. Also supports sequential piping (`run_pipeline`).
* **ToolInstaller:** OS/Arch aware (Windows/Linux/Mac, amd64/arm64). Fetches the latest GitHub release assets, downloads via temp files, extracts zips/tarballs, and places the binaries in `~/.recon/tools/bin/`. Called automatically by `ScanSession._ensure_external_tools()`.
* **NucleiModule:** Runs a full default-template nuclei scan (`-jsonl -silent -etags dos,fuzz`, 600s budget) when nuclei is installed/auto-installed; falls back to a small built-in ~17-path checklist (clearly logged as weaker) only when nuclei genuinely isn't available.

---

## 6. Vulnerability Modules & Phases

All modules inherit from `BaseModule` (`recon/modules/__init__.py`), which gives them access to a global rate-limiter lock (`_RATE_LOCK`), the shared session context, a `Validator` instance (`self.validator`), and credential capture/propagation helpers (`self.capture_credential()`, `self.try_capture_credential_from_response()`, `self.auth_headers()`, `self.auth_cookies()`).

Modules are executed in logical phases:
* **Phase 1 (Recon & CMS):** `ReconModule` is critical. It spiders the site, extracts forms, inputs, and links, queries Subfinder/crt.sh/WaybackUrls, mines JavaScript for hidden API routes and parameters, and discovers/parses an OpenAPI/Swagger spec if one exists — populating `ctx['endpoints']`, `ctx['forms']`, `ctx['api_endpoints']`, and `ctx['auth_headers']`.
* **Phase 2 (Config/Identity):** Headers, Subdomain Takeover, Secrets Exposure.
* **Phase 3 (Auth):** JWT attacks (active `alg:none`/weak-secret forgery), Broken Auth, OAuth misconfigs, IDOR (differential two-object comparison + AI verification, now also testing OpenAPI path-param identifiers).
* **Phase 4 (Data/Input):** Parameter tampering (real boundary/flag differential testing), File Upload, Mass Assignment (JSON-body differential, verifies the injected field actually took effect).
* **Phase 5 (Injection):** SQLi, NoSQLi, SSTI, XSS, XXE, LFI, CRLF, SSRF, Deserialization, Prototype Pollution. These rely heavily on the `Validator` and, where the vuln class is JSON/XML-body-driven, on `ctx['api_endpoints']`.
* **Phase 6 (Client/Logic):** CORS, CSRF, Clickjacking, Open Redirect, Host Header Injection, WebSockets.
* **Phase 7 (Advanced):** Cache Poisoning, HTTP Request Smuggling, GraphQL introspection, Rate Limiting.
* **External:** `NucleiModule`.
* **Reporting:** `ReportModule` (builds the final markdown, including evidence/confidence/validation_steps per finding).

---

## 7. TUI Architecture (Textual)

Located in `recon/tui/`. Built using the `textual` Python framework.

### Flow & Events
1. **App Initialization:** `YATA RECONApp` mounts the `TargetSetupScreen` (if no args provided) or goes straight to the `DashboardScreen`.
2. **Setup Screen:** Target/thread/auth-header inputs, Quick/Standard/Full profile buttons (backed by `core.session.PRESETS`), and a live 3-column grid of all 35 modules (`core.session.MODULE_LABELS`). Pressing Start Scan calls `app.start_scan_from_setup(config)`.
3. **Worker Thread:** The `ScanSession` runs in a `textual` worker thread (`@work(thread=True)`).
4. **Event Callbacks:** Modules and the Session emit events (e.g., `_emit("finding_added", data)`) via a callback function passed from the TUI.
5. **UI Thread Dispatch:** The callback uses `self.call_from_thread()` to safely route the event to `_process_event()` in the main UI thread.
6. **Widget Updates:** The TUI updates `ScanInfoBar`, `AIAnalysisPanel`, `ScanProgress`, and `FindingPanel` dynamically based on the event payload.
7. **Logs:** Raw standard output from tools is captured by a proxy logger and dumped into a `RichLog` widget.

---

## 8. CLI Flags & Configuration

Configuration is persistent and stored in `~/.recon/config.json`.

**Key Management:**
* `--set-api nvapi-xxxx` : Saves the NVIDIA NIM API key.
* `--api-test` : Validates the saved key.
* `--set-model MODEL` : Change the AI model.

**Scan Options:**
* `-t <target>` : Target domain (e.g., `example.com`).
* `--preset <quick|standard|full>` : Quick (7 modules), Standard (13 modules), Full (all 35).
* `--modules xss,sqli,recon` : Comma-separated list to override preset.
* `--header "Name: Value"` (repeatable) : Extra header sent with every request — scan authenticated areas.
* `--cookie "name=value"` (repeatable) : Extra cookie sent with every request.
* `--threads <int>` / `--timeout <int>` / `--delay <float>` : Concurrency and throttling controls.
* `--no-tui` : Disables Textual UI, dropping back to the legacy headless Rich CLI (useful for CI/CD or logging).
* `--no-auto-install` : Don't auto-download external tools (nuclei/subfinder/katana/waybackurls).
* `--output-dir <path>` : Directory for generated reports (default: `./yata_recon_output`).
* `--interactive` / `-i` : Legacy plain-text wizard instead of the TUI.

---

## 9. Output Artifacts

Every successful scan generates three files in the output directory, timestamped and sanitized (e.g., `yata_recon_example.com_20260924_120000.*`):
1. **`.json`:** Raw, structured data containing scan metadata, context (subdomains, endpoints, discovered parameters), and the full array of findings.
2. **`.md`:** A professional Bug Bounty Report. Includes Executive Summary, Severity counts, detailed finding descriptions with evidence/confidence/validation steps, proof of concepts (PoC URLs), AI-generated remediation steps, and CVSS scores.
3. **`_commands.sh`:** A shell script runbook containing the exact external commands (e.g., `subfinder -d ...`, `katana -u ...`) used during the scan, allowing the user to reproduce the discovery manually.

---

## 10. Extensibility & Internal Design Rules

* **Adding a new Module:** Create `recon/modules/new_mod.py`, inherit `BaseModule`, implement `run()`. Add it to `MODULE_MAP` **and** `MODULE_LABELS` in `recon/core/session.py` — a module that exists as a file but isn't in `MODULE_MAP` will never run under any preset (this happened to `lfi.py` and `host_header.py` for most of this project's history; both are now wired in).
* **Adding a new External Tool:** Add it to `TOOL_REGISTRY` or `PIP_TOOLS` in `recon/core/tool_installer.py`. Use `self.tool_runner.run_sync()` inside the module.
* **Handling Output:** NEVER use `print()` directly inside modules. Use `self.ui.info()`, `self.ui.warn()`, `self.ui.find()`, etc. This ensures output routes correctly regardless of whether the TUI, headless renderer, or standard CLI is active.
* **Validation:** NEVER flag a vulnerability purely based on a static keyword match in a response. ALWAYS pipe responses through `self.validator` (e.g., `differential_test`, `validate_file_exposure`, `validate_reflection`) to check against the baseline soft-404 hash, timing jitter limits, and DOM context.
* **Response truthiness:** NEVER check `if not resp:` / `if resp:` to mean "did the request fail." `requests.Response` is falsy for *any* non-2xx status — always check `resp is None` explicitly. This exact bug silently disabled detection on auth-walled/error-returning endpoints in multiple modules before being fixed project-wide.
* **JSON-body-driven vuln classes:** For NoSQLi, prototype pollution, mass assignment, XXE-via-XML-body, and SSTI/SSRF on API-first targets, test `ctx.get('api_endpoints', [])`'s `json_props`/`xml_template` in addition to (not instead of) classic query-string/form testing — a module that only tests query strings is structurally blind on a target with zero HTML.
* **Differential probes with non-scalar payloads:** if a "true" and "false" probe use a different JSON *type* than the baseline (e.g. an object where a string is expected), a schema-validating API will reject both identically for type reasons alone — that's not a differential result. Compare same-type probes against each other, not against a differently-typed baseline (see `nosql.py`'s `_test_api_endpoints` for the pattern).
