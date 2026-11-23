<p align="center">
  <img src="https://img.shields.io/badge/YATA-v0.9.9-blueviolet?style=for-the-badge&logo=python&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Lines_of_Code-30%2C800%2B-informational?style=for-the-badge" alt="LOC" />
  <img src="https://img.shields.io/badge/Scan_Modules-50-success?style=for-the-badge" alt="Modules" />
</p>

<h1 align="center">🐍 YATA</h1>
<h3 align="center">Yet Another Threat Antagonist</h3>
<h4 align="center"><i>The Cybersecurity Ouroboros</i></h4>

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?logo=opensourceinitiative&logoColor=white" alt="MIT" /></a>
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?logo=apache&logoColor=white" alt="Apache 2.0" /></a>
  <a href="LICENSE-GPL-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu&logoColor=white" alt="GPL v3" /></a>
  <a href="https://www.doi.org/10.58257/IJPREMS55167"><img src="https://img.shields.io/badge/DOI-10.58257%2FIJPREMS55167-10.58257?style=flat&logo=doi&logoColor=white&color=brightgreen" alt="DOI" /></a>
  <img src="https://img.shields.io/badge/NVIDIA-NIM%20LLMs-76B900?logo=nvidia&logoColor=white" alt="NVIDIA" />
</p>

<p align="center">
  An autonomous security agent that <b>attacks</b> a codebase, <b>heals</b> the vulnerabilities it proves,<br/>
  <b>attacks its own remediations</b>, and <b>learns</b> from every assessment.
</p>

---

## 🎯 The Problem

Traditional security workflows are fragmented and manual:

```
Scanner → Find Vulnerability → Developer Investigates → Developer Patches → Developer Tests → Developer Validates
```

Each step is disconnected. Findings are accepted without proof. Patches are trusted without adversarial re-testing. Knowledge is lost between assessments.

## 💡 The Solution

**YATA automates the complete offensive-to-defensive security cycle.**

A vulnerability is **not accepted** until YATA successfully **exploits** it.  
A patch is **not accepted** until YATA **fails to break** it.

```
Repository → HUNTER attacks → Exploit succeeds → HEALER repairs → VALIDATOR attacks again → Patch survives → LEARNER remembers
```

> *A security agent is only as trustworthy as its ability to defeat itself.*

---

## 📊 Project Stats

| Metric | Count |
|:---|:---|
| Total Python Source Files | **161** |
| Lines of Code | **30,800+** |
| Core Agents | **6** (HUNTER, HEALER, VALIDATOR, MUTATOR, LEARNER, REPORTER) |
| Vulnerability Classes (Dev-Side) | **9** |
| RECON Scan Modules (Deploy-Side) | **50** |
| Test Repositories | **19** |
| CLI Commands | **10** |
| TUI Screens | **11** |
| Supported Languages | **3** (Python, JavaScript, TypeScript) |

---

## 🏗️ Architecture

YATA has two sides — **Development** (source code analysis) and **Deployment** (live application scanning):

```
┌─────────────────────────────────────────────────────────────────┐
│                     YATA — Development Side                     │
│                                                                 │
│   ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌──────────┐  │
│   │  HUNTER  │──▶│  HEALER  │──▶│ VALIDATOR │──▶│ LEARNER  │  │
│   │ (Attack) │   │ (Patch)  │   │(Re-Attack)│   │ (Memory) │  │
│   └──────────┘   └──────────┘   └───────────┘   └──────────┘  │
│        │                              │                         │
│        ▼                              ▼                         │
│   ┌──────────┐                 ┌───────────┐                   │
│   │ REPORTER │                 │  MUTATOR  │                   │
│   │ (Output) │                 │ (Payload  │                   │
│   └──────────┘                 │ Variants) │                   │
│                                └───────────┘                   │
├─────────────────────────────────────────────────────────────────┤
│                     YATA — Deployment Side                      │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                    RECON Engine                          │  │
│   │  50 Scan Modules · Multi-Stage FP Elimination           │  │
│   │  OpenAPI-Aware · AI Semantic Validation · External Tools │  │
│   │  Textual TUI · Markdown/JSON/SARIF Reports              │  │
│   └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 Core Agents

### 🏹 HUNTER — Offensive Security Agent
- Builds attack paths using AST-based static analysis
- Executes payloads against live application endpoints
- Proves exploitability with captured evidence
- Supports Python (Flask), JavaScript (Express), and TypeScript

### 🩹 HEALER — Defensive Remediation Agent
- Generates minimal, secure patches
- Applies structural fixes (parameterized queries, safe subprocess calls, path validation)
- Preserves application functionality
- Falls back to deterministic patching when no LLM is available

### ⚔️ VALIDATOR — Adversarial Validation Agent
- Re-runs the original exploit chain against patched code
- Confirms remediation through **real HTTP verification** (Flask `test_client` / Node subprocess)
- A patch is accepted **only** when the exploit fails

### 🧬 MUTATOR — Payload Mutation Agent
- Generates variant payloads to stress-test patches beyond the original exploit
- Uses deterministic curated mutations + optional LLM-generated variants
- Reports battery results: *"X/Y known bypass techniques blocked"*

### 📚 LEARNER — Repository Memory Agent
- Maintains persistent per-repository security knowledge
- Tracks assessment history, vulnerability trends, and patch success rates
- Remembers what worked and what didn't across runs

### 📜 REPORTER — Output Generation Agent
- Generates rich terminal reports, HTML dashboards, and structured JSON
- Includes executive summaries, security score evolution, proven exploits, and agent metrics
- Every finding carries a structured **Evidence Bundle** (proof ID, payload, pre/post-patch response)

---

## 🛡️ Supported Vulnerabilities

### Development Side (Source Code Analysis)

| Vulnerability | OWASP | CWE | Severity | Exploit | Patch | Validate | Languages |
|:---|:---|:---|:---|:---:|:---:|:---:|:---|
| SQL Injection | A03:2021 | CWE-89 | 🔴 CRITICAL | ✅ | ✅ | ✅ | Python, JS/TS |
| Command Injection | A03:2021 | CWE-78 | 🔴 CRITICAL | ✅ | ✅ | ✅ | Python, JS/TS |
| SSRF | A10:2021 | CWE-918 | 🔴 CRITICAL | ✅ | ✅ | ✅ | Python, JS/TS |
| SSTI | A03:2021 | CWE-1336 | 🔴 CRITICAL | ✅ | ✅ | ✅ | Python |
| Insecure Deserialization | A08:2021 | CWE-502 | 🔴 CRITICAL | ✅ | ✅ | ✅ | Python |
| Hardcoded Secrets | A02:2021 | CWE-798 | 🟠 HIGH | ✅ | ✅ | ✅ | Python |
| Path Traversal | A01:2021 | CWE-22 | 🟠 HIGH | ✅ | ✅ | ✅ | Python, JS/TS |
| Cross-Site Scripting | A03:2021 | CWE-79 | 🟡 MEDIUM | ✅ | ✅ | ✅ | Python, JS/TS |
| Open Redirect | A01:2021 | CWE-601 | 🟡 MEDIUM | ✅ | ✅ | ✅ | Python, JS/TS |

### Deployment Side (RECON — Live Application Scanning)

50 scan modules covering the full OWASP spectrum and beyond:

<details>
<summary><b>Click to expand all 50 modules</b></summary>

| Module | Description |
|:---|:---|
| `sqli` | SQL Injection (error/boolean/time/union-based, JSON/XML/path-aware) |
| `nosql` | NoSQL Injection |
| `xss` | Cross-Site Scripting |
| `dom_xss` | DOM-based XSS |
| `cmdi` | Command Injection |
| `ssti` | Server-Side Template Injection |
| `ssrf` | Server-Side Request Forgery |
| `lfi` | Local File Inclusion / Path Traversal |
| `xxe` | XML External Entity Injection |
| `xpath` | XPath Injection |
| `ldap` | LDAP Injection |
| `deserialization` | Insecure Deserialization |
| `smuggling` | HTTP Request Smuggling |
| `jwt` | JWT Forgery (alg:none, weak HMAC) |
| `idor` | Insecure Direct Object Reference |
| `broken_auth` | Broken Authentication |
| `auth_bypass` | Authentication Bypass |
| `auth_flow` | Authentication Flow Analysis |
| `oauth` | OAuth Misconfiguration |
| `saml` | SAML Vulnerabilities |
| `cors` | CORS Misconfiguration |
| `csrf` | Cross-Site Request Forgery |
| `clickjacking` | Clickjacking |
| `open_redirect` | Open Redirect |
| `file_upload` | Unrestricted File Upload |
| `mass_assignment` | Mass Assignment |
| `prototype_pollution` | Prototype Pollution |
| `graphql` | GraphQL Introspection & Injection |
| `graphql_suggest` | GraphQL Field Suggestion Abuse |
| `cache_poisoning` | Web Cache Poisoning |
| `web_cache_deception` | Web Cache Deception |
| `host_header` | Host Header Injection |
| `crlf` | CRLF Injection |
| `hpp` | HTTP Parameter Pollution |
| `http_methods` | Dangerous HTTP Methods |
| `race_condition` | Race Condition / TOCTOU |
| `rate_limit` | Rate Limiting Bypass |
| `secrets` | Exposed Secrets & API Keys |
| `headers` | Security Headers Analysis |
| `cloud_storage` | Cloud Storage Misconfiguration |
| `subdomain_takeover` | Subdomain Takeover |
| `dependency_confusion` | Dependency Confusion |
| `second_order` | Second-Order Injection |
| `websocket` | WebSocket Security |
| `js_analysis` | JavaScript Static Analysis |
| `cms_scanner` | CMS Detection & Vulnerabilities |
| `nuclei_sim` | Nuclei Template Integration |
| `params` | Parameter Discovery |
| `recon` | Crawling, OpenAPI/Swagger Discovery |
| `reporter` | Report Generation (Markdown/JSON/SARIF/Shell) |

</details>

---

## 🌐 Supported Languages

| Language | Detect | Patch | Runtime Validation |
|:---|:---:|:---:|:---|
| Python (Flask) | ✅ | ✅ | In-process via Flask `test_client` |
| JavaScript (Node/Express) | ✅ | ✅ | Real subprocess over HTTP (`node`) |
| TypeScript (`ts-node`) | ✅ | ✅ | Real subprocess over HTTP (`ts-node --transpile-only`) |

> JS/TS runtime exploitation starts the target app as a real Node process on a loopback port and issues real HTTP requests — the same *"prove it happened"* standard as the Flask path.

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/nishantx4/YATA.git
cd YATA
```

### 2. Create Virtual Environment

**Windows PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install

```bash
pip install -e .
```

### 4. Verify

```bash
yata version
```
```
YATA v0.9.9
```

### 5. (Optional) JS/TS Support

```bash
npm install
```

---

## ⚡ Usage

### Run a Security Assessment

```bash
# Safe mode — creates patches without modifying originals (recommended)
yata assess <repository> --safe

# Apply mode — automatically applies validated patches
yata assess <repository> --apply

# Interactive mode — prompts before each patch application
yata assess <repository> --interactive

# Quick demo with bundled test repository
yata --demo
```

### Scan a Live Web Application (RECON)

```bash
# Interactive TUI scanner
yata recon -t example.com

# Full preset, headless-friendly
yata recon -t example.com --preset full

# Local demo against bundled vulnerable app
yata recon --serve-local test_repositories/repo1_login_sqli --preset quick
```

### Interactive TUI Console

```bash
yata tui [repository]
```

### Chat with YATA About a Repository

```bash
yata chat <repository>
```

### Other Commands

```bash
yata help                    # Show all commands
yata discover <path>         # Discover repositories
yata memory <repository>     # View repository memory
yata history <repository>    # View assessment history
yata report <repository>     # Open latest report
yata status                  # Platform statistics
```

---

## 🔐 Evidence Gate

Every round in a YATA report carries a **structured proof bundle**:

- **Proof ID** — Unique hash of the finding
- **Payload** — The exact exploit used
- **Pre-Patch Response** — Captured evidence of successful exploitation
- **Post-Patch Response** — Captured evidence of blocked exploitation

A finding is marked `PROVEN` **only** when the exploit actually reproduced at runtime *and* all evidence artifacts are present. Anything missing is explicitly listed as `UNPROVEN` — never quietly accepted.

---

## 🧠 Repository Memory

YATA doesn't just assess repositories — it **remembers** them.

```
.yata/memory/<repository>/memory.json
```

Persistent tracking of:
- 📈 Assessment history & security score evolution
- 🔍 Vulnerability type trends
- ✅ Patch success/failure rates
- 📊 Repository-level statistics

---

## 🤖 LLM Integration

### NVIDIA NIM (Default)

```bash
cp .env.example .env
# Add: NVIDIA_API_KEY=<your-key>
```

Default model: `meta/llama-3.2-11b-vision-instruct`

### Autonomous Fallback Mode

If no API key is available, YATA automatically switches to **deterministic local engines** with zero LLM requests. No functionality is lost — all detection, patching, and validation work without an API key.

---

## 🧪 Test Repositories

YATA ships with **19 purpose-built vulnerable test repositories** covering every supported vulnerability class across Python, JavaScript, and TypeScript:

<details>
<summary><b>View all test repositories</b></summary>

| Repository | Vulnerability | Language |
|:---|:---|:---|
| `repo1_login_sqli` | SQL Injection (Login) | Python |
| `repo2_search_sqli` | SQL Injection (Search) | Python |
| `repo3_admin_sqli` | SQL Injection (Admin) | Python |
| `repo4_hardcoded_secret` | Hardcoded Secrets | Python |
| `repo5_mixed` | Multiple Vulnerabilities | Python |
| `repo6_command_injection` | Command Injection | Python |
| `repo7_path_traversal` | Path Traversal | Python |
| `repo8_xss` | Cross-Site Scripting | Python |
| `repo9_ssrf` | SSRF | Python |
| `repo10_ssti` | Server-Side Template Injection | Python |
| `repo11_open_redirect` | Open Redirect | Python |
| `repo12_insecure_deserialization` | Insecure Deserialization | Python |
| `repo13_js_command_injection` | Command Injection | JavaScript |
| `repo14_js_path_traversal` | Path Traversal | JavaScript |
| `repo15_js_sql_injection` | SQL Injection | JavaScript |
| `repo16_js_xss` | Cross-Site Scripting | JavaScript |
| `repo17_js_ssrf` | SSRF | JavaScript |
| `repo18_js_open_redirect` | Open Redirect | JavaScript |
| `repo19_ts_command_injection` | Command Injection | TypeScript |

</details>

---

## 📁 Project Structure

```
YATA/
├── yata.py                  # Main entry point & CLI orchestration
├── red_agent.py             # HUNTER — AST-based detection + exploitation
├── blue_agent.py            # HEALER — Patch generation
├── verifier.py              # VALIDATOR — Live HTTP verification (Flask test_client)
├── mutator_agent.py         # MUTATOR — Payload mutation engine
├── learner_agent.py         # LEARNER — Persistent repository memory
├── report_generator.py      # REPORTER — JSON/HTML/Markdown reports
├── attack_library.py        # Curated payload catalogue
├── llm_client.py            # NVIDIA NIM API client
├── chat_agent.py            # Conversational Q&A agent
├── js_detectors.py          # JavaScript/TypeScript vulnerability detection
├── js_patches.py            # JavaScript/TypeScript patch generation
├── js_runtime.py            # Node.js subprocess runtime for JS/TS validation
├── sandbox.py               # Execution sandboxing
├── fallback_patches.py      # Deterministic fallback patching engine
├── commands/                # CLI command modules (10 commands)
│   ├── assess.py, chat.py, discover.py, help.py, history.py,
│   ├── memory.py, recon.py, report.py, status.py, version.py
├── tui/                     # Interactive Textual TUI (11 screens)
│   ├── app.py, engine.py, state.py, markup.py, theme.tcss
│   ├── screens/             # Target, scope, mode, execution, review, etc.
│   └── widgets/             # Header, footer, status bar, workflow
├── recon/                   # RECON deployment-side engine
│   ├── cli.py               # RECON CLI entry point
│   ├── core/                # AI engine, validator, baseline, session, tools
│   └── modules/             # 50 scan modules
├── test_repositories/       # 19 vulnerable test apps
├── pyproject.toml           # Package configuration
└── requirements.txt         # Dependencies
```

---

## 📝 Research Publication

This project is backed by a peer-reviewed research paper published in the **International Journal of Progressive Research in Engineering Management and Science (IJPREMS)**:

> **YATA: Yet Another Thread Antagonist**
>
> Charan Pote, Aarsh Chauhan, Nishant Kale, Sarthak Dhamande, Vivek Dhole, Navdeep Moundekar
>
> *IJPREMS — Volume 06, Issue 10*
>
> 🔗 DOI: [10.58257/IJPREMS55167](https://www.doi.org/10.58257/IJPREMS55167)

```bibtex
@article{pote2026yata,
  title   = {YATA: Yet Another Thread Antagonist},
  author  = {Pote, Charan and Chauhan, Aarsh and Kale, Nishant and Dhamande, Sarthak and Dhole, Vivek and Moundekar, Navdeep},
  journal = {International Journal of Progressive Research in Engineering Management and Science (IJPREMS)},
  volume  = {6},
  number  = {10},
  year    = {2026},
  doi     = {10.58257/IJPREMS55167}
}
```

---

## 🗺️ Roadmap

### ✅ Completed

- [x] 9 vulnerability classes with full exploit → patch → validate cycle
- [x] Multi-language support (Python, JavaScript, TypeScript)
- [x] RECON deployment scanner with 50 modules
- [x] Multi-stage false positive elimination (differential, timing, structural, AI)
- [x] OpenAPI/Swagger-aware API scanning
- [x] Adversarial validation with MUTATOR payload battery
- [x] Persistent repository memory (LEARNER)
- [x] Evidence Gate (structured proof bundles)
- [x] Interactive Textual TUI with 11 screens
- [x] Mission-grounded chat with agentic tools (`rescan()`, `read_file()`)
- [x] HTML, JSON, Markdown, and SARIF report generation
- [x] Native CLI with `pip install -e .`
- [x] Autonomous fallback mode (zero LLM dependency)
- [x] External tool pipeline (Nuclei, Subfinder, Katana, Waybackurls)

### 🔮 Planned

- [ ] GitHub Pull Request automation
- [ ] CI/CD pipeline integration
- [ ] Watch mode (continuous monitoring)
- [ ] Additional languages (Java, Go, PHP, Ruby)
- [ ] Broader JS framework support (NestJS, Fastify, Koa)
- [ ] Advanced agentic chat tools (sandboxed Nmap, exploitation tooling)

---

## 📄 License

This project is **multi-licensed**. You may choose any one of:

| License | File | Badge |
|:---|:---|:---|
| MIT | [LICENSE-MIT](LICENSE-MIT) | ![MIT](https://img.shields.io/badge/License-MIT-yellow.svg) |
| Apache 2.0 | [LICENSE-APACHE](LICENSE-APACHE) | ![Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg) |
| GNU GPL v3 | [LICENSE-GPL-3.0](LICENSE-GPL-3.0) | ![GPL](https://img.shields.io/badge/License-GPLv3-blue.svg) |

Copyright (c) 2026 YATA Contributors

---

<p align="center">
  <b>Built as a Final Year Project at Priyadarshini College of Engineering, Nagpur</b>
</p>

<p align="center">
  <i>"A security agent is only as trustworthy as its ability to defeat itself."</i>
</p>

<p align="center">
  <b>Attack. Heal. Attack Again. Learn.</b>
</p>
