# Changelog — OBSIDIAN

All significant changes documented here.

---

## v10.1.1 — Engine Reliability (Current)

**Determinism, time-budgeting, observability, and ergonomics fixes in the v10 engine.**

- **Deterministic findings** — endpoint selection iterated a `set` (hash-randomized
  per process), so the same scan could yield different results run-to-run.
  `injectable_endpoints()` and the crawl frontier are now sorted.
- **Time-bounded crawl** — the crawler could consume the entire `max_seconds`
  budget before any module ran (per_level was up to ~416 on SAFE). per_level is
  now capped at 50 and the crawl has its own deadline (~40% of the time budget).
- **`--max-seconds` CLI flag** — the time budget can now be overridden from the
  command line (previously only `--max-requests` was adjustable).
- **Module crashes are surfaced** — `_wrap_core` no longer swallows module
  exceptions silently; it logs `"[engine] module <name> crashed: <error>"` to stderr.
- **`payload_variants` now has effect** — the engine forwards the profile value to
  `obsidian_core.PAYLOAD_VARIANTS`; XSS and SQLi payload sets are capped accordingly
  (safe=3, aggressive=8; 0 = full set).
- **Single output stream** — core modules stay quiet under the engine by default so
  their timestamped logs no longer interleave with `[engine]`/`[run]`; use `--verbose`
  to see per-module core logs.
- **Timestamped reports** — default report is now `obsidian_report_<timestamp>.json`,
  so runs no longer clobber the previous report.

---

## v10.1.0 — Tooling Expansion

**New / upgraded external-tool integrations.**

- **New `tool_curl`** — raw-HTTP probe via the curl CLI: dangerous HTTP methods
  (TRACE/XST, PUT, DELETE, PATCH via OPTIONS `Allow`), Cross-Site Tracing detection,
  and HTTP/2 negotiation. Wired into both the classic scan and the v10 engine.
- **New `tool_testssl`** — testssl.sh wrapper for deep TLS/SSL audit (HTTPS only),
  JSON parsing with severity mapping.
- **Upgraded `tool_burpsuite`** — now supports BOTH the community `burp-rest-api`
  REST service and the Burp Suite Enterprise GraphQL API, with a real bounded
  poll loop and graceful degradation when Burp is unreachable.
- **Auto-installer** — added `curl` (apt) and `testssl.sh` (git) to the arsenal registry.
- Verified against a deliberately-vulnerable local target: curl/XST/method findings
  fire and error-based SQLi is detected; `--max-requests` hard cap honoured exactly.

---

## v10.0.1 — Maintenance & Bug Fixes

**Stability/correctness pass — no feature changes.**

- **Fixed `SyntaxError` (backslash in f-string)** in the HTML report builder that
  broke `obsidian_core.py` on Python 3.8–3.11 and silently disabled all detection
  modules under the v10 engine. Now imports and runs on Python 3.8+.
- **`-q/--quiet` now silences module logging** (added a `QUIET` flag) — previously
  150+ module logs printed regardless.
- **Accurate request budget**: all core-module HTTP now counts against the budget,
  and `--max-requests` is enforced as a hard cap (was effectively ignored).
- **Bounded cloud-metadata probing** (4s per-probe timeout + 15s cap) — no more
  ~20s hang on non-cloud targets.
- **Expanded fingerprints**: gunicorn, uvicorn, Caddy, Jetty, Tomcat, IIS, LiteSpeed.
- **Clean piped output**: ANSI colour is stripped automatically when stdout is not a
  TTY (override with `OBSIDIAN_FORCE_COLOR=1`); progress output is now flushed.
- **Docs/self-reference fixes**: tool no longer calls itself `dd.py` in help/version/
  SARIF; README quick-start uses the correct repo and entry points.

---

## v10.0.0 — Codename: NIGHT REAPER

**Theme: Autonomy + Out-of-Band Verification + Rebrand (was "Dark Devil Scanner")**

### New: autonomous decision engine (`obsidian/` package)
- `state.py` — `TargetState` knowledge graph (endpoints, params, technologies,
  behavioral signals, findings) + request/time `Budget`.
- `engine.py` — `Fingerprinter`, `Crawler`, `Planner` with **fingerprint gating**
  and **expected-value scheduling**; adapter that drives the existing 150+
  `module_*` detection functions; finding-driven task expansion.
- `obsidian.py` — independent self-directing CLI runner with JSON reporting.

### New: OAST out-of-band verification (`oast.py`)
- `LocalOASTListener` + `InteractshOAST` backends; `BlindVerifier` workflow.
- Blind SSRF/RCE/XXE/SQLi only reported on a confirmed callback → major FP cut.

### New: async core (`asynccore.py`)
- `AsyncHTTP` with concurrency cap + token-bucket rate limiter + per-host
  politeness; httpx → aiohttp → threaded-requests fallback chain.

### New: profiles + scope enforcement (`profiles.py`)
- `passive` / `safe` / `aggressive` profiles; `aggressive` gated behind
  `--i-have-authorization`. `ScopeGuard` hard-refuses out-of-scope hosts.

### New: plugin architecture (`plugins.py`)
- Drop-in `plugins/*.py` auto-loaded via `PLUGIN` dict or `register()`.
- Example: `plugins/example_security_txt.py`.

### New: extra scanner integrations (`tools_extra.py`)
- Optional wrappers: testssl.sh, retire.js, gitleaks, wapiti, jaeles, dontgo403.
- C2 / implant frameworks intentionally excluded (out of scanner scope).

### Rebrand
- Tool renamed `Dark Devil Scanner` → **OBSIDIAN**; new ASCII banner; version
  bumped 9.0.0 → 10.0.0; workspace dirs `dd_*` → `obs_*`.
- `CODE.py` preserved, rebranded, and renamed `obsidian_core.py` (classic mode).

---

## v9.0.0 — Codename: NIGHT REAPER (Current)

**Theme: Completion + Zero-FP Hardening**

### New Modules (v4.2)
- `module_api2_broken_auth` — API2: Invalid token acceptance, unauthenticated API access
- `module_api4_resource` — API4: Pagination limits, wildcard amplification, deep JSON nesting
- `module_api8_misconfig` — API8: API docs exposure, debug mode, default routes
- `module_hsts_check` — HSTS max-age, includeSubDomains, preload verification
- `module_method_override` — X-HTTP-Method-Override bypass detection
- `module_cert_transparency` — CT log subdomain mining via crt.sh API

### New Tools (v4.2)
- `tool_snallygaster` — sensitive file scanner
- `tool_feroxbuster` — fast content discovery with auto-tune
- `tool_commix` — command injection detection
- `tool_tplmap` — SSTI exploitation confirmation
- `tool_xsstrike` — advanced XSS detection
- `tool_corscanner` / `tool_corsy` — CORS misconfiguration tools
- `tool_jwt_tool` — JWT security testing
- `tool_graphqlmap` — GraphQL injection testing
- `tool_nosqlmap` — NoSQL injection
- `tool_ssrfmap` — SSRF exploitation

### Zero-FP Improvements
- **XSS**: Added benign-probe gate (echo-all param detection), HTML comment gate, similarity gate
- **SQLi**: Baseline stability check (2 baseline fetches), 5-gate error confirmation, statistical timing analysis (median of 3+3)
- **IDOR**: Raised minimum body difference to 15%, added public-data gate, JSON field comparison
- **NoSQLi**: Raised threshold to 80% enlargement, added JSON structure gate, require 2+ operators
- **Rate limiting**: Raised to 10 attempts, added progressive slowdown detection
- **Default creds**: Known-failure baseline comparison, cookie state change detection
- **SSRF**: Response size gate, wildcard response hash guard
- **Cache poisoning**: Dual cache-buster confirmation, clean-request verification
- **Gobuster/FFUF**: Wildcard response filtering, global redirect detection

### ScanContext Engine
Added `ScanContext` class providing:
- Baseline response caching per URL
- Canary collision guard
- Response deduplication (sha1 hash set)
- Content-type gating
- Adaptive rate control (tracks 429s, adjusts delay)
- Wildcard DNS hash guard
- Similarity gate (difflib SequenceMatcher)
- Smart param prioritisation (numeric ID params first)

### Tool Updates
- `tool_subfinder`: Added `-all` and `-recursive` flags (SubFinder v2.6+)
- `tool_httpx`: Added `-tech-detect`, `-title`, `-web-server` enrichment
- `tool_dnsx`: Added CNAME resolution and wildcard filtering
- `tool_nuclei`: Updated to v3.x flags, `-scan-strategy host-spray`, stats, deduplication
- `tool_gobuster`: Wildcard size filtering, global-redirect detection
- `tool_ffuf`: Auto-calibrate (`-ac`), wildcard baseline filtering, redirect detection
- `tool_dalfox`: Added `--mass-param`, `--only-discovery`, `--follow-redirects`
- `tool_katana`: Added `-jc` (JS crawling), `-kf` (known files), `-aff` (form filling)
- `tool_sslscan`: Added version gate for v1.x Heartbleed FP bug

---

## v8.0.0

**Theme: API Security Top 10 (2023) + New Attack Vectors**

### New Modules (v4.1)
- OWASP API Security Top 10 (2023): BFLA, excessive data exposure, API versioning, business logic
- Prototype pollution (server-side + client-side)
- Deserialization detection
- HTTP request smuggling
- URL path traversal
- PHP type juggling
- SSI injection
- XPath injection
- GraphQL injection
- Log injection
- Timing-based username enumeration
- S3/GCS/Azure Blob enumeration
- WebSocket security
- WSDL/SOAP discovery
- JWT algorithm confusion (RS256→HS256)
- SAML misconfiguration detection
- Cloud metadata deep check
- Regex DoS (ReDoS)
- Broken link hijacking
- Password policy enforcement check
- CORS preflight abuse
- Account enumeration (password reset comparison)
- Error fingerprinting (framework version leaks)

---

## v7.0.0

**Theme: Zero-FP Engine + Scale**

### Core Architecture
- Added baseline caching to all injection modules
- Implemented canary token system for XSS
- Boolean SQLi: raised threshold to 50% body difference + stability check
- Time-based SQLi: median timing analysis
- IDOR: numeric-only param gate + error/public-data gates
- Default creds: 500+ credential pairs, failure-baseline comparison

---

## v6.0.0

**Theme: MITRE ATT&CK Mapping**

- Full OWASP→MITRE ATT&CK technique mapping for all modules
- All findings include OWASP ID, OWASP name, MITRE technique ID, MITRE technique name
- CVSS v3.1 pre-configured vectors for 40+ vulnerability types

---

## v5.0.0 — v1.0.0

Initial development iterations covering core OWASP Web Top 10 modules, basic tool integrations, and the scanning framework.

---

## Planned for v10.0.0

- Interactive HTML dashboard with risk scoring
- Multi-target batch mode (from file)
- Docker container
- CI/CD GitHub Actions integration
- Passive recon mode (no active requests, DNS/CT/Shodan only)
- CVE correlation via NVD API
- Slack/Discord notification webhooks
