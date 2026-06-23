# OBSIDIAN — Autonomous Engine (v10.0.0 · NIGHT REAPER)

The `obsidian/` package is a self-directing layer on top of the 150+ detection
modules in `obsidian_core.py`. Instead of running every module in a fixed order,
it maintains **state** about the target and **decides** what to run next.

```
seed → crawl → fingerprint → gate modules → score → run highest-value action
     → update state → expand new work from findings → repeat until budget out
```

---

## Quick start

```bash
pip install -r requirements.txt

# default safe profile
python3 obsidian.py https://target.tld --profile safe

# deep run (gated behind explicit authorization)
python3 obsidian.py https://target.tld --profile aggressive --i-have-authorization

# scoped multi-host run with out-of-band verification + plugins + extra tools
python3 obsidian.py https://app.tld \
    --scope "*.tld,re:^api[0-9]+\.tld$" \
    --oast --plugins plugins --extra-tools -o report.json
```

The original interactive scanner is unchanged and still available:

```bash
python3 obsidian_core.py        # classic 8-phase menu-driven mode
```

---

## The four upgrades

### 1. Decision engine (`engine.py`, `state.py`)
- **`TargetState`** — thread-safe knowledge graph: endpoints, params, technologies,
  behavioral signals (`waf`, `is_api`, `is_wordpress`, `cloud`, `auth_surface`, …),
  findings, and a request/time **budget**.
- **`Fingerprinter`** runs first and populates `signals` so gating has something to
  reason over.
- **`Planner`** holds `ModuleSpec`s, **gates** them by `requires(state)` + profile,
  and schedules by **expected value** = `cvss_weight × confidence × budget ÷ cost`.
- **Finding-driven expansion** — injectable endpoints and signals spawn new,
  narrowly-scoped tasks while the scan runs.

### 2. OAST verification (`oast.py`)
Blind SSRF / RCE / XXE / SQLi are only reported when the target independently
**calls back** to a listener we control.
- `LocalOASTListener` — tiny local HTTP collaborator (internal/SSRF labs, or when
  `--oast-public-host` is reachable).
- `InteractshOAST` — uses the `interactsh-client` binary for internet-facing targets.
- `BlindVerifier` — `token → callback_url → confirm()` workflow. No callback → no
  "Confirmed". This is the biggest false-positive killer.

### 3. Async core (`asynccore.py`)
`AsyncHTTP` fires requests concurrently with three rails: a concurrency **semaphore**,
a global **token-bucket** rate limiter (`profile.rate_limit_rps`), and per-host
politeness. Prefers `httpx`, falls back to `aiohttp`, then to threaded `requests`.

### 4. Plugins + profiles (`plugins.py`, `profiles.py`)
- Drop any `*.py` into `plugins/` exposing a `PLUGIN` dict (or a `register()`
  function) and it auto-loads. See `plugins/example_security_txt.py`.
- **Profiles** are the safety layer, never a rail removal:

  | Profile | Active payloads | Aggressive | Budget | Notes |
  |---|---|---|---|---|
  | `passive` | no | no | 400 req | recon / prod-safe |
  | `safe` *(default)* | yes | no | 2,500 req | non-destructive probes |
  | `aggressive` | yes | yes | 8,000 req | **requires `--i-have-authorization`** |

  No profile performs destructive actions (no deletion, no flooding, no persistence).

---

## Scope enforcement (`ScopeGuard`)
The engine **physically refuses** out-of-scope hosts. The target host is always
in scope; add more with `--scope`:

```
--scope "*.example.com"          # wildcard subdomains
--scope "api.example.com"        # exact host
--scope "re:^app[0-9]+\.x\.io$"  # regex (prefix re:)
```

Every request, crawl link, and module target is checked before it fires.

---

## Extra scanner integrations (`tools_extra.py`)
OBSIDIAN auto-uses these **detection** scanners if installed (skips cleanly if not):
`testssl.sh`, `retire.js`, `gitleaks`, `wapiti`, `jaeles`, `dontgo403`.
Enable with `--extra-tools`.

> **Not included by design:** C2 / implant frameworks (Sliver, Cobalt Strike,
> Mythic, etc.). Those maintain access / run post-exploitation — a different
> category from vulnerability scanning. OBSIDIAN is detection-and-reporting only.

---

## Writing a plugin

```python
# plugins/my_check.py
def run(state, ctx):
    res = ctx.async_get([state.target + "/health"])
    if res and res[0].status == 200 and "debug" in res[0].text.lower():
        return [{"module": "my_check", "title": "Debug endpoint exposed",
                 "severity": "Medium", "url": state.target,
                 "confidence": "Confirmed"}]
    return []

PLUGIN = {"name": "debug_probe", "category": "exposure",
          "profile_min": "safe", "run": run, "cvss_weight": 5}
```

---

## Authorized use
OBSIDIAN tests systems for vulnerabilities and reports them. Run it only against
targets you own or are explicitly authorized (in writing) to assess, and stay
within the scope you were granted. The `aggressive` profile is intentionally
gated behind `--i-have-authorization`.
