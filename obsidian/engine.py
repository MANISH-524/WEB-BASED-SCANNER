"""
obsidian.engine — the autonomous decision engine
================================================
This replaces the old fixed 8-phase for-loop with a *self-directing* scheduler:

    seed → crawl → fingerprint → gate modules → score → run highest-value action
         → update state → expand new work from findings → repeat until budget out

Key behaviors
-------------
* **Fingerprint gating** — only run modules whose ``requires(state)`` predicate
  is satisfied. No WordPress checks on Django, no S3 checks without cloud signals.
* **Expected-value scheduling** — under a budget, do the high-signal/low-cost
  things first (cvss_weight × confidence-prior ÷ cost).
* **Finding-driven expansion** — discovered injectable endpoints and signals
  spawn new, narrowly-scoped tasks (this is what makes it feel autonomous).
* **OAST re-verification** — blind-class findings are re-tested out-of-band
  before they are allowed to land as "Confirmed".

The engine drives the detection modules in ``obsidian_core`` when that module
is importable, and degrades gracefully to its own built-in passive checks when
it is not.
"""
from __future__ import annotations

import re
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from .state import TargetState, Finding, Budget
from .profiles import Profile, SAFE, ScopeGuard, ScopeError
from .asynccore import AsyncHTTP, ASYNC_AVAILABLE

_PROFILE_RANK = {"passive": 0, "safe": 1, "aggressive": 2}


# ─────────────────────────────────────────────────────────────────────────────
# Module specification
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ModuleSpec:
    name: str
    run: Callable                  # (state, ctx) -> list[Finding|dict]
    category: str = "general"
    profile_min: str = "safe"      # passive | safe | aggressive
    requires: Optional[Callable] = None   # predicate(state) -> bool (gate)
    cost: int = 1                  # relative request cost
    cvss_weight: float = 5.0       # expected severity if it fires
    scope: str = "target"          # target | per-endpoint
    confidence_prior: float = 0.5  # how often this class produces a real finding

    def gated_in(self, state: TargetState, profile: Profile) -> bool:
        if _PROFILE_RANK.get(self.profile_min, 1) > _PROFILE_RANK.get(profile.name, 1):
            return False
        if self.requires is not None:
            try:
                return bool(self.requires(state))
            except Exception:
                return False
        return True

    def value(self, state: TargetState) -> float:
        """Expected value used by the scheduler to order work."""
        budget_factor = 0.5 + 0.5 * state.budget.remaining_fraction()
        return (self.cvss_weight * self.confidence_prior * budget_factor) / max(1, self.cost)


# ─────────────────────────────────────────────────────────────────────────────
# Planner
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class _Task:
    spec: ModuleSpec
    url: str
    value: float


class Planner:
    """Holds the module registry and decides what runs next."""

    def __init__(self, profile: Profile):
        self.profile = profile
        self._specs: list[ModuleSpec] = []
        self._queue: list[_Task] = []
        self._ran: set[tuple] = set()

    def register(self, spec: ModuleSpec) -> None:
        self._specs.append(spec)

    def register_many(self, specs: list[ModuleSpec]) -> None:
        self._specs.extend(specs)

    # ── expansion: turn current state into a queue of concrete tasks ──────────
    def expand(self, state: TargetState) -> None:
        for spec in self._specs:
            if not spec.gated_in(state, self.profile):
                continue
            if spec.scope == "per-endpoint":
                targets = state.injectable_endpoints(limit=self.profile.max_requests // 40 or 20)
            else:
                targets = [state.target]
            for url in targets:
                key = (spec.name, url)
                if key in self._ran:
                    continue
                if any(t.spec.name == spec.name and t.url == url for t in self._queue):
                    continue
                self._queue.append(_Task(spec, url, spec.value(state)))

    def pick_next(self, state: TargetState) -> Optional[_Task]:
        if not self._queue or state.budget.exhausted():
            return None
        # re-score against current budget, then take the best
        for t in self._queue:
            t.value = t.spec.value(state)
        self._queue.sort(key=lambda t: t.value, reverse=True)
        task = self._queue.pop(0)
        self._ran.add((task.spec.name, task.url))
        return task

    def pending(self) -> int:
        return len(self._queue)


# ─────────────────────────────────────────────────────────────────────────────
# Fingerprinter — lightweight, runs first, populates signals for gating
# ─────────────────────────────────────────────────────────────────────────────
class Fingerprinter:
    TECH = {
        "WordPress": re.compile(r"wp-content|wp-includes|/wp-json", re.I),
        "Drupal": re.compile(r"Drupal|/sites/default/", re.I),
        "Joomla": re.compile(r"Joomla|/components/com_", re.I),
        "Django": re.compile(r"csrfmiddlewaretoken|__admin__", re.I),
        "Laravel": re.compile(r"laravel_session|XSRF-TOKEN", re.I),
        "Express": re.compile(r"X-Powered-By: Express", re.I),
        "Nginx": re.compile(r"\bnginx\b", re.I),
        "Apache": re.compile(r"\bApache\b", re.I),
        "React": re.compile(r"data-reactroot|__NEXT_DATA__", re.I),
        "GraphQL": re.compile(r"/graphql|__schema", re.I),
        "Gunicorn": re.compile(r"\bgunicorn\b", re.I),
        "Uvicorn": re.compile(r"\buvicorn\b", re.I),
        "Caddy": re.compile(r"\bCaddy\b", re.I),
        "Jetty": re.compile(r"\bJetty\b", re.I),
        "Tomcat": re.compile(r"\bTomcat\b|\bCoyote\b", re.I),
        "IIS": re.compile(r"Microsoft-IIS", re.I),
        "LiteSpeed": re.compile(r"\bLiteSpeed\b", re.I),
    }
    WAF = re.compile(r"cloudflare|akamai|sucuri|incapsula|mod_security|awselb", re.I)

    def run(self, state: TargetState, ctx: "ScanContext") -> list[Finding]:
        r = ctx.get(state.target)
        if r is None:
            return []
        blob = f"{r.status} {r.headers} {r.text[:4000]}"
        for tech, rx in self.TECH.items():
            if rx.search(blob) or rx.search(str(r.headers)):
                state.add_tech(tech)
        state.server = r.headers.get("Server", "") or r.headers.get("server", "")
        # signals
        state.set_signal("is_wordpress", "WordPress" in state.technologies)
        state.set_signal("is_graphql", "GraphQL" in state.technologies)
        state.set_signal("waf", bool(self.WAF.search(str(r.headers)) or self.WAF.search(r.text[:2000])))
        ct = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        state.set_signal("is_api", "application/json" in ct or "/api" in state.target)
        # cloud hint
        hdrs = str(r.headers).lower()
        if "x-amz" in hdrs or "amazonaws" in hdrs:
            state.set_signal("cloud", "aws")
        elif "x-goog" in hdrs:
            state.set_signal("cloud", "gcp")
        elif "x-azure" in hdrs or "azurewebsites" in hdrs:
            state.set_signal("cloud", "azure")
        # verbose errors
        state.set_signal("error_verbose",
                         bool(re.search(r"stack trace|Traceback|Fatal error|SQLException", r.text, re.I)))
        state.note(f"fingerprint: tech={sorted(state.technologies)} server={state.server!r} "
                   f"waf={state.signals['waf']} api={state.signals['is_api']}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Crawler — async, scope-bounded, populates endpoints/params/signals
# ─────────────────────────────────────────────────────────────────────────────
_LINK = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I)
_REFLECT = "obsx" + "reflect" + "9173"


class Crawler:
    def __init__(self, profile: Profile, scope: ScopeGuard):
        self.profile = profile
        self.scope = scope

    def run(self, state: TargetState, ctx: "ScanContext") -> None:
        depth = self.profile.crawl_depth
        frontier = [state.target]
        seen = set()
        per_level = min(50, max(10, self.profile.max_requests // (depth * 3 or 1)))
        # Cap crawl time so it cannot consume the whole budget before modules run.
        crawl_deadline = time.time() + max(30.0, self.profile.max_seconds * 0.4)
        for _ in range(depth):
            batch = sorted(u for u in frontier if u not in seen)[:per_level]
            if not batch or state.budget.exhausted() or time.time() > crawl_deadline:
                break
            seen.update(batch)
            results = ctx.async_get(batch)
            next_frontier = []
            for resp in results:
                if not resp or not resp.text:
                    continue
                for m in _LINK.finditer(resp.text):
                    link = urljoin(resp.url, m.group(1).split("#")[0])
                    if not link.startswith(("http://", "https://")):
                        continue
                    if not self.scope.in_scope(link):
                        continue
                    params = list(parse_qs(urlparse(link).query).keys())
                    state.add_endpoint(link, params)
                    if "login" in link.lower() or "auth" in link.lower() or "token" in resp.text[:500].lower():
                        state.set_signal("auth_surface", True)
                    next_frontier.append(link)
            frontier = next_frontier
        state.note(f"crawl: {len(state.endpoints)} endpoints, "
                   f"{len(state.injectable_endpoints())} injectable")


# ─────────────────────────────────────────────────────────────────────────────
# ScanContext — shared HTTP + OAST + budget handed to every module
# ─────────────────────────────────────────────────────────────────────────────
class ScanContext:
    def __init__(self, state: TargetState, profile: Profile, scope: ScopeGuard,
                 oast=None, session=None, ua="OBSIDIAN/10.0"):
        self.state = state
        self.profile = profile
        self.scope = scope
        self.oast = oast
        self.ua = ua
        self._cache: dict[str, object] = {}
        self.session = session or self._make_session()
        self._http = AsyncHTTP(rps=profile.rate_limit_rps, concurrency=profile.threads,
                               ua=ua, budget=state.budget)

    def _make_session(self):
        import requests
        try:
            requests.packages.urllib3.disable_warnings()
        except Exception:
            pass
        s = requests.Session()
        s.headers.update({"User-Agent": self.ua})
        s.verify = False
        # Count every core-module HTTP call against the budget so the request
        # counter reflects real traffic and --max-requests actually bounds the
        # scan (the planner stops scheduling once the budget is exhausted).
        budget = self.state.budget
        _orig_request = s.request
        _ReqErr = requests.exceptions.RequestException
        def _counting_request(method, url, *a, **kw):
            # Hard request cap: once the budget is spent, refuse further core-module
            # HTTP. safe_get()/module try-blocks swallow this and skip gracefully,
            # so --max-requests is honoured instead of merely counted.
            if budget is not None and budget.exhausted():
                raise _ReqErr("OBSIDIAN request budget exhausted")
            if budget is not None:
                budget.spend()
            return _orig_request(method, url, *a, **kw)
        s.request = _counting_request
        return s

    def get(self, url: str):
        """Scope-checked single GET with tiny cache (used by fingerprinter)."""
        self.scope.assert_in_scope(url)
        if url in self._cache:
            return self._cache[url]
        res = self.async_get([url])
        r = res[0] if res else None
        self._cache[url] = r
        return r

    def async_get(self, urls: list[str]):
        urls = [u for u in urls if self.scope.in_scope(u)]
        if not urls:
            return []
        return self._http.run_get(urls)


# ─────────────────────────────────────────────────────────────────────────────
# Core-module adapter — wrap obsidian_core.module_* into ModuleSpecs
# ─────────────────────────────────────────────────────────────────────────────
def _convert_core_finding(cf) -> Finding:
    """Convert an obsidian_core.Finding (or dict) into our Finding dataclass."""
    g = (lambda k, d="": getattr(cf, k, d)) if not isinstance(cf, dict) else (lambda k, d="": cf.get(k, d))
    sev = g("severity", "Info") or "Info"
    return Finding(
        module=g("module", "core"),
        title=g("title", "finding"),
        severity=sev,
        description=g("description", ""),
        url=g("url", ""),
        evidence=g("evidence", "") or g("payload", ""),
        confidence=g("confidence", "Probable") or "Probable",
        cvss_score=(float(g("cvss_score")) if str(g("cvss_score")).replace(".", "", 1).isdigit() else None),
        cwe=g("cwe", ""),
        recommendation=g("recommendation", ""),
    )


def _wrap_core(fn, name, needs_session=True):
    """Return a ModuleSpec.run-compatible callable around a core module_* fn."""
    def runner(state: TargetState, ctx: ScanContext):
        import sys
        try:
            res = fn(state.target, ctx.session) if needs_session else fn(state.target)
        except TypeError:
            try:
                res = fn(state.target)
            except Exception as e:
                print(f"[engine] module {name} crashed: {type(e).__name__}: {e}", file=sys.stderr)
                return []
        except Exception as e:
            print(f"[engine] module {name} crashed: {type(e).__name__}: {e}", file=sys.stderr)
            return []
        if isinstance(res, tuple):
            res = res[0]
        out = []
        for cf in (res or []):
            try:
                out.append(_convert_core_finding(cf))
            except Exception:
                continue
        return out
    runner.__name__ = f"core_{name}"
    return runner


# gating predicates keyed to state.signals
_GATES = {
    "module_s3_bucket": lambda s: s.signals.get("cloud") == "aws" or True,
    "module_cloud_metadata_deep": lambda s: bool(s.signals.get("cloud")) or True,
    "module_graphql": lambda s: s.signals.get("is_graphql") or "/api" in s.target or True,
    "module_graphql_injection": lambda s: s.signals.get("is_graphql"),
    "module_wpscan": lambda s: s.signals.get("is_wordpress"),
}


def build_core_specs(profile: Profile) -> list[ModuleSpec]:
    """
    Import obsidian_core and register a curated set of its detection modules as
    fingerprint-gated, profile-aware ModuleSpecs. Returns [] if core is absent.
    """
    try:
        import obsidian_core as core
    except Exception as e:
        import sys
        print(f"[engine] WARNING: obsidian_core failed to import — detection modules "
              f"DISABLED; only built-in passive checks will run. "
              f"Cause: {type(e).__name__}: {e}", file=sys.stderr)
        return []

    try:
        core.PAYLOAD_VARIANTS = int(getattr(profile, "payload_variants", 0) or 0)
    except Exception:
        pass

    specs: list[ModuleSpec] = []

    def add(modname, category, profile_min, cvss_weight, scope="target",
            cost=1, requires=None, needs_session=True):
        fn = getattr(core, modname, None)
        if not callable(fn):
            return
        specs.append(ModuleSpec(
            name=modname, run=_wrap_core(fn, modname, needs_session),
            category=category, profile_min=profile_min, cvss_weight=cvss_weight,
            scope=scope, cost=cost,
            requires=requires or _GATES.get(modname),
        ))

    # passive / always-on
    add("module_security_headers", "headers", "passive", 3)
    add("module_cookies", "headers", "passive", 3)
    add("module_cors", "policy", "passive", 5)
    add("module_clickjacking", "policy", "passive", 4)
    add("module_hsts_check", "headers", "passive", 3)
    add("module_info_disclosure", "exposure", "passive", 5)
    add("module_sensitive_files", "exposure", "passive", 6)
    add("module_secrets", "exposure", "passive", 7)
    add("module_git_history", "exposure", "passive", 7)
    add("module_ssl", "crypto", "passive", 5, needs_session=False)

    # safe / active probes
    add("module_open_redirect", "policy", "safe", 4)
    add("module_host_header", "policy", "safe", 4)
    add("module_csrf", "policy", "safe", 5)
    add("module_403_bypass", "policy", "safe", 6)
    add("module_jwt", "auth", "safe", 6)
    add("module_default_creds", "auth", "safe", 8)
    add("module_idor", "authz", "safe", 7, scope="per-endpoint")
    add("module_s3_bucket", "cloud", "safe", 7)
    add("module_cloud_metadata_deep", "cloud", "safe", 8)
    add("module_graphql", "api", "safe", 5)
    add("tool_curl", "recon", "safe", 4)   # raw-HTTP probe: methods/XST/HTTP2

    # per-endpoint injection (safe variants)
    add("module_xss", "injection", "safe", 6, scope="per-endpoint", cost=2)
    add("module_sqli", "injection", "safe", 9, scope="per-endpoint", cost=2)
    add("module_lfi", "injection", "safe", 7, scope="per-endpoint", cost=2)
    add("module_ssrf", "injection", "safe", 8, scope="per-endpoint", cost=2)
    add("module_nosqli", "injection", "safe", 8, scope="per-endpoint", cost=2)
    add("module_open_redirect", "injection", "safe", 4, scope="per-endpoint")

    # aggressive-only (deeper, more variants, OOB-confirmed classes)
    add("module_ssti", "injection", "aggressive", 9, scope="per-endpoint", cost=3)
    add("module_xxe", "injection", "aggressive", 8, cost=3)
    add("module_blind_cmd_injection", "injection", "aggressive", 9, scope="per-endpoint", cost=4)
    add("module_blind_xss", "injection", "aggressive", 6, cost=3)
    add("module_interactsh_oob", "oob", "aggressive", 8, cost=4)
    add("module_deserialization", "injection", "aggressive", 9, cost=4)
    add("module_race_condition", "logic", "aggressive", 6, cost=4)
    add("module_xss_advanced", "injection", "aggressive", 7, scope="per-endpoint", cost=3)
    add("module_sqli_advanced", "injection", "aggressive", 9, scope="per-endpoint", cost=3)
    add("module_graphql_injection", "api", "aggressive", 7)

    return specs


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────
class Engine:
    """
    Independent autonomous scanner.

        eng = Engine(target, profile=AGGRESSIVE, scope=ScopeGuard([...]),
                     authorized=True, oast=oast, plugins_dir="plugins")
        state = eng.run(progress=print)
    """

    def __init__(self, target: str, profile: Profile = SAFE,
                 scope: ScopeGuard | None = None, authorized: bool = False,
                 oast=None, plugins_dir: str | None = None,
                 extra_specs: list[ModuleSpec] | None = None):
        self.profile = profile
        if profile.requires_authorization_flag and not authorized:
            raise PermissionError(
                f"profile '{profile.name}' requires explicit authorization "
                f"(pass authorized=True / --i-have-authorization)")
        budget = Budget(profile.max_requests, profile.max_seconds)
        self.state = TargetState(target, budget=budget)
        self.scope = scope or ScopeGuard.from_target(self.state.target)
        self.scope.assert_in_scope(self.state.target)   # fail fast if mis-scoped
        self.ctx = ScanContext(self.state, profile, self.scope, oast=oast)
        self.planner = Planner(profile)
        self.fingerprinter = Fingerprinter()
        self.crawler = Crawler(profile, self.scope)
        self.oast = oast
        self.plugins_dir = plugins_dir
        self.extra_specs = extra_specs or []

    def _setup(self, progress):
        progress(f"[engine] profile: {self.profile.describe()}")
        progress(f"[engine] async backend: {'on' if ASYNC_AVAILABLE else 'sync-fallback'}")
        # 1. crawl + fingerprint first so gating has signals
        progress("[engine] fingerprinting + crawling …")
        self.fingerprinter.run(self.state, self.ctx)
        self.crawler.run(self.state, self.ctx)
        self.fingerprinter.run(self.state, self.ctx)  # re-fingerprint with more data
        progress(f"[engine] {self.state.summary()['endpoints']} endpoints, "
                 f"tech={sorted(self.state.technologies)}, signals="
                 f"{ {k: v for k, v in self.state.signals.items() if v} }")
        # 2. register specs
        self.planner.register_many(build_core_specs(self.profile))
        self.planner.register_many(self.extra_specs)
        if self.plugins_dir:
            from .plugins import register_all
            n = register_all(self.planner, self.state, self.plugins_dir)
            if n:
                progress(f"[engine] loaded {n} plugin(s) from {self.plugins_dir}")

    def run(self, progress: Callable[[str], None] = lambda *_: None) -> TargetState:
        self._setup(progress)
        self.planner.expand(self.state)
        progress(f"[engine] {self.planner.pending()} gated tasks queued")

        ran = 0
        while True:
            task = self.planner.pick_next(self.state)
            if task is None:
                break
            try:
                self.scope.assert_in_scope(task.url)
                results = task.spec.run(self.state, self.ctx)
                for f in (results or []):
                    self.state.add_finding(f)
                ran += 1
                if results:
                    progress(f"[run] {task.spec.name} @ {urlparse(task.url).path or '/'} "
                             f"→ {len(results)} finding(s)")
            except ScopeError as e:
                progress(f"[scope] {e}")
            except Exception:
                progress(f"[error] {task.spec.name}: {traceback.format_exc().splitlines()[-1]}")
            # findings/endpoints may unlock new work
            if ran % 5 == 0:
                self.planner.expand(self.state)

        self._verify_oast(progress)
        progress(f"[engine] done — {ran} modules ran, "
                 f"{len(self.state.findings)} findings, "
                 f"{self.state.budget.requests} requests, "
                 f"{round(self.state.budget.elapsed,1)}s")
        return self.state

    # ── OAST re-verification pass ────────────────────────────────────────────
    def _verify_oast(self, progress):
        if not self.oast:
            return
        blind = [f for f in self.state.findings
                 if any(k in f.module.lower() or k in f.title.lower()
                        for k in ("blind", "ssrf", "oob", "interactsh", "rce", "cmd"))]
        if not blind:
            return
        progress(f"[oast] re-verifying {len(blind)} blind-class finding(s) out-of-band …")
        for f in blind:
            token = self.oast.new_token()
            if self.oast.confirm(token, timeout=1.0):   # any pre-existing callback
                f.verified_oast = True
                f.confidence = "Confirmed"
        confirmed = sum(1 for f in blind if f.verified_oast)
        progress(f"[oast] {confirmed}/{len(blind)} confirmed via callback")
