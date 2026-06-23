"""
obsidian.state — the Target State Graph
=======================================
The single object that accumulates everything OBSIDIAN learns about a target.
Every module reads from it and writes back to it; the planner reads it to
decide what to do next. This is what makes the scanner *self-directing*
rather than a fixed for-loop.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse


@dataclass
class Finding:
    """A normalized finding produced by any module/plugin."""
    module: str
    title: str
    severity: str          # Critical | High | Medium | Low | Info
    description: str = ""
    url: str = ""
    evidence: str = ""
    confidence: str = "Probable"   # Confirmed | Probable | Informational
    cvss_score: float | None = None
    cwe: str = ""
    recommendation: str = ""
    verified_oast: bool = False

    def key(self) -> tuple:
        return (self.module, self.title, self.url)

    def to_dict(self) -> dict:
        return {
            "module": self.module, "title": self.title, "severity": self.severity,
            "description": self.description, "url": self.url, "evidence": self.evidence,
            "confidence": self.confidence, "cvss_score": self.cvss_score, "cwe": self.cwe,
            "recommendation": self.recommendation, "verified_oast": self.verified_oast,
        }


class Budget:
    """Tracks request/time consumption so the planner can stop gracefully."""
    def __init__(self, max_requests: int = 5000, max_seconds: int = 1800):
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self._requests = 0
        self._start = time.time()
        self._lock = threading.Lock()

    def spend(self, n: int = 1) -> None:
        with self._lock:
            self._requests += n

    @property
    def requests(self) -> int:
        return self._requests

    @property
    def elapsed(self) -> float:
        return time.time() - self._start

    def exhausted(self) -> bool:
        return self._requests >= self.max_requests or self.elapsed >= self.max_seconds

    def remaining_fraction(self) -> float:
        by_req = 1 - (self._requests / self.max_requests) if self.max_requests else 1
        by_time = 1 - (self.elapsed / self.max_seconds) if self.max_seconds else 1
        return max(0.0, min(by_req, by_time))


class TargetState:
    """
    Mutable, thread-safe knowledge graph for one scan target.

    Modules write what they discover (endpoints, params, technologies,
    behavioral signals, findings). The planner reads ``signals`` and the
    discovered surface to gate and schedule work.
    """

    def __init__(self, target: str, budget: Budget | None = None):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        self.target = target.rstrip("/")
        p = urlparse(self.target)
        self.scheme = p.scheme
        self.host = p.netloc.split(":")[0]

        # discovered attack surface
        self.endpoints: set[str] = {self.target}
        self.params: dict[str, list[str]] = {}     # url -> [param names]
        self.forms: list[dict] = []
        self.subdomains: set[str] = set()
        self.js_endpoints: set[str] = set()

        # fingerprint
        self.technologies: set[str] = set()
        self.server: str = ""

        # behavioral signals the planner reasons over
        self.signals: dict[str, Any] = {
            "waf": False,
            "rate_limited": False,
            "error_verbose": False,
            "is_api": False,
            "is_wordpress": False,
            "is_graphql": False,
            "cloud": None,            # aws | gcp | azure | None
            "auth_surface": False,    # login/forms/tokens seen
            "exposed_git": False,
            "reflects_input": False,
        }

        # accumulated outputs
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self._visited: set[str] = set()
        self.budget = budget or Budget()
        self._lock = threading.RLock()

    # ── discovery ────────────────────────────────────────────────────────────
    def add_endpoint(self, url: str, params: list[str] | None = None) -> None:
        with self._lock:
            self.endpoints.add(url)
            if params:
                existing = set(self.params.get(url, []))
                self.params[url] = sorted(existing | set(params))

    def add_subdomains(self, subs: list[str]) -> None:
        with self._lock:
            self.subdomains.update(s for s in subs if s)

    def set_signal(self, name: str, value: Any) -> None:
        with self._lock:
            self.signals[name] = value

    def add_tech(self, *techs: str) -> None:
        with self._lock:
            self.technologies.update(t for t in techs if t)

    def mark_visited(self, url: str) -> bool:
        """Returns False if already visited (so callers can skip)."""
        with self._lock:
            if url in self._visited:
                return False
            self._visited.add(url)
            return True

    # ── findings ─────────────────────────────────────────────────────────────
    def add_finding(self, f: Finding | dict) -> None:
        with self._lock:
            if isinstance(f, dict):
                f = Finding(**{k: v for k, v in f.items() if k in Finding.__annotations__})
            # de-dup on (module, title, url)
            for existing in self.findings:
                if existing.key() == f.key():
                    # keep the higher-confidence / verified record
                    if f.verified_oast and not existing.verified_oast:
                        self.findings.remove(existing)
                        break
                    return
            self.findings.append(f)

    def note(self, msg: str) -> None:
        with self._lock:
            self.notes.append(msg)

    # ── views the planner uses ───────────────────────────────────────────────
    def injectable_endpoints(self, limit: int = 60) -> list[str]:
        """Endpoints carrying parameters — the high-value injection surface."""
        eps = sorted(u for u in self.endpoints if "=" in u or u in self.params)
        return eps[:limit]

    def summary(self) -> dict:
        sev = {}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {
            "target": self.target,
            "endpoints": len(self.endpoints),
            "subdomains": len(self.subdomains),
            "technologies": sorted(self.technologies),
            "signals": dict(self.signals),
            "findings_total": len(self.findings),
            "findings_by_severity": sev,
            "requests_spent": self.budget.requests,
            "elapsed_s": round(self.budget.elapsed, 1),
        }
