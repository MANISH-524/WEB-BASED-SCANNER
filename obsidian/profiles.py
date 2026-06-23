"""
obsidian.profiles — scan profiles + scope enforcement
=====================================================
"Aggressive" is a *profile*, never a removal of safety rails.

    PASSIVE     observe only, no payloads (safe on production / recon)
    SAFE        default; non-destructive active probes
    AGGRESSIVE  deep fuzzing, more payload variants, auth-required tests

Every profile is bounded by a request/time budget and — crucially — by a
``ScopeGuard`` allowlist so the engine *physically cannot* touch a host the
operator has not authorized. No profile ever performs destructive actions
(no data deletion, no flooding/DoS, no persistence).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Profile:
    name: str
    allow_active: bool          # may send probe payloads at all
    allow_aggressive: bool      # deep fuzzing / auth-required / more variants
    crawl_depth: int
    max_requests: int
    max_seconds: int
    threads: int
    rate_limit_rps: float       # global request rate ceiling
    payload_variants: int       # how many payloads per vuln class to try
    requires_authorization_flag: bool = False

    def describe(self) -> str:
        bits = [f"depth={self.crawl_depth}", f"reqs<={self.max_requests}",
                f"rps<={self.rate_limit_rps}", f"variants={self.payload_variants}",
                f"active={self.allow_active}", f"aggressive={self.allow_aggressive}"]
        return f"{self.name.upper()} ({', '.join(bits)})"


PASSIVE = Profile(
    name="passive", allow_active=False, allow_aggressive=False,
    crawl_depth=1, max_requests=400, max_seconds=300, threads=4,
    rate_limit_rps=5.0, payload_variants=0,
)

SAFE = Profile(
    name="safe", allow_active=True, allow_aggressive=False,
    crawl_depth=2, max_requests=2500, max_seconds=900, threads=6,
    rate_limit_rps=10.0, payload_variants=3,
)

AGGRESSIVE = Profile(
    name="aggressive", allow_active=True, allow_aggressive=True,
    crawl_depth=4, max_requests=8000, max_seconds=2400, threads=10,
    rate_limit_rps=20.0, payload_variants=8,
    requires_authorization_flag=True,
)

_PROFILES = {p.name: p for p in (PASSIVE, SAFE, AGGRESSIVE)}


def get_profile(name: str) -> Profile:
    key = (name or "safe").lower()
    if key not in _PROFILES:
        raise ValueError(f"unknown profile '{name}' — choose from {list(_PROFILES)}")
    return _PROFILES[key]


class ScopeError(Exception):
    """Raised when an action targets a host outside the authorized allowlist."""


class ScopeGuard:
    """
    Hard allowlist of in-scope hosts. Anything not matched is refused.

    Patterns accept exact hosts (``app.example.com``), wildcard subdomains
    (``*.example.com``), or full regexes (prefix with ``re:``).
    """

    def __init__(self, patterns: list[str] | None = None, allow_subdomains: bool = True):
        self.allow_subdomains = allow_subdomains
        self._exact: set[str] = set()
        self._suffix: list[str] = []
        self._regex: list[re.Pattern] = []
        for p in (patterns or []):
            self.add(p)

    def add(self, pattern: str) -> None:
        pattern = pattern.strip().lower()
        if not pattern:
            return
        if pattern.startswith("re:"):
            self._regex.append(re.compile(pattern[3:]))
        elif pattern.startswith("*."):
            self._suffix.append(pattern[1:])     # ".example.com"
        else:
            self._exact.add(pattern)
            if self.allow_subdomains:
                self._suffix.append("." + pattern)

    @classmethod
    def from_target(cls, target: str, extra: list[str] | None = None) -> "ScopeGuard":
        host = urlparse(target if "://" in target else "https://" + target).netloc.split(":")[0]
        return cls([host] + (extra or []))

    def host_of(self, url: str) -> str:
        try:
            return urlparse(url if "://" in url else "https://" + url).netloc.split(":")[0].lower()
        except Exception:
            return ""

    def in_scope(self, url: str) -> bool:
        host = self.host_of(url)
        if not host:
            return False
        if host in self._exact:
            return True
        if any(host.endswith(suf) for suf in self._suffix):
            return True
        if any(rx.search(host) for rx in self._regex):
            return True
        return False

    def assert_in_scope(self, url: str) -> None:
        if not self.in_scope(url):
            raise ScopeError(f"out-of-scope target refused: {self.host_of(url)!r}")

    def filter(self, urls: list[str]) -> list[str]:
        return [u for u in urls if self.in_scope(u)]
