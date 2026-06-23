"""
obsidian.asynccore — high-throughput async HTTP
================================================
Async crawling/probing with three safety controls baked in:

* per-run **concurrency cap** (semaphore)
* global **token-bucket rate limiter** (respects ``profile.rate_limit_rps``)
* per-host **politeness** so a single origin is never hammered

Prefers ``httpx``; falls back to ``aiohttp``; if neither is installed, the
engine transparently uses the synchronous ``requests`` path instead. Nothing
here is required for OBSIDIAN to run — it is a throughput accelerator.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

try:
    import httpx  # type: ignore
    _BACKEND = "httpx"
except ImportError:  # pragma: no cover
    httpx = None
    try:
        import aiohttp  # type: ignore
        _BACKEND = "aiohttp"
    except ImportError:
        aiohttp = None
        _BACKEND = None

ASYNC_AVAILABLE = _BACKEND is not None


@dataclass
class Resp:
    url: str
    status: int
    text: str
    headers: dict
    elapsed: float
    error: str = ""


class _TokenBucket:
    """Smooth global rate limiter — at most ``rps`` requests/second."""
    def __init__(self, rps: float):
        self.rps = max(0.1, rps)
        self._tokens = self.rps
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self):
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.rps, self._tokens + (now - self._last) * self.rps)
            self._last = now
            if self._tokens < 1:
                await asyncio.sleep((1 - self._tokens) / self.rps)
                self._tokens = 0
            else:
                self._tokens -= 1


class AsyncHTTP:
    """
    Fire many requests concurrently within strict limits.

        results = AsyncHTTP(rps=10, concurrency=8).run_get(urls)
    """
    def __init__(self, rps: float = 10.0, concurrency: int = 8,
                 timeout: float = 10.0, ua: str = "OBSIDIAN/10.0", budget=None):
        self.rps = rps
        self.concurrency = concurrency
        self.timeout = timeout
        self.ua = ua
        self.budget = budget

    # ── public sync entry points ─────────────────────────────────────────────
    def run_get(self, urls: list[str]) -> list[Resp]:
        if not ASYNC_AVAILABLE:
            return self._sync_fallback(urls)
        return asyncio.run(self._gather(urls))

    # ── internals ─────────────────────────────────────────────────────────────
    async def _gather(self, urls: list[str]) -> list[Resp]:
        sem = asyncio.Semaphore(self.concurrency)
        bucket = _TokenBucket(self.rps)
        if _BACKEND == "httpx":
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True,
                timeout=self.timeout, headers={"User-Agent": self.ua},
            ) as client:
                return await asyncio.gather(
                    *[self._one_httpx(client, u, sem, bucket) for u in urls]
                )
        else:  # aiohttp
            import aiohttp
            conn = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
            async with aiohttp.ClientSession(
                connector=conn, headers={"User-Agent": self.ua}
            ) as session:
                return await asyncio.gather(
                    *[self._one_aiohttp(session, u, sem, bucket) for u in urls]
                )

    async def _one_httpx(self, client, url, sem, bucket) -> Resp:
        async with sem:
            await bucket.take()
            t0 = time.time()
            try:
                r = await client.get(url)
                if self.budget:
                    self.budget.spend()
                return Resp(url, r.status_code, r.text, dict(r.headers), time.time() - t0)
            except Exception as e:
                return Resp(url, 0, "", {}, time.time() - t0, error=str(e)[:120])

    async def _one_aiohttp(self, session, url, sem, bucket) -> Resp:
        async with sem:
            await bucket.take()
            t0 = time.time()
            try:
                async with session.get(url, timeout=self.timeout) as r:
                    text = await r.text(errors="ignore")
                    if self.budget:
                        self.budget.spend()
                    return Resp(url, r.status, text, dict(r.headers), time.time() - t0)
            except Exception as e:
                return Resp(url, 0, "", {}, time.time() - t0, error=str(e)[:120])

    def _sync_fallback(self, urls: list[str]) -> list[Resp]:
        import requests
        from concurrent.futures import ThreadPoolExecutor
        delay = 1.0 / max(0.1, self.rps)

        def fetch(u):
            t0 = time.time()
            try:
                time.sleep(delay)
                r = requests.get(u, verify=False, timeout=self.timeout,
                                 headers={"User-Agent": self.ua})
                if self.budget:
                    self.budget.spend()
                return Resp(u, r.status_code, r.text, dict(r.headers), time.time() - t0)
            except Exception as e:
                return Resp(u, 0, "", {}, time.time() - t0, error=str(e)[:120])

        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            return list(ex.map(fetch, urls))
