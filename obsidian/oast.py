"""
obsidian.oast — Out-of-band (OAST) verification
===============================================
The single highest-impact zero-FP upgrade: blind SSRF / RCE / XXE / SQLi only
get reported when the target independently calls *back* to a listener we
control. No callback → no finding (kills the bulk of false positives).

Two backends, auto-selected:

* ``LocalOASTListener`` — a tiny HTTP server we stand up locally. Confirms
  callbacks when the target can reach the tester host (internal/SSRF labs,
  same-network engagements, or when ``--oast-public-host`` is supplied).
* ``InteractshOAST``   — if the ``interactsh-client`` binary is installed,
  uses a public collaborator domain for internet-facing targets.

This module only *observes* inbound interactions to confirm a vulnerability.
It does not deliver payloads or maintain any access.
"""
from __future__ import annotations

import http.server
import shutil
import socket
import socketserver
import threading
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class Interaction:
    token: str
    kind: str            # http | dns
    remote: str
    detail: str
    ts: float = field(default_factory=time.time)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "obsidian-oast/1.0"

    def _record(self):
        # path looks like /<token>/...
        token = self.path.strip("/").split("/")[0].split("?")[0]
        if token:
            self.server.record(Interaction(  # type: ignore[attr-defined]
                token=token, kind="http",
                remote=self.client_address[0],
                detail=f"{self.command} {self.path}",
            ))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record

    def log_message(self, *_args):  # silence default logging
        return


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, store_cb):
        super().__init__(addr, _Handler)
        self._store_cb = store_cb

    def record(self, interaction: Interaction):
        self._store_cb(interaction)


class LocalOASTListener:
    """Local HTTP collaborator. Tokens map to payload URLs; callbacks confirm."""

    def __init__(self, bind: str = "0.0.0.0", port: int = 0, public_host: str | None = None):
        self._interactions: dict[str, list[Interaction]] = {}
        self._lock = threading.Lock()
        self._server = _Server((bind, port), self._store)
        self.port = self._server.server_address[1]
        # what the *target* should call back to
        self.public_host = public_host or self._guess_host()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @staticmethod
    def _guess_host() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _store(self, interaction: Interaction):
        with self._lock:
            self._interactions.setdefault(interaction.token, []).append(interaction)

    def start(self) -> "LocalOASTListener":
        self._thread.start()
        return self

    def stop(self):
        try:
            self._server.shutdown()
        except Exception:
            pass

    # ── public API used by modules ──────────────────────────────────────────
    def new_token(self) -> str:
        return uuid.uuid4().hex[:16]

    def payload_url(self, token: str, path: str = "") -> str:
        base = f"http://{self.public_host}:{self.port}/{token}"
        return f"{base}/{path.lstrip('/')}" if path else base

    def payload_host(self, token: str) -> str:
        return f"{self.public_host}:{self.port}"

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return bool(self._interactions.get(token))

    def confirm(self, token: str, timeout: float = 8.0, poll: float = 0.4) -> bool:
        """Block up to ``timeout`` seconds for a callback for ``token``."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.was_hit(token):
                return True
            time.sleep(poll)
        return False

    def interactions(self, token: str) -> list[Interaction]:
        with self._lock:
            return list(self._interactions.get(token, []))


class InteractshOAST:
    """Wrapper around the ``interactsh-client`` binary (public collaborator)."""

    def __init__(self):
        self.bin = shutil.which("interactsh-client")
        self.available = bool(self.bin)
        self._proc = None
        self._domain = None
        self._log = []

    def start(self):
        if not self.available:
            return self
        import subprocess
        try:
            self._proc = subprocess.Popen(
                [self.bin, "-json", "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            # interactsh prints the registered domain on the first lines
            for _ in range(20):
                line = self._proc.stdout.readline()
                if "." in line and "interact" in line.lower():
                    self._domain = line.strip().split()[-1]
                    break
            threading.Thread(target=self._drain, daemon=True).start()
        except Exception:
            self.available = False
        return self

    def _drain(self):
        try:
            for line in self._proc.stdout:
                self._log.append(line)
        except Exception:
            pass

    def new_token(self) -> str:
        return uuid.uuid4().hex[:12]

    def payload_host(self, token: str) -> str:
        return f"{token}.{self._domain}" if self._domain else ""

    def confirm(self, token: str, timeout: float = 12.0, poll: float = 0.6) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(token in entry for entry in self._log):
                return True
            time.sleep(poll)
        return False

    def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass


def build_oast(public_host: str | None = None, prefer_public: bool = False):
    """
    Pick the best available OAST backend.
    prefer_public → try interactsh first (needed for internet-facing blind vulns).
    """
    if prefer_public:
        ish = InteractshOAST().start()
        if ish.available and ish._domain:
            return ish
    return LocalOASTListener(public_host=public_host).start()


class BlindVerifier:
    """
    Helper that turns a 'maybe blind vuln' into a Confirmed/Unconfirmed verdict.

        v = BlindVerifier(oast)
        token = v.token()
        url   = v.callback_url(token)      # embed in your payload
        ...inject the payload via the relevant module...
        if v.confirm(token):               # got a callback → real
            finding.verified_oast = True
            finding.confidence = "Confirmed"
    """

    def __init__(self, oast):
        self.oast = oast

    def token(self) -> str:
        return self.oast.new_token()

    def callback_url(self, token: str, path: str = "") -> str:
        if hasattr(self.oast, "payload_url"):
            return self.oast.payload_url(token, path)
        return f"http://{self.oast.payload_host(token)}/{path}".rstrip("/")

    def callback_host(self, token: str) -> str:
        return self.oast.payload_host(token)

    def confirm(self, token: str, timeout: float = 10.0) -> bool:
        return self.oast.confirm(token, timeout=timeout)
