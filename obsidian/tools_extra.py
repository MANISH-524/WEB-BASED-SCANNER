"""
obsidian.tools_extra — additional legitimate scanner integrations
=================================================================
Thin, safe wrappers around well-known **open-source detection/recon scanners**.
Each wrapper:

* checks whether the binary is installed (skips cleanly if not),
* runs it with conservative, non-destructive flags,
* parses output into normalized ``Finding`` dicts.

These complement the binaries already wired into ``obsidian_core`` (nuclei,
subfinder, httpx, ffuf, sqlmap, dalfox, nikto, sslyze, gobuster, …). Everything
here is a *scanner*, not post-exploitation tooling.

Note on C2 frameworks (Sliver/Cobalt-Strike/Mythic/etc.): intentionally NOT
included. Those are command-and-control / implant frameworks for maintaining
access — a different category from vulnerability scanning. OBSIDIAN is
detection-and-reporting only.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Callable


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return -1, "", str(e)


def _f(module, title, severity, desc="", url="", evidence="", rec="", confidence="Probable"):
    return {
        "module": module, "title": title, "severity": severity, "description": desc,
        "url": url, "evidence": evidence[:600], "recommendation": rec, "confidence": confidence,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Individual tool wrappers — each (target) -> list[dict]
# ─────────────────────────────────────────────────────────────────────────────
def tool_testssl(target: str) -> list[dict]:
    """testssl.sh — TLS/SSL configuration & vulnerability scanner."""
    binary = "testssl.sh" if _have("testssl.sh") else ("testssl" if _have("testssl") else None)
    if not binary:
        return []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    rc, out, _ = _run([binary, "--quiet", "--color", "0", "--severity", "MEDIUM", host], timeout=420)
    findings = []
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in ("vulnerable", "heartbleed", "robot", "ccs", "weak", "insecure")):
            sev = "High" if "vulnerable" in low else "Medium"
            findings.append(_f("ssl_testssl", "TLS issue (testssl.sh)", sev,
                               evidence=line.strip(), url=target,
                               rec="Update TLS config / disable weak ciphers & protocols."))
    return findings[:25]


def tool_retirejs(target: str) -> list[dict]:
    """retire.js — detect JS libraries with known vulnerabilities."""
    if not _have("retire"):
        return []
    rc, out, err = _run(["retire", "--outputformat", "json", "--js"], timeout=180)
    findings = []
    try:
        data = json.loads(out or err or "{}")
        for entry in (data.get("data") or []):
            for res in entry.get("results", []):
                for vuln in res.get("vulnerabilities", []):
                    sev = (vuln.get("severity") or "medium").capitalize()
                    findings.append(_f(
                        "outdated_js_retirejs",
                        f"Vulnerable JS: {res.get('component')} {res.get('version')}",
                        sev if sev in ("Critical", "High", "Medium", "Low") else "Medium",
                        desc="; ".join(vuln.get("identifiers", {}).get("summary", []) or []),
                        url=target, rec="Upgrade the vulnerable JavaScript dependency."))
    except Exception:
        pass
    return findings[:40]


def tool_gitleaks(target_dir: str = ".") -> list[dict]:
    """gitleaks — secret detection in a checked-out repo (e.g. exposed .git)."""
    if not _have("gitleaks"):
        return []
    rc, out, _ = _run(["gitleaks", "detect", "--no-banner", "--report-format", "json",
                       "--report-path", "/dev/stdout", "-s", target_dir], timeout=240)
    findings = []
    try:
        for leak in json.loads(out or "[]"):
            findings.append(_f("secrets_gitleaks",
                               f"Leaked secret: {leak.get('RuleID', 'secret')}",
                               "High",
                               evidence=f"{leak.get('File','')}:{leak.get('StartLine','')}",
                               rec="Rotate the exposed credential and purge it from history.",
                               confidence="Confirmed"))
    except Exception:
        pass
    return findings[:50]


def tool_wapiti(target: str, workdir: str = ".") -> list[dict]:
    """Wapiti — black-box web application vulnerability scanner."""
    if not _have("wapiti"):
        return []
    out_json = f"{workdir.rstrip('/')}/wapiti_report.json"
    rc, out, _ = _run(["wapiti", "-u", target, "-f", "json", "-o", out_json,
                       "--flush-session", "-m", "common", "--scope", "folder"], timeout=600)
    findings = []
    try:
        with open(out_json) as fh:
            data = json.load(fh)
        for category, items in (data.get("vulnerabilities") or {}).items():
            for it in items:
                lvl = int(it.get("level", 2))
                sev = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(lvl, "Medium")
                findings.append(_f("wapiti", f"Wapiti: {category}", sev,
                                   desc=it.get("info", ""), url=it.get("path", target),
                                   evidence=it.get("http_request", "")[:400]))
    except Exception:
        pass
    return findings[:60]


def tool_dontgo403(target: str) -> list[dict]:
    """dontgo403 — systematic 403/401 access-control bypass checker."""
    binary = "dontgo403" if _have("dontgo403") else ("byp4xx" if _have("byp4xx") else None)
    if not binary:
        return []
    rc, out, _ = _run([binary, "-u", target], timeout=180)
    findings = []
    for line in out.splitlines():
        if "200" in line and ("bypass" in line.lower() or "->" in line):
            findings.append(_f("403_bypass_tool", "403/401 bypass candidate", "High",
                               evidence=line.strip(), url=target,
                               rec="Enforce authorization server-side on every path/verb."))
    return findings[:20]


def tool_jaeles(target: str, workdir: str = ".") -> list[dict]:
    """Jaeles — signature-based web application scanner."""
    if not _have("jaeles"):
        return []
    rc, out, _ = _run(["jaeles", "scan", "-u", target, "--no-db"], timeout=420)
    findings = []
    for line in out.splitlines():
        if "[VULN]" in line or "[Vulnerable]" in line:
            findings.append(_f("jaeles", "Jaeles signature match", "High",
                               evidence=line.strip(), url=target))
    return findings[:40]


# ─────────────────────────────────────────────────────────────────────────────
# Registry + ModuleSpec factory for the engine
# ─────────────────────────────────────────────────────────────────────────────
EXTRA_TOOLS: dict[str, dict] = {
    "testssl":   {"fn": tool_testssl,   "category": "crypto",    "profile_min": "safe",       "cvss": 5},
    "retirejs":  {"fn": tool_retirejs,  "category": "components", "profile_min": "safe",       "cvss": 5},
    "gitleaks":  {"fn": lambda t: tool_gitleaks("."), "category": "exposure", "profile_min": "safe", "cvss": 7},
    "wapiti":    {"fn": tool_wapiti,    "category": "scanner",   "profile_min": "aggressive", "cvss": 7},
    "dontgo403": {"fn": tool_dontgo403, "category": "authz",     "profile_min": "safe",       "cvss": 6},
    "jaeles":    {"fn": tool_jaeles,    "category": "scanner",   "profile_min": "aggressive", "cvss": 7},
}


def available() -> list[str]:
    """Which extra tools are actually installed on this host."""
    bins = {"testssl": ["testssl.sh", "testssl"], "retirejs": ["retire"],
            "gitleaks": ["gitleaks"], "wapiti": ["wapiti"],
            "dontgo403": ["dontgo403", "byp4xx"], "jaeles": ["jaeles"]}
    return [name for name, cands in bins.items() if any(_have(b) for b in cands)]


def build_extra_specs(profile):
    """Return ModuleSpecs for the extra tools (installed ones run; others skip)."""
    from .engine import ModuleSpec

    def wrap(fn):
        def runner(state, ctx):
            try:
                return fn(state.target)
            except Exception:
                return []
        return runner

    specs = []
    for name, meta in EXTRA_TOOLS.items():
        specs.append(ModuleSpec(
            name=f"tool_{name}", run=wrap(meta["fn"]),
            category=meta["category"], profile_min=meta["profile_min"],
            cvss_weight=meta["cvss"], cost=3, scope="target",
        ))
    return specs
