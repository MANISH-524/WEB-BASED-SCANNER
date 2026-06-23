"""
Example OBSIDIAN plugin — security.txt presence check
=====================================================
Drop any file like this into the ``plugins/`` directory and OBSIDIAN
auto-loads it. This one is intentionally tiny: it shows the contract.

Contract:
    PLUGIN = {
        "name": str,
        "category": str,
        "profile_min": "passive" | "safe" | "aggressive",
        "run": callable(state, ctx) -> list[dict|Finding],
        "requires": optional callable(state) -> bool,   # gating predicate
        "cost": int, "cvss_weight": float,               # scheduling hints
    }
"""
from urllib.parse import urljoin


def check_security_txt(state, ctx):
    """A11y-style passive check: is /.well-known/security.txt published?"""
    findings = []
    for path in ("/.well-known/security.txt", "/security.txt"):
        url = urljoin(state.target + "/", path.lstrip("/"))
        res = ctx.async_get([url])
        r = res[0] if res else None
        if r and r.status == 200 and "contact" in r.text.lower():
            state.note("security.txt present")
            return []   # present = good, nothing to report
    findings.append({
        "module": "plugin_security_txt",
        "title": "Missing security.txt",
        "severity": "Info",
        "description": "No /.well-known/security.txt found. Publishing one gives "
                       "researchers a clear, authorized disclosure channel.",
        "url": state.target,
        "confidence": "Confirmed",
        "recommendation": "Publish /.well-known/security.txt per RFC 9116.",
    })
    return findings


PLUGIN = {
    "name": "security_txt",
    "category": "exposure",
    "profile_min": "passive",
    "run": check_security_txt,
    "cost": 1,
    "cvss_weight": 1.5,
}
