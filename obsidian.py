#!/usr/bin/env python3
"""
OBSIDIAN — Autonomous Web & API Security Framework  (v10.0.0 · NIGHT REAPER)
===========================================================================
Independent, self-directing scanner. Crawls, fingerprints, decides which
detection modules are relevant, schedules them by expected value within a
profile budget, and verifies blind-class findings out-of-band.

USAGE
-----
    python3 obsidian.py https://target.tld --profile safe
    python3 obsidian.py https://target.tld --profile aggressive --i-have-authorization
    python3 obsidian.py https://app.tld --scope "*.tld,re:^api[0-9]+\\.tld$" --oast
    python3 obsidian.py https://target.tld --plugins plugins --extra-tools -o report.json

PROFILES
--------
    passive     observe only, no payloads        (safe on prod / recon)
    safe        default; non-destructive probes
    aggressive  deep fuzzing + auth tests         (requires --i-have-authorization)

AUTHORIZED TESTING ONLY. Detection & reporting — no exploitation, no persistence.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from obsidian import Engine, ScopeGuard, get_profile, __version__, __codename__
from obsidian.banner import render as render_banner


def _build_oast(args):
    if not args.oast:
        return None
    from obsidian.oast import build_oast
    return build_oast(public_host=args.oast_public_host, prefer_public=args.oast_public)


def _extra_specs(profile, want_extra):
    if not want_extra:
        return []
    from obsidian.tools_extra import build_extra_specs, available
    avail = available()
    if avail:
        print(f"  [tools] extra scanners available: {', '.join(avail)}")
    else:
        print("  [tools] no extra scanners installed (testssl/retire/gitleaks/wapiti/…) — skipping")
    return build_extra_specs(profile)


def write_report(state, path: str, duration: float) -> str:
    report = {
        "tool": "OBSIDIAN",
        "version": __version__,
        "codename": __codename__,
        "generated": datetime.now().isoformat(),
        "duration_s": round(duration, 2),
        "summary": state.summary(),
        "findings": [f.to_dict() for f in sorted(
            state.findings,
            key=lambda f: {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(f.severity, 0),
            reverse=True)],
        "notes": state.notes,
    }
    Path(path).write_text(json.dumps(report, indent=2))
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="obsidian", add_help=True,
        description="OBSIDIAN — autonomous web & API security scanner (detection only).")
    ap.add_argument("target", nargs="?", help="target URL (e.g. https://example.com)")
    ap.add_argument("--profile", default="safe", choices=["passive", "safe", "aggressive"],
                    help="scan profile (default: safe)")
    ap.add_argument("--scope", default="", help="comma-separated extra scope patterns "
                    "(host, *.host, or re:REGEX). Target host is always in scope.")
    ap.add_argument("--i-have-authorization", dest="authorized", action="store_true",
                    help="required to run the aggressive profile")
    ap.add_argument("--max-requests", type=int, default=0, help="override request budget")
    ap.add_argument("--max-seconds", type=int, default=0, help="override time budget (seconds)")
    ap.add_argument("--oast", action="store_true", help="enable out-of-band verification listener")
    ap.add_argument("--oast-public", action="store_true",
                    help="prefer a public collaborator (interactsh) for internet-facing targets")
    ap.add_argument("--oast-public-host", default=None,
                    help="host/IP the target should call back to (for the local listener)")
    ap.add_argument("--plugins", default=None, help="directory of drop-in plugins")
    ap.add_argument("--extra-tools", action="store_true",
                    help="register extra scanner integrations (testssl/retire/gitleaks/wapiti/…)")
    ap.add_argument("-o", "--output", default=None,
                    help="JSON report path (default: obsidian_report_<timestamp>.json)")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress live progress")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show per-module core logs (default: only the engine progress stream)")
    args = ap.parse_args(argv)
    if not args.output:
        args.output = f"obsidian_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    if not args.no_banner:
        render_banner(__version__, __codename__)

    if not args.target:
        ap.print_help()
        return 2

    # scope
    extra = [p.strip() for p in args.scope.split(",") if p.strip()]
    scope = ScopeGuard.from_target(args.target, extra)

    # profile (+ optional budget override)
    profile = get_profile(args.profile)
    if args.max_requests:
        profile.max_requests = args.max_requests
    if args.max_seconds:
        profile.max_seconds = args.max_seconds

    progress = (lambda *_: None) if args.quiet else (lambda m: print(f"  {m}", flush=True))
    # Single output stream: the engine progress() is the channel. Core modules
    # stay silent unless --verbose, so their timestamped logs do not interleave.
    try:
        import obsidian_core as _core
        _core.QUIET = bool(args.quiet) or not bool(args.verbose)
    except Exception:
        pass

    oast = _build_oast(args)
    if oast:
        progress("[oast] verification listener active")

    try:
        eng = Engine(
            args.target, profile=profile, scope=scope,
            authorized=args.authorized, oast=oast,
            plugins_dir=args.plugins,
            extra_specs=_extra_specs(profile, args.extra_tools),
        )
    except PermissionError as e:
        print(f"\n  [refused] {e}\n")
        return 3
    except Exception as e:
        print(f"\n  [error] could not start engine: {e}\n")
        return 1

    t0 = time.time()
    try:
        state = eng.run(progress=progress)
    except KeyboardInterrupt:
        print("\n  [interrupted] writing partial report …")
        state = eng.state
    finally:
        if oast:
            try:
                oast.stop()
            except Exception:
                pass

    duration = time.time() - t0
    out = write_report(state, args.output, duration)

    s = state.summary()
    print()
    print("  ──────────────────────────────────────────────────────────")
    print(f"  OBSIDIAN scan complete  ·  {s['findings_total']} findings  ·  {round(duration,1)}s")
    by = s["findings_by_severity"]
    if by:
        print("  " + "  ".join(f"{k}:{v}" for k, v in by.items()))
    print(f"  report → {out}")
    print("  ──────────────────────────────────────────────────────────")
    return 0


if __name__ == "__main__":
    sys.exit(main())
