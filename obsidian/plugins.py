"""
obsidian.plugins — drop-in module loader
=========================================
Anything you put in the ``plugins/`` directory is auto-discovered at startup
and registered with the planner. Two supported shapes:

1. A module-level ``PLUGIN`` dict::

       PLUGIN = {
           "name": "my_check",
           "category": "exposure",
           "profile_min": "safe",         # passive | safe | aggressive
           "run": my_callable,            # (state, ctx) -> list[Finding|dict]
           "requires": lambda s: True,    # optional gate predicate
           "cost": 1, "cvss_weight": 5.0, # optional scoring hints
       }

2. A ``register(planner, state)`` function for full control.

Plugins are sandboxed only by convention — load plugins you trust.
"""
from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path


def discover(plugins_dir: str | Path) -> list[dict]:
    """Import every ``*.py`` in ``plugins_dir`` and collect PLUGIN specs / registrars."""
    plugins_dir = Path(plugins_dir)
    found: list[dict] = []
    if not plugins_dir.is_dir():
        return found

    for path in sorted(plugins_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        mod = _import_file(path)
        if mod is None:
            continue
        if hasattr(mod, "PLUGIN") and isinstance(mod.PLUGIN, dict):
            spec = dict(mod.PLUGIN)
            spec.setdefault("name", path.stem)
            spec["_source"] = path.name
            found.append(spec)
        if hasattr(mod, "register") and callable(mod.register):
            found.append({"name": path.stem, "_register": mod.register, "_source": path.name})
    return found


def _import_file(path: Path):
    try:
        modname = f"obsidian_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(modname, path)
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        sys.stderr.write(f"[plugins] failed to load {path.name}:\n{traceback.format_exc()}\n")
        return None


def register_all(planner, state, plugins_dir: str | Path) -> int:
    """Discover + attach plugins to a planner. Returns count registered."""
    from .engine import ModuleSpec
    count = 0
    for spec in discover(plugins_dir):
        if "_register" in spec:
            try:
                spec["_register"](planner, state)
                count += 1
            except Exception:
                sys.stderr.write(f"[plugins] register() failed for {spec.get('_source')}\n")
            continue
        run = spec.get("run")
        if not callable(run):
            continue
        planner.register(ModuleSpec(
            name=spec["name"],
            run=run,
            category=spec.get("category", "plugin"),
            profile_min=spec.get("profile_min", "safe"),
            requires=spec.get("requires"),
            cost=spec.get("cost", 1),
            cvss_weight=spec.get("cvss_weight", 4.0),
            scope="target",
        ))
        count += 1
    return count
