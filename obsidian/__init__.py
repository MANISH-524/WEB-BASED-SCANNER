"""
OBSIDIAN — Autonomous Web & API Security Framework
==================================================
Codename: NIGHT REAPER   |   v10.0.0

This package is the self-directing "brain" layered on top of the existing
detection modules in ``obsidian_core.py``. Instead of running every module in a
fixed order, OBSIDIAN maintains *state* about the target and *decides* what to
do next based on what it has learned.

Public surface
--------------
    from obsidian import Engine, Profile, ScopeGuard, TargetState
    from obsidian.profiles import PASSIVE, SAFE, AGGRESSIVE

Design pillars
--------------
1. Decision engine   — state graph + planner + fingerprint gating (engine.py)
2. OAST verification — out-of-band confirmation of blind vulns   (oast.py)
3. Async core        — high-throughput crawling / probing         (asynccore.py)
4. Plugins + profiles— extensibility + safety rails               (plugins.py / profiles.py)

Authorized testing only. OBSIDIAN performs *detection and reporting*; it does
not weaponize, exploit, or maintain access.
"""

__version__ = "10.1.1"
__codename__ = "NIGHT REAPER"

from .state import TargetState, Finding
from .profiles import Profile, ScopeGuard, PASSIVE, SAFE, AGGRESSIVE, get_profile
from .engine import Engine, ModuleSpec, Planner

__all__ = [
    "Engine", "ModuleSpec", "Planner",
    "TargetState", "Finding",
    "Profile", "ScopeGuard", "get_profile",
    "PASSIVE", "SAFE", "AGGRESSIVE",
    "__version__", "__codename__",
]
