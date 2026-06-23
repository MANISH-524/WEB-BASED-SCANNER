"""
obsidian.banner — standalone banner for the autonomous runner
"""
from __future__ import annotations
import random
import shutil

E = "\033["

class _C:
    PUR = E + "95m"; GRN = E + "92m"; WHT = E + "97m"; RED = E + "91m"
    CYN = E + "96m"; YLW = E + "93m"; BLU = E + "94m"; DIM = E + "2m"
    BLD = E + "1m";  RST = E + "0m";  BG_RED = E + "41m"

LOGO = r"""
   ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗
  ██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║
  ██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║
  ██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║
  ╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║
   ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

TAGLINES = [
    "  ◢◤  IT DECIDES. IT VERIFIES. IT NEVER GUESSES.  ◥◣",
    "  ◢◤  A SCANNER THAT THINKS BEFORE IT KNOCKS.  ◥◣",
    "  ◢◤  OUT-OF-BAND TRUTH. ZERO FALSE CONFESSIONS.  ◥◣",
    "  ◢◤  AUTONOMOUS. ADAPTIVE. ACCOUNTABLE.  ◥◣",
]

def render(version: str = "10.0.0", codename: str = "NIGHT REAPER", color: bool = True):
    c = _C if color else type("X", (), {k: "" for k in vars(_C) if not k.startswith("_")})
    w = min(shutil.get_terminal_size((90, 24)).columns - 2, 80)
    print(f"  {c.PUR}{'━'*w}{c.RST}")
    for i, line in enumerate(LOGO.strip("\n").split("\n")):
        col = (c.PUR + c.BLD) if i % 2 == 0 else (c.CYN + c.BLD)
        print(f"{col}{line}{c.RST}")
    print()
    print(f"  {c.CYN}{c.BLD}  ▸ v{version}  ·  {codename}  ·  Autonomous Decision Engine{c.RST}")
    print(f"  {c.PUR}  ▸ OWASP Web+API Top 10 · MITRE ATT&CK · CVSS v3.1 · OAST-Verified · Profiles{c.RST}")
    print()
    print(f"  {c.DIM}{random.choice(TAGLINES)}{c.RST}")
    print()
    msg = "  ⚠  AUTHORIZED SECURITY TESTING ONLY — STAY IN SCOPE, GET IT IN WRITING  ⚠"
    print(f"  {c.BG_RED}{c.WHT}{c.BLD}{msg[:w]}{c.RST}")
    print(f"  {c.PUR}{'━'*w}{c.RST}")
    print()
