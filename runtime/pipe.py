#!/usr/bin/env python3
"""
pipe.py - ExaBGP named pipe communication

Handles: inject/withdraw via pipe, FlowSpec-VPN flat format conversion.
"""

import re
from pathlib import Path

PIPE_DIR = Path("/run/exabgp")
PIPE_IN = PIPE_DIR / "exabgp.in"
PIPE_OUT = PIPE_DIR / "exabgp.out"


def to_flat_flowspec_vpn(route):
    """Convert match{}/then{} FlowSpec-VPN format to FLAT format for ExaBGP API pipe.

    ExaBGP tokenizer cannot handle section-style blocks when rd is present."""
    if "match {" not in route or "then {" not in route:
        return route  # Already flat or not flowspec-vpn
    m = re.search(r"announce flow route rd ([^ ]+) match \{ ([^}]+) \} then \{ ([^}]+) \}", route)
    if not m:
        return route
    rd, match_inner, then_inner = m.group(1), m.group(2), m.group(3)
    match_flat = match_inner.strip().rstrip(";").replace(";", " ").strip()
    then_flat = then_inner.strip().rstrip(";").replace(";", " ").strip()
    if "extended-community" not in then_flat and "target:" in route:
        rt_m = re.search(r"target:([\d:]+)", route)
        if rt_m:
            then_flat = then_flat + f" extended-community [ target:{rt_m.group(1)} ]"
    return f"announce flow route rd {rd} {match_flat} {then_flat}"


def ensure_pipes():
    """Ensure named pipes exist for ExaBGP communication.
    ExaBGP requires BOTH exabgp.in and exabgp.out to enable the CLI API."""
    import subprocess
    if not PIPE_DIR.exists():
        print(f"Creating pipe directory {PIPE_DIR} (requires sudo)")
        subprocess.run(["sudo", "mkdir", "-p", str(PIPE_DIR)], check=True)

    if not PIPE_IN.exists():
        print(f"Creating named pipe {PIPE_IN}")
        subprocess.run(["sudo", "mkfifo", str(PIPE_IN)], check=False)
    if not PIPE_OUT.exists():
        print(f"Creating named pipe {PIPE_OUT}")
        subprocess.run(["sudo", "mkfifo", str(PIPE_OUT)], check=False)
    subprocess.run(["sudo", "chmod", "666", str(PIPE_IN), str(PIPE_OUT)], check=False)


def write_route(route, log_path=None):
    """Write route to ExaBGP pipe. Converts FlowSpec-VPN to flat format if needed.

    Returns True on success, False on failure.
    """
    import session as session_mod
    if "announce flow route rd" in route and ("match {" in route or "then {" in route):
        route = to_flat_flowspec_vpn(route)
    try:
        with open(PIPE_IN, "w") as f:
            f.write(route + "\n")
            f.flush()
        if log_path:
            session_mod.log("Route written to pipe", log_path)
        return True
    except Exception as e:
        if log_path:
            session_mod.log(f"ERROR writing to pipe: {e}", log_path)
        return False


def write_withdraw(route, log_path=None):
    """Write withdraw to ExaBGP pipe. No format conversion needed."""
    import session as session_mod
    try:
        with open(PIPE_IN, "w") as f:
            f.write(route + "\n")
            f.flush()
        if log_path:
            session_mod.log("Withdraw written to pipe", log_path)
        return True
    except Exception as e:
        if log_path:
            session_mod.log(f"ERROR writing withdraw to pipe: {e}", log_path)
        return False
