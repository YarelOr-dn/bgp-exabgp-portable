"""BGP Port Guard - Server-side iptables protection for port 179.

Problem: When ExaBGP dies, the kernel RSTs every incoming SYN on port 179.
Rapid SYN/RST exchange from PE-4 triggers firewall IDS/rate-limiting, which
then blocks ALL traffic between PE-4 and this server for a cooldown period.

Solution: A permanent DROP rule silently discards SYNs when ExaBGP isn't
running. An ACCEPT rule inserted before it enables traffic when ExaBGP is up.

    iptables chain (top to bottom):
        ACCEPT tcp --dport 179  [only when ExaBGP running]
        DROP   tcp --dport 179  [permanent guard - prevents kernel RST]

Usage:
    import bgp_guard
    bgp_guard.install()          # one-time: add permanent DROP
    bgp_guard.open_port()        # ExaBGP starting: add ACCEPT
    bgp_guard.close_port()       # ExaBGP stopped: remove ACCEPT -> falls back to DROP
    bgp_guard.status()           # check current state
"""

import subprocess
import logging

log = logging.getLogger("bgp_guard")

_ACCEPT_RULE = ["-p", "tcp", "--dport", "179", "-j", "ACCEPT",
                "-m", "comment", "--comment", "bgp_guard_accept"]
_DROP_RULE = ["-p", "tcp", "--dport", "179", "-j", "DROP",
              "-m", "comment", "--comment", "bgp_guard_drop"]


def _ipt(*args, check=False):
    """Run an iptables command with sudo. Returns (returncode, stdout)."""
    cmd = ["sudo", "iptables"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return r.returncode, r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning("iptables command failed: %s", e)
        return 1, str(e)


def _rule_exists(rule_parts):
    """Check if rule exists in INPUT chain."""
    rc, _ = _ipt("-C", "INPUT", *rule_parts)
    return rc == 0


def install():
    """Install the permanent DROP guard rule. Safe to call multiple times."""
    if _rule_exists(_DROP_RULE):
        return True
    rc, _ = _ipt("-A", "INPUT", *_DROP_RULE)
    if rc == 0:
        log.info("Installed permanent DROP guard for port 179")
    else:
        log.error("Failed to install DROP guard rule")
    return rc == 0


def uninstall():
    """Remove both guard rules. Use only for full cleanup."""
    close_port()
    while _rule_exists(_DROP_RULE):
        _ipt("-D", "INPUT", *_DROP_RULE)
    log.info("Uninstalled all guard rules")


def open_port():
    """Allow traffic to port 179 (ExaBGP is running). Inserts ACCEPT before DROP."""
    if _rule_exists(_ACCEPT_RULE):
        return True
    install()
    rc, _ = _ipt("-I", "INPUT", "1", *_ACCEPT_RULE)
    if rc == 0:
        log.info("Port 179 OPEN (ACCEPT rule active)")
    return rc == 0


def close_port():
    """Block traffic to port 179 silently (ExaBGP stopped). Removes ALL port 179
    ACCEPT rules (not just bgp_guard_accept), so the DROP catches everything.
    Stale ACCEPT rules from manual iptables commands would otherwise bypass the guard."""
    removed = False
    while _rule_exists(_ACCEPT_RULE):
        _ipt("-D", "INPUT", *_ACCEPT_RULE)
        removed = True
    stale = _remove_stale_179_accepts()
    if removed or stale:
        log.info("Port 179 CLOSED (guard DROP active - SYNs silently dropped)"
                 + (f", removed {stale} stale ACCEPT rule(s)" if stale else ""))
    return True


def _remove_stale_179_accepts():
    """Remove any non-guard ACCEPT rules for port 179 in INPUT chain.
    These can accumulate from manual iptables commands and bypass the DROP guard."""
    removed = 0
    for _ in range(20):
        rc, out = _ipt("-S", "INPUT")
        if rc != 0:
            break
        found = False
        for line in out.splitlines():
            if "dpt:179" in line and "ACCEPT" in line and "bgp_guard_accept" not in line:
                parts = line.split()
                if parts[0] == "-A" and parts[1] == "INPUT":
                    rule_spec = parts[2:]
                    _ipt("-D", "INPUT", *rule_spec)
                    removed += 1
                    found = True
                    break
        if not found:
            break
    return removed


def status():
    """Return current guard state."""
    has_drop = _rule_exists(_DROP_RULE)
    has_accept = _rule_exists(_ACCEPT_RULE)
    if has_accept:
        mode = "OPEN"
        detail = "ACCEPT active, ExaBGP can receive connections"
    elif has_drop:
        mode = "GUARDED"
        detail = "DROP active, SYNs silently discarded (no RST)"
    else:
        mode = "UNPROTECTED"
        detail = "No guard rules -- kernel will RST incoming SYNs"
    return {
        "mode": mode,
        "drop_rule": has_drop,
        "accept_rule": has_accept,
        "detail": detail,
    }
