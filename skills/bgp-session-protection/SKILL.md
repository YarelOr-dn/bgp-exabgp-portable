---
name: bgp-session-protection
description: "CRITICAL - BGP session protection. Agent must NEVER kill ExaBGP or stop a BGP session unless user explicitly requests it."
---

# BGP Session Protection (ABSOLUTE RULE)

**The agent must NEVER stop, kill, restart, or disrupt a running ExaBGP process or BGP session.**

This rule overrides ALL other considerations. No debugging strategy, config change, feature
implementation, or troubleshooting approach justifies killing a running BGP session.

## What "explicitly requests" means

The user must use one of these EXACT phrases in their CURRENT message:
- `/BGP stop`
- "stop the BGP session" / "stop ExaBGP"
- "kill the BGP session" / "kill ExaBGP"
- "bring down BGP" / "shut down BGP"

If the user's message does NOT contain one of these, the session is UNTOUCHABLE.

## Forbidden actions (unless user explicitly requests stop)

1. `bgp_tool.py stop` -- NEVER run this
2. `kill` / `pkill` / `SIGTERM` / `SIGKILL` on any ExaBGP PID
3. `bgp_tool.py start` when a session is already alive (kills the running one)
4. Modifying `/tmp/exabgp_*.conf` while ExaBGP is running (requires restart to take effect)
5. Modifying `exabgp.env` while ExaBGP is running
6. Any `admin-state disabled` on the device BGP neighbor
7. Any `no neighbor` or neighbor deletion on the device
8. Removing the device's .999 sub-interface or static route
9. Removing the DNAAS bridge-domain AC

## What to do instead

- **Debugging a BGP issue?** Use `bgp_tool.py verify`, `bgp_tool.py diagnose`, `show bgp` on device. Read-only.
- **Need to change ExaBGP config?** Tell the user: "ExaBGP config change requires restart. Run /BGP stop then /BGP PE-4 to re-setup."
- **Session stuck in Connect?** Run `diagnose --fix` (adds iptables rules without touching ExaBGP).
- **FortiGate IDS blocking?** Tell the user the recovery steps. Do NOT kill ExaBGP.
- **Need routes injected/withdrawn?** Use `bgp_tool.py inject` / `withdraw` -- these work on a live session.

## Why this rule exists

The pe_4.log from March 3-4 shows the agent killed ExaBGP **31 times** in 2 days via SIGTERM,
plus 9 SIGKILL events. Each kill dropped the BGP session, triggered FortiGate IDS quarantine,
and made recovery harder. The agent was the #1 cause of BGP session instability.
