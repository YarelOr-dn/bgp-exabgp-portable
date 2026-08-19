#!/usr/bin/env python3
"""
bgp_switch.py - Move the SINGLE ExaBGP instance (and the cron watchdog) between
DUTs safely and reversibly.

Why this exists: ExaBGP here is single-instance (one privileged :179 listener +
one global /run/exabgp/exabgp.{in,out} pipe), so you cannot run two sessions at
once. Switching the peering from DUT A to DUT B is therefore a MANAGED SWITCH:
stop the old session (its session file goes `closed`, so the cron watchdog stops
guarding it and follows whatever becomes `active`), then start the new one with
the correct per-device parameters. The switched-FROM DUT peer must also be
admin-disabled on every switch.

Division of labour (keeps DNOS config going through the transactional MCP):
  * This helper executes the EXABGP side (stop old, start new) by reusing the
    tested bgp_tool.py, and moves the watchdog implicitly via session status.
  * It PRINTS the exact DNOS enable/disable deltas for the old and new DUT; apply
    them with dnos_atomic_commit (indented or one-liner - the MCP flattens both).

Usage:
  python3 bgp_switch.py list
  python3 bgp_switch.py plan   --to RR-SA-2
  python3 bgp_switch.py switch --to RR-SA-2 [--execute]

Profiles are the built-in PROFILES below, merged with an optional
~/.bgp_switch_profiles.json (same schema) so new DUTs can be added without
editing this file.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

import session  # noqa: E402  (bgp_tool.py session lib)

BGP_TOOL = str(BASE_DIR / "bgp_tool.py")
PROFILE_OVERRIDE = Path.home() / ".bgp_switch_profiles.json"

# Per-DUT switch profiles. exabgp.* -> bgp_tool.py start args. dnos_enable/
# dnos_disable -> full-path DNOS lines to apply via dnos_atomic_commit on that
# DUT. Validated live 2026-07-09 (rr_evpn <-> RR-SA-2).
PROFILES = {
    "RR-SA-2": {
        "session_id": "rr_evpn",
        "exabgp": {
            "peer_ip": "100.70.0.205",     # RR-SA-2 bundle-100.999 inband
            "peer_as": "1234567",          # RR neighbor per-neighbor local-as (no-prepend)
            "local_as": "65200",           # RR neighbor remote-as
            "local_address": "100.64.11.95",  # host OOB IP (must == RR neighbor addr)
            "families": "l2vpn-evpn",
        },
        "dut": "RR-SA-2",
        "dnos_enable": [
            "interfaces bundle-100.999 admin-state enabled",
            "protocols bgp 123 neighbor 100.64.11.95 remote-as 65200",
            "protocols bgp 123 neighbor 100.64.11.95 admin-state enabled",
            "protocols bgp 123 neighbor 100.64.11.95 ebgp-multihop 10",
            "protocols bgp 123 neighbor 100.64.11.95 update-source bundle-100.999",
            "protocols bgp 123 neighbor 100.64.11.95 local-as 1234567 type no-prepend",
            "protocols bgp 123 neighbor 100.64.11.95 address-family l2vpn-evpn send-community community-type both",
            "protocols bgp 123 neighbor 100.64.11.95 address-family l2vpn-evpn soft-reconfiguration inbound",
        ],
        "dnos_disable": [
            "protocols bgp 123 neighbor 100.64.11.95 admin-state disabled",
            "interfaces bundle-100.999 admin-state disabled",
        ],
    },
}


def load_profiles():
    profiles = dict(PROFILES)
    try:
        if PROFILE_OVERRIDE.exists():
            with open(PROFILE_OVERRIDE) as f:
                profiles.update(json.load(f))
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] could not read {PROFILE_OVERRIDE}: {exc}")
    return profiles


def _session_for(profiles, sid):
    for name, p in profiles.items():
        if p.get("session_id") == sid:
            return name, p
    return None, None


def active_sessions():
    """Return [(session_id, pid)] for sessions whose ExaBGP is alive."""
    out = []
    for s in session.list_sessions():
        pid = s.get("exabgp_pid")
        if s.get("status") == "active" and pid and session.is_process_alive(pid):
            out.append((s.get("session_id"), pid))
    return out


def cmd_list(args):
    profiles = load_profiles()
    print("=== switch profiles ===")
    for name, p in profiles.items():
        e = p["exabgp"]
        print(f"  {name}: session={p['session_id']} peer={e['peer_ip']} "
              f"peer-as={e['peer_as']} local-as={e['local_as']} "
              f"local-addr={e['local_address']} fam={e['families']}")
    print("\n=== live ExaBGP sessions ===")
    act = active_sessions()
    if not act:
        print("  (none active)")
    for sid, pid in act:
        name, _ = _session_for(profiles, sid)
        print(f"  {sid} (PID {pid}) -> profile {name or '?'} [ACTIVE, watchdog-guarded]")


def _dnos_block(lines):
    return "\n".join(lines)


def _print_plan(profiles, target, tp, others):
    e = tp["exabgp"]
    start_cmd = (f"python3 {BGP_TOOL} start --session-id {tp['session_id']} "
                 f"--peer-ip {e['peer_ip']} --peer-as {e['peer_as']} "
                 f"--local-as {e['local_as']} --local-address {e['local_address']} "
                 f"--families {e['families']}")
    print(f"=== SWITCH PLAN -> {target} (session {tp['session_id']}) ===\n")
    step = 1
    for sid, pid in others:
        oname, op = _session_for(profiles, sid)
        print(f"[{step}] STOP old ExaBGP session '{sid}' (PID {pid}) "
              f"-> file goes 'closed', watchdog stops guarding it:")
        print(f"      python3 {BGP_TOOL} stop --session-id {sid} --confirm-kill")
        step += 1
        if op:
            print(f"[{step}] DISABLE switched-from peer on {op['dut']} "
                  f"(apply via dnos_atomic_commit):")
            print("      " + _dnos_block(op["dnos_disable"]).replace("\n", "\n      "))
            step += 1
        else:
            print(f"[{step}] DISABLE switched-from peer for '{sid}' "
                  f"(no profile - admin-down its neighbor + .999 manually).")
            step += 1
    print(f"[{step}] START new ExaBGP session -> file becomes 'active', "
          f"watchdog now guards it:")
    print(f"      {start_cmd}")
    step += 1
    print(f"[{step}] ENABLE new DUT {tp['dut']} .999 + neighbor + AFI "
          f"(apply via dnos_atomic_commit - this makes it connect):")
    print("      " + _dnos_block(tp["dnos_enable"]).replace("\n", "\n      "))
    step += 1
    print(f"[{step}] VERIFY: python3 {BGP_TOOL} verify --session-id {tp['session_id']}")
    print("\n(dnos_atomic_commit config_text for ENABLE, ready to paste:)")
    print("----8<----")
    print(_dnos_block(tp["dnos_enable"]))
    print("---->8----")


def cmd_plan(args):
    profiles = load_profiles()
    tp = profiles.get(args.to)
    if not tp:
        raise SystemExit(f"unknown device '{args.to}'. Known: {', '.join(profiles)}")
    others = [(sid, pid) for sid, pid in active_sessions() if sid != tp["session_id"]]
    _print_plan(profiles, args.to, tp, others)


def cmd_switch(args):
    profiles = load_profiles()
    tp = profiles.get(args.to)
    if not tp:
        raise SystemExit(f"unknown device '{args.to}'. Known: {', '.join(profiles)}")
    target_sid = tp["session_id"]

    act = active_sessions()
    if any(sid == target_sid for sid, _ in act):
        print(f"[OK] session '{target_sid}' ({args.to}) already active. "
              f"Verify: python3 {BGP_TOOL} verify --session-id {target_sid}")
        return
    others = [(sid, pid) for sid, pid in act if sid != target_sid]

    if not args.execute:
        _print_plan(profiles, args.to, tp, others)
        print("\n[DRY-RUN] re-run with --execute to perform the ExaBGP side "
              "(stop old + start new). Apply the DNOS deltas via dnos_atomic_commit.")
        return

    # 1) stop every other live session (watchdog will drop them; --confirm-kill
    #    is authorized because the operator explicitly ran `switch --execute`).
    for sid, pid in others:
        print(f"[*] stopping old session '{sid}' (PID {pid}) ...")
        subprocess.run([sys.executable, BGP_TOOL, "stop",
                        "--session-id", sid, "--confirm-kill"],
                       cwd=str(BASE_DIR))
        oname, op = _session_for(profiles, sid)
        if op:
            print(f"[ACTION-REQUIRED] disable switched-from peer on {op['dut']} "
                  f"via dnos_atomic_commit:\n----8<----\n"
                  f"{_dnos_block(op['dnos_disable'])}\n---->8----")

    # 2) start the target session.
    e = tp["exabgp"]
    print(f"[*] starting new session '{target_sid}' -> {args.to} ...")
    subprocess.run([sys.executable, BGP_TOOL, "start",
                    "--session-id", target_sid,
                    "--peer-ip", e["peer_ip"], "--peer-as", e["peer_as"],
                    "--local-as", e["local_as"], "--local-address", e["local_address"],
                    "--families", e["families"]], cwd=str(BASE_DIR))

    print(f"\n[ACTION-REQUIRED] enable new DUT {tp['dut']} via dnos_atomic_commit "
          f"(this makes it connect):\n----8<----\n"
          f"{_dnos_block(tp['dnos_enable'])}\n---->8----")
    print(f"\n[*] then verify: python3 {BGP_TOOL} verify --session-id {target_sid}")
    print(f"[OK] ExaBGP side switched to {args.to}. Watchdog now guards "
          f"'{target_sid}'.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Switch the single ExaBGP instance between DUTs")
    sub = ap.add_subparsers(dest="command")
    sub.add_parser("list", help="Show profiles + live sessions")
    p_plan = sub.add_parser("plan", help="Print the switch plan (dry-run)")
    p_plan.add_argument("--to", required=True, help="Target device (profile name)")
    p_sw = sub.add_parser("switch", help="Switch to a device")
    p_sw.add_argument("--to", required=True, help="Target device (profile name)")
    p_sw.add_argument("--execute", action="store_true",
                      help="Perform the ExaBGP side (stop old + start new); "
                           "without it, prints the plan only")
    args = ap.parse_args(argv)
    if args.command == "list":
        cmd_list(args)
    elif args.command == "plan":
        cmd_plan(args)
    elif args.command == "switch":
        cmd_switch(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
