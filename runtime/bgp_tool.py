#!/usr/bin/env python3
"""
bgp_tool.py - ExaBGP Lifecycle Manager for BGP Peering Tool

CLI entry point. Delegates to session, pipe, config_gen modules.

Commands:
    start     - Start ExaBGP with a config, register session
    stop      - Graceful stop of ExaBGP session
    status    - Check session status (process alive, BGP state)
    inject    - Inject a route via named pipe
    withdraw  - Withdraw a route via named pipe
    list      - List all sessions
    cleanup   - Emergency cleanup of orphaned sessions
    verify    - Quick health check: ExaBGP alive + TCP state
    diagnose  - Check BgpTrius iptables on device, optionally fix

Usage:
    python3 bgp_tool.py start --config <path> --session-id <id> [--peer-ip <ip>]
    python3 bgp_tool.py stop --session-id <id>
    python3 bgp_tool.py inject --session-id <id> --route "<exabgp_route_string>"
    python3 bgp_tool.py diagnose --session-id <id> [--fix]
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import config_gen
import pipe
import route_parser
import session

# Backends and malform for extended commands
from backends import exabgp as exabgp_backend
from backends import gobgp as gobgp_backend
from backends import scapy_tcp
import malform
from builders import BUILDERS
from attributes import ATTRIBUTE_TESTS
import bgp_guard

BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
DEVICE_DEFAULT_IP = config_gen.DEVICE_DEFAULT_IP
EXABGP_DEFAULT_IP = config_gen.EXABGP_DEFAULT_IP

# How long cmd_start actively polls for the BGP TCP session to reach
# ESTABLISHED before reinjecting saved routes. The old code blind-slept 6s and
# reinjected regardless of FSM state; if the peer is in idle-hold/connect-retry
# backoff (e.g. after a prior OPEN error) establishment takes far longer, so a
# fixed sleep both loses routes and hides the real delay from the operator.
DEFAULT_ESTABLISH_TIMEOUT = 60
ESTABLISH_POLL_INTERVAL = 2


def _extract_peer_ip_from_config(config_path):
    """Parse ExaBGP config to find the actual neighbor IP address."""
    import re
    try:
        with open(config_path) as f:
            for line in f:
                m = re.match(r'\s*neighbor\s+(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    return m.group(1)
    except (FileNotFoundError, PermissionError):
        pass
    return None


def cmd_start(args):
    """Start ExaBGP session. ExaBGP runs indefinitely until /BGP stop."""
    session_id = args.session_id
    log_path = session.setup_log(session_id)

    existing = session.load_session(session_id)
    if existing and existing.get("status") == "active":
        pid = existing.get("exabgp_pid")
        if pid and session.is_process_alive(pid):
            session.log(f"Session {session_id} already active (PID {pid}). ExaBGP runs until /BGP stop.", log_path)
            print(json.dumps(existing, indent=2))
            return

    for s in session.list_sessions():
        other_pid = s.get("exabgp_pid")
        if s.get("session_id") != session_id and s.get("status") == "active" and other_pid and session.is_process_alive(other_pid):
            session.log(f"[WARN] Another session '{s['session_id']}' has live ExaBGP (PID {other_pid}). "
                        f"Will NOT kill it. If you need to switch devices, run '/BGP stop' on the other session first.", log_path)
            print(json.dumps({
                "error": f"Another session '{s['session_id']}' has live ExaBGP (PID {other_pid}). "
                         f"Stop it first with: bgp_tool.py stop --session-id {s['session_id']} --confirm-kill",
                "blocking_session": s["session_id"],
                "blocking_pid": other_pid
            }, indent=2))
            return

    orphans_killed = session.kill_orphan_exabgp_processes(spare_pid=os.getpid(), log_path=log_path)
    if orphans_killed:
        session.log(f"Pre-start cleanup: killed {orphans_killed} orphan(s)", log_path)

    if args.config:
        config_path = args.config
    elif args.peer_ip and args.peer_as:
        families = args.families.split(",") if args.families else None
        local_addr = getattr(args, "local_address", None) or "100.64.6.134"
        config_path = config_gen.generate_config(
            session_id, args.peer_ip, int(args.peer_as),
            local_as=int(args.local_as) if args.local_as else 65200,
            local_address=local_addr,
            families=families,
            hold_time=int(args.hold_time) if args.hold_time else 600,
            ebgp_multihop=int(args.multihop) if args.multihop else 10,
        )
        session.log(f"Generated config at {config_path}", log_path)
    else:
        print("ERROR: Provide --config <path> or --peer-ip + --peer-as")
        sys.exit(1)

    pipe.ensure_pipes()

    bgp_guard.open_port()
    session.log(f"Port 179 guard: OPEN (ACCEPT active)", log_path)

    session.log(f"Starting ExaBGP with config: {config_path}", log_path)
    pid, exabgp_log = exabgp_backend.start_exabgp(config_path, session_id, log_path)

    session.log(f"ExaBGP started with PID {pid}", log_path)

    selected_afis = []
    if getattr(args, "selected_afis", None):
        selected_afis = [s.strip() for s in args.selected_afis.split(",") if s.strip()]
    elif args.families:
        selected_afis = [s.strip() for s in args.families.split(",") if s.strip()]

    prev_session = session.load_session(session_id)
    prev_routes = prev_session.get("injected_routes", []) if prev_session else []
    injected_routes = [r.get("route", r) if isinstance(r, dict) else r for r in prev_routes]
    prev_scale = prev_session.get("scale_injections", []) if prev_session else []

    route_entries = [{"route": r, "injected_at": session.now_iso()} for r in injected_routes]

    config_peer_ip = _extract_peer_ip_from_config(config_path)

    session_data = {
        "session_id": session_id,
        "status": "active",
        "created": session.now_iso(),
        "exabgp_pid": pid,
        "exabgp_config": config_path,
        "exabgp_log": str(exabgp_log),
        "peer_ip": config_peer_ip or args.peer_ip or "unknown",
        "peer_as": args.peer_as or "unknown",
        "exabgp_ip": EXABGP_DEFAULT_IP,
        "device_ip": config_peer_ip or getattr(args, "device_ip", None) or args.peer_ip or DEVICE_DEFAULT_IP,
        "selected_afis": selected_afis,
        "target_device": getattr(args, "target_device", None),
        "dnaas_leaf": getattr(args, "dnaas_leaf", None),
        "applied_configs": {},
        "injected_routes": route_entries,
        "scale_injections": prev_scale,
    }

    all_entries = list(route_entries)
    for si in prev_scale:
        builder = BUILDERS.get(si.get("builder"))
        if builder:
            scale_routes = builder(**si["params"])
            for r in scale_routes[:si.get("injected_count", len(scale_routes))]:
                all_entries.append({"route": r, "injected_at": si.get("injected_at")})

    adv_state = route_parser.build_advertised_state(all_entries, session_data)
    adv_state["routes"] = adv_state.get("routes", [])[:10]
    session_data["advertised_state"] = adv_state
    session_data["routes_injected"] = len(all_entries)
    session.save_session(session_id, session_data)

    time.sleep(2)
    if not session.is_process_alive(pid):
        session.log(f"WARNING: ExaBGP process died immediately. Check {exabgp_log}", log_path)
        bgp_guard.close_port()
        session.log("Port 179 guard: CLOSED (ExaBGP dead, SYNs silently dropped)", log_path)
        session_data["status"] = "error"
        session_data["error_detail"] = f"ExaBGP died on start. See {exabgp_log}"
        session.save_session(session_id, session_data)
        print(json.dumps(session_data, indent=2))
        return

    session.log(f"ExaBGP running (PID {pid}). Session {session_id} active.", log_path)

    # Actively wait for the BGP TCP session to reach ESTABLISHED before
    # reinjecting saved routes (was a blind 6s sleep). This makes start report
    # the true time-to-establish and warn immediately when the peer never
    # comes up (idle-hold backoff, or OPEN rejected due to local-as/peer-as
    # mismatch) instead of silently returning "active" with routes pushed into
    # a down session.
    establish_timeout = int(getattr(args, "establish_timeout", None) or DEFAULT_ESTABLISH_TIMEOUT)
    if injected_routes or prev_scale:
        session.log(f"Waiting up to {establish_timeout}s for BGP to reach ESTABLISHED...", log_path)
    established, tcp_state, waited_sec = _wait_for_establish(pid, establish_timeout, log_path)
    session_data["tcp_state"] = tcp_state
    session_data["established"] = established
    session_data["establish_wait_sec"] = round(waited_sec, 1)
    if established:
        session.log(f"BGP TCP ESTABLISHED after {waited_sec:.1f}s.", log_path)
    else:
        session.log(
            f"[WARN] BGP not ESTABLISHED after {waited_sec:.1f}s (tcp_state={tcp_state}). "
            f"Peer may be in idle-hold/connect-retry backoff, or the OPEN was rejected "
            f"(verify local-as {args.local_as or '?'} vs device neighbor remote-as; "
            f"run 'bgp_tool.py diagnose --session-id {session_id}'). "
            f"Reinjecting saved routes anyway; ExaBGP will send them once established.",
            log_path,
        )
    session.save_session(session_id, session_data)

    if injected_routes:
        session.log(f"Reinjecting {len(injected_routes)} manual route(s)...", log_path)
        for route in injected_routes:
            if pipe.write_route(route, log_path):
                session.log(f"Reinjected: {route[:60]}...", log_path)
            else:
                session.log(f"Reinject failed: {route[:60]}...", log_path)

    if prev_scale:
        from builders.scale import inject_batch_fast
        for si in prev_scale:
            builder = BUILDERS.get(si.get("builder"))
            if builder:
                scale_routes = builder(**si["params"])
                count = si.get("injected_count", len(scale_routes))
                session.log(f"Reinjecting scale {si['mode']}: {count} routes...", log_path)
                result = inject_batch_fast(scale_routes[:count], log_path=log_path)
                session.log(f"Scale reinject done: {result['injected']}/{count} in {result['elapsed_sec']}s", log_path)

    print(json.dumps(session_data, indent=2))


def cmd_stop(args):
    """Stop ExaBGP session. Requires --confirm-kill when session is alive."""
    session_id = args.session_id
    log_path = session.setup_log(session_id)
    session_data = session.load_session(session_id)

    if not session_data:
        session.log(f"No session found: {session_id}", log_path)
        return

    pid = session_data.get("exabgp_pid")
    is_alive = pid and session.is_process_alive(pid)
    if is_alive and not getattr(args, "confirm_kill", False):
        print(json.dumps({
            "error": "REFUSED: ExaBGP is ALIVE (PID " + str(pid) + "). "
                     "Stopping will drop the BGP session. "
                     "Add --confirm-kill if user explicitly requested stop.",
            "session_id": session_id,
            "exabgp_pid": pid,
            "tcp_state": _check_tcp_state(pid) or "UNKNOWN",
            "hint": "Only use --confirm-kill when user said '/BGP stop' or 'stop/kill BGP'"
        }, indent=2))
        return

    pid = session_data.get("exabgp_pid")
    if pid and session.is_process_alive(pid):
        session.log(f"Sending SIGTERM to ExaBGP process group (PID {pid})", log_path)
        exabgp_backend.stop_exabgp(pid)
        if not session.is_process_alive(pid):
            session.log("ExaBGP stopped gracefully", log_path)
        else:
            session.log("ExaBGP did not stop in 5s, sent SIGKILL", log_path)
    else:
        session.log(f"ExaBGP not running (PID {pid})", log_path)

    orphans = session.kill_orphan_exabgp_processes(spare_pid=os.getpid(), log_path=log_path)
    if orphans:
        session.log(f"Post-stop sweep: killed {orphans} leftover process(es)", log_path)

    any_other_active = False
    for s in session.list_sessions():
        if s.get("session_id") != session_id and s.get("exabgp_alive"):
            any_other_active = True
            break
    if not any_other_active:
        bgp_guard.close_port()
        session.log("Port 179 guard: CLOSED (no active sessions, SYNs silently dropped)", log_path)

    session_data["status"] = "closed"
    session_data["closed_at"] = session.now_iso()
    session.save_session(session_id, session_data)
    session.log(f"Session {session_id} closed", log_path)
    print(json.dumps(session_data, indent=2))


def cmd_status(args):
    """Check session status with full advertised_state knowledge."""
    session_id = args.session_id
    session_data = session.load_session(session_id)

    if not session_data:
        print(json.dumps({"error": f"No session found: {session_id}"}))
        return

    pid = session_data.get("exabgp_pid")
    alive = session.is_process_alive(pid) if pid else False

    injected = session_data.get("injected_routes", [])

    adv_state = session_data.get("advertised_state")
    if not adv_state and injected:
        adv_state = route_parser.build_advertised_state(injected, session_data)
        session_data["advertised_state"] = adv_state
        session.save_session(session_id, session_data)

    status = {
        "session_id": session_id,
        "status": session_data.get("status"),
        "exabgp_pid": pid,
        "exabgp_alive": alive,
        "peer_ip": session_data.get("peer_ip"),
        "device_ip": session_data.get("device_ip"),
        "target_device": session_data.get("target_device"),
        "dnaas_leaf": session_data.get("dnaas_leaf"),
        "selected_afis": session_data.get("selected_afis", []),
        "injected_routes_count": session_data.get("routes_injected",
            len(injected) + sum(s.get("injected_count", 0) for s in session_data.get("scale_injections", []))
        ),
        "scale_injections": len(session_data.get("scale_injections", [])),
        "created": session_data.get("created"),
    }

    if adv_state:
        status["advertised_state"] = {
            "summary": adv_state.get("summary", {}),
            "capabilities": adv_state.get("capabilities", {}),
        }

    exabgp_log = session_data.get("exabgp_log")
    if exabgp_log and Path(exabgp_log).exists():
        try:
            with open(exabgp_log) as f:
                lines = f.readlines()
                last_lines = lines[-20:] if len(lines) > 20 else lines
                for line in reversed(last_lines):
                    if "ESTABLISHED" in line.upper() or "state" in line.lower():
                        status["bgp_state_hint"] = line.strip()
                        break
                status["last_log_lines"] = [l.strip() for l in last_lines[-5:]]
        except Exception:
            pass

    print(json.dumps(status, indent=2))


KNOWN_UNSUPPORTED_COMBINATIONS = [
    {
        "actions": {"redirect-ip", "redirect-to-rt"},
        "bug": "SW-206876",
        "syslog": "BGP_FLOWSPEC_UNSUPPORTED_RULE",
        "detail": "DNOS cannot combine redirect-ip (Simpson) + redirect-to-rt in single FlowSpec rule",
    },
]


def _check_known_unsupported(actions: dict) -> dict | None:
    """Pre-check if action combination is known-unsupported by DNOS."""
    action_keys = set(actions.keys()) - {"rate-limit", "discard"}
    for combo in KNOWN_UNSUPPORTED_COMBINATIONS:
        if combo["actions"].issubset(action_keys):
            return combo
    return None


def _check_flowspec_syslog(session_data: dict, log_path: str) -> str | None:
    """SSH to device, enable 'set logging terminal', wait for FLOWSPEC syslog.

    Returns the syslog message if BGP_FLOWSPEC_UNSUPPORTED_RULE detected, else None.
    DNOS has no 'show logging' command -- must use 'set logging terminal' for real-time
    capture or SSH to Linux shell for /var/log/syslog.
    """
    try:
        import paramiko
    except ImportError:
        return None

    peer_ip = session_data.get("peer_ip") or session_data.get("device_ip")
    if not peer_ip:
        return None

    ncc_cache_path = os.path.expanduser("~/.cursor/bgp-reference/active_ncc.json")
    ssh_host = peer_ip
    ssh_user = "dnroot"
    ssh_pass = "dnroot"

    if os.path.exists(ncc_cache_path):
        try:
            with open(ncc_cache_path) as f:
                ncc = json.load(f)
            if ncc.get("hostname"):
                ssh_host = ncc["hostname"]
        except Exception:
            pass

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ssh_host, username=ssh_user, password=ssh_pass, timeout=8)
        chan = client.invoke_shell()
        time.sleep(1)
        chan.recv(4096)

        chan.send("set logging terminal\n")
        time.sleep(0.5)
        chan.recv(4096)

        time.sleep(5)

        output = ""
        while chan.recv_ready():
            output += chan.recv(8192).decode("utf-8", errors="replace")

        chan.send("unset logging terminal\n")
        time.sleep(0.3)
        chan.close()
        client.close()

        for line in output.split("\n"):
            if "FLOWSPEC_UNSUPPORTED_RULE" in line:
                session.log(f"[SYSLOG] {line.strip()}", log_path)
                return line.strip()

        return None
    except Exception as e:
        session.log(f"Syslog check failed: {e}", log_path)
        return None


def cmd_inject(args):
    """Inject a route via named pipe. Parses and tracks structured state."""
    session_id = args.session_id
    route = args.route
    log_path = session.setup_log(session_id)

    session_data = session.load_session(session_id)
    if not session_data:
        print(f"ERROR: No session found: {session_id}")
        sys.exit(1)

    if session_data.get("status") != "active":
        print(f"ERROR: Session {session_id} is not active (status: {session_data.get('status')})")
        sys.exit(1)

    if not route.startswith("announce"):
        route = f"announce {route}"

    pre_parsed = route_parser.parse_route(route)
    pre_actions = pre_parsed.get("actions", {})
    unsupported = _check_known_unsupported(pre_actions)

    session.log(f"Injecting route: {route}", log_path)

    try:
        if not pipe.write_route(route, log_path):
            raise RuntimeError("Failed to write route to ExaBGP pipe")

        ts = session.now_iso()
        if "injected_routes" not in session_data:
            session_data["injected_routes"] = []
        session_data["injected_routes"].append({
            "route": route,
            "injected_at": ts,
        })

        if "advertised_state" not in session_data:
            session_data["advertised_state"] = route_parser.build_advertised_state(
                session_data["injected_routes"], session_data
            )
        else:
            route_parser.update_state_on_inject(
                session_data["advertised_state"], route, injected_at=ts
            )

        session.save_session(session_id, session_data)

        parsed = route_parser.parse_route(route)
        result = {
            "status": "injected",
            "route": route,
            "parsed": {
                "type": parsed.get("type"),
                "afi_safi": parsed.get("afi_safi"),
                "destination": parsed.get("match", {}).get("destination") or parsed.get("prefix"),
                "rd": parsed.get("rd"),
                "route_targets": parsed.get("route_targets", []),
                "actions": parsed.get("actions", {}),
            },
        }

        if unsupported:
            result["warning"] = (
                f"[{unsupported['bug']}] Known unsupported combination: "
                f"{unsupported['detail']}. PfxAccepted may show 1 but rule "
                f"will NOT be programmed in hardware. Check device syslog for "
                f"{unsupported['syslog']}."
            )
            session.log(f"[WARN] {result['warning']}", log_path)

        is_flowspec = parsed.get("type", "").startswith("flowspec")
        if is_flowspec and not getattr(args, "skip_syslog", False):
            syslog_msg = _check_flowspec_syslog(session_data, log_path)
            if syslog_msg:
                result["syslog_rejection"] = syslog_msg
                result["status"] = "injected_but_rejected"
                session.log(f"[SYSLOG REJECTION] {syslog_msg}", log_path)

        if is_flowspec and not unsupported:
            result["verify_hint"] = (
                "Use /SPIRENT stream to send traffic matching this FlowSpec rule "
                "and verify data-plane forwarding."
            )

        print(json.dumps(result))
    except Exception as e:
        session.log(f"ERROR injecting route: {e}", log_path)
        print(json.dumps({"status": "error", "error": str(e)}))
        sys.exit(1)


def _build_vpls_pw_cmd(action, rd, ve_id, base, offset, size, next_hop, rt,
                        control_word=True, fat_label=False, mtu=0):
    """Build ExaBGP announce/withdraw vpls-pw command string.

    L2Info Extended Community (RFC 4761) control byte mapping for DNOS:
      bit 1 (0x02) = control-word (C)
      bit 2 (0x04) = FAT-label-receive (Fr)
      bit 3 (0x08) = FAT-label-send (Fs)
    """
    control_byte = 0
    if control_word:
        control_byte |= 0x02
    if fat_label:
        control_byte |= 0x0C
    l2info_hex = f"0x800A13{control_byte:02X}{mtu:04X}0000"

    ec_list = [f"target:{rt}", l2info_hex]
    ec_str = "[ " + " ".join(ec_list) + " ]"

    return (
        f"{action} vpls-pw rd {rd} endpoint {ve_id} base {base} "
        f"offset {offset} size {size} next-hop {next_hop} "
        f"extended-community {ec_str}"
    )


def cmd_vpls(args):
    """Inject or withdraw a VPLS pseudowire route."""
    session_id = args.session_id
    log_path = session.setup_log(session_id)

    session_data = session.load_session(session_id)
    if not session_data:
        print(f"ERROR: No session found: {session_id}")
        sys.exit(1)

    action = "withdraw" if args.withdraw else "announce"
    route = _build_vpls_pw_cmd(
        action=action,
        rd=args.rd,
        ve_id=args.ve_id,
        base=args.base,
        offset=args.offset,
        size=args.size,
        next_hop=args.next_hop,
        rt=args.rt,
        control_word=not args.no_control_word,
        fat_label=args.fat_label,
        mtu=args.mtu,
    )

    session.log(f"VPLS {action}: {route}", log_path)

    if not pipe.write_route(route, log_path):
        print(json.dumps({"status": "error", "error": "Failed to write to ExaBGP pipe"}))
        sys.exit(1)

    ts = session.now_iso()
    if action == "announce":
        if "injected_routes" not in session_data:
            session_data["injected_routes"] = []
        session_data["injected_routes"].append({"route": route, "injected_at": ts})
    else:
        announce_form = route.replace("withdraw", "announce", 1)
        session_data["injected_routes"] = [
            r for r in session_data.get("injected_routes", [])
            if (r.get("route", r) if isinstance(r, dict) else r) != announce_form
        ]

    session.save_session(session_id, session_data)
    print(json.dumps({
        "status": "ok",
        "action": action,
        "route": route,
        "vpls": {
            "rd": args.rd,
            "ve_id": args.ve_id,
            "base": args.base,
            "offset": args.offset,
            "size": args.size,
            "next_hop": args.next_hop,
            "rt": args.rt,
        },
    }))


def cmd_withdraw(args):
    """Withdraw route(s) via named pipe. Supports --route, --last, or --all."""
    session_id = args.session_id
    log_path = session.setup_log(session_id)

    session_data = session.load_session(session_id)
    if not session_data:
        print(f"ERROR: No session found: {session_id}")
        sys.exit(1)

    injected = session_data.get("injected_routes", [])

    if args.all:
        routes_to_withdraw = [
            (r.get("route", r) if isinstance(r, dict) else r)
            for r in injected
        ]
        if not routes_to_withdraw:
            print(json.dumps({"status": "nothing", "message": "No injected routes to withdraw"}))
            return
    elif args.last:
        n = args.last
        if not injected:
            print(json.dumps({"status": "nothing", "message": "No injected routes to withdraw"}))
            return
        routes_to_withdraw = [
            (r.get("route", r) if isinstance(r, dict) else r)
            for r in injected[-n:]
        ]
    elif args.route:
        routes_to_withdraw = [args.route]
    else:
        print("ERROR: Provide --route, --last N, or --all")
        sys.exit(1)

    withdrawn = []
    for route in routes_to_withdraw:
        if not route.startswith("withdraw"):
            if route.startswith("announce"):
                route = route.replace("announce", "withdraw", 1)
            else:
                route = f"withdraw {route}"

        session.log(f"Withdrawing route: {route}", log_path)
        try:
            pipe.write_withdraw(route, log_path)
            withdrawn.append(route)

            if "advertised_state" in session_data:
                route_parser.update_state_on_withdraw(
                    session_data["advertised_state"], route
                )
            time.sleep(0.05)
        except Exception as e:
            session.log(f"ERROR withdrawing route: {e}", log_path)

    if args.all:
        session_data["injected_routes"] = []
    elif args.last:
        session_data["injected_routes"] = injected[:-args.last]
    else:
        announce_form = withdrawn[0].replace("withdraw", "announce", 1) if withdrawn else ""
        session_data["injected_routes"] = [
            r for r in injected
            if (r.get("route", r) if isinstance(r, dict) else r) != announce_form
        ]

    session.save_session(session_id, session_data)
    print(json.dumps({
        "status": "withdrawn",
        "count": len(withdrawn),
        "routes": withdrawn,
        "remaining": len(session_data["injected_routes"]),
    }))


def cmd_list(args):
    """List all sessions."""
    sessions = session.list_sessions()
    print(json.dumps({"sessions": sessions, "count": len(sessions)}, indent=2))


def cmd_malform(args):
    """Send malformed BGP message via raw TCP."""
    try:
        msg_bytes = malform.build(args.type, rd=getattr(args, "rd", None))
    except ValueError as e:
        print(json.dumps({"success": False, "error": str(e)}))
        sys.exit(1)
    result = malform.sender.send_malformed(
        args.target_ip, 179, msg_bytes,
        local_as=args.local_as, peer_as=args.peer_as,
    )
    result["malform_type"] = args.type
    result["message_size"] = len(msg_bytes)
    print(json.dumps(result, indent=2))


def cmd_hexdump(args):
    """Hexdump Simpson redirect-ip UPDATE bytes."""
    builder = scapy_tcp.SimpsonRedirectBuilder()
    update = builder.build_update(
        rd=args.rd, redirect_ip=args.redirect_ip, rt=args.rt,
        dest_prefix=getattr(args, "dest_prefix", None),
        src_prefix=getattr(args, "src_prefix", None),
    )
    print(builder.hexdump(update))


def _wait_for_establish(pid, timeout, log_path=None):
    """Poll the ExaBGP TCP state until it reaches ESTAB or timeout elapses.

    Returns (established: bool, tcp_state: str, waited_sec: float).

    This replaces the old blind ``time.sleep(6)`` before route reinjection.
    Establishment can lag well past a few seconds when the peer is in
    idle-hold/connect-retry backoff (typically right after an OPEN error such
    as a local-as/peer-as mismatch), so we actively wait and report how long it
    took instead of returning "active" while the FSM is still Idle/Connect.
    """
    start = time.time()
    tcp_state = None
    while True:
        tcp_state = _check_tcp_state(pid)
        if tcp_state == "ESTAB":
            return True, tcp_state, time.time() - start
        # A half-open/closing state means the peer actively refused/reset the
        # session (e.g. OPEN error); stop early so the caller surfaces it fast.
        if tcp_state in ("CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT"):
            return False, tcp_state, time.time() - start
        if not session.is_process_alive(pid):
            return False, "DEAD", time.time() - start
        if time.time() - start >= timeout:
            return False, tcp_state or "UNKNOWN", time.time() - start
        time.sleep(ESTABLISH_POLL_INTERVAL)


def _check_tcp_state(pid):
    """Check TCP connection state for an ExaBGP process. Returns state string or None.
    Tries pid match first, falls back to port 179 match (setcap'd binary may hide pid from ss)."""
    try:
        out = subprocess.check_output(
            ["ss", "-tnp"], timeout=5, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if f"pid={pid}" in line and "179" in line:
                return line.split()[0]
        for line in out.splitlines():
            if ":179 " in line or ":179\t" in line:
                state = line.split()[0]
                if state in ("ESTAB", "SYN-SENT", "SYN-RECV", "CLOSE-WAIT",
                             "FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT"):
                    return state
    except Exception:
        pass
    return None


def cmd_verify(args):
    """Quick health check: is ExaBGP alive and TCP ESTABLISHED?"""
    session_id = args.session_id
    session_data = session.load_session(session_id)
    if not session_data:
        print(json.dumps({"status": "error", "message": f"No session: {session_id}"}))
        return

    pid = session_data.get("exabgp_pid")
    alive = session.is_process_alive(pid) if pid else False
    tcp = _check_tcp_state(pid) if alive else None

    result = {
        "session_id": session_id,
        "exabgp_pid": pid,
        "exabgp_alive": alive,
        "tcp_state": tcp or ("DEAD" if not alive else "UNKNOWN"),
        "healthy": alive and tcp == "ESTAB",
        "routes_tracked": session_data.get("routes_injected", 0),
        "scale_modes": [si["mode"] for si in session_data.get("scale_injections", [])],
    }
    if not result["healthy"]:
        if not alive:
            result["action"] = "ExaBGP process dead. Restart with --preload."
        elif tcp == "CLOSE-WAIT":
            result["action"] = "BGP session dropped (peer sent NOTIFICATION). Kill and restart."
        elif tcp != "ESTAB":
            result["action"] = f"TCP in {tcp} state. Run 'bgp_tool.py diagnose --session-id {session_id}' to check BgpTrius iptables."
    print(json.dumps(result, indent=2))


def _ssh_device_shell(device_ip, username, password, commands, timeout=15):
    """SSH to DNOS device, enter shell, run commands, return output."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(device_ip, port=22, username=username, password=password, timeout=10)
        chan = client.invoke_shell(width=200, height=50)
        chan.settimeout(timeout)
        import time as _t
        _t.sleep(1)
        chan.recv(65535)

        chan.send("run start shell\n")
        _t.sleep(2)
        out = chan.recv(65535).decode(errors="replace")
        if "Password:" in out or "password:" in out:
            chan.send(f"{password}\n")
            _t.sleep(1)
            chan.recv(65535)

        results = []
        for cmd in commands:
            chan.send(f"{cmd}\n")
            _t.sleep(1.5)
            result = chan.recv(65535).decode(errors="replace")
            results.append(result)

        chan.send("exit\n")
        _t.sleep(0.5)
        client.close()
        return results
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return [f"SSH ERROR: {e}"]


def _ssh_dnos_cli(device_ip, username, password, commands, timeout=20, per_cmd_wait=2.0):
    """SSH to a DNOS device and run commands in DNOS CLI (NOT linux shell).

    Each command is sent and ``per_cmd_wait`` seconds are given for output. Returns
    a list of (cmd, output) tuples in order. Used by interface-bounce recovery and
    by show-config probes that must run in DNOS CLI rather than the underlying
    Linux shell.
    """
    import paramiko as _pm
    import time as _t
    client = _pm.SSHClient()
    client.set_missing_host_key_policy(_pm.AutoAddPolicy())
    results = []
    try:
        client.connect(device_ip, port=22, username=username, password=password,
                       timeout=10, banner_timeout=10, auth_timeout=10,
                       allow_agent=False, look_for_keys=False)
        chan = client.invoke_shell(width=200, height=50)
        chan.settimeout(timeout)
        _t.sleep(1.2)
        try:
            chan.recv(99999)
        except Exception:
            pass
        for cmd in commands:
            wait = per_cmd_wait if "commit" not in cmd else max(per_cmd_wait, 5.0)
            chan.send(cmd + "\n")
            _t.sleep(wait)
            buf = b""
            for _ in range(10):
                if chan.recv_ready():
                    try:
                        buf += chan.recv(99999)
                    except Exception:
                        break
                    _t.sleep(0.2)
                else:
                    break
            raw = buf.decode(errors="ignore")
            # DNOS colours pipe-include matches with ANSI codes; strip them so
            # downstream regexes match against the raw keyword.
            import re as _re
            clean = _re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
            results.append((cmd, clean))
    except Exception as e:
        results.append(("__ssh_error__", f"SSH ERROR: {e}"))
    finally:
        try:
            client.close()
        except Exception:
            pass
    return results


def _find_update_source(device_ip, username, password, peer_ip):
    """Discover the BGP neighbor's update-source interface for ``peer_ip``.

    DNOS ``show config protocols bgp`` requires the ASN, so we first discover
    the local BGP ASN from ``show bgp summary``, then query the per-neighbor
    config. Falls back to ``show interfaces | include 999`` (lab convention:
    server-facing sub-interface ends in .999) when the per-neighbor lookup
    fails. Returns the interface name (e.g. ``ge100-18/0/6.999``) or ``None``.
    """
    import re
    out = _ssh_dnos_cli(device_ip, username, password, [
        "show bgp summary | include identifier | no-more",
    ], per_cmd_wait=2.5)
    asn = None
    for _, body in out:
        m = re.search(r"local AS number (\d+)", body)
        if m:
            asn = m.group(1)
            break

    if asn:
        out = _ssh_dnos_cli(device_ip, username, password, [
            f"show config protocols bgp {asn} neighbor {peer_ip} | include update-source | no-more",
        ], per_cmd_wait=2.5)
        for _, body in out:
            for line in body.splitlines():
                m = re.search(r"update-source\s+([\w/.-]+)", line)
                if m:
                    return m.group(1)

    # Fallback: this lab convention puts the ExaBGP-facing sub-if at .999
    out = _ssh_dnos_cli(device_ip, username, password, [
        "show interfaces | include 999 | no-more",
    ], per_cmd_wait=3.0)
    for _, body in out:
        for line in body.splitlines():
            m = re.search(r"\b([\w/-]+\.999)\b", line)
            if m:
                return m.group(1)
    return None


def _bounce_update_source(device_ip, username, password, iface, log_path=None):
    """Bounce a DNOS sub-interface (admin-state disabled then enabled) with commits.

    Resolves a stale BgpTrius/CoPP filter that RSTs inbound TCP/179 after a
    line-card / sub-if state desync (typically post-reboot). Returns a dict with
    the per-step output for traceability.
    """
    cmds = [
        "end",
        "configure",
        "rollback 0",
        f"interfaces {iface} admin-state disabled",
        "commit",
        f"interfaces {iface} admin-state enabled",
        "commit",
        "end",
    ]
    out = _ssh_dnos_cli(device_ip, username, password, cmds, per_cmd_wait=2.0)
    steps = [{"cmd": c, "output": o[-300:]} for c, o in out]
    success = any("Commit succeeded" in o for _, o in out)
    if log_path:
        try:
            session.log(f"Bounced update-source iface {iface} on {device_ip}: success={success}", log_path)
        except Exception:
            pass
    return {"interface": iface, "success": success, "steps": steps}


_CLUSTER_NCC_CACHE_PATH = os.path.expanduser("~/.cursor/bgp-reference/cluster_ncc_cache.json")


def _load_cluster_cache():
    try:
        with open(_CLUSTER_NCC_CACHE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cluster_cache(cache):
    try:
        os.makedirs(os.path.dirname(_CLUSTER_NCC_CACHE_PATH), exist_ok=True)
        with open(_CLUSTER_NCC_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def _probe_ssh_auth(ip, username, password, timeout=4):
    """Return True only when paramiko gets a real session (TCP+AUTH+shell)."""
    try:
        import paramiko
    except ImportError:
        return False
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, username=username, password=password,
                  timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                  allow_agent=False, look_for_keys=False)
        c.close()
        return True
    except Exception:
        return False


def _identify_active_ncc(ip, username, password, timeout=6):
    """SSH to a working cluster IP, parse 'show system' to identify the active NCC.
    Returns (active_host_serial, ncc_dns_map) or (None, {})."""
    try:
        import paramiko, re
    except ImportError:
        return None, {}
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, username=username, password=password,
                  timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                  allow_agent=False, look_for_keys=False)
        chan = c.invoke_shell()
        time.sleep(1.0)
        chan.recv(99999)
        chan.send("show system | no-more\n")
        time.sleep(2.5)
        out = chan.recv(99999).decode(errors="ignore")
        chan.send("show interfaces | include mgmt-ncc | no-more\n")
        time.sleep(2.5)
        out2 = chan.recv(99999).decode(errors="ignore")
        chan.close()
        c.close()
    except Exception:
        return None, {}

    active_host = None
    for line in out.splitlines():
        if "active-up" in line and "NCC" in line:
            m = re.search(r"\|\s*([\w\d\-]+)\s*\|\s*active-up", line)
            if m:
                active_host = m.group(1)
                break
            sn = re.search(r"\|\s*([\w\d\-]+)\s*\|\s*$", line)
            if sn:
                active_host = sn.group(1).strip()
                break

    ncc_dns_map = {}
    for line in out2.splitlines():
        m = re.search(r"\|\s*(mgmt-ncc-\d)\s*\|.*?\|\s*([\d\.]+)/\d+", line)
        if m:
            ncc_dns_map[m.group(1)] = m.group(2)
    return active_host, ncc_dns_map


def _candidate_cluster_ips(dev_entry):
    """Build ordered list of candidate IPs for a (cluster) device entry from SCALER DB."""
    ips = []
    seen = set()
    def add(ip):
        if ip and ip not in seen:
            ips.append(ip); seen.add(ip)

    add(dev_entry.get("ip"))
    for ip in dev_entry.get("cluster_ncc_ips", []) or []:
        add(ip)
    extra = dev_entry.get("alternative_ips") or []
    for ip in extra:
        add(ip)
    return ips


def _resolve_device_creds(session_data, return_meta=False):
    """Resolve device IP+credentials.

    For DNOS clusters, the canonical ``ip`` field in the SCALER DB is the
    cluster mgmt VIP, which on this lab is bound to a separate sshd that
    rejects ``dnroot/dnroot``. The active NCC's per-node mgmt IP accepts the
    universal lab credentials. This resolver probes a candidate list and
    returns the first IP that completes a real SSH auth -- mirroring the fix
    applied to the topology SSH button (see DEVELOPMENT_GUIDELINES.md
    2026-04-27 entry on per-NCC IP priority).

    Returns ``(ip, user, password)`` (legacy 3-tuple) or, when
    ``return_meta=True``, a dict with the chosen ip, the candidates tried,
    cache hit/miss, and the discovered active NCC hostname.
    """
    import base64
    db_path = Path.home() / "SCALER" / "db" / "devices.json"
    if not db_path.exists():
        return ({} if return_meta else (None, None, None))

    target = session_data.get("target_device", "")
    with open(db_path) as f:
        db = json.load(f)

    dev_entry = None
    for dev in db.get("devices", []):
        hostname = dev.get("hostname", "")
        aliases = [a.lower() for a in dev.get("aliases", [])]
        if not target:
            continue
        if (target.lower() in hostname.lower()
                or hostname.lower() in target.lower()
                or target.lower() in aliases):
            dev_entry = dev
            break

    if not dev_entry:
        return ({} if return_meta else (None, None, None))

    user = dev_entry.get("username", "dnroot")
    try:
        pw = base64.b64decode(dev_entry["password"]).decode()
    except Exception:
        pw = dev_entry.get("password", "dnroot")

    is_cluster = bool(dev_entry.get("is_cluster"))
    primary_ip = dev_entry.get("ip")

    if not is_cluster:
        if return_meta:
            return {
                "ip": primary_ip, "username": user, "password": pw,
                "is_cluster": False, "candidates": [primary_ip],
                "tried": [], "cache_hit": False, "active_ncc_host": None,
            }
        return primary_ip, user, pw

    cache = _load_cluster_cache()
    cache_key = dev_entry.get("hostname", target)
    cached = cache.get(cache_key, {}) if isinstance(cache, dict) else {}
    cached_ip = cached.get("active_ncc_ip")

    candidates = []
    if cached_ip:
        candidates.append(cached_ip)
    for ip in _candidate_cluster_ips(dev_entry):
        if ip not in candidates:
            candidates.append(ip)

    tried = []
    chosen_ip = None
    for ip in candidates:
        ok = _probe_ssh_auth(ip, user, pw, timeout=4)
        tried.append({"ip": ip, "auth_ok": ok})
        if ok:
            chosen_ip = ip
            break

    if not chosen_ip:
        if return_meta:
            return {
                "ip": primary_ip, "username": user, "password": pw,
                "is_cluster": True, "candidates": candidates,
                "tried": tried, "cache_hit": False, "active_ncc_host": None,
                "error": "no candidate IP accepted dnroot auth",
            }
        return primary_ip, user, pw

    active_host = None
    ncc_dns_map = {}
    if cached_ip != chosen_ip or not cached.get("active_ncc_host"):
        active_host, ncc_dns_map = _identify_active_ncc(chosen_ip, user, pw)

    cache[cache_key] = {
        "active_ncc_ip": chosen_ip,
        "active_ncc_host": active_host or cached.get("active_ncc_host"),
        "vip": primary_ip,
        "cluster_ncc_ips": list({**(cached.get("ncc_dns_map") or {}), **ncc_dns_map}.values())
                            or dev_entry.get("cluster_ncc_ips") or [],
        "ncc_dns_map": {**(cached.get("ncc_dns_map") or {}), **ncc_dns_map},
        "resolved_at": int(time.time()),
    }
    _save_cluster_cache(cache)

    if return_meta:
        return {
            "ip": chosen_ip, "username": user, "password": pw,
            "is_cluster": True, "candidates": candidates, "tried": tried,
            "cache_hit": cached_ip == chosen_ip,
            "active_ncc_host": cache[cache_key]["active_ncc_host"],
            "vip": primary_ip,
        }
    return chosen_ip, user, pw


def cmd_resolve(args):
    """CLI: resolve a device hostname to a working SSH IP (cluster-aware).

    Usage:
        bgp_tool.py resolve --device PE-4
        bgp_tool.py resolve --device PE-4 --refresh   # ignore cache, re-probe
    """
    target = args.device
    fake_session = {"target_device": target}
    if getattr(args, "refresh", False):
        cache = _load_cluster_cache()
        cache.pop(target, None)
        for dev in (json.load(open(Path.home() / "SCALER" / "db" / "devices.json"))
                    .get("devices", [])):
            if (target.lower() in dev.get("hostname", "").lower()
                    or dev.get("hostname", "").lower() in target.lower()):
                cache.pop(dev["hostname"], None)
        _save_cluster_cache(cache)

    meta = _resolve_device_creds(fake_session, return_meta=True)
    print(json.dumps(meta, indent=2))


def _measure_tcp179(peer_ip, samples=4, per_attempt_timeout=2.0):
    """Measure TCP/179 reachability with timing.

    Returns dict {state, avg_ms, samples_open, samples_refused, samples_timeout, errno}.
    state is one of 'open' | 'fast_rst' | 'slow_drop' | 'mixed'.

    Distinguishes:
      - open       : TCP handshake succeeds                   -> control plane up
      - fast_rst   : ECONNREFUSED in <50ms (sub-RTT*5)        -> DNOS BgpTrius/local filter RST
      - slow_drop  : timeout (no response) >per_attempt_timeout-> FortiGate IDS / silent drop
      - mixed      : inconsistent (transient/edge state)
    """
    import socket as _sock
    import time as _t
    open_n = 0
    refused_n = 0
    timeout_n = 0
    rtts = []
    last_errno = None
    for _ in range(max(1, samples)):
        s = _sock.socket()
        s.settimeout(per_attempt_timeout)
        t0 = _t.perf_counter()
        try:
            s.connect((peer_ip, 179))
            elapsed_ms = (_t.perf_counter() - t0) * 1000
            rtts.append(elapsed_ms)
            open_n += 1
        except OSError as e:
            elapsed_ms = (_t.perf_counter() - t0) * 1000
            rtts.append(elapsed_ms)
            last_errno = e.errno
            if e.errno == 111:
                refused_n += 1
            else:
                timeout_n += 1
        finally:
            try:
                s.close()
            except Exception:
                pass

    avg_ms = (sum(rtts) / len(rtts)) if rtts else 0.0
    if open_n == samples:
        state = "open"
    elif refused_n == samples and avg_ms < 50.0:
        state = "fast_rst"
    elif timeout_n == samples or avg_ms >= per_attempt_timeout * 1000 * 0.9:
        state = "slow_drop"
    else:
        state = "mixed"
    return {
        "state": state,
        "avg_ms": round(avg_ms, 2),
        "samples": samples,
        "samples_open": open_n,
        "samples_refused": refused_n,
        "samples_timeout": timeout_n,
        "errno": last_errno,
    }


def _check_fortigate_ids(peer_ip, timeout=2):
    """Classify TCP/179 reachability for the peer.

    The original heuristic (port 179 closed + port 22 open => FortiGate IDS) was
    wrong for cluster devices that RST inbound BGP at the DNOS BgpTrius layer
    after a sub-interface state desync (e.g., post-reboot). True FortiGate IDS
    quarantine is a *silent drop* (timeout), while a stale BgpTrius rule sends
    a *fast TCP RST* (ECONNREFUSED in <50 ms).

    Distinguishes:
      - 'open'                 : TCP handshake succeeds, BGP can establish.
      - 'dnos_filter'          : Sub-RTT RST -> bounce update-source sub-if on device.
      - 'fortigate_ids'        : Silent drop / timeout -> wait for IDS quarantine to clear.
      - 'unreachable'          : Other failure mode (no route, etc.)

    Returns a dict the rest of the diagnose flow uses.
    """
    import subprocess as _sp

    measurement = _measure_tcp179(peer_ip)
    if measurement["state"] == "open":
        return {"blocked": False, "measurement": measurement}

    try:
        r22 = _sp.run(["nc", "-z", "-w", str(timeout), peer_ip, "22"],
                       capture_output=True, timeout=timeout + 2)
        ssh_open = r22.returncode == 0
    except Exception:
        ssh_open = False

    if measurement["state"] == "fast_rst":
        return {
            "blocked": True,
            "block_kind": "dnos_filter",
            "tcp_179_open": False,
            "tcp_22_open": ssh_open,
            "likely_fortigate_ids": False,
            "measurement": measurement,
            "recovery": "Bounce BGP update-source sub-interface on device (admin-state disabled -> commit -> enabled -> commit). Auto-fix: bgp_tool.py diagnose --session-id <id> --fix",
        }
    if measurement["state"] == "slow_drop":
        return {
            "blocked": True,
            "block_kind": "fortigate_ids",
            "tcp_179_open": False,
            "tcp_22_open": ssh_open,
            "likely_fortigate_ids": True,
            "measurement": measurement,
            "recovery": "Admin-disable BGP neighbor on device, wait 2-5 min for FortiGate quarantine to expire, then re-enable + start ExaBGP",
        }
    return {
        "blocked": True,
        "block_kind": "mixed",
        "tcp_179_open": False,
        "tcp_22_open": ssh_open,
        "likely_fortigate_ids": ssh_open,
        "measurement": measurement,
        "recovery": "Mixed reachability. Re-run diagnose; if still mixed, bounce sub-if (--fix) or wait for transient.",
    }


def cmd_diagnose(args):
    """Diagnose BGP session stuck in Connect -- check FortiGate IDS block first, then BgpTrius iptables."""
    session_id = args.session_id
    session_data = session.load_session(session_id)
    if not session_data:
        print(json.dumps({"status": "error", "message": f"No session: {session_id}"}))
        return

    pid = session_data.get("exabgp_pid")
    alive = session.is_process_alive(pid) if pid else False
    tcp = _check_tcp_state(pid) if alive else None

    if alive and tcp == "ESTAB":
        print(json.dumps({
            "status": "ok",
            "message": "Session is already ESTABLISHED. No diagnosis needed.",
            "tcp_state": "ESTAB"
        }, indent=2))
        return

    peer_ip = session_data.get("device_ip") or DEVICE_DEFAULT_IP
    try:
        config_path = session_data.get("exabgp_config", "")
        with open(config_path) as f:
            for line in f:
                if line.strip().startswith("neighbor "):
                    peer_ip = line.strip().split()[1]
                    break
    except Exception:
        pass

    fg_check = _check_fortigate_ids(peer_ip)
    if not fg_check["blocked"]:
        # TCP/179 reachable end-to-end. Either ExaBGP is just not running, or it
        # is in Connect/Active for an unrelated reason (e.g. peer admin-down).
        # Skip the BgpTrius iptables fallback -- it has a known false-positive
        # because DNOS keeps a default 'drop tcp/179 unless mark==0x65179' rule
        # and the new classifier already proves the network path is open.
        m = fg_check.get("measurement", {})
        print(json.dumps({
            "status": "no_block_detected",
            "message": "TCP/179 reachable to peer. ExaBGP not Established for another reason "
                        "(process not running, neighbor admin-down on device, etc.).",
            "tcp_state": tcp or ("DEAD" if not alive else "UNKNOWN"),
            "peer_ip": peer_ip,
            "tcp_179_open": True,
            "tcp_179_avg_ms": m.get("avg_ms"),
            "next_steps": [
                "Run: bgp_tool.py status --session-id <id>",
                "If exabgp_alive=false, restart with: bgp_tool.py start --session-id <id>",
                "If session up but neighbor in Active/Connect, check device-side neighbor admin-state",
            ],
        }, indent=2))
        return

    if fg_check["blocked"]:
        kind = fg_check.get("block_kind", "mixed")
        measurement = fg_check.get("measurement", {})

        if kind == "dnos_filter":
            diagnosis = {
                "status": "dnos_filter_blocked",
                "message": "DNOS BgpTrius/local filter is RST-ing TCP/179 (sub-RTT refused) -- "
                           "typically a stale sub-interface CoPP/iptables rule after a reboot or interface flap.",
                "tcp_state": tcp or ("DEAD" if not alive else "UNKNOWN"),
                "peer_ip": peer_ip,
                "tcp_179_open": False,
                "tcp_22_open": fg_check.get("tcp_22_open", False),
                "tcp_179_avg_ms": measurement.get("avg_ms"),
                "root_cause": "Stale DNOS BgpTrius / sub-interface filter for the BGP update-source. "
                              "TCP RST returns in <50 ms (~1 RTT) instead of being silently dropped.",
                "fix_available": True,
                "fix_steps": [
                    f"1. Resolve device active NCC IP (cluster-aware) for the peer at {peer_ip}",
                    "2. Read the BGP neighbor 'update-source' interface from the device config",
                    "3. SSH into the device and bounce that interface: admin-state disabled -> commit -> admin-state enabled -> commit",
                    "4. Re-test TCP/179 (handshake should now succeed in 1-2 ms)",
                    "5. ExaBGP should auto-establish (TCP socket retry on next connect timer)",
                ],
                "auto_fix_command": f"bgp_tool.py diagnose --session-id {session_id} --fix",
            }

            if not getattr(args, "fix", False):
                print(json.dumps(diagnosis, indent=2))
                return

            device_ip = getattr(args, "device_ip", None)
            username = getattr(args, "username", None)
            password = getattr(args, "password", None)
            if not device_ip:
                device_ip, username, password = _resolve_device_creds(session_data)
            username = username or "dnroot"
            password = password or "dnroot"

            if not device_ip:
                diagnosis["fix_applied"] = False
                diagnosis["fix_error"] = "Cannot resolve device OOB IP for cluster-aware bounce. " \
                                          "Pass --device-ip explicitly."
                print(json.dumps(diagnosis, indent=2))
                return

            print(json.dumps({"status": "applying_fix",
                              "step": "find_update_source",
                              "device_ip": device_ip,
                              "peer_ip": peer_ip}), flush=True)
            iface = _find_update_source(device_ip, username, password, peer_ip)
            if not iface:
                diagnosis["fix_applied"] = False
                diagnosis["fix_error"] = "Could not discover BGP neighbor update-source interface from device config."
                print(json.dumps(diagnosis, indent=2))
                return

            print(json.dumps({"status": "applying_fix",
                              "step": "bounce_subinterface",
                              "interface": iface}), flush=True)
            bounce_result = _bounce_update_source(device_ip, username, password, iface, log_path=log_path)
            diagnosis["fix_applied"] = bounce_result["success"]
            diagnosis["interface_bounced"] = iface
            diagnosis["bounce_steps"] = bounce_result["steps"]

            import time as _t
            _t.sleep(3)
            post_meas = _measure_tcp179(peer_ip)
            diagnosis["tcp_state_after_fix"] = post_meas["state"]
            diagnosis["tcp_179_avg_ms_after_fix"] = post_meas["avg_ms"]
            tcp_after = _check_tcp_state(pid) if alive else None
            diagnosis["session_recovered"] = tcp_after == "ESTAB" or post_meas["state"] == "open"

            print(json.dumps(diagnosis, indent=2))
            return

        if kind == "fortigate_ids":
            diagnosis = {
                "status": "fortigate_ids_blocked",
                "message": "FortiGate IDS is silently dropping TCP/179 (timeout, no RST) -- IDS quarantine in effect.",
                "tcp_state": tcp or ("DEAD" if not alive else "UNKNOWN"),
                "peer_ip": peer_ip,
                "tcp_179_open": False,
                "tcp_22_open": fg_check.get("tcp_22_open", False),
                "tcp_179_avg_ms": measurement.get("avg_ms"),
                "root_cause": "FortiGate firewall (100.70.0.254) IDS quarantine -- typically triggered by a previous SYN/RST storm on port 179.",
                "fix_available": True,
                "fix_steps": [
                    "1. Admin-disable or delete BGP neighbor on device (stops SYNs that refresh quarantine)",
                    "2. Wait 2-5 minutes for FortiGate IDS quarantine to expire",
                    f"3. Verify: nc -z {peer_ip} 179 (must succeed)",
                    "4. Re-enable neighbor + start ExaBGP simultaneously",
                    "5. PERMANENT FIX: Add 'passive enabled' to device neighbor config",
                ],
            }
            print(json.dumps(diagnosis, indent=2))
            return

        diagnosis = {
            "status": "tcp_179_unreachable",
            "message": "TCP/179 unreachable but reachability is mixed -- could be transient.",
            "tcp_state": tcp or ("DEAD" if not alive else "UNKNOWN"),
            "peer_ip": peer_ip,
            "measurement": measurement,
            "fix_available": False,
        }
        print(json.dumps(diagnosis, indent=2))
        return

    server_ip = session_data.get("exabgp_ip", "100.64.6.134")
    local_addr = "100.64.6.134"
    try:
        with open(session_data.get("exabgp_config", "")) as f:
            for line in f:
                if "local-address" in line:
                    local_addr = line.split(";")[0].strip().split()[-1]
                    break
    except Exception:
        pass

    device_ip = getattr(args, "device_ip", None)
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)

    if not device_ip:
        device_ip, username, password = _resolve_device_creds(session_data)

    if not device_ip:
        print(json.dumps({
            "status": "error",
            "message": "Cannot resolve device OOB IP. Use --device-ip, --username, --password.",
            "tcp_state": tcp or "UNKNOWN"
        }, indent=2))
        return

    username = username or "dnroot"
    password = password or "dnroot"
    peer_ip = session_data.get("device_ip") or DEVICE_DEFAULT_IP

    print(json.dumps({"status": "checking", "device_ip": device_ip, "server_ip": local_addr}), flush=True)

    results = _ssh_device_shell(device_ip, username, password, [
        "iptables -L INPUT -n --line-numbers | head -20"
    ])

    iptables_out = results[0] if results else ""
    has_bgptrius = "0x65179" in iptables_out or "65179" in iptables_out
    has_drop_179 = "DROP" in iptables_out and "179" in iptables_out
    has_accept_server = local_addr in iptables_out and "ACCEPT" in iptables_out

    diagnosis = {
        "status": "diagnosed",
        "tcp_state": tcp or ("DEAD" if not alive else "UNKNOWN"),
        "exabgp_alive": alive,
        "bgptrius_detected": has_bgptrius,
        "drop_179_present": has_drop_179,
        "accept_rules_present": has_accept_server,
        "iptables_snippet": iptables_out[:1500],
    }

    if has_bgptrius and has_drop_179 and not has_accept_server:
        diagnosis["root_cause"] = "BgpTrius iptables blocking -- DROP rules for port 179 without ACCEPT for server IP"
        diagnosis["fix_available"] = True
        diagnosis["fix_commands"] = [
            f"iptables -I INPUT 3 -p tcp -s {local_addr} --sport 179 -j ACCEPT",
            f"iptables -I INPUT 3 -p tcp -s {local_addr} --dport 179 -j ACCEPT",
            f"iptables -I INPUT 3 -p tcp -d {peer_ip} --dport 179 -j ACCEPT",
        ]
    elif has_bgptrius and has_accept_server:
        diagnosis["root_cause"] = "ACCEPT rules already present but session still not ESTABLISHED -- check network path or BGP config"
        diagnosis["fix_available"] = False
    elif not has_bgptrius:
        diagnosis["root_cause"] = "No BgpTrius iptables rules detected -- issue is elsewhere (network path, BGP config, firewall)"
        diagnosis["fix_available"] = False
    else:
        diagnosis["root_cause"] = "Unclear -- review iptables output manually"
        diagnosis["fix_available"] = False

    if getattr(args, "fix", False) and diagnosis.get("fix_available"):
        print(json.dumps({"status": "applying_fix", "commands": diagnosis["fix_commands"]}), flush=True)
        fix_results = _ssh_device_shell(device_ip, username, password, diagnosis["fix_commands"])
        diagnosis["fix_applied"] = True
        diagnosis["fix_output"] = [r[:500] for r in fix_results]

        import time as _t
        _t.sleep(5)
        tcp_after = _check_tcp_state(pid) if alive else None
        diagnosis["tcp_state_after_fix"] = tcp_after or "UNKNOWN"
        diagnosis["session_recovered"] = tcp_after == "ESTAB"

    print(json.dumps(diagnosis, indent=2))


def _rebuild_advertised_state(session_data):
    """Recalculate advertised_state and routes_injected from current session data."""
    from builders.scale import reconstruct_injected_routes
    all_route_entries = list(session_data.get("injected_routes", []))
    for si in session_data.get("scale_injections", []):
        count = si.get("injected_count", 0)
        si_routes = reconstruct_injected_routes(si["mode"], si["params"], count)
        for r in si_routes:
            all_route_entries.append({"route": r, "injected_at": si.get("injected_at")})

    adv_state = route_parser.build_advertised_state(all_route_entries, session_data)
    adv_state["routes"] = adv_state.get("routes", [])[:10]
    session_data["advertised_state"] = adv_state
    session_data["routes_injected"] = len(all_route_entries)


def _preload_routes(session_id, session_data, routes, mode, log_path):
    """Restart ExaBGP with routes pre-loaded via process API.

    Instead of pipe injection (~183 rps), this embeds all routes in a loader
    script that ExaBGP reads on startup. Routes are parsed before the BGP
    session comes up and sent in the initial UPDATE burst -- typically 3-20x
    faster than pipe injection for large route counts.

    Merges with existing scale_injections from other modes so multiple
    --preload calls accumulate routes across modes.
    """
    import time as _time
    from builders.scale import reconstruct_injected_routes
    from backends import exabgp as exabgp_backend

    start = _time.perf_counter()

    existing_routes = []
    for si in session_data.get("scale_injections", []):
        if si["mode"] != mode:
            count = si.get("injected_count", 0)
            existing_routes.extend(reconstruct_injected_routes(si["mode"], si["params"], count))
    for ir in session_data.get("injected_routes", []):
        r = ir.get("route", "")
        if r.startswith("announce"):
            existing_routes.append(r)

    all_routes = existing_routes + routes
    session.log(f"Preload: {len(routes)} new ({mode}) + {len(existing_routes)} existing = {len(all_routes)} total", log_path)

    loader_script = Path(f"/tmp/exabgp_{session_id}_loader.sh")
    routes_file = Path(f"/tmp/exabgp_{session_id}_routes.txt")
    with open(routes_file, "w") as f:
        f.write("\n".join(all_routes) + "\n")

    with open(loader_script, "w") as f:
        f.write(f"#!/bin/bash\ncat {routes_file}\nsleep infinity\n")
    loader_script.chmod(0o755)

    gen_elapsed = _time.perf_counter() - start
    session.log(f"Preload: wrote {len(all_routes)} routes in {gen_elapsed:.2f}s", log_path)

    pid = session_data.get("exabgp_pid")
    if pid and session.is_process_alive(pid):
        session.log("Preload: stopping current ExaBGP", log_path)
        exabgp_backend.stop_exabgp(pid)
    session.kill_orphan_exabgp_processes(spare_pid=os.getpid(), log_path=log_path)

    families = session_data.get("selected_afis", [])
    peer_ip = session_data.get("device_ip") or session_data.get("peer_ip") or DEVICE_DEFAULT_IP
    peer_as = session_data.get("peer_as") or "1234567"

    config_content = f"""process scale-loader {{
    run {loader_script};
    encoder text;
}}

neighbor {peer_ip} {{
    router-id 100.64.6.134;
    local-address 100.64.6.134;
    local-as 65200;
    peer-as {peer_as};
    hold-time 180;
    passive true;
    listen 179;
    outgoing-ttl 64;

    family {{
{chr(10).join(f'        {fam};' for fam in families)}
    }}

    api {{
        processes [ scale-loader ];
    }}
}}
"""
    config_path = f"/tmp/exabgp_{session_id}.conf"
    with open(config_path, "w") as f:
        f.write(config_content)

    pipe.ensure_pipes()
    new_pid, exabgp_log_path = exabgp_backend.start_exabgp(config_path, session_id, log_path)
    session_data["exabgp_pid"] = new_pid
    session_data["exabgp_config"] = config_path
    session_data["exabgp_log"] = str(exabgp_log_path)

    _time.sleep(2)
    if not session.is_process_alive(new_pid):
        bgp_guard.close_port()
        return {"injected": 0, "failed": len(routes), "total": len(routes),
                "elapsed_sec": round(_time.perf_counter() - start, 2),
                "routes_per_sec": 0, "error": "ExaBGP died on preload start"}

    tcp_state = _check_tcp_state(new_pid)
    if tcp_state and tcp_state != "ESTAB":
        session.log(f"WARNING: TCP state is {tcp_state} after preload start (expected ESTAB)", log_path)

    elapsed = _time.perf_counter() - start
    session.log(
        f"Preload: ExaBGP restarted (PID {new_pid}), "
        f"{len(all_routes)} total routes ({len(routes)} new {mode}) in {elapsed:.1f}s",
        log_path,
    )
    return {
        "injected": len(routes), "failed": 0, "total": len(routes),
        "all_preloaded": len(all_routes),
        "elapsed_sec": round(elapsed, 2),
        "routes_per_sec": round(len(routes) / elapsed, 1) if elapsed > 0 else 0,
        "method": "preload",
    }


def cmd_scale(args):
    """Bulk inject routes for scale/stress testing."""
    session_id = args.session_id
    log_path = session.setup_log(session_id)

    session_data = session.load_session(session_id)
    if not session_data or session_data.get("status") != "active":
        print(json.dumps({"error": f"No active session: {session_id}. Start ExaBGP first."}))
        sys.exit(1)

    mode = args.mode
    builder = BUILDERS.get(f"scale-{mode}")
    if not builder:
        valid = [k.replace("scale-", "") for k in BUILDERS if k.startswith("scale-")]
        print(json.dumps({"error": f"Unknown scale mode: {mode}. Use: {', '.join(valid)}"}))
        sys.exit(1)

    kwargs = {
        "count": getattr(args, "count", None) or 1000,
    }

    if mode in ("batch", "stress"):
        kwargs["prefix_range"] = getattr(args, "prefix_range", None) or "10.0.0.0/24-10.0.9.0/24"
        kwargs["rd"] = args.rd or "1.1.1.1:100"
        kwargs["rt"] = args.rt or "1234567:300"
        kwargs["redirect_ip"] = getattr(args, "redirect_ip", None) or "10.0.0.230"
    if mode == "stress":
        kwargs["base_prefix"] = getattr(args, "base_prefix", None) or "10.0.0.0/24"
        kwargs["rd_template"] = getattr(args, "rd_template", None) or "1.1.1.1:{n}"
    if mode in ("flowspec-ipv4", "flowspec-ipv6"):
        kwargs["action"] = getattr(args, "action", None) or "rate-limit 0"
    if mode == "flowspec-vpn-ipv4":
        kwargs["action"] = getattr(args, "action", None) or "rate-limit 0"
        kwargs["rd"] = args.rd or "1.1.1.1:200"
        kwargs["rt"] = args.rt or "1234567:301"
        if getattr(args, "base_source", None):
            kwargs["base_source"] = args.base_source
        if getattr(args, "source_mask", None):
            kwargs["source_mask"] = args.source_mask
    if mode == "flowspec-vpn-ipv6":
        kwargs["action"] = getattr(args, "action", None) or "rate-limit 0"
        kwargs["rd"] = args.rd or "1.1.1.1:200"
        kwargs["rt"] = args.rt or "1234567:401"
        if getattr(args, "base_source", None):
            kwargs["base_source"] = args.base_source
        if getattr(args, "source_mask", None):
            kwargs["source_mask"] = args.source_mask

    from builders.scale import inject_batch, inject_batch_fast, withdraw_all, reconstruct_injected_routes

    if getattr(args, "withdraw", False):
        keep = getattr(args, "keep", 0) or 0
        matching = [si for si in session_data.get("scale_injections", []) if si["mode"] == mode]
        if not matching:
            print(json.dumps({"error": f"No scale injection found for mode '{mode}' in session. Nothing to withdraw."}))
            sys.exit(1)

        si = matching[-1]
        total = si.get("injected_count", 0)
        routes = reconstruct_injected_routes(mode, si["params"], total)

        if keep > 0 and keep < len(routes):
            routes_to_withdraw = routes[keep:]
        else:
            routes_to_withdraw = routes
            keep = 0

        result = withdraw_all(routes_to_withdraw)
        result["mode"] = mode
        result["action"] = "withdraw"
        result["kept"] = keep
        result["withdrawn"] = len(routes_to_withdraw)

        if keep > 0:
            si["injected_count"] = keep
        else:
            session_data["scale_injections"] = [
                s for s in session_data.get("scale_injections", []) if s is not si
            ]

        _rebuild_advertised_state(session_data)
        session.save_session(session_id, session_data)
        session.log(f"Withdraw {mode}: {result['withdrawn']} withdrawn, {keep} kept ({result['elapsed_sec']}s)", log_path)
        print(json.dumps(result, indent=2))
        return

    routes = builder(**kwargs)
    rate = getattr(args, "rate", None)
    fast = getattr(args, "fast", False)
    preload = getattr(args, "preload", False)

    if preload:
        result = _preload_routes(session_id, session_data, routes, mode, log_path)
    elif fast or len(routes) > 500:
        result = inject_batch_fast(routes, log_path=log_path)
    else:
        result = inject_batch(routes, rate=float(rate) if rate else None, log_path=log_path)
    result["mode"] = mode

    ts = session.now_iso()
    if "scale_injections" not in session_data:
        session_data["scale_injections"] = []
    new_entry = {
        "mode": mode,
        "builder": f"scale-{mode}",
        "params": kwargs,
        "injected_count": result["injected"],
        "failed_count": result["failed"],
        "injected_at": ts,
        "elapsed_sec": result["elapsed_sec"],
        "routes_per_sec": result["routes_per_sec"],
    }
    session_data["scale_injections"] = [
        si for si in session_data["scale_injections"] if si["mode"] != mode
    ] + [new_entry]

    _rebuild_advertised_state(session_data)
    session.save_session(session_id, session_data)
    session.log(f"Scale {mode}: {result['injected']} routes tracked in session.", log_path)

    if preload:
        import time as _t
        _t.sleep(3)
        pid = session_data.get("exabgp_pid")
        tcp = _check_tcp_state(pid) if pid and session.is_process_alive(pid) else None
        if tcp and tcp != "ESTAB":
            result["warning"] = f"BGP session may have dropped (TCP: {tcp}). Check 'bgp_tool.py verify --session-id {session_id}'"
            session.log(f"WARNING: post-preload TCP state is {tcp}, expected ESTAB", log_path)
        elif not pid or not session.is_process_alive(pid):
            result["warning"] = "ExaBGP process died after preload"
            session.log("WARNING: ExaBGP process not alive after preload", log_path)
        else:
            result["post_check"] = "healthy"

    print(json.dumps(result, indent=2))


def cmd_engine_start(args):
    """Start GoBGP daemon (for unicast/VPN/EVPN - FlowSpec parked)."""
    mgr = gobgp_backend.GoBGPManager(args.session_id)
    result = mgr.start(
        peer_ip=args.peer_ip,
        peer_as=int(args.peer_as),
        local_as=int(args.local_as) if args.local_as else 65200,
        families=args.families.split(",") if args.families else None,
        grpc_port=int(args.grpc_port) if args.grpc_port else 50051,
    )
    print(json.dumps(result, indent=2))


def cmd_engine_stop(args):
    """Stop GoBGP daemon."""
    mgr = gobgp_backend.GoBGPManager(args.session_id)
    mgr.stop()
    print(json.dumps({"stopped": True, "session_id": args.session_id}, indent=2))


def cmd_engine_inject(args):
    """Inject route via GoBGP (unicast, l3vpn, flowspec - FlowSpec-VPN parked)."""
    mgr = gobgp_backend.GoBGPManager(args.session_id)
    mgr.grpc_port = int(args.grpc_port) if args.grpc_port else 50051
    route_type = args.type
    if route_type == "unicast":
        result = mgr.inject_unicast(prefix=args.prefix, nexthop=args.nexthop)
    elif route_type == "l3vpn":
        result = mgr.inject_l3vpn(
            rd=args.rd, prefix=args.prefix, nexthop=args.nexthop, rt=args.rt
        )
    elif route_type == "flowspec":
        result = mgr.inject_flowspec(match=args.match, action=args.action)
    elif route_type == "flowspec-vpn":
        result = mgr.inject_flowspec_vpn(
            rd=args.rd, match=args.match, action=args.action, rt=args.rt
        )
    else:
        result = {"success": False, "error": f"Unknown type: {route_type}"}
    print(json.dumps(result, indent=2))


def cmd_attribute_test(args):
    """Run attribute test - build route and optionally inject."""
    from attributes import build as attr_build

    test_name = args.test_name
    kwargs = {
        "prefix": getattr(args, "prefix", None) or "10.0.0.0/24",
        "nexthop": getattr(args, "nexthop", None) or "100.70.0.32",
        "rd": getattr(args, "rd", None) or "1.1.1.1:100",
        "rt": getattr(args, "rt", None) or "1234567:300",
        "redirect_ip": getattr(args, "redirect_ip", None) or "10.0.0.230",
        "dest_prefix": getattr(args, "dest_prefix", None) or "10.0.0.0/24",
    }
    kwargs = {k: v for k, v in kwargs.items() if v is not None}

    try:
        route = attr_build(test_name, **kwargs)
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    result = {"test_name": test_name, "route": route}
    if getattr(args, "inject", False) and args.session_id:
        session_data = session.load_session(args.session_id)
        if session_data and session_data.get("status") == "active":
            log_path = session.setup_log(args.session_id)
            if pipe.write_route(route, log_path):
                result["injected"] = True
            else:
                result["injected"] = False
                result["error"] = "Pipe write failed"
        else:
            result["injected"] = False
            result["error"] = "No active session"
    print(json.dumps(result, indent=2))


def cmd_cleanup(args):
    """Emergency cleanup of a session (kill ExaBGP + ALL orphans, mark closed)."""
    session_id = args.session_id
    log_path = session.setup_log(session_id)
    session_data = session.load_session(session_id)

    if not session_data:
        session.log(f"No session found: {session_id}", log_path)
        return

    pid = session_data.get("exabgp_pid")
    if pid and session.is_process_alive(pid):
        session.log(f"Emergency kill ExaBGP (PID {pid})", log_path)
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    orphans = session.kill_orphan_exabgp_processes(spare_pid=os.getpid(), log_path=log_path)
    if orphans:
        session.log(f"Cleanup sweep: killed {orphans} orphaned process(es)", log_path)

    bgp_guard.close_port()
    session.log("Port 179 guard: CLOSED (emergency cleanup)", log_path)

    config_path = session_data.get("exabgp_config")
    if config_path and Path(config_path).exists():
        Path(config_path).unlink()
        session.log(f"Removed config: {config_path}", log_path)

    session_data["status"] = "closed"
    session_data["closed_at"] = session.now_iso()
    session_data["cleanup_result"] = "emergency"
    session.save_session(session_id, session_data)
    session.log(f"Session {session_id} emergency cleanup complete", log_path)

    print(json.dumps(session_data, indent=2))
    print("\nNOTE: Device configs may still need rollback. Check applied_configs in session file.")


def main():
    parser = argparse.ArgumentParser(
        description="BGP Peering Tool - ExaBGP Lifecycle Manager"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    p_start = subparsers.add_parser("start", help="Start ExaBGP session")
    p_start.add_argument("--session-id", required=True, help="Unique session ID")
    p_start.add_argument("--config", help="Path to ExaBGP config file")
    p_start.add_argument("--peer-ip", help="BGP peer IP (generates config if no --config)")
    p_start.add_argument("--peer-as", help="BGP peer AS number")
    p_start.add_argument("--local-as", default="65200", help="Local AS (default: 65200)")
    p_start.add_argument("--families", help="Comma-separated families (DNOS or ExaBGP names)")
    p_start.add_argument("--selected-afis", dest="selected_afis", help="Comma-separated DNOS AFI names")
    p_start.add_argument("--device-ip", dest="device_ip", default=DEVICE_DEFAULT_IP, help=f"Device .999 IP (default: {DEVICE_DEFAULT_IP})")
    p_start.add_argument("--target-device", dest="target_device", help="Target device name for session")
    p_start.add_argument("--dnaas-leaf", dest="dnaas_leaf", help="DNAAS leaf name for session")
    p_start.add_argument("--hold-time", default="180", help="Hold time (default: 180)")
    p_start.add_argument("--multihop", default="10", help="eBGP multihop (default: 10)")
    p_start.add_argument("--establish-timeout", dest="establish_timeout", type=int, default=DEFAULT_ESTABLISH_TIMEOUT, help=f"Seconds to actively wait for BGP ESTABLISHED before reinjecting routes (default: {DEFAULT_ESTABLISH_TIMEOUT})")
    p_start.add_argument("--local-address", dest="local_address", help="ExaBGP bind IP (must match device neighbor config)")
    p_start.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="ExaBGP log level")

    p_stop = subparsers.add_parser("stop", help="Stop ExaBGP session (requires --confirm-kill if alive)")
    p_stop.add_argument("--session-id", required=True)
    p_stop.add_argument("--confirm-kill", action="store_true",
                        help="Confirm kill of live session. ONLY use when user explicitly said stop/kill.")

    p_status = subparsers.add_parser("status", help="Check session status")
    p_status.add_argument("--session-id", required=True)

    p_inject = subparsers.add_parser("inject", help="Inject a route")
    p_inject.add_argument("--session-id", required=True)
    p_inject.add_argument("--route", required=True, help="ExaBGP route string")
    p_inject.add_argument("--skip-syslog", dest="skip_syslog", action="store_true",
                          help="Skip post-inject syslog check (faster, use for bulk)")

    p_withdraw = subparsers.add_parser("withdraw", help="Withdraw route(s)")
    p_withdraw.add_argument("--session-id", required=True)
    p_withdraw.add_argument("--route", help="ExaBGP route string (optional if using --last/--all)")
    p_withdraw.add_argument("--last", type=int, nargs="?", const=1, help="Withdraw last N injected routes (default: 1)")
    p_withdraw.add_argument("--all", action="store_true", help="Withdraw all injected routes")

    subparsers.add_parser("list", help="List all sessions")

    p_cleanup = subparsers.add_parser("cleanup", help="Emergency cleanup")
    p_cleanup.add_argument("--session-id", required=True)

    p_malform = subparsers.add_parser("malform", help="Send malformed BGP message")
    p_malform.add_argument("--target-ip", dest="target_ip", required=True)
    p_malform.add_argument("--type", required=True, choices=list(malform.MALFORMATIONS.keys()))
    p_malform.add_argument("--local-as", type=int, default=65200)
    p_malform.add_argument("--peer-as", type=int, default=1234567)

    p_hexdump = subparsers.add_parser("hexdump", help="Hexdump Simpson redirect-ip UPDATE")
    p_hexdump.add_argument("--rd", required=True)
    p_hexdump.add_argument("--redirect-ip", required=True)
    p_hexdump.add_argument("--rt", required=True)
    p_hexdump.add_argument("--dest-prefix", dest="dest_prefix")
    p_hexdump.add_argument("--src-prefix", dest="src_prefix")

    p_scale = subparsers.add_parser("scale", help="Bulk inject routes (scale/stress)")
    p_scale.add_argument("--session-id", required=True)
    p_scale.add_argument("--mode", required=True, choices=["batch", "stress", "flowspec-ipv4", "flowspec-ipv6", "flowspec-vpn-ipv4", "flowspec-vpn-ipv6"])
    p_scale.add_argument("--prefix-range", dest="prefix_range", help="START/MASK-END/MASK for batch")
    p_scale.add_argument("--base-prefix", dest="base_prefix", help="Base prefix for stress")
    p_scale.add_argument("--rd", default="1.1.1.1:100")
    p_scale.add_argument("--rt", default=None, help="Route-target (auto-detected per mode if not specified)")
    p_scale.add_argument("--redirect-ip", dest="redirect_ip")
    p_scale.add_argument("--count", type=int, help="Number of routes")
    p_scale.add_argument("--rd-template", dest="rd_template", help="RD template for stress, {n}=index")
    p_scale.add_argument("--rate", type=float, help="Routes per second (optional)")
    p_scale.add_argument("--action", help="FlowSpec action (default: rate-limit 0)")
    p_scale.add_argument("--base-source", dest="base_source", help="Base source prefix for source+dest match (e.g. 192.168.0.0)")
    p_scale.add_argument("--source-mask", dest="source_mask", type=int, help="Source prefix mask (defaults to same as dest mask)")
    p_scale.add_argument("--fast", action="store_true", help="Use fast batch injection (auto for >500 routes)")
    p_scale.add_argument("--preload", action="store_true", help="Restart ExaBGP with routes pre-loaded (fastest for 1K+ routes, drops session briefly)")
    p_scale.add_argument("--withdraw", action="store_true", help="Withdraw routes instead of injecting (reads from session state)")
    p_scale.add_argument("--keep", type=int, default=0, help="Keep first N routes, withdraw the rest (use with --withdraw)")

    p_verify = subparsers.add_parser("verify", help="Quick health check: ExaBGP alive + TCP state")
    p_verify.add_argument("--session-id", required=True)

    p_diag = subparsers.add_parser("diagnose", help="Diagnose Connect state: check BgpTrius iptables, optionally fix")
    p_diag.add_argument("--session-id", required=True)
    p_diag.add_argument("--device-ip", dest="device_ip", help="Device OOB IP for SSH (auto-resolved from SCALER DB if omitted)")
    p_diag.add_argument("--username", default=None, help="SSH username (default: from SCALER DB or dnroot)")
    p_diag.add_argument("--password", default=None, help="SSH password (default: from SCALER DB or dnroot)")
    p_diag.add_argument("--fix", action="store_true", help="Auto-apply iptables ACCEPT rules if BgpTrius blocking detected")

    p_resolve = subparsers.add_parser("resolve", help="Resolve a device hostname to a working SSH IP (cluster-aware probe)")
    p_resolve.add_argument("--device", required=True, help="Device hostname or alias (e.g. PE-4)")
    p_resolve.add_argument("--refresh", action="store_true", help="Ignore cache and re-probe candidate IPs")

    p_attr = subparsers.add_parser("attribute-test", help="Build/inject attribute test route")
    p_attr.add_argument("--test-name", required=True, choices=list(ATTRIBUTE_TESTS.keys()))
    p_attr.add_argument("--session-id", help="Session to inject into")
    p_attr.add_argument("--inject", action="store_true", help="Inject via pipe")
    p_attr.add_argument("--prefix")
    p_attr.add_argument("--nexthop")
    p_attr.add_argument("--rd")
    p_attr.add_argument("--rt")
    p_attr.add_argument("--redirect-ip", dest="redirect_ip")
    p_attr.add_argument("--dest-prefix", dest="dest_prefix")

    p_eng_start = subparsers.add_parser("engine-start", help="Start GoBGP (unicast/VPN/EVPN)")
    p_eng_start.add_argument("--session-id", default="default")
    p_eng_start.add_argument("--peer-ip", required=True)
    p_eng_start.add_argument("--peer-as", required=True)
    p_eng_start.add_argument("--local-as", default="65200")
    p_eng_start.add_argument("--families", help="Comma-separated: ipv4-unicast, ipv4-vpn, l2vpn-evpn")
    p_eng_start.add_argument("--grpc-port", default="50051")

    p_eng_stop = subparsers.add_parser("engine-stop", help="Stop GoBGP")
    p_eng_stop.add_argument("--session-id", default="default")

    p_eng_inject = subparsers.add_parser("engine-inject", help="Inject via GoBGP")
    p_eng_inject.add_argument("--session-id", default="default")
    p_eng_inject.add_argument("--type", required=True, choices=["unicast", "l3vpn", "flowspec", "flowspec-vpn"])
    p_eng_inject.add_argument("--prefix")
    p_eng_inject.add_argument("--nexthop")
    p_eng_inject.add_argument("--rd")
    p_eng_inject.add_argument("--rt")
    p_eng_inject.add_argument("--match")
    p_eng_inject.add_argument("--action")
    p_eng_inject.add_argument("--grpc-port", default="50051")

    p_vpls = subparsers.add_parser("vpls", help="Inject/withdraw VPLS pseudowire route")
    p_vpls.add_argument("--session-id", required=True)
    p_vpls.add_argument("--rd", required=True, help="Route Distinguisher (e.g. 3.3.3.3:500)")
    p_vpls.add_argument("--ve-id", type=int, required=True, help="VPLS Edge ID (endpoint)")
    p_vpls.add_argument("--base", type=int, required=True, help="Label base")
    p_vpls.add_argument("--offset", type=int, default=1, help="Label offset (default: 1)")
    p_vpls.add_argument("--size", type=int, default=8, help="Label block size (default: 8)")
    p_vpls.add_argument("--next-hop", required=True, help="MPLS next-hop IP")
    p_vpls.add_argument("--rt", required=True, help="Route target (e.g. 100:100)")
    p_vpls.add_argument("--withdraw", action="store_true", help="Withdraw instead of announce")
    p_vpls.add_argument("--no-control-word", action="store_true", help="Disable control word flag")
    p_vpls.add_argument("--fat-label", action="store_true", help="Enable FAT label flags")
    p_vpls.add_argument("--mtu", type=int, default=0, help="L2 MTU (default: 0)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "inject": cmd_inject,
        "withdraw": cmd_withdraw,
        "list": cmd_list,
        "cleanup": cmd_cleanup,
        "malform": cmd_malform,
        "hexdump": cmd_hexdump,
        "scale": cmd_scale,
        "verify": cmd_verify,
        "diagnose": cmd_diagnose,
        "resolve": cmd_resolve,
        "attribute-test": cmd_attribute_test,
        "engine-start": cmd_engine_start,
        "engine-stop": cmd_engine_stop,
        "engine-inject": cmd_engine_inject,
        "vpls": cmd_vpls,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
