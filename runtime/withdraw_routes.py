#!/usr/bin/env python3
"""
withdraw_routes.py - Standalone route withdrawal tool for ExaBGP sessions.

Withdraw FlowSpec/FlowSpec-VPN/unicast routes from an active ExaBGP session,
with optional DUT verification via SSH.

Usage:
  python3 withdraw_routes.py --session-id pe_4 --all                     # withdraw everything
  python3 withdraw_routes.py --session-id pe_4 --last 5                  # withdraw last 5 routes
  python3 withdraw_routes.py --session-id pe_4 --scale flowspec-vpn-ipv4 # withdraw scale routes
  python3 withdraw_routes.py --session-id pe_4 --scale flowspec-vpn-ipv4 --keep 100  # keep first 100
  python3 withdraw_routes.py --session-id pe_4 --route "withdraw flow route rd ..."  # single route
  python3 withdraw_routes.py --session-id pe_4 --all --verify            # withdraw + check DUT
  python3 withdraw_routes.py --session-id pe_4 --dry-run --all           # show what would be withdrawn
  python3 withdraw_routes.py --list                                      # list sessions + route counts
"""

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

import pipe
import session
from builders.scale import reconstruct_injected_routes


PIPE_IN = Path("/run/exabgp/exabgp.in")


def pipe_write(command, timeout_sec=5):
    """Write to ExaBGP pipe with non-blocking fallback."""
    if not PIPE_IN.exists():
        print(f"  [ERROR] Pipe not found: {PIPE_IN}")
        return False
    try:
        fd = os.open(str(PIPE_IN), os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, (command + "\n").encode())
        os.close(fd)
        return True
    except OSError:
        old = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(timeout_sec)
        try:
            with open(PIPE_IN, "w") as f:
                f.write(command + "\n")
                f.flush()
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            return True
        except (TimeoutError, Exception) as e:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            print(f"  [ERROR] Pipe write failed: {e}")
            return False


def to_withdraw(route):
    """Convert an announce route to withdraw form."""
    if route.startswith("withdraw"):
        return route
    if route.startswith("announce"):
        return route.replace("announce", "withdraw", 1)
    return f"withdraw {route}"


def collect_manual_routes(session_data):
    """Extract all manually injected routes from session."""
    routes = []
    for entry in session_data.get("injected_routes", []):
        r = entry.get("route", entry) if isinstance(entry, dict) else entry
        routes.append(r)
    return routes


def collect_scale_routes(session_data, mode):
    """Reconstruct scale routes for a given mode from session state."""
    for si in session_data.get("scale_injections", []):
        if si["mode"] == mode:
            count = si.get("injected_count", 0)
            return reconstruct_injected_routes(mode, si["params"], count), si
    return [], None


def withdraw_batch(routes, delay=0.02, dry_run=False):
    """Withdraw a list of routes with progress display."""
    total = len(routes)
    success = 0
    failed = 0

    for i, route in enumerate(routes):
        wr = to_withdraw(route)
        if dry_run:
            if i < 5 or i == total - 1:
                print(f"  [DRY] {wr[:100]}...")
            elif i == 5:
                print(f"  ... ({total - 6} more) ...")
            success += 1
            continue

        if pipe_write(wr):
            success += 1
        else:
            failed += 1

        if total > 50 and (i + 1) % 500 == 0:
            pct = ((i + 1) / total) * 100
            print(f"  [{pct:5.1f}%] Withdrawn {i + 1}/{total} ({failed} failed)")

        if delay > 0:
            time.sleep(delay)

    return {"withdrawn": success, "failed": failed, "total": total}


def verify_dut(device_ip, username, password, commands):
    """SSH to DUT and run verification commands. Returns dict of results."""
    try:
        import paramiko
    except ImportError:
        return {"error": "paramiko not installed"}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(device_ip, username=username, password=password, timeout=10)
        shell = client.invoke_shell()
        time.sleep(2)
        shell.recv(4096)

        results = {}
        for name, cmd in commands:
            shell.send(cmd + " | no-more\n")
            time.sleep(3)
            out = shell.recv(65536).decode(errors="replace")
            results[name] = out

        shell.close()
        client.close()
        return results
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return {"error": str(e)}


def resolve_device_creds(session_data):
    """Resolve device OOB IP and credentials from SCALER DB."""
    import base64
    db_path = Path.home() / "SCALER" / "db" / "devices.json"
    if not db_path.exists():
        return None, None, None

    target = session_data.get("target_device", "")
    with open(db_path) as f:
        db = json.load(f)

    for dev in db.get("devices", []):
        hostname = dev.get("hostname", "")
        if target and (target.lower() in hostname.lower() or hostname.lower() in target.lower()):
            try:
                pw = base64.b64decode(dev["password"]).decode()
            except Exception:
                pw = dev["password"]
            return dev["ip"], dev.get("username", "dnroot"), pw
    return None, None, None


def print_summary(result, mode_label, elapsed):
    """Print withdrawal summary."""
    print()
    print("=" * 60)
    print(f"  Withdrawal Complete: {mode_label}")
    print("=" * 60)
    print(f"  Withdrawn: {result['withdrawn']}")
    print(f"  Failed:    {result['failed']}")
    print(f"  Total:     {result['total']}")
    print(f"  Elapsed:   {elapsed:.1f}s")
    if result["total"] > 0 and elapsed > 0:
        print(f"  Rate:      {result['total'] / elapsed:.0f} routes/sec")
    print("=" * 60)


def cmd_list():
    """List all sessions with route counts."""
    sessions = session.list_sessions()
    if not sessions:
        print("No sessions found.")
        return

    print()
    print(f"{'Session ID':<20} {'Status':<10} {'Device':<15} {'Routes':<10} {'ExaBGP':<8}")
    print("-" * 70)
    for s in sessions:
        sid = s.get("session_id", "?")
        status = s.get("status", "?")
        device = s.get("target_device") or s.get("peer_ip", "?")
        routes = s.get("routes_injected", 0)
        alive = "ALIVE" if s.get("exabgp_alive") else "DEAD"
        print(f"{sid:<20} {status:<10} {device:<15} {routes:<10} {alive:<8}")

    print()
    for s in sessions:
        sid = s.get("session_id", "?")
        data = session.load_session(sid)
        if not data:
            continue
        manual = len(data.get("injected_routes", []))
        scales = data.get("scale_injections", [])
        if manual or scales:
            print(f"  {sid}:")
            if manual:
                print(f"    Manual routes: {manual}")
            for si in scales:
                cnt = si.get("injected_count", 0)
                print(f"    Scale {si['mode']}: {cnt} routes")


def main():
    parser = argparse.ArgumentParser(description="Withdraw routes from ExaBGP session")
    parser.add_argument("--session-id", help="Session ID (e.g. pe_4)")
    parser.add_argument("--route", help="Single route string to withdraw")
    parser.add_argument("--last", type=int, help="Withdraw last N manually injected routes")
    parser.add_argument("--all", action="store_true", help="Withdraw ALL routes (manual + scale)")
    parser.add_argument("--manual", action="store_true", help="Withdraw only manually injected routes")
    parser.add_argument("--scale", metavar="MODE", help="Withdraw scale routes for a mode (e.g. flowspec-vpn-ipv4)")
    parser.add_argument("--keep", type=int, default=0, help="Keep first N routes when withdrawing scale (use with --scale)")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between withdrawals in seconds (default: 0.02)")
    parser.add_argument("--verify", action="store_true", help="Verify on DUT after withdrawal via SSH")
    parser.add_argument("--device-ip", help="DUT OOB IP for verification (auto-resolved if omitted)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be withdrawn without doing it")
    parser.add_argument("--list", action="store_true", help="List sessions and route counts")

    args = parser.parse_args()

    if args.list:
        cmd_list()
        return

    if not args.session_id:
        parser.print_help()
        print("\n[ERROR] --session-id is required (or use --list to see sessions)")
        sys.exit(1)

    session_data = session.load_session(args.session_id)
    if not session_data:
        print(f"[ERROR] No session found: {args.session_id}")
        sys.exit(1)

    if not args.dry_run and session_data.get("status") != "active":
        print(f"[WARN] Session {args.session_id} status is '{session_data.get('status')}' (not active)")

    log_path = session.setup_log(args.session_id)
    start_time = time.perf_counter()

    if args.route:
        wr = to_withdraw(args.route)
        print(f"Withdrawing single route: {wr[:80]}...")
        if args.dry_run:
            print("  [DRY RUN] Would withdraw above route")
        else:
            if pipe_write(wr):
                announce_form = wr.replace("withdraw", "announce", 1)
                session_data["injected_routes"] = [
                    r for r in session_data.get("injected_routes", [])
                    if (r.get("route", r) if isinstance(r, dict) else r) != announce_form
                ]
                session.save_session(args.session_id, session_data)
                print("  [OK] Route withdrawn")
            else:
                print("  [ERROR] Failed to withdraw")
                sys.exit(1)

    elif args.last:
        manual = collect_manual_routes(session_data)
        to_remove = manual[-args.last:]
        if not to_remove:
            print("No manual routes to withdraw.")
            return
        print(f"Withdrawing last {len(to_remove)} manually injected route(s)...")
        result = withdraw_batch(to_remove, delay=args.delay, dry_run=args.dry_run)
        if not args.dry_run:
            session_data["injected_routes"] = session_data.get("injected_routes", [])[:-args.last]
            session.save_session(args.session_id, session_data)
        print_summary(result, f"Last {args.last} manual routes", time.perf_counter() - start_time)

    elif args.scale:
        routes, si = collect_scale_routes(session_data, args.scale)
        if not routes:
            print(f"[ERROR] No scale injection found for mode '{args.scale}' in session.")
            sys.exit(1)

        if args.keep > 0 and args.keep < len(routes):
            to_remove = routes[args.keep:]
            print(f"Withdrawing {len(to_remove)} scale routes ({args.scale}), keeping first {args.keep}...")
        else:
            to_remove = routes
            print(f"Withdrawing all {len(to_remove)} scale routes ({args.scale})...")

        result = withdraw_batch(to_remove, delay=args.delay, dry_run=args.dry_run)

        if not args.dry_run:
            if args.keep > 0:
                si["injected_count"] = args.keep
            else:
                session_data["scale_injections"] = [
                    s for s in session_data.get("scale_injections", []) if s is not si
                ]
            session.save_session(args.session_id, session_data)

        print_summary(result, f"Scale {args.scale}", time.perf_counter() - start_time)

    elif args.manual:
        manual = collect_manual_routes(session_data)
        if not manual:
            print("No manual routes to withdraw.")
            return
        print(f"Withdrawing {len(manual)} manually injected route(s)...")
        result = withdraw_batch(manual, delay=args.delay, dry_run=args.dry_run)
        if not args.dry_run:
            session_data["injected_routes"] = []
            session.save_session(args.session_id, session_data)
        print_summary(result, "All manual routes", time.perf_counter() - start_time)

    elif args.all:
        manual = collect_manual_routes(session_data)
        all_routes = list(manual)

        scale_modes = []
        for si in session_data.get("scale_injections", []):
            mode = si["mode"]
            count = si.get("injected_count", 0)
            routes = reconstruct_injected_routes(mode, si["params"], count)
            all_routes.extend(routes)
            scale_modes.append(f"{mode}({count})")

        if not all_routes:
            print("No routes to withdraw.")
            return

        print(f"Withdrawing ALL {len(all_routes)} routes:")
        print(f"  Manual: {len(manual)}")
        if scale_modes:
            print(f"  Scale:  {', '.join(scale_modes)}")

        result = withdraw_batch(all_routes, delay=args.delay, dry_run=args.dry_run)
        if not args.dry_run:
            session_data["injected_routes"] = []
            session_data["scale_injections"] = []
            session.save_session(args.session_id, session_data)
        print_summary(result, "ALL routes", time.perf_counter() - start_time)

    else:
        parser.print_help()
        print("\n[ERROR] Specify --route, --last N, --manual, --scale MODE, or --all")
        sys.exit(1)

    if args.verify and not args.dry_run:
        print("\n--- DUT Verification ---")
        device_ip = args.device_ip
        username = password = None
        if not device_ip:
            device_ip, username, password = resolve_device_creds(session_data)
        if not device_ip:
            print("  [WARN] Cannot resolve device IP for verification. Use --device-ip.")
            return

        username = username or "dnroot"
        password = password or "dnroot"
        print(f"  Checking {device_ip} (waiting 5s for convergence)...")
        time.sleep(5)

        verify_cmds = [
            ("summary", "show bgp ipv4 flowspec-vpn summary"),
            ("ncp", "show flowspec ncp 0"),
        ]
        results = verify_dut(device_ip, username, password, verify_cmds)

        if "error" in results:
            print(f"  [ERROR] Verification failed: {results['error']}")
            return

        for name, output in results.items():
            print(f"\n  [{name.upper()}]")
            for line in output.split("\n"):
                line = line.strip()
                if any(k in line for k in ["PfxAccepted", "Established", "100.64.6.134",
                                            "Flow:", "Status:", "Actions:", "Address-Family"]):
                    print(f"    {line}")


if __name__ == "__main__":
    main()
