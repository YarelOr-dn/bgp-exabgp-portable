#!/usr/bin/env python3
"""
SW-206876 TC runner: 3 scenarios on PE-4 (VRF ALPHA).
  Scenario 1: redirect-to-rt only   -> expected: Redirect-vrf: ZULU, Installed
  Scenario 2: redirect-to-ip only   -> expected: Redirect-ip-nh: 49.49.49.9, Installed
  Scenario 3: both together         -> expected: Redirect-ip-nh + Redirect-vrf, Installed

All scenarios use ExaBGP pipe - no session kill, no clear bgp neighbor.
Same destination prefix (100.100.100.1/32) for all rules.

Usage:
  python3 tc_runner.py 1                # inject scenario 1
  python3 tc_runner.py 1 withdraw       # withdraw scenario 1
  python3 tc_runner.py 2                # inject scenario 2
  python3 tc_runner.py 2 withdraw       # withdraw scenario 2
  python3 tc_runner.py 3                # inject scenario 3
  python3 tc_runner.py 3 withdraw       # withdraw scenario 3
  python3 tc_runner.py all              # inject all 3 sequentially
  python3 tc_runner.py all withdraw     # withdraw all 3
"""

import sys, os, time, subprocess, paramiko

PE4_MGMT = "100.64.4.98"
PE4_USER = "dnroot"
PE4_PASS = "dnroot"
BGP_TOOL = os.path.expanduser("~/SCALER/FLOWSPEC_VPN/exabgp/bgp_tool.py")
SESSION_ID = "pe_4"
FLOWSPEC_DEST = "100.100.100.1/32"

SCENARIOS = {
    "1": {
        "name": "redirect-to-rt ONLY",
        "desc": "1234567:101 -> VRF ZULU",
        "expected": "Redirect-vrf: ZULU, Installed",
        "routes": [
            f"announce flow route rd 4.4.4.4:100 destination {FLOWSPEC_DEST} redirect 1234567:101 extended-community [ target:1234567:300 ]",
        ],
    },
    "2": {
        "name": "redirect-to-ip ONLY (Simpson)",
        "desc": "49.49.49.9",
        "expected": "Redirect-ip-nh: 49.49.49.9, Installed",
        "routes": [
            f"announce flow route rd 4.4.4.4:100 destination {FLOWSPEC_DEST} redirect 49.49.49.9 extended-community [ target:1234567:300 ]",
        ],
    },
    "3": {
        "name": "BOTH redirect-to-ip + redirect-to-rt",
        "desc": "49.49.49.9 + 1234567:101",
        "expected": "Redirect-ip-nh + Redirect-vrf, Installed",
        "routes": [
            f"announce flow route rd 4.4.4.4:100 destination {FLOWSPEC_DEST} redirect 49.49.49.9 extended-community [ target:1234567:300 redirect:1234567:101 ]",
        ],
    },
}


def bgp_tool_inject(route):
    try:
        result = subprocess.run(
            ["python3", BGP_TOOL, "inject", "--session-id", SESSION_ID, "--route", route],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"  [WARN] inject failed: {result.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"  [WARN] inject timed out (30s) -- falling back to direct pipe write")
        return pipe_write(route)


def bgp_tool_withdraw(route):
    withdraw_route = route.replace("announce", "withdraw", 1) if route.startswith("announce") else route
    try:
        result = subprocess.run(
            ["python3", BGP_TOOL, "withdraw", "--session-id", SESSION_ID, "--route", withdraw_route],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"  [WARN] withdraw failed: {result.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"  [WARN] withdraw timed out (30s) -- falling back to direct pipe write")
        return pipe_write(withdraw_route)


def pipe_write(command):
    """Direct write to ExaBGP pipe as fallback when bgp_tool.py hangs.
    Uses O_NONBLOCK to avoid hanging if ExaBGP is not reading."""
    pipe_path = "/run/exabgp/exabgp.in"
    if not os.path.exists(pipe_path):
        print(f"  [ERROR] Pipe not found: {pipe_path}")
        return False
    try:
        fd = os.open(pipe_path, os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, (command + "\n").encode())
        os.close(fd)
        return True
    except OSError as e:
        print(f"  [WARN] Non-blocking pipe write failed ({e}), retrying with blocking open (5s)...")
        import signal
        def _timeout(signum, frame):
            raise TimeoutError("pipe open blocked")
        old = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(5)
        try:
            with open(pipe_path, "w") as f:
                f.write(command + "\n")
                f.flush()
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            return True
        except TimeoutError:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            print(f"  [ERROR] Pipe write blocked for 5s -- ExaBGP may not be reading the pipe")
            return False
        except Exception as e2:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            print(f"  [ERROR] Pipe write failed: {e2}")
            return False


def check_pe4():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PE4_MGMT, username=PE4_USER, password=PE4_PASS, timeout=10)
    shell = client.invoke_shell()
    time.sleep(2)
    shell.recv(4096)

    results = {}
    for name, cmd in [
        ("summary", "show bgp ipv4 flowspec-vpn summary"),
        ("ncp6", "show flowspec ncp 6"),
    ]:
        shell.send(cmd + " | no-more\n")
        time.sleep(3)
        out = shell.recv(65536).decode()
        results[name] = out

    shell.close()
    client.close()
    return results


def print_result(label, results):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    for line in results["ncp6"].split("\n"):
        line = line.strip()
        if any(k in line for k in ["Actions:", "Status:", "Vrf:", "Flow:", "Address-Family",
                                     "Redirect-vrf", "Redirect-ip"]):
            print(f"  {line}")
    for line in results["summary"].split("\n"):
        if "100.64.6.134" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p in ("Active", "Idle", "Connect") or p.isdigit():
                    if i == len(parts) - 1:
                        print(f"  PfxAccepted: {p}")
                        break
    print()


def run_inject(scenario_id):
    sc = SCENARIOS[scenario_id]
    print(f"\n[Scenario {scenario_id}] Injecting {sc['name']} ({sc['desc']})...")
    for i, route in enumerate(sc["routes"]):
        print(f"  Route {i+1}/{len(sc['routes'])}: {route[:80]}...")
        bgp_tool_inject(route)
        time.sleep(1)
    time.sleep(5)
    results = check_pe4()
    print_result(f"SCENARIO {scenario_id}: {sc['name']}", results)
    print(f"  Expected: {sc['expected']}")


def run_withdraw(scenario_id):
    sc = SCENARIOS[scenario_id]
    print(f"\n[Scenario {scenario_id}] Withdrawing {sc['name']} ({sc['desc']})...")
    for i, route in enumerate(sc["routes"]):
        print(f"  Withdrawing route {i+1}/{len(sc['routes'])}: {route[:80]}...")
        bgp_tool_withdraw(route)
        time.sleep(1)
    time.sleep(5)
    results = check_pe4()
    print_result(f"SCENARIO {scenario_id} AFTER WITHDRAW", results)
    print(f"  All routes for scenario {scenario_id} withdrawn.")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0)

    scenario = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "inject"

    valid_scenarios = list(SCENARIOS.keys()) + ["all"]
    if scenario not in valid_scenarios:
        print(f"[ERROR] Unknown scenario '{scenario}'. Use: 1, 2, 3, or all")
        sys.exit(1)

    if action not in ("inject", "withdraw"):
        print(f"[ERROR] Unknown action '{action}'. Use: inject (default) or withdraw")
        sys.exit(1)

    print("=" * 60)
    print("  SW-206876 FlowSpec-VPN Redirect Priority Test")
    print(f"  Device: PE-4 (YOR_CL_PE-4)")
    print(f"  VRF: ALPHA (FlowSpec RT: 1234567:300)")
    print(f"  Action: {action.upper()}")
    print("=" * 60)

    targets = list(SCENARIOS.keys()) if scenario == "all" else [scenario]

    for sc_id in targets:
        if action == "inject":
            run_inject(sc_id)
        else:
            run_withdraw(sc_id)

    print(f"\n{'='*60}")
    print(f"  DONE -- {action.upper()} for scenario(s): {', '.join(targets)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
