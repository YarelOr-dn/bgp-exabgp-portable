#!/usr/bin/env python3
"""BGP Watchdog - Monitors ExaBGP health and manages port 179 guard.

Designed to run periodically via cron (every 30-60s). Detects when ExaBGP
died unexpectedly and:
  1. Closes port 179 guard (prevents RST flood that triggers firewall IDS)
  2. Optionally auto-restarts ExaBGP with its last known config
  3. Logs all actions to the watchdog log

Usage:
    python3 bgp_watchdog.py                    # check + guard only
    python3 bgp_watchdog.py --auto-restart     # check + guard + restart dead sessions
    python3 bgp_watchdog.py --status           # print current state and exit
    python3 bgp_watchdog.py --install-cron     # install cron job
    python3 bgp_watchdog.py --remove-cron      # remove cron job

Cron entry (every 30s via two offset entries):
    * * * * * cd /home/dn/SCALER/FLOWSPEC_VPN/exabgp && python3 bgp_watchdog.py --auto-restart 2>> logs/watchdog.log
    * * * * * sleep 30 && cd /home/dn/SCALER/FLOWSPEC_VPN/exabgp && python3 bgp_watchdog.py --auto-restart 2>> logs/watchdog.log
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

import bgp_guard
import session
from backends import exabgp as exabgp_backend
import pipe

LOG_FILE = BASE_DIR / "logs" / "watchdog.log"
BACKOFF_FILE = BASE_DIR / "logs" / "watchdog_backoff.json"
CRON_MARKER = "# bgp_watchdog"
EXABGP_DIR = str(BASE_DIR)
FORTIGATE_CHECK_TIMEOUT = 2
BACKOFF_INITIAL_S = 30
BACKOFF_MAX_S = 300
BACKOFF_MULTIPLIER = 2


def _is_peer_reachable(peer_ip):
    """Check if peer device is reachable via ICMP ping.
    CRITICAL: Do NOT use nc -z (TCP SYN) to probe port 179! Each SYN
    refreshes the FortiGate IDS quarantine timer, preventing it from
    ever expiring. Ping uses ICMP which the FortiGate doesn't quarantine."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(FORTIGATE_CHECK_TIMEOUT), peer_ip],
            capture_output=True, timeout=FORTIGATE_CHECK_TIMEOUT + 2
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_peer_ip(sess_data):
    """Extract peer IP from session's ExaBGP config."""
    config_path = sess_data.get("exabgp_config", "")
    try:
        with open(config_path) as f:
            for line in f:
                if line.strip().startswith("neighbor "):
                    return line.strip().split()[1]
    except Exception:
        pass
    return sess_data.get("device_ip", "100.70.0.206")


def _is_tcp_established(pid):
    """Check if ExaBGP (or any child in its process group) has an ESTABLISHED
    TCP connection on port 179. ExaBGP 5.x spawns child processes that hold
    the actual TCP socket, so we check for any ESTAB on port 179."""
    try:
        result = subprocess.run(
            ["ss", "-tnp", "sport = :179 or dport = :179"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "ESTAB" in line and "179" in line:
                return True
        return False
    except Exception:
        return False


def _load_backoff_state():
    """Load persistent backoff state between cron runs."""
    try:
        with open(BACKOFF_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_backoff_state(state):
    try:
        BACKOFF_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BACKOFF_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass


def _get_backoff_delay(sid, backoff_state):
    """Get current backoff delay for a session. Returns seconds to wait."""
    entry = backoff_state.get(sid, {})
    failures = entry.get("consecutive_failures", 0)
    if failures == 0:
        return 0
    delay = min(BACKOFF_INITIAL_S * (BACKOFF_MULTIPLIER ** (failures - 1)), BACKOFF_MAX_S)
    return delay


def _reinject_routes(sid, sess_data):
    """Re-inject previously tracked routes after a successful watchdog restart.

    ExaBGP is stateless across restarts -- routes injected via the named pipe
    are not persisted in ExaBGP's config. The session JSON tracks them in
    injected_routes[]. After the watchdog restarts ExaBGP and TCP is ESTABLISHED,
    this function writes them back to the pipe so PE-4 sees them again.
    """
    raw_routes = sess_data.get("injected_routes", [])
    if not raw_routes:
        return

    unique_routes = []
    seen = set()
    for entry in raw_routes:
        route_str = entry.get("route", "") if isinstance(entry, dict) else str(entry)
        if route_str and route_str not in seen:
            seen.add(route_str)
            unique_routes.append(route_str)

    if not unique_routes:
        return

    log(f"[REINJECT] {sid}: waiting 4s for BGP to fully establish before re-injecting "
        f"{len(unique_routes)} route(s)...")
    time.sleep(4)

    success = 0
    for route_str in unique_routes:
        try:
            if pipe.write_route(route_str):
                log(f"[REINJECT] {sid}: OK -- {route_str[:80]}...")
                success += 1
            else:
                log(f"[REINJECT] {sid}: FAILED (pipe write) -- {route_str[:80]}...")
        except Exception as e:
            log(f"[REINJECT] {sid}: ERROR -- {e}")

    log(f"[REINJECT] {sid}: {success}/{len(unique_routes)} routes re-injected")


def _should_attempt_restart(sid, backoff_state):
    """Check if enough time has passed since last failure for this session."""
    entry = backoff_state.get(sid, {})
    last_fail = entry.get("last_failure_ts")
    if not last_fail:
        return True
    delay = _get_backoff_delay(sid, backoff_state)
    elapsed = time.time() - last_fail
    return elapsed >= delay

def _resolve_device_creds():
    """Get PE-4 OOB credentials from SCALER DB.
    For cluster devices (hostname contains 'CL'), resolves the active NCC
    hostname via SSH to the management VIP, then returns the NCC hostname
    as the SSH target instead of the VIP (VIP rejects SSH on clusters)."""
    db_path = Path.home() / "SCALER" / "db" / "devices.json"
    mgmt_ip = "100.64.4.98"
    username = "dnroot"
    password = "dnroot"
    is_cluster = False
    try:
        with open(db_path) as f:
            db = json.load(f)
        for d in db.get("devices", []):
            if "PE-4" in d.get("hostname", "").upper() or "pe4" in d.get("id", ""):
                mgmt_ip = d.get("ip", mgmt_ip)
                username = d.get("username", username)
                import base64
                raw_pw = d.get("password", password)
                try:
                    password = base64.b64decode(raw_pw).decode()
                except Exception:
                    password = raw_pw
                if "_CL_" in d.get("hostname", "").upper() or "CL" in d.get("hostname", "").upper():
                    is_cluster = True
                break
    except Exception:
        pass

    if is_cluster:
        ncc_host = _resolve_active_ncc(mgmt_ip, username, password)
        if ncc_host:
            return ncc_host, username, password

    return mgmt_ip, username, password


NCC_STATE_FILE = Path.home() / ".cursor" / "bgp-reference" / "active_ncc.json"
NCC_CACHE_TTL = 300


def _resolve_active_ncc(mgmt_ip, username, password):
    """For cluster devices, find the active NCC serial number (SSH hostname).

    Resolution order:
      1. Cache (valid for 5 min -- NCC switchovers are rare but must be detected)
      2. Query device via 'show system' through MCP run_show_command
      3. SSH-probe both NCCs (try each, the one that accepts is active)
      4. Last-known fallback from cache (ignore TTL)
    """
    cached = _load_ncc_cache()
    if cached and (time.time() - cached.get("resolved_at", 0)) < NCC_CACHE_TTL:
        return cached["hostname"]

    discovered = _discover_active_ncc_from_device()
    if discovered:
        _save_ncc_cache(discovered)
        if cached and cached.get("hostname") != discovered:
            log(f"[NCC] Active NCC changed: {cached['hostname']} -> {discovered}")
        return discovered

    probed = _probe_ncc_ssh(username, password, cached)
    if probed:
        _save_ncc_cache(probed)
        return probed

    if cached:
        log(f"[NCC] Using stale cache: {cached['hostname']} (discovery failed)")
        return cached["hostname"]

    return "kvm108-cl408d-ncc1"


def _load_ncc_cache():
    try:
        with open(NCC_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def _save_ncc_cache(hostname):
    try:
        NCC_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(NCC_STATE_FILE, "w") as f:
            json.dump({"hostname": hostname, "resolved_at": time.time()}, f)
    except Exception:
        pass


def _invalidate_ncc_cache():
    """Force re-resolution on next call by setting resolved_at to 0."""
    try:
        if NCC_STATE_FILE.exists():
            with open(NCC_STATE_FILE) as f:
                data = json.load(f)
            data["resolved_at"] = 0
            with open(NCC_STATE_FILE, "w") as f:
                json.dump(data, f)
    except Exception:
        pass


def _discover_active_ncc_from_device():
    """Parse 'show system' output to find the active NCC serial number.
    Uses the SCALER DB devices.json to get NCC info, or queries via SSH
    to the MCP-connected device (MCP uses its own stored connection)."""
    db_path = Path.home() / "SCALER" / "db" / "devices.json"
    try:
        show_sys = _run_show_system_via_mcp()
        if show_sys:
            return _parse_active_ncc_serial(show_sys)
    except Exception:
        pass
    return None


def _run_show_system_via_mcp():
    """Try to get 'show system' output via a lightweight method.
    Reads the Network Mapper's cached device data if available."""
    device_dir = Path.home() / "SCALER" / "db"
    cache_file = device_dir / "pe4_show_system.cache"
    try:
        if cache_file.exists():
            import stat
            age = time.time() - cache_file.stat().st_mtime
            if age < 600:
                return cache_file.read_text()
    except Exception:
        pass

    try:
        import paramiko
        cached = _load_ncc_cache()
        targets = []
        if cached:
            targets.append(cached["hostname"])
        targets.extend(["kvm108-cl408d-ncc1", "kvm108-cl408d-ncc0"])
        seen = set()
        for target in targets:
            if target in seen:
                continue
            seen.add(target)
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target, port=22, username="dnroot", password="dnroot", timeout=5)
                chan = client.invoke_shell(width=200, height=50)
                chan.settimeout(10)
                time.sleep(1)
                chan.recv(65535)
                chan.send("show system | no-more\n")
                time.sleep(3)
                output = chan.recv(65535).decode(errors="replace")
                chan.close()
                client.close()
                if "NCC" in output and "active-up" in output:
                    try:
                        cache_file.parent.mkdir(parents=True, exist_ok=True)
                        cache_file.write_text(output)
                    except Exception:
                        pass
                    return output
            except Exception:
                continue
    except Exception:
        pass
    return None


def _parse_active_ncc_serial(show_system_output):
    """Parse 'show system' table to find the NCC with 'active-up' operational state.
    Returns its Serial Number field (the SSH hostname).

    Table columns (pipe-separated, 0-indexed after split):
      [1] Type | [2] Id | [3] Admin | [4] Operational | [5] Model |
      [6] Uptime | [7] Description | [8] Serial Number
    """
    for line in show_system_output.splitlines():
        if "NCC" in line and "active-up" in line:
            parts = line.split("|")
            if len(parts) >= 9:
                serial = parts[8].strip()
                if serial:
                    return serial
    return None


def _probe_ncc_ssh(username, password, cached):
    """Try SSH to each known NCC hostname. The active NCC accepts SSH;
    the standby may reject or timeout."""
    import paramiko
    candidates = ["kvm108-cl408d-ncc0", "kvm108-cl408d-ncc1"]
    if cached:
        known = cached.get("hostname", "")
        if known in candidates:
            candidates.remove(known)
            candidates.insert(0, known)

    for ncc in candidates:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ncc, port=22, username=username, password=password, timeout=5)
            client.close()
            return ncc
        except Exception:
            continue
    return None


# DNAAS fabric p2p ranges (inband, directly-connected, do NOT cross the FortiGate/OOB DG).
FABRIC_PEER_SUBNETS = ("100.70.212.",)


def _is_fabric_peer(peer_ip):
    """True if the BGP peer is on a directly-connected DNAAS fabric p2p (inband).

    Such peers do NOT traverse the FortiGate / OOB default-gateway, so the OOB
    DG-ARP restart gate (_clear_device_arp_and_verify_dg) is irrelevant and would
    wrongly block auto-restart -- skip it for these."""
    return bool(peer_ip) and any(str(peer_ip).startswith(p) for p in FABRIC_PEER_SUBNETS)


def _clear_device_arp_and_verify_dg(sess_data, _retried=False):
    """Clear ARP on PE-4, then ping DG from SERVER to force ARP re-resolution.

    DNOS CLI does NOT have a native 'ping' command (produces 'Unknown word').
    Instead we: clear arp on device via SSH, close SSH, then ping the peer IP
    from the server. The ICMP echo-reply forces PE-4 to ARP-resolve the DG
    (FortiGate 100.70.0.254) for the return path.

    If SSH fails and we detect a possible NCC switchover, invalidates cache
    and retries once with the re-resolved NCC hostname.

    Sequence:
      1. SSH to active NCC hostname (cluster) or mgmt IP (standalone)
      2. clear arp (DNOS CLI command -- works)
      3. Close SSH
      4. From server: ping peer IP -- forces device to ARP for DG on reply
      5. From server: ping DG IP -- verify FortiGate path is up
      6. Return True only if both pings succeed
    """
    import paramiko
    DG_IP = "100.70.0.254"
    peer_ip = _get_peer_ip(sess_data)
    ssh_target, username, password = _resolve_device_creds()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ssh_target, port=22, username=username, password=password, timeout=10)
        chan = client.invoke_shell(width=200, height=50)
        chan.settimeout(15)
        time.sleep(1)
        chan.recv(65535)

        chan.send("clear arp\n")
        time.sleep(2)
        chan.recv(65535)
        log(f"[ARP] Cleared ARP on {ssh_target}")

        chan.close()
        client.close()

    except Exception as e:
        log(f"[ARP] Failed to clear ARP on {ssh_target}: {e}")
        if not _retried and ("Authentication" in str(e) or "connect" in str(e).lower()):
            log(f"[NCC] SSH to {ssh_target} failed -- possible NCC switchover, invalidating cache")
            _invalidate_ncc_cache()
            ssh_target2, _, _ = _resolve_device_creds()
            if ssh_target2 != ssh_target:
                log(f"[NCC] Re-resolved active NCC: {ssh_target} -> {ssh_target2}, retrying ARP clear")
                return _clear_device_arp_and_verify_dg(sess_data, _retried=True)
        return False

    time.sleep(1)

    dg_ok = _is_peer_reachable(DG_IP)
    if not dg_ok:
        log(f"[ARP] DG {DG_IP} unreachable from server -- FortiGate path broken")
        return False
    log(f"[ARP] DG {DG_IP} reachable from server")

    peer_ok = _is_peer_reachable(peer_ip)
    if not peer_ok:
        log(f"[ARP] Peer {peer_ip} unreachable from server after ARP clear -- L2 path broken")
        return False
    log(f"[ARP] Peer {peer_ip} reachable from server -- ARP refreshed via ICMP reply path")
    return True


def _is_exabgp_passive(config_path):
    """Check if ExaBGP config uses passive mode (listen only, no outbound connect)."""
    try:
        with open(config_path) as f:
            for line in f:
                stripped = line.strip()
                if stripped == "passive true;" or stripped == "passive true":
                    return True
                if stripped.startswith("listen "):
                    return True
    except Exception:
        pass
    return False


def _fix_passive_config(config_path):
    """Switch an ExaBGP config from passive to active mode.
    Passive-passive deadlock: both sides listen, neither connects.
    Fix: ExaBGP connects (active), device listens (passive enabled)."""
    try:
        with open(config_path) as f:
            lines = f.readlines()
        fixed = []
        changed = False
        for line in lines:
            stripped = line.strip()
            if stripped in ("passive true;", "passive true"):
                fixed.append(line.replace("passive true", "passive false"))
                changed = True
            elif stripped.startswith("listen "):
                fixed.append(line.replace("listen", "connect", 1))
                changed = True
            else:
                fixed.append(line)
        if changed:
            with open(config_path, "w") as f:
                f.writelines(fixed)
            log(f"[FIX] Switched {config_path} from passive to active mode "
                f"(passive false; connect 179;)")
    except Exception as e:
        log(f"[ERROR] Failed to fix passive config {config_path}: {e}")


def _is_tcp_179_open(peer_ip):
    """Single TCP probe to port 179 on the peer. Returns True if connection
    succeeds (port open, FortiGate not blocking). Uses a raw socket with
    short timeout to send exactly ONE SYN -- not a storm."""
    import socket as _sock
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((peer_ip, 179))
        s.close()
        return result == 0
    except Exception:
        return False


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def check_and_guard(auto_restart=False):
    """Main watchdog loop iteration.

    Two-pass approach: scan all sessions first, then act. This prevents
    close_port() from killing the ACCEPT rule when a dead session is found
    but other sessions are still alive.
    """
    bgp_guard.install()

    sessions = session.list_sessions()
    active_sessions = [s for s in sessions if s.get("status") == "active"]

    if not active_sessions:
        guard_st = bgp_guard.status()
        if guard_st["accept_rule"]:
            bgp_guard.close_port()
            log("No active sessions but ACCEPT was open -- closed guard")
        return

    backoff_state = _load_backoff_state()

    alive_sids = []
    dead_sessions = []
    storm_sessions = []
    for sess in active_sessions:
        sid = sess.get("session_id", "?")
        pid = sess.get("exabgp_pid")
        alive = session.is_process_alive(pid) if pid else False
        if alive:
            tcp_ok = _is_tcp_established(pid)
            if tcp_ok:
                alive_sids.append(sid)
                if sid in backoff_state:
                    del backoff_state[sid]
                    _save_backoff_state(backoff_state)
                sess_data = session.load_session(sid)
                if sess_data and sess_data.get("reinject_pending"):
                    _reinject_routes(sid, sess_data)
                    sess_data["reinject_pending"] = False
                    session.save_session(sid, sess_data)
            else:
                storm_sessions.append(sess)
        else:
            dead_sessions.append(sess)

    for sess in storm_sessions:
        sid = sess.get("session_id", "?")
        pid = sess.get("exabgp_pid")
        sess_data = session.load_session(sid)
        last_restart = sess_data.get("last_watchdog_restart") or sess_data.get("created", "") if sess_data else ""
        try:
            from datetime import datetime as _dt
            restart_ts = _dt.fromisoformat(last_restart.replace("Z", "+00:00"))
            age_s = (datetime.now(timezone.utc) - restart_ts).total_seconds()
        except Exception:
            age_s = 999
        if age_s < 30:
            log(f"[GRACE] Session {sid} (PID {pid}) -- TCP not yet established but "
                f"started {age_s:.0f}s ago (grace period 30s). Skipping storm kill.")
            alive_sids.append(sid)
            continue

        config_path = sess_data.get("exabgp_config", "") if sess_data else ""
        is_passive = _is_exabgp_passive(config_path)
        if is_passive:
            log(f"[DEADLOCK] Session {sid} (PID {pid}) -- ExaBGP is in PASSIVE mode "
                f"(listen only). Device likely also passive. This is a TCP deadlock, "
                f"NOT a SYN storm. Killing and switching to active mode.")
            try:
                exabgp_backend.stop_exabgp(pid)
                session.kill_orphan_exabgp_processes(spare_pid=os.getpid())
            except Exception:
                pass
            _fix_passive_config(config_path)
            sess_data_dl = session.load_session(sid)
            if sess_data_dl:
                sess_data_dl["watchdog_deadlock_fixes"] = sess_data_dl.get("watchdog_deadlock_fixes", 0) + 1
                session.save_session(sid, sess_data_dl)
            dead_sessions.append(sess)
            continue

        log(f"[STORM] Session {sid} (PID {pid}) -- ExaBGP ALIVE but TCP NOT established "
            f"for {age_s:.0f}s (reconnect storm). Killing to prevent FortiGate IDS trigger.")
        try:
            exabgp_backend.stop_exabgp(pid)
            session.kill_orphan_exabgp_processes(spare_pid=os.getpid())
        except Exception:
            pass
        bgp_guard.close_port()
        entry = backoff_state.get(sid, {"consecutive_failures": 0})
        entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
        entry["last_failure_ts"] = time.time()
        entry["last_storm_kill"] = datetime.now(timezone.utc).isoformat()
        backoff_state[sid] = entry
        _save_backoff_state(backoff_state)
        sess_data_sk = session.load_session(sid)
        if sess_data_sk:
            sess_data_sk["watchdog_storm_kills"] = sess_data_sk.get("watchdog_storm_kills", 0) + 1
            session.save_session(sid, sess_data_sk)
        dead_sessions.append(sess)
        delay = _get_backoff_delay(sid, backoff_state)
        log(f"  Backoff: attempt #{entry['consecutive_failures']}, "
            f"next retry in {delay}s")

    for sess in dead_sessions:
        sid = sess.get("session_id", "?")
        pid = sess.get("exabgp_pid")
        if sess not in storm_sessions:
            log(f"[ALERT] Session {sid} (PID {pid}) -- ExaBGP DEAD")

    if not alive_sids and not auto_restart:
        bgp_guard.close_port()
        log("All sessions dead, no auto-restart -- guard CLOSED")
        return

    if not alive_sids and dead_sessions:
        bgp_guard.close_port()
        log("All sessions dead -- guard CLOSED (prevents RST flood)")

    if alive_sids:
        guard_st = bgp_guard.status()
        if not guard_st["accept_rule"]:
            bgp_guard.open_port()
            log(f"ACCEPT rule was missing but {len(alive_sids)} session(s) alive "
                f"({', '.join(alive_sids)}) -- guard OPENED")

    if auto_restart:
        for sess in dead_sessions:
            sid = sess.get("session_id", "?")
            sess_data = session.load_session(sid)
            if not sess_data:
                log(f"Cannot restart {sid}: session data not found")
                continue

            config_path = sess_data.get("exabgp_config")
            if not config_path or not Path(config_path).exists():
                log(f"Cannot restart {sid}: config missing ({config_path})")
                continue

            if not _should_attempt_restart(sid, backoff_state):
                delay = _get_backoff_delay(sid, backoff_state)
                entry = backoff_state.get(sid, {})
                elapsed = time.time() - entry.get("last_failure_ts", 0)
                remaining = max(0, delay - elapsed)
                log(f"[BACKOFF] {sid}: waiting {remaining:.0f}s more "
                    f"(attempt #{entry.get('consecutive_failures', 0)}, "
                    f"delay={delay}s)")
                continue

            peer_ip = _get_peer_ip(sess_data)
            if not _is_peer_reachable(peer_ip):
                log(f"[WARN] {peer_ip} unreachable (ping failed) -- "
                    f"skipping restart of {sid}")
                entry = backoff_state.get(sid, {"consecutive_failures": 0})
                entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
                entry["last_failure_ts"] = time.time()
                backoff_state[sid] = entry
                _save_backoff_state(backoff_state)
                sess_data["fortigate_blocked_at"] = datetime.now(timezone.utc).isoformat()
                session.save_session(sid, sess_data)
                delay = _get_backoff_delay(sid, backoff_state)
                log(f"  Backoff: next retry in {delay}s")
                continue

            log(f"Auto-restarting {sid} (peer reachable via ICMP)...")

            if _is_fabric_peer(peer_ip):
                log(f"[INBAND] {sid}: peer {peer_ip} is on the DNAAS fabric p2p -- "
                    f"skipping OOB DG-ARP gate (no FortiGate in path)")
                arp_ok = True
            else:
                arp_ok = _clear_device_arp_and_verify_dg(sess_data)
            if not arp_ok:
                log(f"[SKIP] {sid}: DG ARP not valid after clear -- "
                    f"L2 return path broken, skipping restart")
                entry = backoff_state.get(sid, {"consecutive_failures": 0})
                entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
                entry["last_failure_ts"] = time.time()
                backoff_state[sid] = entry
                _save_backoff_state(backoff_state)
                continue

            if not _is_tcp_179_open(peer_ip):
                log(f"[SKIP] {sid}: TCP/179 probe to {peer_ip} failed -- "
                    f"FortiGate still blocking, skipping restart")
                entry = backoff_state.get(sid, {"consecutive_failures": 0})
                entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
                entry["last_failure_ts"] = time.time()
                backoff_state[sid] = entry
                _save_backoff_state(backoff_state)
                continue

            log(f"[PRE-CHECK OK] {sid}: DG ARP valid + TCP/179 open -- starting ExaBGP")

            session.kill_orphan_exabgp_processes(spare_pid=os.getpid())
            pipe.ensure_pipes()
            bgp_guard.open_port()

            new_pid, exabgp_log = exabgp_backend.start_exabgp(
                config_path, sid, LOG_FILE
            )

            time.sleep(4)
            if session.is_process_alive(new_pid):
                tcp_ok = _is_tcp_established(new_pid)
                if tcp_ok:
                    log(f"Restarted {sid} successfully (PID {new_pid}, TCP ESTABLISHED)")
                    if sid in backoff_state:
                        del backoff_state[sid]
                        _save_backoff_state(backoff_state)
                    _reinject_routes(sid, sess_data)
                else:
                    log(f"Restarted {sid} (PID {new_pid}) but TCP not yet established -- "
                        f"will verify and reinject on next cycle")
                    sess_data["reinject_pending"] = True

                sess_data["exabgp_pid"] = new_pid
                sess_data["exabgp_log"] = str(exabgp_log)
                sess_data["last_watchdog_restart"] = datetime.now(timezone.utc).isoformat()
                sess_data["watchdog_restarts"] = sess_data.get("watchdog_restarts", 0) + 1
                sess_data["watchdog_auto_restarts"] = sess_data.get("watchdog_auto_restarts", 0) + 1
                if "fortigate_blocked_at" in sess_data:
                    del sess_data["fortigate_blocked_at"]
                session.save_session(sid, sess_data)
                alive_sids.append(sid)
            else:
                log(f"[ERROR] Restart of {sid} failed -- ExaBGP died again")
                entry = backoff_state.get(sid, {"consecutive_failures": 0})
                entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
                entry["last_failure_ts"] = time.time()
                backoff_state[sid] = entry
                _save_backoff_state(backoff_state)

    if not alive_sids:
        bgp_guard.close_port()
        log("No sessions recovered -- guard CLOSED")


def print_status():
    """Print current watchdog state."""
    guard_st = bgp_guard.status()
    sessions = session.list_sessions()
    active = [s for s in sessions if s.get("status") == "active"]

    print(f"Guard mode: {guard_st['mode']}")
    print(f"  DROP rule:   {'present' if guard_st['drop_rule'] else 'MISSING'}")
    print(f"  ACCEPT rule: {'present' if guard_st['accept_rule'] else 'absent'}")
    print(f"  Detail:      {guard_st['detail']}")
    print(f"\nActive sessions: {len(active)}")
    for s in active:
        sid = s.get("session_id", "?")
        pid = s.get("exabgp_pid")
        alive = session.is_process_alive(pid) if pid else False
        auto_r = s.get("watchdog_auto_restarts", 0)
        storm_k = s.get("watchdog_storm_kills", 0)
        deadlock_f = s.get("watchdog_deadlock_fixes", 0)
        total = s.get("watchdog_restarts", 0)
        status = "ALIVE" if alive else "DEAD"
        parts = []
        if auto_r:
            parts.append(f"auto-restarts: {auto_r}")
        if storm_k:
            parts.append(f"storm-kills: {storm_k}")
        if deadlock_f:
            parts.append(f"deadlock-fixes: {deadlock_f}")
        if not parts and total:
            parts.append(f"restarts: {total}")
        extra = f" ({', '.join(parts)})" if parts else ""
        print(f"  {sid}: PID {pid} -- {status}{extra}")

    cron_installed = _is_cron_installed()
    print(f"\nCron job: {'installed' if cron_installed else 'NOT installed'}")


def _is_cron_installed():
    """Check if watchdog cron is installed."""
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        return CRON_MARKER in r.stdout
    except Exception:
        return False


def install_cron():
    """Install the cron job for periodic watchdog runs."""
    if _is_cron_installed():
        print("Cron job already installed")
        return

    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        existing = r.stdout if r.returncode == 0 else ""
    except Exception:
        existing = ""

    entry_1 = f"* * * * * cd {EXABGP_DIR} && python3 bgp_watchdog.py --auto-restart 2>> logs/watchdog.log {CRON_MARKER}"
    entry_2 = f"* * * * * sleep 30 && cd {EXABGP_DIR} && python3 bgp_watchdog.py --auto-restart 2>> logs/watchdog.log {CRON_MARKER}_30"

    new_cron = existing.rstrip("\n") + "\n" + entry_1 + "\n" + entry_2 + "\n"

    proc = subprocess.run(
        ["crontab", "-"], input=new_cron, capture_output=True, text=True, timeout=5
    )
    if proc.returncode == 0:
        print("Cron job installed (runs every 30 seconds)")
        bgp_guard.install()
        print("Permanent DROP guard installed")
    else:
        print(f"Failed to install cron: {proc.stderr}")


def remove_cron():
    """Remove the watchdog cron job."""
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            print("No crontab found")
            return
        lines = [l for l in r.stdout.splitlines() if CRON_MARKER not in l]
        new_cron = "\n".join(lines) + "\n" if lines else ""
        subprocess.run(["crontab", "-"], input=new_cron, capture_output=True, text=True, timeout=5)
        print("Cron job removed")
    except Exception as e:
        print(f"Error removing cron: {e}")


def main():
    parser = argparse.ArgumentParser(description="BGP ExaBGP Watchdog")
    parser.add_argument("--auto-restart", action="store_true",
                        help="Auto-restart dead ExaBGP sessions")
    parser.add_argument("--status", action="store_true",
                        help="Print current state and exit")
    parser.add_argument("--install-cron", action="store_true",
                        help="Install cron job for periodic monitoring")
    parser.add_argument("--remove-cron", action="store_true",
                        help="Remove cron job")
    args = parser.parse_args()

    if args.status:
        print_status()
    elif args.install_cron:
        install_cron()
    elif args.remove_cron:
        remove_cron()
    else:
        check_and_guard(auto_restart=args.auto_restart)


if __name__ == "__main__":
    main()
