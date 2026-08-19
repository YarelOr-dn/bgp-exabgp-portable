#!/usr/bin/env python3
"""
session.py - Session state management for BGP Peering Tool

Handles: load/save/list sessions, process lifecycle helpers, orphan cleanup.
"""

import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent
SESSIONS_DIR = BASE_DIR / "sessions"
LOGS_DIR = BASE_DIR / "logs"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_session(session_id):
    """Load session state from JSON file."""
    path = SESSIONS_DIR / f"{session_id}.json"
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def save_session(session_id, data):
    """Save session state to JSON file."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    path = SESSIONS_DIR / f"{session_id}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def setup_log(session_id):
    """Setup logging to file and return log path."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return LOGS_DIR / f"{session_id}.log"


def log(msg, log_path=None):
    """Log to stdout and optionally to file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    if log_path and log_path != "":
        try:
            with open(log_path, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass


def is_process_alive(pid):
    """Check if a process is running by PID."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def kill_orphan_exabgp_processes(spare_pid=None, spare_session_ids=None, log_path=None):
    """Find and kill orphaned ExaBGP processes. Never kills ExaBGP of other active sessions.

    CRITICAL: Multiple ExaBGP instances connecting to the same peer causes
    BGP NOTIFICATION 6/7 (Connection Collision Resolution). Sessions can run
    concurrently (pe_4, pe_1, etc.) - do NOT kill one when starting another.

    Args:
        spare_pid: If set, do NOT kill this PID (e.g. current process).
        spare_session_ids: If set, do NOT kill ExaBGP PIDs of these session_ids.
        log_path: Optional log file path.
    Returns:
        Number of orphaned processes killed.
    """
    spare_pids = set()
    if spare_pid:
        spare_pids.add(spare_pid)
    if spare_session_ids is not None:
        for sid in spare_session_ids:
            s = load_session(sid)
            if s and s.get("status") == "active":
                pid = s.get("exabgp_pid")
                if pid and is_process_alive(pid):
                    spare_pids.add(pid)
    else:
        for s in list_sessions():
            pid = s.get("exabgp_pid")
            if pid and s.get("exabgp_alive"):
                spare_pids.add(pid)

    # Command-line markers that MENTION "exabgp" but are NOT the ExaBGP daemon.
    # Killing these was the root cause of the user-exabgp-mcp restart loop
    # (368x): the MCP server is launched as `python3 -m user_exabgp_mcp.server`,
    # whose command line contains "exabgp", so the broad "exabgp in line" match
    # SIGKILLed it every watchdog cycle. NEVER kill these.
    NON_DAEMON_MARKERS = (
        "user_exabgp_mcp", "_mcp.server", "mcp_common", "mcp_cli.py",
        "dnos_mcp.py", "bgp_watchdog", "bgp_tool.py", "session.py",
        "recipe_to_dnos_e2e", "grep", "vim ", "nano ", "less ", "tail ",
        "/cat ", "journalctl",
    )
    my_pid = os.getpid()
    killed = 0
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "exabgp" not in line:
                continue
            if any(marker in line for marker in NON_DAEMON_MARKERS):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            if pid == my_pid or pid in spare_pids:
                continue
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
                if log_path:
                    log(f"Killed orphan ExaBGP/socat process PID {pid}", log_path)
            except (OSError, ProcessLookupError):
                pass
    except Exception as e:
        if log_path:
            log(f"Warning during orphan cleanup: {e}", log_path)
    if killed > 0:
        if log_path:
            log(f"Killed {killed} orphaned ExaBGP/socat process(es). "
                "Waiting 3s for TCP state to clear.", log_path)
        else:
            print(f"[cleanup] Killed {killed} orphaned ExaBGP/socat process(es). "
                  "Waiting 3s for TCP state to clear.")
        time.sleep(3)
    return killed


def _find_live_exabgp_pid(config_path):
    """Find a running ExaBGP process by its config file path.
    Returns (pid, True) if found, (None, False) otherwise."""
    if not config_path:
        return None, False
    try:
        import subprocess
        out = subprocess.check_output(
            ["ps", "aux"], timeout=5, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "exabgp" in line and config_path in line and "grep" not in line:
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1]), True
    except Exception:
        pass
    return None, False


def list_sessions():
    """List all sessions with status. Reconciles stale PIDs by scanning running processes."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    sessions = []
    for f in sorted(SESSIONS_DIR.glob("*.json")):
        try:
            with open(f) as fh:
                data = json.load(fh)
                pid = data.get("exabgp_pid")
                alive = is_process_alive(pid) if pid else False

                if not alive:
                    config_path = data.get("exabgp_config", "")
                    live_pid, found = _find_live_exabgp_pid(config_path)
                    if found and live_pid:
                        alive = True
                        pid = live_pid
                        data["exabgp_pid"] = live_pid
                        data["status"] = "active"
                        try:
                            with open(f, "w") as wf:
                                json.dump(data, wf, indent=2)
                        except Exception:
                            pass

                entry = {
                    "session_id": data.get("session_id"),
                    "status": data.get("status") if alive else data.get("status"),
                    "target_device": data.get("target_device"),
                    "dnaas_leaf": data.get("dnaas_leaf"),
                    "peer_ip": data.get("peer_ip"),
                    "device_ip": data.get("device_ip"),
                    "selected_afis": data.get("selected_afis", []),
                    "created": data.get("created"),
                    "exabgp_pid": pid,
                    "exabgp_alive": alive,
                    "routes_injected": data.get("routes_injected",
                        len(data.get("injected_routes", [])) +
                        sum(s.get("injected_count", 0) for s in data.get("scale_injections", []))
                    ),
                }
                adv = data.get("advertised_state", {}).get("summary")
                if adv:
                    entry["advertised_summary"] = adv
                wd_restarts = data.get("watchdog_restarts", 0)
                if wd_restarts:
                    entry["watchdog_restarts"] = wd_restarts
                    entry["last_watchdog_restart"] = data.get("last_watchdog_restart")
                backoff_file = SESSIONS_DIR.parent / "logs" / "watchdog_backoff.json"
                try:
                    with open(backoff_file) as bf:
                        backoff = json.load(bf)
                    sid_backoff = backoff.get(data.get("session_id", ""), {})
                    if sid_backoff.get("last_storm_kill"):
                        entry["last_storm_kill"] = sid_backoff["last_storm_kill"]
                        entry["consecutive_failures"] = sid_backoff.get("consecutive_failures", 0)
                except (FileNotFoundError, json.JSONDecodeError):
                    pass
                sessions.append(entry)
        except Exception as e:
            sessions.append({"file": f.name, "error": str(e)})
    return sessions
