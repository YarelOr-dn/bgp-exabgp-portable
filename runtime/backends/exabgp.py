"""ExaBGP process lifecycle - start, stop, status."""

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / "logs"


def start_exabgp(
    config_path: str,
    session_id: str,
    log_path: Path = None,
) -> tuple:
    """Start ExaBGP process. Returns (pid, exabgp_log_path)."""
    exabgp_log = LOGS_DIR / f"{session_id}_exabgp.log"
    env = os.environ.copy()
    env["exabgp_daemon_daemonize"] = "false"
    env["exabgp_log_enable"] = "true"
    env["exabgp_log_level"] = "INFO"
    env["exabgp_log_all"] = "true"
    env["exabgp_api_pipename"] = "exabgp"
    env["exabgp_api_cli"] = "true"
    env["exabgp_daemon_drop"] = "false"

    exabgp_bin = os.path.expanduser("~/.local/bin/exabgp")
    if not os.path.exists(exabgp_bin):
        exabgp_bin = shutil.which("exabgp") or "exabgp"

    # When config uses passive true + listen 179, ExaBGP needs to bind to
    # privileged port 179. Use a setcap'd Python binary (cap_net_bind_service)
    # so we can run as non-root. Falls back to authbind if available.
    use_setcap_python = None
    use_authbind = False
    try:
        with open(config_path) as f:
            cfg = f.read()
        if "passive true" in cfg and "listen 179" in cfg:
            setcap_bin = "/tmp/python3_bgp"
            if os.path.exists(setcap_bin):
                use_setcap_python = setcap_bin
            else:
                src = shutil.which("python3") or shutil.which("python")
                if src:
                    shutil.copy2(src, setcap_bin)
                    ret = subprocess.run(
                        ["sudo", "setcap", "cap_net_bind_service=+ep", setcap_bin],
                        capture_output=True
                    )
                    if ret.returncode == 0:
                        use_setcap_python = setcap_bin
            if not use_setcap_python:
                use_authbind = (
                    shutil.which("authbind") is not None
                    and os.path.exists("/etc/authbind/byport/179")
                )
    except (OSError, IOError):
        pass

    cmd = [exabgp_bin, config_path]
    if use_setcap_python:
        cmd = [use_setcap_python, exabgp_bin, config_path]
    elif use_authbind:
        cmd = ["authbind", "--deep"] + cmd

    def _set_nice():
        try:
            os.nice(-5)
        except (OSError, PermissionError):
            pass

    logf = open(exabgp_log, "w")
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        preexec_fn=_set_nice if os.name != "nt" else None,
    )
    pid = proc.pid
    logf.close()
    return pid, str(exabgp_log)


def stop_exabgp(pid: int) -> bool:
    """Stop ExaBGP process by PID. Returns True if stopped."""
    if not pid:
        return False
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        for _ in range(5):
            try:
                os.kill(pid, 0)
            except (OSError, ProcessLookupError):
                return True
            time.sleep(1)
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        return True
    except ProcessLookupError:
        return True
    except Exception:
        return False
