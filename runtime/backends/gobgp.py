"""GoBGP daemon lifecycle and route injection."""

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).parent.parent
SESSIONS_DIR = BASE_DIR / "sessions"
LOGS_DIR = BASE_DIR / "logs"

GOBGPD_BIN = os.path.expanduser("~/bin/gobgpd")
GOBGP_BIN = os.path.expanduser("~/bin/gobgp")

DNOS_TO_GOBGP_AFI = {
    "ipv4-unicast": "ipv4-unicast",
    "ipv6-unicast": "ipv6-unicast",
    "ipv4-flowspec": "ipv4-flowspec",
    "ipv4-flowspec-vpn": "l3vpn-ipv4-flowspec",
    "ipv6-flowspec": "ipv6-flowspec",
    "ipv6-flowspec-vpn": "l3vpn-ipv6-flowspec",
    "ipv4-vpn": "l3vpn-ipv4-unicast",
    "ipv6-vpn": "l3vpn-ipv6-unicast",
    "ipv4-labeled-unicast": "ipv4-labelled-unicast",
    "ipv6-labeled-unicast": "ipv6-labelled-unicast",
    "ipv4-multicast": "ipv4-multicast",
    "l2vpn-evpn": "l2vpn-evpn",
    "l2vpn-vpls": "l2vpn-vpls",
    "link-state": "ls-ls",
}

DNOS_TO_GOBGP_CLI = {
    "ipv4-unicast": "ipv4",
    "ipv6-unicast": "ipv6",
    "ipv4-flowspec": "ipv4-flowspec",
    "ipv4-flowspec-vpn": "ipv4-l3vpn-flowspec",
    "ipv6-flowspec": "ipv6-flowspec",
    "ipv6-flowspec-vpn": "ipv6-l3vpn-flowspec",
    "ipv4-vpn": "vpnv4",
    "ipv6-vpn": "vpnv6",
    "l2vpn-evpn": "evpn",
}


def _run(cmd: str, timeout: int = 30) -> Tuple[int, str]:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()
        if result.stderr.strip():
            output += "\n" + result.stderr.strip()
        return result.returncode, output
    except subprocess.TimeoutExpired:
        return 1, "Command timed out"
    except Exception as e:
        return 1, str(e)


class GoBGPManager:
    """Manages GoBGP daemon and route injection."""

    def __init__(self, session_id: str = "default"):
        self.session_id = session_id
        self.config_path = Path(f"/tmp/gobgpd_{session_id}.toml")
        self.log_path = LOGS_DIR / f"gobgpd_{session_id}.log"
        self.pid: Optional[int] = None
        self.peer_ip: Optional[str] = None
        self.peer_as: Optional[int] = None
        self.local_as: int = 65200
        self.local_address: str = "100.64.6.134"
        self.router_id: str = "100.64.6.134"
        self.grpc_port: int = 50051
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    def generate_config(
        self,
        peer_ip: str,
        peer_as: int,
        local_as: int = 65200,
        local_address: str = "100.64.6.134",
        router_id: str = "100.64.6.134",
        families: Optional[List[str]] = None,
        hold_time: int = 600,
        grpc_port: int = 50051,
    ) -> str:
        self.peer_ip = peer_ip
        self.peer_as = peer_as
        self.local_as = local_as
        self.local_address = local_address
        self.router_id = router_id
        self.grpc_port = grpc_port

        if families is None:
            families = list(DNOS_TO_GOBGP_AFI.keys())

        afi_blocks = []
        for fam in families:
            gobgp_name = DNOS_TO_GOBGP_AFI.get(fam, fam)
            afi_blocks.append(f"""[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
    afi-safi-name = "{gobgp_name}"
""")

        afi_section = "\n".join(afi_blocks)
        config = f"""[global.config]
  as = {local_as}
  router-id = "{router_id}"
  port = -1

[global.apply-policy.config]
  default-import-policy = "accept-route"
  default-export-policy = "accept-route"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "{peer_ip}"
    peer-as = {peer_as}
  [neighbors.timers.config]
    hold-time = {hold_time}
    keepalive-interval = {hold_time // 3}
  [neighbors.transport.config]
    local-address = "{local_address}"
    passive-mode = false
    remote-port = 179
    ttl = 64
  [neighbors.ebgp-multihop.config]
    enabled = true
    multihop-ttl = 64
{afi_section}
"""
        self.config_path.write_text(config)
        return str(self.config_path)

    def start(
        self,
        peer_ip: str,
        peer_as: int,
        local_as: int = 65200,
        families: Optional[List[str]] = None,
        hold_time: int = 600,
        grpc_port: int = 50051,
    ) -> Dict:
        self.grpc_port = grpc_port
        config_path = self.generate_config(
            peer_ip=peer_ip, peer_as=peer_as, local_as=local_as,
            families=families, hold_time=hold_time, grpc_port=grpc_port,
        )

        self.stop(quiet=True)

        cmd = (
            f"nohup {GOBGPD_BIN} -f {config_path} "
            f"--api-hosts :{grpc_port} "
            f"--log-level info "
            f"> {self.log_path} 2>&1 &"
        )
        os.system(cmd)
        time.sleep(2)

        rc, out = _run(f"pgrep -f 'gobgpd.*{self.session_id}'")
        if rc == 0 and out.strip():
            self.pid = int(out.strip().split("\n")[0])
        else:
            rc2, out2 = _run("pgrep -n gobgpd")
            if rc2 == 0:
                self.pid = int(out2.strip().split("\n")[0])

        session = {
            "session_id": self.session_id,
            "engine": "gobgp",
            "status": "active",
            "created": datetime.now(timezone.utc).isoformat(),
            "gobgpd_pid": self.pid,
            "peer_ip": peer_ip,
            "peer_as": peer_as,
            "local_as": local_as,
            "grpc_port": grpc_port,
            "config_path": config_path,
            "injected_routes": [],
        }
        self._save_session(session)
        return session

    def stop(self, quiet: bool = False) -> bool:
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                time.sleep(1)
                if not quiet:
                    print(f"Stopped gobgpd (PID {self.pid})")
            except ProcessLookupError:
                pass
            self.pid = None
            return True
        rc, out = _run(f"pgrep -f 'gobgpd.*{self.session_id}'")
        if rc == 0 and out.strip():
            for pid_str in out.strip().split("\n"):
                try:
                    os.kill(int(pid_str), signal.SIGTERM)
                except (ProcessLookupError, ValueError):
                    pass
            time.sleep(1)
            return True
        return False

    def is_alive(self) -> bool:
        if self.pid:
            try:
                os.kill(self.pid, 0)
                return True
            except (OSError, ProcessLookupError):
                pass
        return False

    def get_neighbor_state(self) -> Dict:
        rc, out = _run(f"{GOBGP_BIN} -p {self.grpc_port} neighbor")
        return {"exit_code": rc, "output": out}

    def inject_route(self, afi_cli: str, route_args: str) -> Dict:
        cmd = f"{GOBGP_BIN} -p {self.grpc_port} global rib -a {afi_cli} add {route_args}"
        rc, out = _run(cmd)
        result = {"success": rc == 0, "command": cmd, "output": out}
        session = self._load_session()
        if session:
            session.setdefault("injected_routes", []).append({
                "afi": afi_cli, "args": route_args,
                "injected_at": datetime.now(timezone.utc).isoformat(),
                "success": rc == 0,
            })
            self._save_session(session)
        return result

    def inject_flowspec_vpn(self, rd: str, match: str, action: str, rt: str) -> Dict:
        route_args = f"rd {rd} match {match} then {action} rt {rt}"
        return self.inject_route("ipv4-l3vpn-flowspec", route_args)

    def inject_flowspec(self, match: str, action: str) -> Dict:
        return self.inject_route("ipv4-flowspec", f"match {match} then {action}")

    def inject_unicast(self, prefix: str, nexthop: str, **kwargs) -> Dict:
        cmd = f"{GOBGP_BIN} -p {self.grpc_port} global rib -a ipv4 add {prefix} nexthop {nexthop}"
        rc, out = _run(cmd)
        return {"success": rc == 0, "command": cmd, "output": out}

    def inject_l3vpn(self, rd: str, prefix: str, nexthop: str, rt: str, label: int = 100) -> Dict:
        cmd = (
            f"{GOBGP_BIN} -p {self.grpc_port} global rib -a vpnv4 add "
            f"{prefix} rd {rd} nexthop {nexthop} rt {rt} label {label}"
        )
        rc, out = _run(cmd)
        return {"success": rc == 0, "command": cmd, "output": out}

    def _load_session(self) -> Optional[Dict]:
        path = SESSIONS_DIR / f"{self.session_id}.json"
        if path.exists():
            return json.loads(path.read_text())
        return None

    def _save_session(self, data: Dict):
        path = SESSIONS_DIR / f"{self.session_id}.json"
        path.write_text(json.dumps(data, indent=2))
