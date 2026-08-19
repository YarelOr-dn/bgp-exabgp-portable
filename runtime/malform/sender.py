"""TCP session manager for sending malformed BGP messages."""

import socket
import struct
import time

from ._common import BGP_MARKER, BGP_OPEN, BGP_KEEPALIVE, BGP_NOTIFICATION, build_bgp_header


def build_open(local_as: int, hold_time: int, router_id: str) -> bytes:
    """Build BGP OPEN message with capabilities."""
    version = 4
    rid_bytes = socket.inet_aton(router_id)
    cap_4byte_as = struct.pack("!BBHI", 65, 4, 0, local_as)
    cap_mp = struct.pack("!BBHBHB", 1, 4, 0, 1, 0, 134)
    caps = cap_4byte_as + cap_mp
    opt_params = struct.pack("!BB", 2, len(caps)) + caps
    my_as = local_as if local_as <= 65535 else 23456
    payload = struct.pack("!BHH", version, my_as, hold_time)
    payload += rid_bytes
    payload += struct.pack("!B", len(opt_params))
    payload += opt_params
    return build_bgp_header(BGP_OPEN, payload)


def send_malformed(
    target_ip: str,
    target_port: int,
    malformed_bytes: bytes,
    local_as: int = 65200,
    peer_as: int = 1234567,
    router_id: str = "100.64.6.134",
) -> dict:
    """Establish BGP session, send malformed message, return response dict."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((target_ip, target_port))

        open_msg = build_open(local_as, 180, router_id)
        sock.sendall(open_msg)
        data = sock.recv(4096)

        keepalive = build_bgp_header(BGP_KEEPALIVE, b"")
        sock.sendall(keepalive)
        time.sleep(1)
        sock.recv(4096)

        sock.sendall(malformed_bytes)

        time.sleep(2)
        try:
            response = sock.recv(4096)
            if len(response) >= 21 and response[18] == BGP_NOTIFICATION:
                return {
                    "success": True,
                    "response": "NOTIFICATION",
                    "error_code": response[19],
                    "error_subcode": response[20],
                }
            return {"success": True, "response": f"Got {len(response)} bytes"}
        except socket.timeout:
            return {"success": True, "response": "No response (timeout)"}
        finally:
            sock.close()

    except Exception as e:
        return {"success": False, "error": str(e)}


def send_raw(target_ip: str, target_port: int, malformed_bytes: bytes) -> dict:
    """Send raw malformed bytes without establishing session (for bad-marker, bad-length)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, target_port))
        sock.sendall(malformed_bytes)
        time.sleep(2)
        try:
            response = sock.recv(4096)
            if len(response) >= 21 and response[18] == BGP_NOTIFICATION:
                return {
                    "success": True,
                    "response": "NOTIFICATION",
                    "error_code": response[19],
                    "error_subcode": response[20],
                }
            return {"success": True, "response": f"Got {len(response)} bytes"}
        except socket.timeout:
            return {"success": True, "response": "No response (timeout)"}
        finally:
            sock.close()
    except Exception as e:
        return {"success": False, "error": str(e)}
