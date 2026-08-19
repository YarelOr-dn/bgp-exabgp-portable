#!/usr/bin/env python3
"""
Deploy and run the BGP negative test directly on RR-SA-2 via SSH tunnel.
Uses paramiko to establish SSH connection and forward TCP to BGP port.
"""
import paramiko
import socket
import struct
import time
import json
import sys
from datetime import datetime

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

BGP_MARKER = b'\xff' * 16
BGP_TYPE_OPEN = 1
BGP_TYPE_UPDATE = 2
BGP_TYPE_NOTIFICATION = 3
BGP_TYPE_KEEPALIVE = 4

AFI_IPV4 = 1
SAFI_FLOWSPEC = 133

MALFORMED_PDUS = {
    "type_14": {
        "description": "FlowSpec filter type 14 (unrecognized, content error)",
        "hex": "ffffffffffffffffffffffffffffffff003b02000000244001010240020402010002c010088008006400000001800e0b0001850000050e18c00001",
    },
    "type_255": {
        "description": "FlowSpec filter type 255 (0xFF, unrecognized, content error)",
        "hex": "ffffffffffffffffffffffffffffffff003b02000000244001010240020402010002c010088008006400000001800e0b000185000005ff18c00001",
    },
    "type_19": {
        "description": "FlowSpec filter type 19 (0x13, unrecognized, content error)",
        "hex": "ffffffffffffffffffffffffffffffff003b02000000244001010240020402010002c010088008006400000001800e0b0001850000051318c00001",
    },
}


def build_open(my_as, hold_time, bgp_id_str):
    bgp_id = socket.inet_aton(bgp_id_str)
    cap_mp_flowspec = struct.pack('!BBHB', 1, 4, AFI_IPV4, 0) + struct.pack('!B', SAFI_FLOWSPEC)
    cap_4byte_as = struct.pack('!BBI', 65, 4, my_as)
    opt_params = b''
    for cap in [cap_mp_flowspec, cap_4byte_as]:
        opt_params += struct.pack('!BB', 2, len(cap)) + cap
    open_body = struct.pack('!BHH', 4, my_as if my_as <= 65535 else 23456, hold_time)
    open_body += bgp_id
    open_body += struct.pack('!B', len(opt_params))
    open_body += opt_params
    msg_len = 19 + len(open_body)
    return BGP_MARKER + struct.pack('!HB', msg_len, BGP_TYPE_OPEN) + open_body


def build_keepalive():
    return BGP_MARKER + struct.pack('!HB', 19, BGP_TYPE_KEEPALIVE)


def recv_msg(channel, timeout=10):
    channel.settimeout(timeout)
    buf = b''
    try:
        while len(buf) < 19:
            chunk = channel.recv(4096)
            if not chunk:
                return None, 0, b''
            buf += chunk
        msg_len = struct.unpack('!H', buf[16:18])[0]
        while len(buf) < msg_len:
            chunk = channel.recv(4096)
            if not chunk:
                break
            buf += chunk
        msg_type = buf[18]
        payload = buf[19:msg_len]
        return msg_type, msg_len, payload
    except socket.timeout:
        return None, 0, b''


def parse_notification(payload):
    if len(payload) < 2:
        return 0, 0, ""
    code, subcode = struct.unpack('!BB', payload[:2])
    data = payload[2:].hex() if len(payload) > 2 else ""
    return code, subcode, data


def try_namespace_connection(ssh_client, target_ip, target_port=179):
    """Try to connect to BGP via SSH direct-tcpip channel."""
    transport = ssh_client.get_transport()
    try:
        channel = transport.open_channel(
            "direct-tcpip",
            (target_ip, target_port),
            ("127.0.0.1", 0),
            timeout=5
        )
        return channel
    except Exception as e:
        print(f"  [FAIL] direct-tcpip to {target_ip}:{target_port}: {e}")
        return None


def main():
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{'='*70}")
    print(f"SW-243977 Verification via SSH Tunnel to RR-SA-2")
    print(f"Management IP: {HOST}  |  Time: {ts}")
    print(f"{'='*70}")

    print(f"\n[1/5] Establishing SSH connection to {HOST}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for port in [2222, 22]:
        try:
            client.connect(HOST, port=port, username=USER, password=PASS, timeout=10)
            print(f"  [OK] SSH connected via port {port}")
            break
        except Exception as e:
            print(f"  [WARN] Port {port}: {e}")
    else:
        print("  [FAIL] Could not connect via SSH")
        return

    print(f"\n[2/5] Attempting direct-tcpip tunnel to BGP port 179...")
    target_ips = [
        ("127.0.0.1", "loopback"),
        ("100.70.0.205", "bundle-100.999"),
        ("2.2.2.2", "lo0/router-id"),
        ("0.0.0.0", "any"),
    ]

    channel = None
    for ip, desc in target_ips:
        print(f"  Trying {ip} ({desc})...")
        channel = try_namespace_connection(client, ip)
        if channel:
            print(f"  [OK] Channel opened to {ip}:179")
            break
    
    if not channel:
        print("  [FAIL] No tunnel path to BGP port 179")
        print("  BGP runs in host_ns, SSH is in management namespace")
        client.close()
        return

    my_as = 65200
    bgp_id = "100.64.6.134"
    hold_time = 180

    print(f"\n[3/5] BGP session establishment (AS={my_as})...")
    open_msg = build_open(my_as, hold_time, bgp_id)
    channel.sendall(open_msg)
    print(f"  [SENT] OPEN")

    msg_type, msg_len, payload = recv_msg(channel, timeout=10)
    if msg_type == BGP_TYPE_OPEN:
        peer_as = struct.unpack('!H', payload[1:3])[0]
        peer_id = socket.inet_ntoa(payload[5:9])
        print(f"  [RECV] OPEN (AS={peer_as}, id={peer_id})")
    elif msg_type == BGP_TYPE_NOTIFICATION:
        code, subcode, data = parse_notification(payload)
        print(f"  [FAIL] NOTIFICATION {code}/{subcode}")
        channel.close()
        client.close()
        return
    else:
        print(f"  [FAIL] Unexpected message type: {msg_type}")
        channel.close()
        client.close()
        return

    ka = build_keepalive()
    channel.sendall(ka)
    print(f"  [SENT] KEEPALIVE")

    msg_type, _, payload = recv_msg(channel, timeout=10)
    if msg_type == BGP_TYPE_KEEPALIVE:
        print(f"  [RECV] KEEPALIVE -- ESTABLISHED")
    else:
        print(f"  [WARN] Got msg type {msg_type}, continuing...")

    print(f"\n[4/5] Sending malformed FlowSpec UPDATE PDUs...")
    results = {}
    all_pass = True

    for name, info in MALFORMED_PDUS.items():
        raw = bytes.fromhex(info["hex"])
        print(f"\n  --- {name}: {info['description']} ---")

        channel.sendall(raw)
        print(f"  [SENT] Malformed UPDATE ({len(raw)} bytes)")

        time.sleep(2)

        channel.sendall(ka)
        print(f"  [SENT] KEEPALIVE probe")

        msg_type, _, payload = recv_msg(channel, timeout=15)

        if msg_type == BGP_TYPE_KEEPALIVE:
            print(f"  [PASS] Session alive -- NLRI discarded")
            results[name] = "PASS"
        elif msg_type == BGP_TYPE_NOTIFICATION:
            code, subcode, data = parse_notification(payload)
            print(f"  [FAIL] NOTIFICATION {code}/{subcode} -- session reset!")
            results[name] = f"FAIL (NOTIFICATION {code}/{subcode})"
            all_pass = False
            break
        elif msg_type == BGP_TYPE_UPDATE:
            channel.sendall(ka)
            msg_type2, _, payload2 = recv_msg(channel, timeout=5)
            if msg_type2 in (BGP_TYPE_KEEPALIVE, BGP_TYPE_UPDATE):
                print(f"  [PASS] Session alive after UPDATE exchange")
                results[name] = "PASS"
            elif msg_type2 == BGP_TYPE_NOTIFICATION:
                code, subcode, _ = parse_notification(payload2)
                print(f"  [FAIL] Delayed NOTIFICATION {code}/{subcode}")
                results[name] = f"FAIL (NOTIFICATION {code}/{subcode})"
                all_pass = False
                break
        elif msg_type is None:
            try:
                channel.sendall(ka)
                msg_type2, _, _ = recv_msg(channel, timeout=5)
                if msg_type2 == BGP_TYPE_KEEPALIVE:
                    print(f"  [PASS] Session alive (delayed)")
                    results[name] = "PASS"
                    continue
            except Exception:
                pass
            print(f"  [FAIL] No response -- connection likely reset")
            results[name] = "FAIL (connection lost)"
            all_pass = False
            break

    try:
        channel.close()
    except Exception:
        pass
    client.close()

    verdict = "FIX CONFIRMED" if all_pass and len(results) == len(MALFORMED_PDUS) else "BUG PRESENT"
    untested = set(MALFORMED_PDUS.keys()) - set(results.keys())
    for name in untested:
        results[name] = "SKIP (session died earlier)"

    print(f"\n{'='*70}")
    print(f"[5/5] RESULTS")
    print(f"{'='*70}")
    for name, r in results.items():
        tag = "[PASS]" if r == "PASS" else "[FAIL]" if "FAIL" in r else "[SKIP]"
        print(f"  {tag} {name}: {r}")
    print(f"\n  Overall: {verdict}")
    print(f"{'='*70}\n")

    return {"bug": "SW-243977", "verdict": verdict, "results": results}


if __name__ == "__main__":
    main()
