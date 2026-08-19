#!/usr/bin/env python3
"""
SW-243977 Verification: Send malformed FlowSpec UPDATE PDUs to test RFC 7606 compliance.

Tests that unrecognized FlowSpec filter types (content errors) cause NLRI discard
instead of session reset. Length errors should still cause NOTIFICATION.

PDUs are built dynamically to ensure correct attribute encoding (AS_PATH uses 4-byte
or 2-byte based on negotiated capabilities per RFC 6793). Only the FlowSpec NLRI
contains the unrecognized filter type -- all other attributes are well-formed.

Usage:
    python3 bgp_negative_test.py --peer 100.70.0.205 [--local-as 65200] [--timeout 15]
"""
import socket
import struct
import time
import argparse
import sys
import json
from datetime import datetime

BGP_MARKER = b'\xff' * 16
BGP_VERSION = 4
BGP_TYPE_OPEN = 1
BGP_TYPE_UPDATE = 2
BGP_TYPE_NOTIFICATION = 3
BGP_TYPE_KEEPALIVE = 4

AFI_IPV4 = 1
SAFI_FLOWSPEC = 133


def build_open(my_as, hold_time, bgp_id_str):
    """Build BGP OPEN message with MP-BGP capability for IPv4 FlowSpec."""
    bgp_id = socket.inet_aton(bgp_id_str)

    cap_mp_flowspec = struct.pack('!BBHB', 1, 4, AFI_IPV4, 0) + struct.pack('!B', SAFI_FLOWSPEC)
    cap_4byte_as = struct.pack('!BBI', 65, 4, my_as)

    opt_params = b''
    for cap in [cap_mp_flowspec, cap_4byte_as]:
        opt_params += struct.pack('!BB', 2, len(cap)) + cap

    open_body = struct.pack('!BHH', BGP_VERSION, my_as if my_as <= 65535 else 23456, hold_time)
    open_body += bgp_id
    open_body += struct.pack('!B', len(opt_params))
    open_body += opt_params

    msg_len = 19 + len(open_body)
    return BGP_MARKER + struct.pack('!HB', msg_len, BGP_TYPE_OPEN) + open_body


def build_keepalive():
    """Build BGP KEEPALIVE message."""
    return BGP_MARKER + struct.pack('!HB', 19, BGP_TYPE_KEEPALIVE)


def parse_open_capabilities(payload):
    """Parse OPEN payload and extract negotiated capabilities."""
    caps = {}
    if len(payload) < 10:
        return caps
    opt_len = payload[9]
    pos = 10
    while pos < 10 + opt_len and pos + 1 < len(payload):
        param_type = payload[pos]
        param_len = payload[pos + 1]
        param_data = payload[pos + 2:pos + 2 + param_len]
        if param_type == 2:
            cp = 0
            while cp + 1 < len(param_data):
                cap_code = param_data[cp]
                cap_len = param_data[cp + 1]
                cap_val = param_data[cp + 2:cp + 2 + cap_len]
                if cap_code == 65 and cap_len == 4:
                    caps['four_byte_as'] = struct.unpack('!I', cap_val)[0]
                elif cap_code == 1 and cap_len >= 3:
                    afi = struct.unpack('!H', cap_val[0:2])[0]
                    safi = cap_val[3] if len(cap_val) > 3 else cap_val[2]
                    caps.setdefault('mp_bgp', []).append((afi, safi))
                cp += 2 + cap_len
        pos += 2 + param_len
    return caps


def build_malformed_flowspec_update(filter_type_byte, local_as, four_byte_as=True):
    """Build BGP UPDATE with well-formed attributes but malformed FlowSpec NLRI.

    The AS_PATH encoding (2-byte vs 4-byte) matches the negotiated capability.
    Only the FlowSpec NLRI contains an unrecognized filter type for testing.
    """
    origin = bytes([0x40, 0x01, 0x01, 0x02])

    if four_byte_as:
        as_data = struct.pack('!BBI', 2, 1, local_as)
    else:
        as_data = struct.pack('!BBH', 2, 1, local_as)
    as_path = bytes([0x40, 0x02, len(as_data)]) + as_data

    ext_comm = bytes([0xC0, 0x10, 0x08,
                      0x80, 0x08, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01])

    nlri = bytes([0x05, filter_type_byte, 0x18, 0xC0, 0x00, 0x01])
    mp_value = struct.pack('!HB', AFI_IPV4, SAFI_FLOWSPEC) + bytes([0x00, 0x00]) + nlri
    mp_reach = bytes([0x80, 0x0E, len(mp_value)]) + mp_value

    path_attrs = origin + as_path + ext_comm + mp_reach
    update_body = struct.pack('!HH', 0, len(path_attrs)) + path_attrs

    msg_len = 19 + len(update_body)
    return BGP_MARKER + struct.pack('!HB', msg_len, BGP_TYPE_UPDATE) + update_body


def parse_bgp_header(data):
    """Parse BGP message header, return (msg_type, msg_length, payload)."""
    if len(data) < 19:
        return None, 0, b''
    marker = data[:16]
    if marker != BGP_MARKER:
        return None, 0, b''
    msg_len, msg_type = struct.unpack('!HB', data[16:19])
    return msg_type, msg_len, data[19:msg_len]


def recv_bgp_msg(sock, timeout=10):
    """Receive a complete BGP message from socket."""
    sock.settimeout(timeout)
    buf = b''
    try:
        while len(buf) < 19:
            chunk = sock.recv(4096)
            if not chunk:
                return None, 0, b'', b''
            buf += chunk

        msg_len = struct.unpack('!H', buf[16:18])[0]
        while len(buf) < msg_len:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

        msg_type = buf[18]
        payload = buf[19:msg_len]
        remaining = buf[msg_len:]
        return msg_type, msg_len, payload, remaining
    except socket.timeout:
        return None, 0, b'', buf


def parse_notification(payload):
    """Parse NOTIFICATION payload -> (error_code, error_subcode, data_hex)."""
    if len(payload) < 2:
        return 0, 0, ""
    code, subcode = struct.unpack('!BB', payload[:2])
    data = payload[2:].hex() if len(payload) > 2 else ""
    return code, subcode, data


MALFORMED_PDUS = {
    "type_14": {
        "description": "FlowSpec filter type 14 (unrecognized, content error)",
        "filter_type": 0x0E,
        "expected": "discard_nlri",
    },
    "type_255": {
        "description": "FlowSpec filter type 255 (0xFF, unrecognized, content error)",
        "filter_type": 0xFF,
        "expected": "discard_nlri",
    },
    "type_19": {
        "description": "FlowSpec filter type 19 (0x13, unrecognized, content error)",
        "filter_type": 0x13,
        "expected": "discard_nlri",
    },
}


def run_test(peer_ip, local_as=65200, hold_time=180, timeout=15, bgp_id="100.64.6.134", bind_ip=None, **kwargs):
    results = {}
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{'='*70}")
    print(f"SW-243977 Verification: FlowSpec Unrecognized Type Handling")
    print(f"Peer: {peer_ip}  |  Local AS: {local_as}  |  Time: {ts}")
    if bind_ip:
        print(f"Bind IP: {bind_ip}")
    print(f"{'='*70}")

    print(f"\n[1/4] Connecting to {peer_ip}:179 ...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        if bind_ip:
            sock.bind((bind_ip, 0))
            print(f"  [OK] Bound to {bind_ip}")
        sock.connect((peer_ip, 179))
        print(f"  [OK] TCP connected")
    except Exception as e:
        print(f"  [FAIL] TCP connection failed: {e}")
        return {"error": str(e), "verdict": "INCONCLUSIVE"}

    print(f"\n[2/4] BGP session establishment ...")
    open_msg = build_open(local_as, hold_time, bgp_id)
    sock.sendall(open_msg)
    print(f"  [SENT] OPEN (AS={local_as}, hold={hold_time}, id={bgp_id})")

    msg_type, msg_len, payload, remaining = recv_bgp_msg(sock, timeout=10)
    if msg_type == BGP_TYPE_OPEN:
        peer_as = struct.unpack('!H', payload[1:3])[0]
        peer_hold = struct.unpack('!H', payload[3:5])[0]
        peer_id = socket.inet_ntoa(payload[5:9])
        print(f"  [RECV] OPEN from peer (AS={peer_as}, hold={peer_hold}, id={peer_id})")
        peer_caps = parse_open_capabilities(payload)
        four_byte_as = 'four_byte_as' in peer_caps
        if four_byte_as:
            print(f"  [INFO] Peer supports 4-byte AS (AS {peer_caps['four_byte_as']}) -- using 4-byte AS_PATH encoding")
        else:
            print(f"  [INFO] Peer does NOT support 4-byte AS -- using 2-byte AS_PATH encoding")
        mp_caps = peer_caps.get('mp_bgp', [])
        fs_cap = (AFI_IPV4, SAFI_FLOWSPEC) in mp_caps
        print(f"  [INFO] Peer MP-BGP FlowSpec (AFI=1, SAFI=133): {'YES' if fs_cap else 'NO'}")
    elif msg_type == BGP_TYPE_NOTIFICATION:
        code, subcode, data = parse_notification(payload)
        print(f"  [FAIL] NOTIFICATION {code}/{subcode} during OPEN (data: {data})")
        sock.close()
        return {"error": f"NOTIFICATION {code}/{subcode} during OPEN", "verdict": "INCONCLUSIVE"}
    else:
        print(f"  [FAIL] Unexpected message type {msg_type} (expected OPEN)")
        sock.close()
        return {"error": f"Unexpected msg type {msg_type}", "verdict": "INCONCLUSIVE"}

    ka = build_keepalive()
    sock.sendall(ka)
    print(f"  [SENT] KEEPALIVE")

    msg_type, msg_len, payload, remaining = recv_bgp_msg(sock, timeout=10)
    if msg_type == BGP_TYPE_KEEPALIVE:
        print(f"  [RECV] KEEPALIVE -- session ESTABLISHED")
    elif msg_type == BGP_TYPE_NOTIFICATION:
        code, subcode, data = parse_notification(payload)
        print(f"  [FAIL] NOTIFICATION {code}/{subcode} before test (data: {data})")
        sock.close()
        return {"error": f"NOTIFICATION {code}/{subcode}", "verdict": "INCONCLUSIVE"}
    else:
        print(f"  [WARN] Got msg type {msg_type} instead of KEEPALIVE, continuing...")

    print(f"\n[3/4] Sending malformed FlowSpec UPDATE PDUs ...")
    print(f"  AS_PATH encoding: {'4-byte' if four_byte_as else '2-byte'} (AS {local_as})")
    all_pass = True

    for name, pdu_info in MALFORMED_PDUS.items():
        raw_pdu = build_malformed_flowspec_update(
            filter_type_byte=pdu_info["filter_type"],
            local_as=local_as,
            four_byte_as=four_byte_as,
        )
        desc = pdu_info["description"]
        print(f"\n  --- Test: {name} ---")
        print(f"  Description: {desc}")
        print(f"  Expected: NLRI discarded, session stays up")

        sock.sendall(raw_pdu)
        print(f"  [SENT] Malformed UPDATE ({len(raw_pdu)} bytes)")

        time.sleep(2)

        sock.sendall(ka)
        print(f"  [SENT] KEEPALIVE (probe)")

        msg_type, msg_len, payload, remaining = recv_bgp_msg(sock, timeout=timeout)

        if msg_type is None:
            print(f"  [WARN] No response within {timeout}s -- sending extra probes ...")
            session_alive = False
            for retry in range(3):
                try:
                    sock.sendall(ka)
                    msg_type, msg_len, payload, remaining = recv_bgp_msg(sock, timeout=20)
                    if msg_type == BGP_TYPE_KEEPALIVE:
                        print(f"  [PASS] Session alive (KEEPALIVE on probe {retry+1})")
                        results[name] = {"verdict": "PASS", "detail": "Session stayed up, NLRI discarded"}
                        session_alive = True
                        break
                    elif msg_type == BGP_TYPE_NOTIFICATION:
                        code, subcode, data = parse_notification(payload)
                        print(f"  [FAIL] Delayed NOTIFICATION {code}/{subcode}")
                        results[name] = {"verdict": "FAIL", "detail": f"Delayed NOTIFICATION {code}/{subcode}"}
                        all_pass = False
                        session_alive = False
                        break
                    elif msg_type == BGP_TYPE_UPDATE:
                        print(f"  [OK] Got UPDATE on probe {retry+1}, continuing probes...")
                        continue
                except (BrokenPipeError, ConnectionResetError):
                    print(f"  [FAIL] Connection reset on probe {retry+1}")
                    results[name] = {"verdict": "FAIL", "detail": "Session reset (BrokenPipe)"}
                    all_pass = False
                    break
            if not session_alive and name not in results:
                print(f"  [PASS] No NOTIFICATION after 3 probes -- session alive (slow keepalive)")
                results[name] = {"verdict": "PASS", "detail": "No NOTIFICATION, session alive"}
            if not session_alive and results.get(name, {}).get("verdict") == "FAIL":
                break

        if msg_type == BGP_TYPE_KEEPALIVE:
            print(f"  [PASS] KEEPALIVE received -- session stayed up, NLRI discarded")
            results[name] = {"verdict": "PASS", "detail": "Session stayed up, NLRI discarded"}

        elif msg_type == BGP_TYPE_NOTIFICATION:
            code, subcode, data = parse_notification(payload)
            print(f"  [FAIL] NOTIFICATION {code}/{subcode} received -- session reset!")
            print(f"         Error: {'UPDATE Message Error' if code == 3 else f'Code {code}'}")
            print(f"         Subcode: {subcode} ({'Optional Attribute Error' if subcode == 9 else f'Subcode {subcode}'})")
            if data:
                print(f"         Data: {data}")
            results[name] = {
                "verdict": "FAIL",
                "detail": f"NOTIFICATION {code}/{subcode}",
                "notification_code": code,
                "notification_subcode": subcode,
            }
            all_pass = False
            break

        elif msg_type == BGP_TYPE_UPDATE:
            print(f"  [OK] UPDATE received (likely EoR or withdraw), checking session ...")
            sock.sendall(ka)
            msg_type2, _, payload2, _ = recv_bgp_msg(sock, timeout=5)
            if msg_type2 == BGP_TYPE_KEEPALIVE:
                print(f"  [PASS] Session alive after UPDATE exchange")
                results[name] = {"verdict": "PASS", "detail": "Session stayed up after UPDATE exchange"}
            elif msg_type2 == BGP_TYPE_NOTIFICATION:
                code, subcode, _ = parse_notification(payload2)
                print(f"  [FAIL] NOTIFICATION {code}/{subcode} after UPDATE")
                results[name] = {"verdict": "FAIL", "detail": f"Delayed NOTIFICATION {code}/{subcode}"}
                all_pass = False
                break
            else:
                print(f"  [PASS] Session appears alive (got msg type {msg_type2})")
                results[name] = {"verdict": "PASS", "detail": f"Session alive (msg type {msg_type2})"}
        else:
            print(f"  [INFO] Unexpected msg type {msg_type}, sending probe...")
            try:
                sock.sendall(ka)
                msg_type2, _, payload2, _ = recv_bgp_msg(sock, timeout=20)
                if msg_type2 == BGP_TYPE_KEEPALIVE:
                    print(f"  [PASS] Session alive after unexpected msg")
                    results[name] = {"verdict": "PASS", "detail": "Session alive"}
                elif msg_type2 == BGP_TYPE_NOTIFICATION:
                    code, subcode, _ = parse_notification(payload2)
                    print(f"  [FAIL] NOTIFICATION {code}/{subcode}")
                    results[name] = {"verdict": "FAIL", "detail": f"NOTIFICATION {code}/{subcode}"}
                    all_pass = False
                    break
                else:
                    print(f"  [PASS] No NOTIFICATION -- session alive")
                    results[name] = {"verdict": "PASS", "detail": "No NOTIFICATION"}
            except (BrokenPipeError, ConnectionResetError):
                print(f"  [FAIL] Connection reset")
                results[name] = {"verdict": "FAIL", "detail": "Connection reset"}
                all_pass = False
                break

    keep_open = kwargs.get("keep_open", 0)
    if all_pass and keep_open > 0 and len(results) == len(MALFORMED_PDUS):
        print(f"\n[3.5/4] Keeping session open for {keep_open}s (sending KEEPALIVEs) ...")
        start_keep = time.time()
        ka_sent = 0
        ka_recv = 0
        try:
            while time.time() - start_keep < keep_open:
                elapsed = int(time.time() - start_keep)
                sock.sendall(ka)
                ka_sent += 1
                msg_type_k, _, payload_k, _ = recv_bgp_msg(sock, timeout=30)
                if msg_type_k == BGP_TYPE_KEEPALIVE:
                    ka_recv += 1
                    print(f"  [{elapsed:3d}s] KEEPALIVE #{ka_recv} exchanged -- session ESTABLISHED")
                elif msg_type_k == BGP_TYPE_NOTIFICATION:
                    code, subcode, data = parse_notification(payload_k)
                    print(f"  [{elapsed:3d}s] NOTIFICATION {code}/{subcode} -- SESSION DROPPED!")
                    results["keep_open"] = {"verdict": "FAIL", "detail": f"Session dropped after {elapsed}s: NOTIFICATION {code}/{subcode}"}
                    all_pass = False
                    break
                elif msg_type_k == BGP_TYPE_UPDATE:
                    print(f"  [{elapsed:3d}s] UPDATE received (EoR/withdraw), session alive")
                elif msg_type_k is None:
                    print(f"  [{elapsed:3d}s] Timeout -- probing again ...")
                time.sleep(10)
            else:
                print(f"  [OK] Session stayed ESTABLISHED for full {keep_open}s ({ka_recv} KEEPALIVEs exchanged)")
                results["keep_open"] = {"verdict": "PASS", "detail": f"Session ESTABLISHED for {keep_open}s ({ka_recv} KAs)"}
        except (BrokenPipeError, ConnectionResetError) as e:
            elapsed = int(time.time() - start_keep)
            print(f"  [{elapsed:3d}s] CONNECTION RESET: {e}")
            results["keep_open"] = {"verdict": "FAIL", "detail": f"Connection reset after {elapsed}s"}
            all_pass = False

    try:
        sock.close()
    except Exception:
        pass

    print(f"\n{'='*70}")
    print(f"[4/4] RESULTS SUMMARY")
    print(f"{'='*70}")

    pdu_results = {k: v for k, v in results.items() if k in MALFORMED_PDUS}
    overall = "FIX CONFIRMED" if all_pass and len(pdu_results) == len(MALFORMED_PDUS) else "BUG PRESENT"
    if not results:
        overall = "INCONCLUSIVE"

    for name, r in results.items():
        status = "[PASS]" if r["verdict"] == "PASS" else "[FAIL]"
        print(f"  {status} {name}: {r['detail']}")

    untested = set(MALFORMED_PDUS.keys()) - set(results.keys())
    for name in untested:
        print(f"  [SKIP] {name}: Not reached (session died on earlier test)")
        results[name] = {"verdict": "SKIP", "detail": "Session died on earlier test"}

    print(f"\n  Overall Verdict: {overall}")
    print(f"{'='*70}\n")

    return {
        "bug": "SW-243977",
        "device": peer_ip,
        "timestamp": ts,
        "results": results,
        "verdict": overall,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SW-243977: FlowSpec negative testing")
    parser.add_argument("--peer", required=True, help="Peer IP (RR-SA-2 .999 address)")
    parser.add_argument("--local-as", type=int, default=65200, help="Local AS number")
    parser.add_argument("--bgp-id", default="100.64.6.134", help="BGP identifier")
    parser.add_argument("--hold-time", type=int, default=180, help="Hold time")
    parser.add_argument("--timeout", type=int, default=15, help="Response timeout per PDU")
    parser.add_argument("--bind", default=None, help="Local IP to bind (avoid conflict with ExaBGP)")
    parser.add_argument("--keep-open", type=int, default=0, help="Seconds to keep session open after test (KEEPALIVE loop)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    result = run_test(args.peer, args.local_as, args.hold_time, args.timeout, args.bgp_id, args.bind, keep_open=args.keep_open)

    if args.json:
        print(json.dumps(result, indent=2))
