#!/usr/bin/env python3
"""
Run the BGP negative test on RR-SA-2 by:
1. SSH to port 2222 (Linux shell)
2. Upload a minimal test script
3. Execute it inside host_ns (where BGP runs) using nsenter/ip netns exec
"""
import paramiko
import time
import sys
import base64

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"
PORT = 2222

TEST_SCRIPT = r'''
import socket, struct, time, json, sys

BGP_MARKER = b'\xff' * 16

def build_open(my_as, hold_time, bgp_id):
    bgp_id_b = socket.inet_aton(bgp_id)
    cap_mp = struct.pack('!BBHB', 1, 4, 1, 0) + struct.pack('!B', 133)
    cap_4b = struct.pack('!BBI', 65, 4, my_as)
    opt = b''
    for c in [cap_mp, cap_4b]:
        opt += struct.pack('!BB', 2, len(c)) + c
    body = struct.pack('!BHH', 4, my_as if my_as <= 65535 else 23456, hold_time) + bgp_id_b + struct.pack('!B', len(opt)) + opt
    return BGP_MARKER + struct.pack('!HB', 19+len(body), 1) + body

def build_ka():
    return BGP_MARKER + struct.pack('!HB', 19, 4)

def recv_msg(s, t=10):
    s.settimeout(t)
    buf = b''
    try:
        while len(buf) < 19:
            c = s.recv(4096)
            if not c: return None, b''
            buf += c
        ml = struct.unpack('!H', buf[16:18])[0]
        while len(buf) < ml:
            c = s.recv(4096)
            if not c: break
            buf += c
        return buf[18], buf[19:ml]
    except: return None, b''

PDUS = {
    "type_14": "ffffffffffffffffffffffffffffffff003b02000000244001010240020402010002c010088008006400000001800e0b0001850000050e18c00001",
    "type_255": "ffffffffffffffffffffffffffffffff003b02000000244001010240020402010002c010088008006400000001800e0b000185000005ff18c00001",
    "type_19": "ffffffffffffffffffffffffffffffff003b02000000244001010240020402010002c010088008006400000001800e0b0001850000051318c00001",
}

results = {}
for target_ip in ["127.0.0.1", "100.70.0.205", "2.2.2.2"]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, 179))
        print(f"TCP_OK:{target_ip}")
        s.sendall(build_open(65200, 180, "100.64.6.134"))
        mt, pl = recv_msg(s, 10)
        if mt == 1:
            peer_as = struct.unpack('!H', pl[1:3])[0]
            peer_id = socket.inet_ntoa(pl[5:9])
            print(f"OPEN_OK:AS={peer_as},ID={peer_id}")
            s.sendall(build_ka())
            mt2, _ = recv_msg(s, 10)
            if mt2 == 4:
                print("ESTABLISHED")
                all_pass = True
                for name, hexdata in PDUS.items():
                    raw = bytes.fromhex(hexdata)
                    s.sendall(raw)
                    time.sleep(2)
                    s.sendall(build_ka())
                    mt3, pl3 = recv_msg(s, 15)
                    if mt3 == 4:
                        print(f"PASS:{name}")
                        results[name] = "PASS"
                    elif mt3 == 3:
                        c, sc = struct.unpack('!BB', pl3[:2])
                        print(f"FAIL:{name}:NOTIFICATION_{c}_{sc}")
                        results[name] = f"FAIL:NOTIF_{c}_{sc}"
                        all_pass = False
                        break
                    elif mt3 == 2:
                        s.sendall(build_ka())
                        mt4, pl4 = recv_msg(s, 5)
                        if mt4 in (4, 2):
                            print(f"PASS:{name}")
                            results[name] = "PASS"
                        elif mt4 == 3:
                            c, sc = struct.unpack('!BB', pl4[:2])
                            print(f"FAIL:{name}:NOTIFICATION_{c}_{sc}")
                            results[name] = f"FAIL:NOTIF_{c}_{sc}"
                            all_pass = False
                            break
                    else:
                        try:
                            s.sendall(build_ka())
                            mt5, _ = recv_msg(s, 5)
                            if mt5 == 4:
                                print(f"PASS:{name}")
                                results[name] = "PASS"
                                continue
                        except: pass
                        print(f"FAIL:{name}:NO_RESPONSE")
                        results[name] = "FAIL:NO_RESPONSE"
                        all_pass = False
                        break
                untested = set(PDUS.keys()) - set(results.keys())
                for n in untested:
                    results[n] = "SKIP"
                verdict = "FIX_CONFIRMED" if all_pass and len(results) == len(PDUS) else "BUG_PRESENT"
                print(f"VERDICT:{verdict}")
                print(f"RESULTS:{json.dumps(results)}")
        elif mt == 3:
            c, sc = struct.unpack('!BB', pl[:2])
            print(f"OPEN_FAIL:NOTIFICATION_{c}_{sc}")
        else:
            print(f"OPEN_FAIL:UNEXPECTED_{mt}")
        s.close()
        break
    except Exception as e:
        print(f"TCP_FAIL:{target_ip}:{e}")
        try: s.close()
        except: pass
else:
    print("ALL_TARGETS_UNREACHABLE")
'''

def main():
    print(f"[1] Connecting to {HOST}:{PORT}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=10)
    except paramiko.AuthenticationException:
        print(f"  [FAIL] Auth failed on port {PORT}")
        return
    print(f"  [OK] Connected")
    
    b64_script = base64.b64encode(TEST_SCRIPT.encode()).decode()
    
    print(f"\n[2] Uploading test script to /tmp/bgp_neg_test.py...")
    stdin, stdout, stderr = client.exec_command(
        f'echo "{b64_script}" | base64 -d > /tmp/bgp_neg_test.py && echo UPLOADED',
        timeout=10
    )
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(f"  {out.strip()} {err.strip()}")
    
    if "UPLOADED" not in out:
        print("  [FAIL] Script upload failed")
        client.close()
        return
    
    print(f"\n[3] Checking available namespace tools...")
    for cmd in ["which nsenter", "which ip", "ls /var/run/netns/"]:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        print(f"  {cmd}: {out} {err}")
    
    print(f"\n[4] Running test in host_ns namespace...")
    
    test_cmds = [
        "nsenter --net=/proc/1/ns/net python3 /tmp/bgp_neg_test.py",
        "ip netns exec host_ns python3 /tmp/bgp_neg_test.py",
        "python3 /tmp/bgp_neg_test.py",
    ]
    
    for cmd in test_cmds:
        print(f"\n  Trying: {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
        out = stdout.read().decode()
        err = stderr.read().decode()
        
        if out.strip():
            print(f"  Output:")
            for line in out.strip().split('\n'):
                print(f"    {line}")
            if err.strip():
                print(f"  Stderr: {err.strip()[:200]}")
            
            if "ESTABLISHED" in out or "VERDICT:" in out or "TCP_OK" in out:
                print(f"\n  [OK] Test executed successfully with: {cmd.split()[0]}")
                break
            elif "TCP_FAIL" in out and "ALL_TARGETS_UNREACHABLE" in out:
                print(f"  [INFO] All targets unreachable from this namespace, trying next...")
                continue
            elif "Permission denied" in err or "Operation not permitted" in err:
                print(f"  [INFO] Permission denied, trying next...")
                continue
        else:
            if err.strip():
                print(f"  Error: {err.strip()[:200]}")
            if "Permission denied" in err or "not permitted" in err:
                continue
    
    print(f"\n[5] Cleanup...")
    client.exec_command("rm -f /tmp/bgp_neg_test.py", timeout=5)
    client.close()
    print("  [DONE]")


if __name__ == "__main__":
    main()
