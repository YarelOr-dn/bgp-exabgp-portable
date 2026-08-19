import sys, socket, struct, time, binascii
sys.path.insert(0, "/home/dn/SCALER/FLOWSPEC_VPN/exabgp/backends")
from scapy_tcp import CombinedRedirectBuilder, _build_bgp_header, BGP_KEEPALIVE, BGP_OPEN, BGP_UPDATE, BGP_NOTIFICATION

BGP_TYPES = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE"}

def parse_bgp_msgs(data):
    """Parse BGP messages from raw bytes, return list of (type, payload)."""
    msgs = []
    offset = 0
    while offset + 19 <= len(data):
        marker = data[offset:offset+16]
        if marker != b'\xff' * 16:
            break
        length = struct.unpack("!H", data[offset+16:offset+18])[0]
        msg_type = data[offset+18]
        payload = data[offset+19:offset+length]
        msgs.append((msg_type, payload, length))
        offset += length
    return msgs

builder = CombinedRedirectBuilder()
update = builder.build_combined_update(
    rd="4.4.4.4:100",
    redirect_ip="49.49.49.9",
    redirect_rt="1234567:101",
    rt="1234567:300",
    dest_prefix="100.100.100.1/32",
    local_as=65200,
)
print(f"UPDATE built: {len(update)} bytes")

target_ip = "100.70.0.206"
local_as = 65200
peer_as = 1234567
hold_time = 600
router_id = "100.64.6.134"

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    print(f"Connecting to {target_ip}:179...")
    sock.connect((target_ip, 179))
    print("TCP connected")

    open_msg = builder._build_open(local_as, hold_time, router_id)
    print(f"Sending OPEN ({len(open_msg)} bytes): {binascii.hexlify(open_msg).decode()}")
    sock.sendall(open_msg)

    print("Waiting for peer OPEN...")
    data = sock.recv(4096)
    print(f"Received {len(data)} bytes: {binascii.hexlify(data[:64]).decode()}...")
    
    msgs = parse_bgp_msgs(data)
    for msg_type, payload, length in msgs:
        tname = BGP_TYPES.get(msg_type, f"UNKNOWN({msg_type})")
        print(f"  BGP {tname} (len={length})")
        if msg_type == 3:  # NOTIFICATION
            if len(payload) >= 2:
                ecode = payload[0]
                esubcode = payload[1]
                edata = payload[2:]
                print(f"    Error Code: {ecode}, SubCode: {esubcode}")
                print(f"    Data: {binascii.hexlify(edata).decode()}")
        elif msg_type == 1:  # OPEN
            if len(payload) >= 6:
                version = payload[0]
                peer_as_recv = struct.unpack("!H", payload[1:3])[0]
                peer_hold = struct.unpack("!H", payload[3:5])[0]
                peer_rid = socket.inet_ntoa(payload[5:9])
                print(f"    Version: {version}, AS: {peer_as_recv}, HoldTime: {peer_hold}, RouterID: {peer_rid}")

    keepalive = _build_bgp_header(BGP_KEEPALIVE, b"")
    print(f"Sending KEEPALIVE...")
    sock.sendall(keepalive)
    
    time.sleep(1)
    try:
        sock.settimeout(5)
        data2 = sock.recv(4096)
        print(f"After KEEPALIVE, received {len(data2)} bytes")
        msgs2 = parse_bgp_msgs(data2)
        for msg_type, payload, length in msgs2:
            tname = BGP_TYPES.get(msg_type, f"UNKNOWN({msg_type})")
            print(f"  BGP {tname} (len={length})")
            if msg_type == 3:
                if len(payload) >= 2:
                    print(f"    Error: {payload[0]}/{payload[1]}, Data: {binascii.hexlify(payload[2:]).decode()}")
    except socket.timeout:
        print("No response to KEEPALIVE (timeout)")

    print(f"Sending UPDATE ({len(update)} bytes)...")
    sock.sendall(update)

    time.sleep(3)
    try:
        sock.settimeout(5)
        data3 = sock.recv(4096)
        print(f"After UPDATE, received {len(data3)} bytes")
        msgs3 = parse_bgp_msgs(data3)
        for msg_type, payload, length in msgs3:
            tname = BGP_TYPES.get(msg_type, f"UNKNOWN({msg_type})")
            print(f"  BGP {tname} (len={length})")
            if msg_type == 3:
                if len(payload) >= 2:
                    print(f"    Error: {payload[0]}/{payload[1]}, Data: {binascii.hexlify(payload[2:]).decode()}")
    except socket.timeout:
        print("No NOTIFICATION after UPDATE (timeout) -- route likely accepted!")

    print("Holding session for 30s for verification...")
    start = time.time()
    while time.time() - start < 30:
        sock.sendall(keepalive)
        time.sleep(10)
        try:
            sock.settimeout(5)
            d = sock.recv(4096)
            if d:
                msgs = parse_bgp_msgs(d)
                for mt, pl, ln in msgs:
                    tname = BGP_TYPES.get(mt, f"UNKNOWN({mt})")
                    print(f"  BGP {tname} (len={ln})")
                    if mt == 3:
                        print(f"    Error: {pl[0]}/{pl[1]}")
        except socket.timeout:
            pass

    notification = _build_bgp_header(BGP_NOTIFICATION, struct.pack("!BB", 6, 0))
    sock.sendall(notification)
    sock.close()
    print("Session closed cleanly")

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
