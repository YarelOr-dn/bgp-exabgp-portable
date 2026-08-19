import sys
sys.path.insert(0, "/home/dn/SCALER/FLOWSPEC_VPN/exabgp/backends")
from scapy_tcp import CombinedRedirectBuilder

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
print("Hexdump:")
print(builder.hexdump(update))
print()
print("Starting BGP session to PE-4 (100.70.0.206), holding for 120s...")
sys.stdout.flush()
result = builder.send_and_hold(
    target_ip="100.70.0.206",
    target_port=179,
    update_bytes=update,
    hold_seconds=120,
    local_as=65200,
    peer_as=1234567,
)
print(f"Result: {result}")
