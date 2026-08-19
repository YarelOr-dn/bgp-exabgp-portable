#!/usr/bin/env python3
"""Check bgpd traces on RR-SA-2 for FlowSpec handling of malformed PDUs."""
import paramiko
import time

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

def run_cmd(shell, cmd, wait=4):
    shell.send(cmd + "\n")
    time.sleep(wait)
    out = b''
    while shell.recv_ready():
        out += shell.recv(65536)
    return out.decode(errors='replace')

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10,
                   allow_agent=False, look_for_keys=False)

    shell = client.invoke_shell(width=250, height=50)
    time.sleep(3)
    shell.recv(8192)

    print("=== RR-SA-2 bgpd traces around test time (21:21 UTC) ===\n")

    print("[1] FlowSpec-related traces at test time...")
    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include 21:21 | include flowspec | no-more", wait=6)
    print(out)

    print("[2] All traces around 21:21 for our peer...")
    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include 21:21 | include 100.64.6.134 | no-more", wait=6)
    print(out)

    print("[3] NOTIFICATION traces...")
    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include 21:21 | include NOTIFICATION | no-more", wait=6)
    print(out)

    print("[4] Broader FlowSpec traces (21:16-21:22)...")
    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include 21:16 | include flowspec | no-more", wait=6)
    print(out)

    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include 21:17 | include flowspec | no-more", wait=6)
    print(out)

    print("[5] treat-as-withdraw or discard traces...")
    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include treat | no-more", wait=6)
    print(out)

    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include withdraw | include 21:21 | no-more", wait=6)
    print(out)

    print("[6] BGP session state for 100.64.6.134...")
    out = run_cmd(shell, "show file traces routing_engine/bgpd_traces | include ADJCHANGE | include 100.64.6.134 | no-more", wait=6)
    print(out)

    print("[7] Current BGP summary for our peer...")
    out = run_cmd(shell, "show bgp summary | include 100.64.6.134 | no-more", wait=4)
    print(out)

    shell.close()
    client.close()

if __name__ == "__main__":
    main()
