#!/usr/bin/env python3
"""Apply test neighbor config on PE-4 for SW-243977 verification."""
import paramiko
import time

HOST = "100.64.7.197"
USER = "dnroot"
PASS = "dnroot"

CONFIG_COMMANDS = [
    "configure",
    "protocols bgp 1234567 neighbor 100.64.6.135 admin-state enabled",
    "protocols bgp 1234567 neighbor 100.64.6.135 remote-as 65200",
    "protocols bgp 1234567 neighbor 100.64.6.135 description SW-243977-test",
    "protocols bgp 1234567 neighbor 100.64.6.135 ebgp-multihop 10",
    "protocols bgp 1234567 neighbor 100.64.6.135 passive enabled",
    "protocols bgp 1234567 neighbor 100.64.6.135 update-source ge100-18/0/6.999",
    "protocols bgp 1234567 neighbor 100.64.6.135 timers hold-time 180",
    "protocols bgp 1234567 neighbor 100.64.6.135 address-family ipv4-flowspec send-community community-type both",
    "protocols bgp 1234567 neighbor 100.64.6.135 address-family ipv4-flowspec soft-reconfiguration inbound",
    "commit",
    "exit",
]

def apply():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10)
    
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(2)
    boot = shell.recv(4096).decode(errors='replace')
    print(f"[CONNECTED] {boot.strip()[-60:]}")
    
    for cmd in CONFIG_COMMANDS:
        shell.send(cmd + "\n")
        time.sleep(1.5)
        resp = shell.recv(8192).decode(errors='replace').replace('\r', '').strip()
        has_error = 'ERROR' in resp.upper()
        tag = "[ERROR]" if has_error else "[OK]"
        short_cmd = cmd[:70]
        if has_error:
            print(f"{tag} {short_cmd}: {resp}")
        else:
            print(f"{tag} {short_cmd}")
    
    time.sleep(1)
    shell.send("show bgp neighbors 100.64.6.135 | include state | no-more\n")
    time.sleep(2)
    resp = shell.recv(8192).decode(errors='replace')
    print(f"\n[VERIFY] BGP neighbor state: {resp.strip()}")
    
    shell.close()
    client.close()
    print("\n[DONE]")

if __name__ == "__main__":
    apply()
