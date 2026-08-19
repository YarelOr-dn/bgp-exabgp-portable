#!/usr/bin/env python3
"""Apply config changes to RR-SA-2 via SSH (paramiko)."""
import paramiko
import time
import sys

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

CONFIG_COMMANDS = [
    "configure",
    "interfaces bundle-100.999 admin-state enabled",
    "protocols bgp 123 neighbor 100.64.6.134 admin-state enabled",
    "protocols bgp 123 neighbor 100.64.6.134 passive enabled",
    "commit",
    "exit",
]

def apply():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10)
    
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1)
    output = shell.recv(4096).decode(errors='replace')
    print(f"[CONNECTED] {output.strip()[-80:]}")
    
    for cmd in CONFIG_COMMANDS:
        shell.send(cmd + "\n")
        time.sleep(1.5)
        resp = shell.recv(8192).decode(errors='replace')
        clean = resp.replace('\r', '').strip()
        if clean:
            for line in clean.split('\n'):
                line = line.strip()
                if line and 'ERROR' in line.upper():
                    print(f"[ERROR] {cmd}: {line}")
                elif line:
                    print(f"[OK] {cmd}: {line}")
        else:
            print(f"[OK] {cmd}")
    
    shell.send("show interfaces bundle-100.999 | include Admin | no-more\n")
    time.sleep(1)
    resp = shell.recv(8192).decode(errors='replace')
    print(f"\n[VERIFY] bundle-100.999: {resp.strip()}")
    
    shell.send("show bgp neighbors 100.64.6.134 | include passive | no-more\n")
    time.sleep(1)
    resp = shell.recv(8192).decode(errors='replace')
    print(f"[VERIFY] neighbor passive: {resp.strip()}")
    
    shell.close()
    client.close()
    print("\n[DONE] Config applied successfully")

if __name__ == "__main__":
    apply()
