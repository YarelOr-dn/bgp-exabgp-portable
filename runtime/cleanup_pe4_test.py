#!/usr/bin/env python3
"""Remove test neighbor from PE-4 after SW-243977 verification."""
import paramiko
import time

HOST = "100.64.7.197"
USER = "dnroot"
PASS = "dnroot"

CLEANUP_COMMANDS = [
    "configure",
    "no protocols bgp 1234567 neighbor 100.64.6.135",
    "commit",
    "exit",
]

def cleanup():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10)
    
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(2)
    shell.recv(4096)
    
    for cmd in CLEANUP_COMMANDS:
        shell.send(cmd + "\n")
        time.sleep(1.5)
        resp = shell.recv(8192).decode(errors='replace').replace('\r', '').strip()
        tag = "[ERROR]" if 'ERROR' in resp.upper() else "[OK]"
        print(f"{tag} {cmd}")
    
    shell.close()
    client.close()
    print("[DONE] Test neighbor removed from PE-4")

if __name__ == "__main__":
    cleanup()
