#!/usr/bin/env python3
"""Check if we can get a Linux shell on RR-SA-2 and check Python availability."""
import paramiko
import time

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

def run_cmd(shell, cmd, wait=2):
    shell.send(cmd + "\n")
    time.sleep(wait)
    out = b''
    while shell.recv_ready():
        out += shell.recv(8192)
    return out.decode(errors='replace')

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10)
    
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(2)
    boot = shell.recv(4096).decode(errors='replace')
    print(f"[BOOT] {boot.strip()[-100:]}")
    
    print("\n[1] Entering Linux shell via 'run start shell'...")
    out = run_cmd(shell, "run start shell", wait=3)
    print(out.strip()[-200:])
    
    print("\n[2] Sending password...")
    out = run_cmd(shell, "dnroot", wait=2)
    print(out.strip()[-200:])
    
    print("\n[3] Checking we're in bash...")
    out = run_cmd(shell, "whoami && hostname && which python3", wait=2)
    print(out.strip())
    
    print("\n[4] Checking BGP port 179 on loopback...")
    out = run_cmd(shell, "ss -tlnp | grep 179", wait=2)
    print(out.strip())
    
    print("\n[5] Checking mgmt IP can reach port 179...")
    out = run_cmd(shell, "nc -z -w 1 127.0.0.1 179; echo RC=$?", wait=2)
    print(out.strip())
    
    print("\n[6] Checking /tmp writeable...")
    out = run_cmd(shell, "touch /tmp/bgp_test_check && echo WRITABLE && rm /tmp/bgp_test_check", wait=1)
    print(out.strip())
    
    shell.close()
    client.close()

if __name__ == "__main__":
    main()
