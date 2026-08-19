#!/usr/bin/env python3
"""Check g_mgmt_v999 BD on DNAAS-LEAF-B15 and add RR-SA-2 AC if missing."""
import paramiko
import time

HOST = "100.64.101.6"
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
    shell.recv(4096)
    
    print("[1] Checking g_mgmt_v999 bridge-domain on B15...")
    out = run_cmd(shell, "show config network-services bridge-domain instance g_mgmt_v999 | no-more")
    print(out)
    
    print("\n[2] Checking interfaces ge100-0/0/6 and ge100-0/0/7 sub-interfaces...")
    out = run_cmd(shell, "show interfaces | include ge100-0/0/6 | no-more")
    print(out)
    out = run_cmd(shell, "show interfaces | include ge100-0/0/7 | no-more")
    print(out)
    
    print("\n[3] Checking if any .999 sub-if exists on ge100-0/0/6 or ge100-0/0/7...")
    out = run_cmd(shell, "show config interfaces ge100-0/0/6.999 | no-more")
    print(out)
    out = run_cmd(shell, "show config interfaces ge100-0/0/7.999 | no-more")
    print(out)
    
    shell.close()
    client.close()

if __name__ == "__main__":
    main()
