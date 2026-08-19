#!/usr/bin/env python3
"""Access DNAAS-LEAF-B15 with correct credentials and check g_mgmt_v999."""
import paramiko
import time

HOST = "100.64.101.6"
USER = "sisaev"
PASS = "Drive1234!"

def run_cmd(shell, cmd, wait=3):
    shell.send(cmd + "\n")
    time.sleep(wait)
    out = b''
    while shell.recv_ready():
        out += shell.recv(16384)
    return out.decode(errors='replace')

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10,
                   allow_agent=False, look_for_keys=False)
    
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(3)
    boot = shell.recv(8192).decode(errors='replace')
    print(f"[BOOT] {boot.strip()}")
    
    print("\n[1] Show system hostname...")
    out = run_cmd(shell, "show system | no-more")
    print(out[:500])
    
    print("\n[2] Check g_mgmt_v999 BD...")
    out = run_cmd(shell, "show config network-services bridge-domain instance g_mgmt_v999 | no-more")
    print(out[:1000])
    
    print("\n[3] Check ge100-0/0/6 sub-interfaces (RR-SA-2 facing port)...")
    out = run_cmd(shell, "show interfaces | include ge100-0/0/6 | no-more")
    print(out[:500])
    
    print("\n[4] Check bundle-60000.999...")
    out = run_cmd(shell, "show config interfaces bundle-60000.999 | no-more")
    print(out[:500])
    
    shell.close()
    client.close()

if __name__ == "__main__":
    main()
