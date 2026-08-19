#!/usr/bin/env python3
"""Check which bundle ge100-0/0/6 belongs to on DNAAS-LEAF-B15."""
import paramiko
import time

HOST = "100.64.101.6"
USER = "sisaev"
PASS = "Drive1234!"

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

    shell = client.invoke_shell(width=200, height=50)
    time.sleep(3)
    shell.recv(8192)

    print("[1] Check which bundle ge100-0/0/6 is in...")
    out = run_cmd(shell, "show config interfaces ge100-0/0/6 | no-more")
    print(out)

    print("[2] Check bundle membership via LACP/LAG...")
    out = run_cmd(shell, "show lacp interfaces | include ge100-0/0/6 | no-more")
    print(out)

    print("[3] List all bundles with their members...")
    out = run_cmd(shell, "show config interfaces | include bundle | no-more", wait=6)
    print(out[:2000])

    print("[4] Check LLDP to find RR-SA-2...")
    out = run_cmd(shell, "show lldp neighbor ge100-0/0/6 | no-more")
    print(out)

    print("[5] Check RR-SA-2 facing bundles (check if bundle-100 has ge100-0/0/6)...")
    out = run_cmd(shell, "show config interfaces bundle-100 | no-more")
    print(out)

    print("[6] Check all bundles that have ge100-0/0/6...")
    out = run_cmd(shell, "show config interfaces | include ge100-0/0/6 | no-more")
    print(out)

    print("[7] Check existing .999 sub-interfaces on bundles...")
    out = run_cmd(shell, "show interfaces | include 999 | no-more")
    print(out)

    shell.close()
    client.close()

if __name__ == "__main__":
    main()
