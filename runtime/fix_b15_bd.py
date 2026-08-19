#!/usr/bin/env python3
"""Fix DNAAS-LEAF-B15: enable bundle-100.999 and add to g_mgmt_v999 BD."""
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

    print("=" * 60)
    print("DNAAS-LEAF-B15: Enable bundle-100.999 + add to g_mgmt_v999")
    print("=" * 60)

    print("\n[1] Check current bundle-100.999 config...")
    out = run_cmd(shell, "show config interfaces bundle-100.999 | no-more")
    print(out)

    print("[2] Check current BD membership...")
    out = run_cmd(shell, "show config network-services bridge-domain instance g_mgmt_v999 | no-more")
    print(out)

    print("[3] Entering config mode...")
    run_cmd(shell, "configure")

    print("[4] Enable bundle-100.999...")
    run_cmd(shell, "interfaces bundle-100.999 admin-state enabled")

    needs_l2 = True
    needs_vlan = True
    if "l2-service enabled" in out:
        needs_l2 = False
    if "vlan-id 999" in out:
        needs_vlan = False

    if needs_l2:
        print("[4a] Setting l2-service enabled...")
        run_cmd(shell, "interfaces bundle-100.999 l2-service enabled")
    if needs_vlan:
        print("[4b] Setting vlan-id 999...")
        run_cmd(shell, "interfaces bundle-100.999 vlan-id 999")

    print("[5] Adding bundle-100.999 to g_mgmt_v999 BD...")
    run_cmd(shell, "network-services bridge-domain instance g_mgmt_v999 interface bundle-100.999")

    print("[6] Committing...")
    out = run_cmd(shell, "commit", wait=15)
    print(out)

    if "ERROR" in out or "Aborted" in out:
        print("[ERROR] Commit failed")
        run_cmd(shell, "rollback 0", wait=5)
        run_cmd(shell, "exit")
    else:
        print("[OK] Commit succeeded")
        run_cmd(shell, "exit")

    print("\n[7] Verify BD config now includes bundle-100.999...")
    out = run_cmd(shell, "show config network-services bridge-domain instance g_mgmt_v999 | no-more")
    print(out)

    print("[8] Verify bundle-100.999 is UP...")
    out = run_cmd(shell, "show interfaces bundle-100.999 | no-more")
    print(out)

    print("[9] Verify in operational view...")
    out = run_cmd(shell, "show interfaces | include 999 | no-more")
    print(out)

    shell.close()
    client.close()
    print("\n[DONE]")

if __name__ == "__main__":
    main()
