#!/usr/bin/env python3
"""Check B15 using pexpect for interactive SSH."""
import pexpect
import sys

HOST = "100.64.101.6"
USER = "dnroot"
PASS = "dnroot"

def main():
    cmd = f"ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=keyboard-interactive,password {USER}@{HOST}"
    child = pexpect.spawn(cmd, timeout=15, encoding='utf-8')
    child.logfile_read = sys.stdout

    idx = child.expect(["password:", "Password:", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
    if idx in (0, 1):
        child.sendline(PASS)
    elif idx == 2:
        print("[TIMEOUT] No password prompt")
        return
    else:
        print("[EOF] Connection closed")
        return

    child.expect(["#", ">", pexpect.TIMEOUT], timeout=10)

    child.sendline("show system | no-more")
    child.expect(["#", ">", pexpect.TIMEOUT], timeout=10)

    child.sendline("show config network-services bridge-domain instance g_mgmt_v999 | no-more")
    child.expect(["#", ">", pexpect.TIMEOUT], timeout=10)

    child.sendline("show interfaces | include ge100-0/0/6 | no-more")
    child.expect(["#", ">", pexpect.TIMEOUT], timeout=10)

    child.sendline("show config interfaces bundle-60000.999 | no-more")
    child.expect(["#", ">", pexpect.TIMEOUT], timeout=10)

    child.sendline("exit")
    child.close()

if __name__ == "__main__":
    main()
