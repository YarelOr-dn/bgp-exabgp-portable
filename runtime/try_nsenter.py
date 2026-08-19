#!/usr/bin/env python3
"""Try nsenter with correct syntax and also try sudo."""
import paramiko
import time

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=2222, username=USER, password=PASS, timeout=10)
    
    commands = [
        ("whoami", "check user"),
        ("id", "check permissions"),
        ("nsenter --target 1 --net python3 /tmp/bgp_neg_test.py", "nsenter with --target 1"),
        ("nsenter --target 1 --net -- python3 /tmp/bgp_neg_test.py", "nsenter with --"),
        ("sudo nsenter --target 1 --net python3 /tmp/bgp_neg_test.py", "sudo nsenter"),
        ("sudo ip netns exec host_ns python3 /tmp/bgp_neg_test.py", "sudo ip netns exec"),
        ("nsenter --net=/var/run/netns/host_ns python3 /tmp/bgp_neg_test.py", "nsenter with host_ns path"),
    ]
    
    for cmd, desc in commands:
        print(f"\n[{desc}] {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if out:
            for line in out.split('\n')[:5]:
                print(f"  OUT: {line}")
        if err:
            for line in err.split('\n')[:3]:
                print(f"  ERR: {line}")
        
        if "TCP_OK" in out or "ESTABLISHED" in out or "VERDICT" in out:
            print(f"\n  [SUCCESS] Test ran via: {desc}")
            break
    
    client.close()

if __name__ == "__main__":
    main()
