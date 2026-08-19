#!/usr/bin/env python3
"""Try sudo with password piped via -S flag."""
import paramiko

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=2222, username=USER, password=PASS, timeout=10)
    
    commands = [
        f"echo '{PASS}' | sudo -S nsenter --target 1 --net -- python3 /tmp/bgp_neg_test.py",
        f"echo '{PASS}' | sudo -S ip netns exec host_ns python3 /tmp/bgp_neg_test.py",
        f"echo '{PASS}' | sudo -S python3 -c \"import os; os.system('nsenter --target 1 --net -- python3 /tmp/bgp_neg_test.py')\"",
        f"echo '{PASS}' | sudo -S bash -c 'nsenter --target 1 --net -- python3 /tmp/bgp_neg_test.py'",
    ]
    
    for i, cmd in enumerate(commands):
        print(f"\n[{i+1}] {cmd[:80]}...")
        stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if out:
            for line in out.split('\n')[:10]:
                print(f"  OUT: {line}")
        if err:
            for line in err.split('\n')[:5]:
                if "[sudo]" not in line and "password" not in line.lower():
                    print(f"  ERR: {line}")
        
        if "TCP_OK" in out or "ESTABLISHED" in out or "VERDICT" in out:
            print(f"\n  === TEST EXECUTED SUCCESSFULLY ===")
            break
    
    client.close()

if __name__ == "__main__":
    main()
