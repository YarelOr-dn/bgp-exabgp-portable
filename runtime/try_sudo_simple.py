#!/usr/bin/env python3
"""Debug sudo behavior on RR-SA-2."""
import paramiko
import time

HOST = "100.64.4.205"
USER = "dnroot"
PASS = "dnroot"

def run(client, cmd, desc):
    print(f"\n[{desc}] {cmd}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
    time.sleep(2)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    print(f"  OUT: '{out[:200]}'")
    print(f"  ERR: '{err[:200]}'")

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=2222, username=USER, password=PASS, timeout=10)
    
    run(client, "echo HELLO", "basic echo")
    run(client, f"echo '{PASS}' | sudo -S whoami", "sudo whoami")
    run(client, f"echo '{PASS}' | sudo -S id", "sudo id")
    run(client, f"echo '{PASS}' | sudo -S cat /proc/1/net/tcp | head -5", "sudo cat proc tcp")
    run(client, f"echo '{PASS}' | sudo -S grep 00B3 /proc/1/net/tcp", "sudo grep port 179")
    
    client.close()

if __name__ == "__main__":
    main()
