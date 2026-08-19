#!/usr/bin/env python3
"""Try accessing DNAAS leaves with known credentials."""
import paramiko
import time

LEAVES = [
    ("B14", "100.64.101.5", "sisaev"),
    ("B10", "100.64.101.3", "sisaev"),
    ("B15", "100.64.101.6", "sisaev"),
    ("B15", "100.64.101.6", "dnroot"),
]

PASSWORDS = ["sisaev", "dnroot", "Drivenets1!", "drivenets", "dn1234", "admin", "DnRoot1!"]

def try_connect(host, port, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password, 
                       timeout=5, allow_agent=False, look_for_keys=False,
                       auth_timeout=5)
        return client
    except Exception:
        return None

def main():
    for leaf_name, ip, default_user in LEAVES:
        print(f"\n{'='*50}")
        print(f"Trying {leaf_name} ({ip})...")
        
        for port in [22, 2222]:
            for user in [default_user, "dnroot", "admin"]:
                for pwd in PASSWORDS:
                    client = try_connect(ip, port, user, pwd)
                    if client:
                        print(f"  [OK] {user}@{ip}:{port} with '{pwd}'")
                        
                        shell = client.invoke_shell(width=200, height=50)
                        time.sleep(2)
                        boot = shell.recv(4096).decode(errors='replace')
                        
                        shell.send("show system | no-more\n")
                        time.sleep(2)
                        out = b''
                        while shell.recv_ready():
                            out += shell.recv(8192)
                        resp = out.decode(errors='replace')
                        
                        if "Hostname" in resp or "#" in resp:
                            print(f"  [OK] Got CLI! First 200 chars: {resp[:200]}")
                        
                        shell.close()
                        client.close()
                        
                        if leaf_name == "B15":
                            print(f"\n  === B15 ACCESS FOUND: {user}/{pwd} port {port} ===")
                            return user, pwd, port
                        break
                    
                if client:
                    break
            if client:
                break
    
    print("\n[FAIL] Could not access B15")
    return None, None, None

if __name__ == "__main__":
    main()
