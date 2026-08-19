#!/usr/bin/env python3
"""Apply DNOS config/ops via SSH - used for BGP neighbor add/remove/clear."""
import json
import base64
import sys
from pathlib import Path

# Add parent for device_manager
sys.path.insert(0, str(Path(__file__).parent.parent))
from test_verifier.device_manager import DeviceManager

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["clear", "disable", "add-passive", "set-passive"], help="Action to perform")
    args = parser.parse_args()

    dm = DeviceManager()
    dm.load_devices()
    conn = dm.get_connection("RR-SA-2")
    if not conn:
        conn = dm.connect_device("RR-SA-2")
    if not conn or not conn.connected:
        print("ERROR: Could not connect to RR-SA-2")
        sys.exit(1)

    if args.action == "clear":
        ok, out = conn.run_command("clear bgp neighbor 100.64.6.134")
        print(out)
        sys.exit(0 if ok else 1)

    if args.action == "disable":
        config_lines = [
            "protocols",
            "bgp 123",
            "neighbor 100.64.6.134",
            "admin-state disabled",
            "exit",
            "exit",
            "exit",
        ]
        ok, out = conn.run_config_command(config_lines, commit=True)
        print(out)
        sys.exit(0 if ok else 1)

    if args.action == "set-passive":
        # Add passive to existing neighbor (minimal change)
        config_lines = [
            "protocols",
            "bgp 123",
            "neighbor 100.64.6.134",
            "passive",
            "exit",
            "exit",
            "exit",
        ]
        ok, out = conn.run_config_command(config_lines, commit=True)
        print(out)
        sys.exit(0 if ok else 1)

    if args.action == "add-passive":
        config_lines = [
            "protocols",
            "bgp 123",
            "neighbor 100.64.6.134",
            "remote-as 65200",
            "admin-state enabled",
            "passive",
            "ebgp-multihop 10",
            "update-source bundle-100.999",
            "local-as 1234567 type no-prepend",
            "address-family ipv4-unicast",
            "send-community community-type both",
            "soft-reconfiguration inbound",
            "exit",
            "exit",
            "exit",
            "exit",
            "exit",
        ]
        ok, out = conn.run_config_command(config_lines, commit=True)
        print(out)
        sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
