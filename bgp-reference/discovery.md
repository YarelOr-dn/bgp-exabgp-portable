# BGP Tool - DNAAS Path Discovery

## Overview

Discover the path from this server to the target DNOS device via the DNAAS fabric:

```
Server (100.64.6.134) -> Firewall (100.70.0.254) -> DNAAS Spine -> DNAAS Leaf -> Target Device
```

VLAN 999 (inband management) is carried in bridge-domain `g_mgmt_v999` on DNAAS leaves.

## Discovery Steps

### 0. Cluster-Aware Device Resolve (MANDATORY first step)

Before anything else, run:

```bash
python3 ~/SCALER/FLOWSPEC_VPN/exabgp/bgp_tool.py resolve --device <Device>
```

For DNOS clusters (`is_cluster: true`) the SCALER DB `ip` field is the cluster mgmt
VIP, which on this lab uses a different sshd that **rejects `dnroot/dnroot`**. The
resolver probes the candidate list (cached active NCC -> VIP -> `cluster_ncc_ips[]`),
returns the first IP that AUTHs, identifies the active NCC (`kvm108-cl408d-ncc0`
vs `ncc1`), and caches the winner in `~/.cursor/bgp-reference/cluster_ncc_cache.json`.
Cache hit costs ~0.5 s; first probe is ~10 s.

Use the returned `ip` for ALL subsequent SSH/show/config calls. Never use the bare
DB `ip` for cluster devices unless `bgp_tool.py resolve` confirms it works. Use
`--refresh` after a known NCC switchover. This is the same pattern the topology SSH
button now uses (per-NCC IP > VIP).

### 1. List Devices

Use `list_devices` (network-mapper MCP) to get available devices. Match user's target to a device name.

### 2. Get Target Device LLDP

Use `get_device_lldp(target_device)` to find:
- Which DNAAS leaf the target connects to (remote device name contains "DNAAS-LEAF" or "LEAF-B")
- The local interface on the target (e.g., `ge400-0/0/0`) and remote port on leaf

### 3. Get Target Device Interfaces

Use `get_device_interfaces(target_device)` to find:
- The bundle that contains the LLDP port (e.g., `ge400-0/0/0` is in `bundle-100`)
- This is the **device bundle** -- we add `bundle-100.999` sub-interface on it

### 4. Get DNAAS Leaf Config

Use `get_device_config(dnaas_leaf)` or `run_show_command` to find:
- The bundle on the leaf for the target (check `show config interfaces <port> | include bundle-id`)
- Bridge-domain `g_mgmt_v999` -- check existing ACs. We add `bundle-X.999` (target-facing side)

### 5. Check for Existing .999 Sub-Interface

Use `get_device_config(target_device, section='interfaces')` to check if `bundle-Y.999` already exists. If yes, re-use it (verify no IP conflict).

### 6. Store Discovered Path

Record in session state:
```json
{
  "target_device": "RR-SA-2",
  "dnaas_leaf": "DNAAS-LEAF-B15",
  "leaf_bundle": "bundle-X",
  "device_bundle": "bundle-100",
  "device_has_999": false
}
```

## Path Cache

Check `learned/patterns.json` -> `dnaas_path_cache` for previously discovered paths. If valid (device still in list_devices), reuse. Otherwise re-discover.

## AskQuestion Integration

When multiple options exist, use **AskQuestion** tool. Never assume; always ask the user.

- **Multiple physical interfaces from device to DNAAS:** LLDP may show several interfaces connecting to different DNAAS leaves or ports. Collect all options and use AskQuestion:
  - "Device X has multiple interfaces connecting to DNAAS. Which one to use for .999 sub-interface?"
  - Options: e.g. `["bundle-100 (via ge400-0/0/0 to DNAAS-LEAF-B15)", "bundle-200 (via ge800-0/0/0 to DNAAS-LEAF-B16)"]`
- **Multiple DNAAS leaves connected:** Device may connect to more than one leaf. Use AskQuestion:
  - "Device X connects to multiple DNAAS leaves. Which one?"
  - Options: list leaf names with bundle IDs
- **Only one option:** Auto-select without asking. Do not AskQuestion when there is a single interface or single DNAAS leaf.

## Edge Cases

- **Multiple links:** Target may have 2+ ports to same leaf (LACP bundle). Both are in the same bundle. Use bundle sub-interface.
- **No LLDP to leaf:** Device may not be DNAAS-connected. Report to user.
- **DNAAS leaf not in network-mapper:** Ask user for leaf name and bundle.
