---
name: bgp-preflight-mcp-verification
description: "/BGP pre-flight MCP reachability before ExaBGP"
---

# BGP Pre-Flight Verification (MCP-First)

Before starting ExaBGP or diagnosing a failed BGP session, the agent MUST verify DUT-side
reachability using MCP Network Mapper `run_show_command`. Do NOT rely solely on `nc -z` or
`bgp_tool.py diagnose` -- they cannot distinguish between firewall blocks and missing routes.

## Mandatory Checks (in order)

### 1. Static Route Exists on DUT

```
run_show_command(device, "show route <server_ip> | no-more")
```

Expected: `Known via "static"` with `next-hop 100.70.0.254 via ge100-18/0/6.999`.

If "% Network not in table": the DUT has NO return path. Fix FIRST:

```
config
protocols static address-family ipv4-unicast route 100.64.0.0/20 next-hop 100.70.0.254
commit
end
```

### 2. .999 Sub-Interface Exists and Is Up

```
run_show_command(device, "show interfaces ge*-*/0/*.999 | no-more")
```

Expected: admin-state UP, oper-state UP, IPv4 address 100.70.0.206/24.

### 3. BGP Neighbor Config Matches ExaBGP

```
run_show_command(device, "show config protocols bgp <asn> neighbor 100.64.6.134 | no-more")
```

Check: remote-as matches ExaBGP local-as, passive enabled is set, address-families have
at least one common AFI with ExaBGP config.

### 4. ExaBGP AFI/SAFI Alignment

ExaBGP `family {}` block MUST include AFIs that the DUT neighbor has configured.
Zero common AFIs = PE sends NOTIFICATION and drops every connection.

| DUT address-family | ExaBGP family keyword |
|--------------------|-----------------------|
| ipv4-unicast       | ipv4 unicast          |
| ipv4-vpn           | ipv4 mpls-vpn         |
| ipv4-flowspec      | ipv4 flow             |
| ipv6-vpn           | ipv6 mpls-vpn         |
| ipv6-flowspec      | ipv6 flow             |

FlowSpec-VPN (SAFI 134) requires explicit `ipv4 flow-vpn` in ExaBGP AND
`address-family ipv4-flowspec-vpn` on the DUT (if DNOS supports it).

## When MCP Is Unavailable

If `run_show_command` fails or Network Mapper MCP is not responding:

1. Warn the user: "Network Mapper MCP is unavailable. Cannot verify DUT-side routing.
   Proceeding with SSH fallback (slower, less reliable)."
2. Fall back to paramiko SSH via management IP (100.64.7.197)
3. Run the same commands manually
4. Log the MCP failure for the user to investigate

## Why This Rule Exists

On 2026-03-09, the agent spent 45+ minutes and multiple 5-7 minute FortiGate quarantine
waits diagnosing a "FortiGate IDS block" that was actually a missing static route on PE-4.
`show config protocols static` returned EMPTY. A single `run_show_command` MCP call would
have found this in under 2 seconds. The `bgp_tool.py diagnose` tool misdiagnosed because
`nc -z` timeout looks identical whether caused by firewall block or missing return route.
