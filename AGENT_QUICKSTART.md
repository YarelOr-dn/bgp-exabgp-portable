# Portable /BGP — agent quickstart

ExaBGP **does not run on this laptop**. It runs on the lab DNAAS host (in-band). This package only installs Cursor command/skills + an MCP client pointing at a local SSH tunnel.

## Day one

1. Clone this repo.
2. `bash install-bgp.sh --host <exabgp-host>` (or `--dry-run` first).
3. In another terminal: `ssh -N -L 9304:127.0.0.1:9304 <exabgp-host>`
4. Reload Cursor so `user-exabgp-mcp` binds to `http://127.0.0.1:9304/sse`.
5. Run `/BGP`. With no `~/.cursor/bgp_profile.json`, the agent **must AskQuestion**:
   - your allocated global VLAN range
   - VLAN ID for this peering (inside that range)
   - DUT, inband subnet / DUT IP / gateway
   - AFI/SAFI (multi-select + All): ipv4-unicast, ipv6-unicast, ipv4-flowspec, ipv4-flowspec-vpn, ipv6-flowspec, ipv6-flowspec-vpn, ipv4-vpn, ipv6-vpn, ipv4-labeled-unicast, ipv6-labeled-unicast, ipv4-multicast, ipv4-rt-constrains, l2vpn-evpn, l2vpn-vpls, link-state
   - confirm IL DNAAS global BD `g_*_v<VLAN>` from dry-run (never silent `g_mgmt_v999`)
6. Well-formed routes: MCP `exabgp_inject`. Named wire malform: `exabgp_malform` `list_types=true` then execute with lease. EVPN raw UPDATEs: Spirent MCP, not ExaBGP.
7. Do not `/BGP stop` unless you hold the ExaBGP lease and you explicitly asked to stop.

## Profile schema (`~/.cursor/bgp_profile.json`)

```json
{
  "vlan": 2100,
  "vlan_range": "2100-2199",
  "bd_name": "g_example_v2100",
  "subnet": "24",
  "dut_ip": "10.x.x.x",
  "gateway": "10.x.x.1",
  "dut": "PE-X",
  "dnaas_leaf": "DNAAS-LEAF-...",
  "bundle": "bundle-100",
  "subif": "bundle-100.2100",
  "selected_afis": ["l2vpn-evpn", "ipv4-unicast"],
  "onboarded_at": "ISO-8601"
}
```

chmod 0600. `/BGP reset-profile` deletes it and re-asks.

## Host facts (this lab)

- MCP: host loopback `:9304` (`user-exabgp-mcp`)
- BGP TCP: host `:179`, pipes `/run/exabgp/exabgp.{in,out}`
- Neighbor toward ExaBGP is the host OOB IP (often `100.64.6.134` or `100.64.11.95` per DUT)

## Tools

`exabgp_session_lock` / `exabgp_session_release` / `exabgp_onboard` / `exabgp_start` (`selected_afis`) / `exabgp_verify` / `exabgp_inject` / `exabgp_withdraw` / `exabgp_malform` / `exabgp_stop`
