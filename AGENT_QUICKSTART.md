# Portable /BGP — agent quickstart

ExaBGP **does not run on this laptop**. It runs on the lab DNAAS host (in-band). This package only installs Cursor command/skills + an MCP client pointing at a local SSH tunnel.

## Day one

1. Clone this repo.
2. `bash install-bgp.sh --host <exabgp-host>` (`--host` required; `--dry-run` still needs `--host`).
3. Keep tunnel up: `bash bgp-tunnel.sh <exabgp-host>` (`ssh -N -L 9304:127.0.0.1:9304`).
4. Reload Cursor so `user-exabgp-mcp` binds to `http://127.0.0.1:9304/sse`.
5. Run `/BGP` in **Plan mode** (AskQuestion). With no `~/.cursor/bgp_profile.json`, the agent asks VLAN range, VLAN, DUT, subnet, AFI/SAFI + All. Lock status first (`acquire=false`). Onboard: plan → `execute=true` dry_run (`DRY_RUN_OK`) → `confirm_commit=true` on the host MCP (no dnos-config). Never silent `g_mgmt_v999`.
6. Optional Spirent EVPN raw: second tunnel `ssh -N -L 9301:127.0.0.1:9301 <host>` (not vendored here).
7. Well-formed routes: MCP `exabgp_inject`. Named wire malform: `exabgp_malform`. Do not `/BGP stop` unless you hold the lease and explicitly asked to stop.

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

`exabgp_session_lock` / `exabgp_session_release` / `exabgp_onboard` / `exabgp_start` (`selected_afis`) / `exabgp_verify` / `exabgp_inject` / `exabgp_withdraw` / `exabgp_malform` / `exabgp_rfc_synthesize` / `exabgp_family_register` / `exabgp_capability_probe` / `exabgp_family_promote` / `exabgp_stop`

RFC-driven new AFI/SAFI: paste RFC, build FAMILY_SCHEMA, `exabgp_rfc_synthesize`, then dump-only probe. Live send needs the lease. `BGP_FAMILY_AUTOPUBLISH` is a host MCP env flag (off = review queue).
