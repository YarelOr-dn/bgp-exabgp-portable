---
description: Portable BGP peering via this DNAAS host ExaBGP (MCP-backed)
---
# /BGP - Portable (ExaBGP stays on the DNAAS host)

Orchestrate BGP peering from the **shared DNAAS-connected ExaBGP host**. Do not run ExaBGP or `bgp_tool.py` on this laptop. Native MCP only: `user-exabgp-mcp` (SSH tunnel to host `127.0.0.1:9304`).

## First skill load (mandatory)

If `~/.cursor/bgp_profile.json` is missing (or user said `/BGP setup` / `/BGP reset-profile`):

1. **AskQuestion** (plan mode; include an All option where lists apply):
   - Allocated global VLAN **range** (e.g. `2100-2199`)
   - **VLAN ID** for this peering (must sit in that range; reject otherwise)
   - Target **DUT** hostname
   - Inband **subnet**, **DUT IP**, **gateway** (do not assume `100.70.0.0/24`)
   - DNAAS **leaf** / **bundle** if more than one (or "discover")
   - **AFI/SAFI** (allow_multiple + **All**): ipv4-unicast, ipv6-unicast, ipv4-flowspec, ipv4-flowspec-vpn, ipv6-flowspec, ipv6-flowspec-vpn, ipv4-vpn, ipv6-vpn, ipv4-labeled-unicast, ipv6-labeled-unicast, ipv4-multicast, ipv4-rt-constrains, l2vpn-evpn, l2vpn-vpls, link-state
2. `exabgp_session_lock` with `owner` = their username, `dut` = DUT.
3. `exabgp_onboard` with `execute` **false** (dry-run): `vlan`, `vlan_range`, `device`, optional `dnaas_leaf`/`bundle`.
4. If verdict `BD_AMBIGUOUS` or `NO_BD`: AskQuestion on discovered BD names. Never attach `g_mgmt_v999` unless they typed VLAN **999**.
5. AskQuestion confirm BD + sub-if from dry-run.
6. Persist `~/.cursor/bgp_profile.json` (chmod 0600) with keys: `vlan`, `vlan_range`, `bd_name`, `subnet`, `dut_ip`, `gateway`, `dut`, `dnaas_leaf`, `bundle`, `subif`, `selected_afis`, `onboarded_at`.
7. After confirm: `exabgp_onboard` `execute=true` then apply `dnos_deltas` via **host** `dnos_atomic_commit` (dry_run first). Then `exabgp_start` with `selected_afis` (comma-separated) only if no live session or they hold the lease **and** the current message is an explicit switch/stop. Then `exabgp_verify`.

Later `/BGP` with a profile skips the wizard unless `/BGP setup` or `/BGP reset-profile`. Change families: `/BGP` AskQuestion AFI again, then `exabgp_inject` / restart only with explicit switch.

## Routes vs malform

- Well-formed routes: `exabgp_inject` / `exabgp_withdraw` (`afi` and/or `route` ExaBGP string). Pipe syntax only.
- Named wire malform: `exabgp_malform` `list_types=true` then AskQuestion the type, `execute=true` + `target_ip` + lease. Catalog: bad-marker, bad-length, oversized, truncated-nlri, bad-afi-safi, duplicate-attr, bad-origin, bad-community, bad-extcommunity-0x0c. Not arbitrary bytes; not every AFI field.
- EVPN RT-6/7/8 / Host impersonation wire tricks: Spirent `spirent_bgp_raw_update` / `spirent_raw_frame` / `spirent_bgp_malform` (separate MCP), not ExaBGP.

## Native MCP

First choice: `exabgp_preflight`, `exabgp_onboard`, `exabgp_session_lock`, `exabgp_session_release`, `exabgp_start`, `exabgp_inject`, `exabgp_withdraw`, `exabgp_malform`, `exabgp_verify`, `exabgp_diagnose`, `exabgp_stop`.

Do not run the host ExaBGP CLI or the BGP learning-prune helper from this laptop. If MCP is disconnected: tell them to start `ssh -N -L 9304:127.0.0.1:9304 <exabgp-host>` and reload Cursor. CLI fallback only if MCP still down: SSH to the ExaBGP host and run `bgp_tool.py list` (read-only).

## Hard rules

- ExaBGP is single-instance on the host (`:179` + `/run/exabgp`). Never start a second session.
- Never stop/kill ExaBGP unless the **current** user message is an explicit stop **and** they hold `exabgp_session_lock`.
- `exabgp_start` requires `confirmed_no_live_session=true` or an explicit switch.
- `exabgp_malform` execute=true is raw TCP to the DUT; requires lease; can drop the BGP session. Dry-run first.
- VLAN outside the stored/asked range is rejected.

## Modes

| Input | Mode |
|---|---|
| `/BGP` | STATUS via `exabgp_verify` / lock status; if no profile, first-load wizard |
| `/BGP <Device>` | SETUP: profile + onboard + AFI AskQuestion + start/verify |
| `/BGP stop` | STOP only with lock + explicit phrase via `exabgp_stop` |
| `/BGP setup` / `/BGP reset-profile` | Re-run first-load AskQuestion |
| inject / malform in chat | `exabgp_inject` or `exabgp_malform` after AskQuestion |
