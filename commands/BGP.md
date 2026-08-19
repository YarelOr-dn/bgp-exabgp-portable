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
   - Target **DUT** hostname (must be in IL `~/SCALER/db/devices.json`, e.g. PE-* / RR-SA-* — not Houston `HO-*`)
   - DUT **BGP ASN** (the DUT's local AS; never invent 1234567)
   - Inband **subnet**, **DUT IP**, **gateway** (gateway = inband next-hop toward this host, **not** the DUT IP)
   - DNAAS **leaf** from IL only: `DNAAS-LEAF-B10/B14/B15/D16` (never `HO-DNAAS-*`)
   - **AFI/SAFI** (allow_multiple + **All**): ipv4-unicast, ipv6-unicast, ipv4-flowspec, ipv4-flowspec-vpn, ipv6-flowspec, ipv6-flowspec-vpn, ipv4-vpn, ipv6-vpn, ipv4-labeled-unicast, ipv6-labeled-unicast, ipv4-multicast, ipv4-rt-constrains, l2vpn-evpn, l2vpn-vpls, link-state
2. `exabgp_session_lock` with `acquire=true`, `owner` = their username, `dut` = DUT. If `/BGP` has no profile yet, still call `exabgp_session_lock` with `acquire=false` first and print lock status.
3. If verdict `DEVICE_BUSY`: print holder `owner`, `dut`, `age_sec`. Do **not** steal. Force only if the **current** message is an explicit stop/switch for that holder.
4. `exabgp_onboard` with `execute` **false** (plan only): `vlan`, `vlan_range`, `device`, `selected_afis`, optional `dnaas_leaf`/`bundle`. Omit leaf to auto-walk (`NEED_DISCOVER` / `LEAF_AMBIGUOUS` / `NO_LEAF`).
5. If verdict `BD_AMBIGUOUS`, `LEAF_AMBIGUOUS`, or `NO_BD`: AskQuestion on discovered names. Never attach `g_mgmt_v999` unless they typed VLAN **999**.
6. AskQuestion confirm BD + sub-if from the plan.
7. Persist `~/.cursor/bgp_profile.json` (chmod 0600) with keys: `vlan`, `vlan_range`, `bd_name`, `subnet`, `dut_ip`, `gateway`, `dut`, `dnaas_leaf`, `bundle`, `subif`, `selected_afis`, `onboarded_at`.
8. `exabgp_onboard` `execute=true` `confirm_commit=false` — host **dry_run only** (verdict `DRY_RUN_OK`). Show diffs. Do not use a general DNOS config MCP.
9. After user confirms diffs: `exabgp_onboard` `execute=true` `confirm_commit=true` (lease required). Then `exabgp_start` with `selected_afis` only if no live session or they hold the lease **and** the current message is an explicit switch/stop. Then `exabgp_verify`.

Later `/BGP` with a profile: start with `exabgp_session_lock` `acquire=false` (status). Skip wizard unless `/BGP setup` or `/BGP reset-profile`. Change families: AskQuestion AFI again, persist `selected_afis`, then `exabgp_inject` / restart only with explicit switch.

## Routes vs malform

- Well-formed routes: `exabgp_inject` / `exabgp_withdraw` (`afi` and/or `route` ExaBGP string). Pipe syntax only.
- Named wire malform: `exabgp_malform` `list_types=true` then AskQuestion the type, `execute=true` + `target_ip` + lease. Catalog: bad-marker, bad-length, oversized, truncated-nlri, bad-afi-safi, duplicate-attr, bad-origin, bad-community, bad-extcommunity-0x0c. Not arbitrary bytes; not every AFI field.
- EVPN RT-6/7/8 / Host impersonation wire tricks: Spirent `spirent_bgp_raw_update` / `spirent_raw_frame` / `spirent_bgp_malform` (separate MCP), not ExaBGP.

## Extend /BGP with a new AFI/SAFI or capability (RFC-driven)

Users improve the shared framework without per-request host intervention (review queue unless `BGP_FAMILY_AUTOPUBLISH=1`).

1. Paste the RFC excerpt. Build a FAMILY_SCHEMA spec (do not guess DNOS CLI). Closed encodings: `u8:<int>`, `u16:<int>`, `u32:<int>`, `hex:<even-hex>`, `ipv4:<a.b.c.d>`, `ipv6:<addr>`, `rd:<x:y>`, `prefix:<cidr>`, `rt:<x:y>`, `arg:<name>`.
2. `exabgp_rfc_synthesize` with `spec_json` (host is deterministic; you supply the spec). Optional `plugin_src` is AST-rejected then imported only in `python3 -I -S` with sockets disabled. Spec-only is preferred (zero user code).
3. Review dump (`open_hex` / `update_hex`). Gates: `validate_spec` then AST then sandbox then dump-and-reparse then size <= 4096.
4. Flag `BGP_FAMILY_AUTOPUBLISH` off (default): verdict `QUEUED_FOR_REVIEW`; promote with `exabgp_family_promote`. Flag on: `AUTO_PUBLISHED` into shared `families/registry.json`.
5. Instant path: `exabgp_family_register` (`publish=true` after a clean spec).
6. `exabgp_capability_probe` default `mode=dump_only` (no socket). Live `execute=true` requires lease. `transient` connects `target_ip:179`. `probe_port` binds an ephemeral listener. Never writes the ExaBGP pipe. Advanced ExaBGP-pipe per-family patches stay manual.

## Native MCP

First choice: `exabgp_preflight`, `exabgp_onboard`, `exabgp_session_lock`, `exabgp_session_release`, `exabgp_start`, `exabgp_inject`, `exabgp_withdraw`, `exabgp_malform`, `exabgp_rfc_synthesize`, `exabgp_family_register`, `exabgp_family_list`, `exabgp_capability_probe`, `exabgp_family_promote`, `exabgp_verify`, `exabgp_diagnose`, `exabgp_stop`.

Do not run the host ExaBGP CLI or the BGP learning-prune helper from this laptop. If MCP is disconnected: tell them to start `ssh -N -L 9304:127.0.0.1:9304 <exabgp-host>` and reload Cursor. CLI fallback only if MCP still down: SSH to the ExaBGP host and run `bgp_tool.py list` (read-only).

## Hard rules

- ExaBGP is single-instance on the host (`:179` + `/run/exabgp`). Never start a second session.
- Never stop/kill ExaBGP unless the **current** user message is an explicit stop **and** they hold `exabgp_session_lock`.
- `exabgp_start` requires `confirmed_no_live_session=true` or an explicit switch.
- `exabgp_malform` execute=true is raw TCP to the DUT; requires lease; can drop the BGP session. Dry-run first.
- VLAN outside the stored/asked range is rejected.
- Every `/BGP` starts with lock status (`exabgp_session_lock` `acquire=false`). `DEVICE_BUSY` prints holder; no silent steal.
- Onboard commits run **inside** `user-exabgp-mcp` (`confirm_commit`). Do not tunnel `:9300`.

## Modes

| Input | Mode |
|---|---|
| `/BGP` | STATUS via `exabgp_verify` / lock status; if no profile, first-load wizard |
| `/BGP <Device>` | SETUP: profile + onboard + AFI AskQuestion + start/verify |
| `/BGP stop` | STOP only with lock + explicit phrase via `exabgp_stop` |
| `/BGP setup` / `/BGP reset-profile` | Re-run first-load AskQuestion |
| inject / malform in chat | `exabgp_inject` or `exabgp_malform` after AskQuestion |
