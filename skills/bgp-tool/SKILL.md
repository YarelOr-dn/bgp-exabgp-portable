---
name: bgp-tool
description: "/BGP ExaBGP session tool routing and protection"
---

# BGP Peering Tool Rules

## SESSION PROTECTION (READ FIRST)

**NEVER stop, kill, restart, or disrupt a running ExaBGP process.** See `~/.cursor/rules/bgp-session-protection.mdc`.
`bgp_tool.py stop` requires `--confirm-kill` flag. Only use when user explicitly said stop/kill.

## Context

When editing files under `SCALER/FLOWSPEC_VPN/exabgp/`, you are working on the BGP Peering Tool.

**Read first:**
1. `~/.cursor/rules/bgp-session-protection.mdc` for absolute session protection rule
2. `~/.cursor/skills/bgp-peering-tool/SKILL.md` for architecture overview
3. `~/.cursor/commands/BGP.md` for the full workflow

## ExaBGP 5.0.1 Rules

- Family names: `ipv4 flow` (NOT flowspec), `ipv4 flow-vpn` (NOT flowspec-vpn)
- `ipv6 flow` family WORKS (parser bug was patched; confirmed 2026-02-25 with 4K IPv6 FlowSpec rules)
- Named pipes at `/run/exabgp/exabgp.{in,out}` must exist before start
- Hold-time: always 180s to match DNOS default
- local-address is the server OOB IP: `100.64.6.134`
- router-id is the ExaBGP inband IP: `100.70.0.32`

## ExaBGP API Pipe Format (CRITICAL)

- **ALL FlowSpec via pipe MUST use FLAT format** — match{}/then{} silently fails (returns 'error' on exabgp.out, no log)
- SAFI 133: `announce flow route destination <prefix> <action>` (e.g., `announce flow route destination 10.0.0.0/24 rate-limit 0`)
- SAFI 134: `announce flow route rd X destination <prefix> redirect <ip> extended-community [ target:RT ]`
- IPv6 SAFI 133: same syntax, ExaBGP auto-detects AFI from address format
- IPv6 SAFI 134: same as IPv4 SAFI 134 but with IPv6 destination — ExaBGP detects AFI from prefix
- **Always check exabgp.out after pipe writes** — `timeout 1 cat /run/exabgp/exabgp.out` → 'error' or 'done'
- **Always test 1 route before bulk injection** — verify PfxAccepted on device before sending thousands

## VPN RT Discovery (MANDATORY)

Before injecting ANY VPN route (FlowSpec-VPN, L3VPN, EVPN, VPLS):
1. Query: `run_show_command(device, "show config network-services vrf")` or `get_device_config(device, section='network-services')`
2. Parse import RTs per VRF per address-family (ipv4-flowspec, ipv6-flowspec, ipv4-unicast)
3. AskQuestion: which VRF to target? Show VRF name + its import RTs
4. Use the discovered RT — NEVER use hardcoded defaults when device config is available
5. If VRF has no `import-vpn` for the selected AFI, warn user before injecting
- See `~/.cursor/bgp-reference/route-injection.md` "VPN Route Target Discovery" for full protocol

## Scale Injection

- Use `bgp_tool.py scale --mode <mode> --count N --fast`
- Modes: `flowspec-ipv4`, `flowspec-ipv6` (SAFI 133), `flowspec-vpn-ipv4` (SAFI 134), `flowspec-vpn-ipv6` (SAFI 134), `batch`, `stress`
- `flowspec-vpn-ipv4` accepts `--rd`, `--rt`, `--base-source`, `--source-mask` for source+dest match
- `flowspec-vpn-ipv6` accepts `--rd`, `--rt`, `--base-source`, `--source-mask` for source+dest match
- Default RTs: `1234567:301` (ipv4-flowspec), `1234567:401` (ipv6-flowspec)
- `--withdraw` flag: withdraw routes for a mode (reads from session state, reconstructs exact format). `--keep N` to retain first N routes
- Rate: ~2000 rps via `inject_batch_fast` (batch_size=200, blocking pipe writes)
- TCAM shared pool: IPv4=12K, IPv6=4K (FlowSpec + FlowSpec-VPN combined)
- Verify: `show system npu-resources resource-type flowspec`
- **Mixed IPv4+IPv6 with source+dest:** Do NOT combine in a single `--preload`. Preload IPv4 first, then inject IPv6 via `--fast` (ExaBGP drops session after ~325 IPv6 when combined)

## Health Check

- `bgp_tool.py verify --session-id <id>` -- instant check: ExaBGP alive + TCP ESTABLISHED
- Returns `healthy: true/false` with actionable `action` message when unhealthy
- After every `--preload`, `cmd_scale` auto-checks TCP state and warns if session dropped
- **ALWAYS run `verify` after preload** before waiting 90s for routes to process -- catches session drops in 3s instead of 90s

## Reset a storming / contended peering -> ONLY the DUT session valid (learned 2026-07-13)

**Symptom:** the DUT/RR neighbor sits in `Connect`/`Active` for hours (its `Up/Down`
timer NEVER resets), high `MsgSent`, no routes received/reflected -- while
`bgp_tool` reports the session "established" (that is its CACHED store value, NOT
truth). ExaBGP log shows `[STORM] ... ExaBGP ALIVE but TCP NOT established for
<N>s (reconnect storm). Killing to prevent FortiGate IDS trigger`.

**Truth source = the DUT side**, never ExaBGP's report:
`dnos_run_show_commands(<RR>, "show bgp l2vpn evpn summary | include <exabgp-ip>")`
-> State must be `Established` and `Up/Down` must have RESET to seconds. A stale
`bgp_tool` `established:true`/`tcp_state:ESTAB` with the DUT still `Connect` = NOT up.

**Root causes (any/all):**
1. MULTIPLE ExaBGP sessions contend for the single `local-address -> peer:179`
   socket. Only one TCP from a given source IP exists; if a session with the WRONG
   `local-as` grabs it (e.g. `pe1_evpn_b11` local-as 1234567 while the RR neighbor
   expects `remote-as 65200`), the DUT rejects the OPEN -> permanent `Connect`.
   ExaBGP is single-instance by design; two `active` sessions to the same peer = bug.
2. The cron WATCHDOG (`bgp_watchdog.py --auto-restart`, 2 crontab entries) revives
   EVERY session whose state file is `active` (even dead/wrong ones) -> the wrong
   session keeps "popping back".
3. The `:179` guard (iptables `bgp_guard_accept`/`bgp_guard_drop`) is CLOSED when no
   session is active -> drops the DUT's inbound SYNs. A clean `start` reopens it
   (log: `Port 179 guard: OPEN`).
4. A **FortiGate IDS** in the path (host OOB `100.64.11.95` <-> RR inband
   `100.70.0.205`) RESETS a storming BGP TCP; the watchdog then kills the session to
   avoid tripping the IDS. If the path/IDS blocks it, NO restart establishes it, and
   leaving it storming risks getting the host flagged.

**Reset procedure (drive to ONE valid DUT session):**
1. `bgp_tool.py list` -> find EVERY `status:active` session. There must be exactly
   ONE (the DUT you want).
2. Close every OTHER session: `bgp_tool.py stop --session-id <s> --confirm-kill`
   (marks its file `closed` so the watchdog stops guarding it); kill lingering procs
   `pkill -f "exabgp_<s>.conf"`.
3. Confirm only ONE ExaBGP config proc remains:
   `ps -eo pid,args | grep [e]xabgp | grep -v user_exabgp_mcp`.
4. Confirm the target's `local-as` MATCHES the DUT neighbor's `remote-as`
   (RR-SA-2 expects remote-as 65200 -> ExaBGP local-as 65200). Wrong AS = permanent
   `Connect`.
5. Clean re-establish: `stop --confirm-kill` then `start ...`; watch for
   `Port 179 guard: OPEN` + `BGP TCP ESTABLISHED after <N>s`.
6. VERIFY ON THE DUT: State `Established` + `Up/Down` reset. If it stays `Connect`
   with the timer NOT resetting, the path/IDS is blocking (cause 4) -- do NOT keep
   restarting (storm risks IDS). Stop the session and fix the path/allowlist first.

**Watchdog control:** it protects a healthy session but revives wrong ones. For
"only the DUT valid": ensure ONLY the DUT session is `active` (all others `closed`)
so the watchdog guards just it. To fully stop it (explicit user request), comment
the 2 crontab lines
(`crontab -l | sed -E 's/^([^#].*bgp_watchdog.*)$/#DISABLED &/' | crontab -`) -- but
then a storming session is NOT auto-killed, so only disable it with all sessions
stopped or one proven stable.

**If IDS-blocked:** the peering cannot come up until the FortiGate allowlists
`<host-oob> <-> <RR-inband>:179` (or IDS session-reset is disabled for it). Infra
change, not a BGP-config fix. Confirm via the watchdog log `[STORM] ... FortiGate
IDS` lines + the DUT `Up/Down` never resetting.

## DNOS Config Rules

- Static route: `protocols static address-family ipv4-unicast route ...` (NOT routing-options)
- ebgp-multihop: always required (peer not directly connected)
- update-source: set to the `.999` sub-interface
- send-community: `community-type both`
- Always validate with `validate_config()` before apply

## Session State

- All sessions stored in `sessions/<id>.json`
- Every applied config must have rollback commands stored
- Session file is the recovery mechanism for lost context
- Never delete active session files

## Python Code Style

- Use argparse for CLI
- Use JSON for all state files
- Log to both stdout and `logs/<session_id>.log`
- Handle SIGTERM gracefully in bgp_tool.py
- Use subprocess for ExaBGP process management (not os.system)

## EVPN RT-3/6/7/8 injection + fabric bypass + direct-vendor peering (learned 2026-07-15, SW-252580)

ExaBGP announce.py (patched, `reactor/api/command/announce.py`) now emits EVPN
route-types beyond the base 1/2/4/5. All via `announce/withdraw evpn <subtype>`:
- RT-3 IMET:  `evpn multicast rd <rd> ethernet-tag <n> ip <orig> label <vni> pmsi <vtep> next-hop <nh> extended-community [ target:<rt> 0x030c000000000008 <mcast-flags-ec> ]`
- RT-6 SMET:  `evpn smet rd <rd> [ethernet-tag n] [source <ip>] group <ip> originator <ip> flags <0xNN> next-hop <nh> extended-community [ target:<rt> ]`
- RT-7/8:     `evpn join-sync|leave-sync rd <rd> esi <esi> ethernet-tag <n> group <ip> originator <ip> flags <0xNN> [max-response-time <n> (RT-8)] next-hop <nh> extended-community [ <es-import-ec> <evi-rt-ec> ]`
Flags octet (RT-6/7/8): v1=0x01 v2=0x02 v3=0x04 IE=0x08. RT-8 trailer order (as
Junos parses it) = Reserved(4)+Flags(1)+MaxRespTime(1). RT-3 Multicast-Flags EC =
0x0609 + 2-oct flags (bit0=I IGMP-proxy, bit1=M MLD). RT-6/7/8 are built as raw
GenericEVPN(code) so the NLRI registry is untouched (received routes keep generic
decode = safe). Shared builder `_parse_evpn_mcast(words, code)`; offline-validate
with `python3 -c "from exabgp.reactor.api.command import announce as A; A._parse_evpn_mcast(<words>, <code>)"`.

FABRIC BYPASS (avoid the FortiGate IDS RST-storm on the OOB<->RR-inband :179 path):
peer ExaBGP to the RR over a DNAAS fabric VLAN p2p instead of OOB. Host h263 has
fabric NICs to DNAAS-LEAF-B10; VLAN 212 /30 (h263 fab212=100.70.212.2 <-> RR
bundle-100.212=100.70.212.1), BD g_yor_v212 single-tag on B10/B09/B15. Established
instantly, stable, injections land immediately. Watchdog is inband-aware
(`_is_fabric_peer` / `FABRIC_PEER_SUBNETS`, skips OOB DG-ARP gate). Full per-device
deltas: `SCALER/FLOWSPEC_VPN/exabgp/DEVELOPMENT_GUIDELINES.md`.

DIRECT peering to a non-DNOS vendor when the DNOS RR won't carry the route-type:
DNOS RR supports EVPN route-types 1-5 ONLY (drops 6/7/8). To inject RT-6/7/8 to a
Junos MX, peer ExaBGP DIRECTLY (iBGP, same fabric AS) with the RR/DNOS box as a
pure L3 ROUTER: h263 static to MX-lo via the RR fabric IP; MX static to h263 /30
via the RR loopback (`next-hop <RR-lo> resolve`) + a new EVPN neighbor group for
ExaBGP; ExaBGP 2nd neighbor block. Multihop BGP transits IP-forwarding; DNOS never
parses the RT as BGP, so its 1-5-only limitation is bypassed.
