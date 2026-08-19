# BGP Peering Tool - Development Guidelines

Updated: 2026-02-16 for modular restructure (builders/, malform/, backends/, attributes/).

## Modular Structure (2026-02)

- **bgp_tool.py** — CLI entry point; delegates to modules
- **session.py, pipe.py, config_gen.py** — ExaBGP lifecycle, pipe, config
- **builders/** — Route string generators (flowspec, flowspec_vpn, unicast, vpn, evpn, scale, ...)
- **malform/** — BGP malformation builders (bad-marker, truncated-nlri, bad-extcommunity-0x0c, ...)
- **backends/** — exabgp.py, gobgp.py, scapy_tcp.py (Simpson redirect-ip)
- **attributes/** — Attribute testing lab (communities, as_path, med_locpref, flowspec_ec, next_hop)

**GoBGP:** Use `bgp_tool.py engine-start`, `engine-stop`, `engine-inject` for unicast, l3vpn, flowspec. FlowSpec-VPN (SAFI 134) is parked — GoBGP FSM sends TCP FIN after OPEN. Use ExaBGP for flow-vpn.

## Critical ExaBGP Config for DNOS Peering

When generating ExaBGP config for DNOS devices, always include:

- `passive true` - ExaBGP listens; PE initiates TCP (required for BgpTrius/NSR compatibility)
- `listen 179` - Bind to BGP port (requires setcap'd Python binary at /tmp/python3_bgp)
- `outgoing-ttl 64` - For eBGP multihop
- `hold-time 600` - 10-minute hold timer for stability during long operations
- `router-id` - Use same value as local-address (e.g. 100.64.6.134)
- **Do NOT use** `incoming-ttl` - it sets IP_TTL on the socket (not MIN_TTL), killing SYN-ACKs
- **Do NOT use** `passive false` / `connect 179` - BgpTrius iptables DROP unmarked inbound SYN-ACKs

### Why passive mode?

DNOS BgpTrius (BGP NSR) installs iptables rules that DROP all TCP port 179 traffic
without mark 0x65179. When ExaBGP initiates (active mode), the PE's SYN-ACK comes
back to our server, but the return SYN from ExaBGP hits the PE's INPUT chain and
gets dropped because BgpTrius NFQUEUE doesn't mark packets from external peers.
Passive mode reverses the flow: PE initiates the SYN (marked by BgpTrius OUTPUT chain),
ExaBGP just accepts it.

### Device-side iptables (ephemeral)

NSR devices also need ACCEPT rules inserted before the DROP rules:
```
iptables -I INPUT 3 -p tcp -s 100.64.6.134 --sport 179 -j ACCEPT
iptables -I INPUT 3 -p tcp -s 100.64.6.134 --dport 179 -j ACCEPT
iptables -I INPUT 3 -p tcp -d <device_ip> --dport 179 -j ACCEPT
```
These are lost on NCC restart/reboot. Re-apply after any such event.

## Supported AFI/SAFI (All 15 DNOS Families)

All 15 DNOS address families are supported. See `DNOS_TO_EXABGP` and `ALL_EXABGP_FAMILIES` in `bgp_tool.py`.

| DNOS | ExaBGP |
|------|--------|
| ipv4-unicast | ipv4 unicast |
| ipv6-unicast | ipv6 unicast |
| ipv4-flowspec | ipv4 flow |
| ipv4-flowspec-vpn | ipv4 flow-vpn |
| ipv6-flowspec | ipv6 flow |
| ipv6-flowspec-vpn | ipv6 flow-vpn |
| ipv4-vpn | ipv4 mpls-vpn |
| ipv6-vpn | ipv6 mpls-vpn |
| ipv4-labeled-unicast | ipv4 nlri-mpls |
| ipv6-labeled-unicast | ipv6 nlri-mpls |
| ipv4-multicast | ipv4 multicast |
| ipv4-rt-constrains | ipv4 rtc |
| l2vpn-evpn | l2vpn evpn |
| l2vpn-vpls | l2vpn vpls |
| link-state | bgp-ls bgp-ls |

## ExaBGP Patches Required (site-packages)

1. **Extended communities (IPv6 flow-vpn):**
   - `exabgp/bgp/message/update/attribute/community/extended/communities.py`: ExtendedCommunitiesIPv6.unpack - fallback to 8-byte when total not multiple of 20
   - `exabgp/bgp/message/update/attribute/community/extended/traffic.py`: TrafficRedirectIPv6.unpack - use data[2:20] and data[:20] (was data[2:11]/data[:11])

2. **RTC (ipv4 rtc) family:**
   - `exabgp/configuration/neighbor/family.py`: Add `'rtc': (AFI.ipv4, SAFI.rtc)` to ipv4 convert dict

3. **Route-target announce/withdraw:**
   - `exabgp/configuration/static/__init__.py`: Add `route_target` handler and `_parse_route_target`
   - `exabgp/configuration/configuration.py`: Add `'route-target'` to static commands
   - `exabgp/reactor/api/command/announce.py`: Add `announce route-target` and `withdraw route-target` handlers

4. **FlowSpec-VPN rd/next-hop via API pipe (2026-02):**
   - `exabgp/configuration/flow/__init__.py`: Add `ParseFlowRoute.known` and `ParseFlowRoute.action` to `ParseFlow`; add `nlri-set` and `nlri-nexthop` handlers in `route()` function
   - `exabgp/configuration/announce/flow.py`: Add `rd`, `route-distinguisher`, `next-hop` to `known`; add `nlri-set` and `nlri-nexthop` to `action`; add handlers in `flow()` function
   - Enables: `announce flow route rd 1.1.1.1:100 destination 10.0.0.0/24 redirect 10.0.0.230 extended-community [ target:1234567:300 ]` via pipe (FLAT format only!)

5. **4-byte ASN Route Target encoding fix (2026-02-16):**
   - `exabgp/configuration/static/parser.py`: `_HEADER['target4']` was `bytes([0x01, 0x02])` (Type 1 = IPv4). Fixed to `bytes([0x02, 0x02])` (Type 2 = 4-byte ASN, per RFC 5668). Same fix for `origin4`.
   - Without this fix, RT:1234567:300 encodes as IPv4 type, causing DNOS to display `RT:0.18.214.135:300` and fail VRF import.

## Route Injection

Use `bgp_tool.py inject` with route strings from `route_builder.py`. Named pipe: `/run/exabgp/exabgp.in`.

Route types: flowspec, flowspec-vpn, unicast, multicast, labeled-unicast, l3vpn, evpn-type2, evpn-type5, vpls, rtc.

**FlowSpec-VPN:** Requires ExaBGP patch #4 above. GoBGP is parked (FSM sends TCP FIN after OPEN). Use ExaBGP for flow-vpn. `bgp_tool.py` routes flowspec-vpn through ExaBGP pipe when session has `exabgp_pid` and `status=active`. Malformation testing via `malform/` package; Simpson redirect-ip via `backends/scapy_tcp.py`.

**CRITICAL - FlowSpec-VPN API Pipe Format:**
Use FLAT format only (no `match { }` / `then { }` wrappers). The ExaBGP tokenizer cannot handle section-style blocks when `rd` is present in the route string.

Working:  `announce flow route rd 1.1.1.1:100 destination 10.0.0.0/24 source 16.16.16.0/30 redirect 10.0.0.230 extended-community [ target:1234567:300 ]`
Broken:   `announce flow route rd 1.1.1.1:100 match { destination 10.0.0.0/24; } then { redirect 10.0.0.230; }`

## Session Management (Critical)

### Orphan Process Cleanup
`session.kill_orphan_exabgp_processes()` kills only orphaned ExaBGP processes. It NEVER kills ExaBGP of other active sessions (pe_4, pe_1, etc. can run concurrently). Multiple ExaBGP instances connecting to the same peer cause BGP NOTIFICATION 6/7 (Connection Collision) - but different sessions peer to different devices, so they can coexist.

### Cleanup at Stop
Kill ExaBGP + children. Verify dead after 2 seconds:
```bash
kill -TERM <pid>; sleep 2; kill -9 <pid> 2>/dev/null; pkill -f 'socat.*exabgp'
```

### Post-Injection Verification
After injecting FlowSpec-VPN redirect-ip routes, verify:
1. `show flowspec ncp 0` on target device — rule installed locally
2. `show bgp ipv4 flowspec-vpn summary` — check PE peers still Established
3. If PE sessions flap (NOTIFICATION 3/9) → **DNOS reflection encoding bug**, not ExaBGP

## Known DNOS Bug: FlowSpec-VPN Redirect-IP Reflection (2026-02-16)

**Root cause**: `bgp_attr.c` `bgp_packet_mpattr_start_v4_flowspec_vpn` allocates 24-byte NH buffer (IPv6 VPN size) for ALL FlowSpec-VPN MP_REACH_NLRI. For redirect-ip routes with IPv4 next-hop:
- Sets NH_LEN=4, writes 0.0.0.0 instead of the actual redirect IP
- stream_forward() advances by 24, not 4
- 20 zero bytes bleed into NLRI space
- PE cannot parse the NLRI → NOTIFICATION 3/9

**Local install works**: RR installs the route correctly in its own VRF. `show flowspec ncp 0` shows "Redirect-ip-nh: 10.0.0.230". The bug is ONLY in the reflected UPDATE to PE peers.

**Proof via XRAY**:
```
run packet-capture ncc interface any count 100 filter-expression "port 179" verbose
```
Compare non-redirect FlowSpec-VPN UPDATE (NH_LEN=0, clean NLRI) vs redirect-ip UPDATE (NH_LEN=4, 24 zero bytes, corrupted NLRI). PE responds with NOTIFICATION 3/9 and TCP FIN.

## Revert if Broken

If changes cause session failure: verify `passive true`, `listen 179`, `outgoing-ttl 64`,
`hold-time 600` in generated config. Check that `/tmp/python3_bgp` exists with setcap
`cap_net_bind_service`. Check device-side iptables ACCEPT rules are present.
Never revert to `passive false` / `connect 179` / `incoming-ttl` -- those are confirmed broken
on NSR devices (BgpTrius iptables mark filtering).

## BgpTrius Diagnosis (bgp_tool.py diagnose)

When session is stuck in Connect after start:
```bash
python3 bgp_tool.py diagnose --session-id <id>           # inspect iptables
python3 bgp_tool.py diagnose --session-id <id> --fix      # inspect + auto-apply ACCEPT rules
```
Auto-resolves device OOB IP from SCALER DB. SSHes to device shell, inspects INPUT chain for
BgpTrius DROP rules on port 179, checks if ACCEPT rules for server IP exist. With `--fix`,
inserts ACCEPT rules at position 3 (before DROP). Reports JSON with root cause, fix commands,
and post-fix TCP state. Rules are ephemeral -- re-run after NCC restart/reboot.

## Watchdog must not kill non-daemon "exabgp" processes (2026-06-16)

`session.kill_orphan_exabgp_processes()` previously killed ANY `ps aux` line containing
`exabgp` (except spared PIDs). The `user-exabgp-mcp` MCP server runs as
`python3 -m user_exabgp_mcp.server` -- its command line contains "exabgp", so the watchdog
cron (every 30s) SIGKILLed it ~every cycle, causing a 368x systemd restart loop.

Fix: `kill_orphan_exabgp_processes()` now skips a `NON_DAEMON_MARKERS` allowlist
(`user_exabgp_mcp`, `_mcp.server`, `mcp_common`, `bgp_watchdog`, `bgp_tool.py`, `session.py`,
editors, `grep`, etc.) and never kills its own PID. It still kills real orphan ExaBGP daemons
(FortiGate storm protection unchanged). When adding any new process whose command line mentions
"exabgp" but is NOT the daemon, add its marker to `NON_DAEMON_MARKERS`.

Infra durability (all local MCPs): systemd drop-ins at
`~/.config/systemd/user/<svc>.service.d/10-durability.conf` set `Restart=always` +
`StartLimitIntervalSec=0` so a local MCP always recovers and systemd never permanently
gives up after a fast crash burst.

## EVPN RT-3 IMET emission (added 2026-07-15, SW-252580 cross-vendor error-handling)

The patched ExaBGP API handler `reactor/api/command/announce.py` now supports a
`multicast` (alias `inclusive-multicast` / `imet`) EVPN subtype in BOTH
`announce evpn` and `withdraw evpn`, in addition to the prior
mac-advertisement / ethernet-segment / ethernet-ad (Type-2/4/1). It builds a
real RFC 7432/9251 Type-3 IMET NLRI + a PMSI Ingress-Replication tunnel
attribute so a receiver (Junos MX, DNOS) accepts it as a valid flooding tunnel,
and passes extended-communities through verbatim so you can craft malformed ECs.

Syntax:
```
announce evpn multicast rd <rd> ethernet-tag <tag> ip <originator-ip> \
  [label <vni>] [pmsi <tunnel-ip>] next-hop <nh> \
  extended-community [ target:<rt> 0x030c000000000008 <mcast-flags-ec> ]
```
- `ip` = Originating Router IP (IMET NLRI key); `pmsi` = tunnel endpoint (defaults to `ip`).
- `label <vni>` -> PMSI raw label = VNI (VXLAN). `0x030c000000000008` = encapsulation:vxlan EC.
- Multicast Flags EC (RFC 9251 s9.4) = `0x0609` + 2-octet flags + reserved, e.g.
  `0x0609000000000000` = M=0/I=0 (malformed per RFC), `0x0609000000010000` = I=1 (IGMP proxy).

VERIFIED FINDING (SW-252580 Q2): a malformed Multicast Flags EC (M=0/I=0) on an
IMET is NOT enforced by Junos MX 23.4R1.9 (jun204-rt02) NOR by the DNOS RR
(RR-SA-2). RR accepted + reflected it intact; MX installed the route ACTIVE
(0 hidden) and RETAINED the EC verbatim as `evpn-mcast-flags:0x0` with no
malformed/treat-as-withdraw log. i.e. both are PERMISSIVE, contrary to the
RFC 9251 "treat-as-malformed / ignore the EC" MUST. Note: the ExaBGP<->RR-inband
session storms under the FortiGate IDS RST; the inject only lands when the
watchdog catches a stable window (see fabric-bypass note / h263 LEAF-B10 links).

## rr_evpn peering: DNAAS fabric bypass (VLAN 212 p2p) - added 2026-07-15

The ExaBGP<->RR-SA-2 EVPN session previously peered OOB (local-address
100.64.11.95 -> RR 100.70.0.205, ebgp-multihop) which crosses a FortiGate IDS
that RST-resets the BGP TCP (storm: "lost TCP session with peer"). FIX: peer over
the DNAAS fabric instead, directly connected, no FortiGate.

Topology: host h263 has fabric NICs enp94s0f0np0->DNAAS-LEAF-B10 ge100-0/0/0 and
enp94s0f1np1->B10 ge100-0/0/1. New dedicated p2p:
- VLAN 212, subnet 100.70.212.0/30. h263 fab212(enp94s0f1np1)=.2, RR
  bundle-100.212=.1. BD g_yor_v212 (single-tag 212) on B10/B09/B15.
- Path: h263 enp94s0f1np1 -> B10 ge100-0/0/1.212 + bundle-60000.212 -> B09
  bundle-60001.212(->B10) + bundle-60004.212(->B15) -> B15 bundle-60000.212 +
  bundle-100.212 -> RR bundle-100.212.
- B10 ge100-0/0/1 was fully consumed by g_nogah_v200 (qinq vlan-id list 1-4094
  -> outer 200); carved 212 out: `no interfaces ge100-0/0/1.200 vlan-id list
  1-4094` then re-add `1-211,213-4094` (reversible).
- RR neighbor 100.70.212.2 remote-as 65200 local-as 1234567 update-source
  bundle-100.212 (NO ebgp-multihop, directly connected). Old OOB neighbor
  100.64.11.95 KEPT admin-enabled as idle fallback.
- ExaBGP /tmp/exabgp_rr_evpn.conf: local-address+router-id 100.70.212.2,
  neighbor 100.70.212.1, local-as 65200 peer-as 1234567, family l2vpn evpn.

Result: Established instantly (0.0s), stable, injections land immediately with no
storm. To switch back to OOB, restore local-address 100.64.11.95 + neighbor
100.70.0.205 in the conf (RR still has the 100.64.11.95 neighbor).

CAVEAT: bgp_watchdog._clear_device_arp_and_verify_dg is OOB/FortiGate-specific.
The fabric session is directly connected + stable so it should not need restarts,
but if ExaBGP dies the DG-ARP precheck could block auto-restart. TODO: make the
watchdog fabric-path aware (skip the OOB DG-ARP gate when peer is on 100.70.212/30).

## EVPN RT-6 SMET encoder + direct ExaBGP<->Junos peering (added 2026-07-15, SW-252580 Q1/Q3)

announce.py now also supports `announce/withdraw evpn smet` (alias
selective-multicast) = RFC 9251 Type-6 SMET, built as a raw GenericEVPN(code=6)
(registry untouched; received RT-6 keep generic decode). NLRI:
RD + ethernet-tag + src-len[+src] + grp-len + group + orig-len + originator +
Flags(1). Flags bits v1=0x01 v2=0x02 v3=0x04 IE=0x08.
Syntax: `announce evpn smet rd <rd> [ethernet-tag N] [source <ip>] group <ip>
originator <ip> flags <0xNN> next-hop <nh> extended-community [ target:<rt> ]`.

KEY: DNOS (RR-SA-2 build) implements EVPN route-types **1-5 only** (CLI help:
`route-type <1-5>`), so it treat-as-withdraws RT-6/7/8 -- a DNOS RR will NOT
reflect RFC 9251 mcast routes to a Junos client. To test Junos directly, peer
ExaBGP<->MX with the RR as a pure L3 ROUTER (not BGP RR):
- h263: `ip route add <MX-lo>/32 via 100.70.212.1 dev fab212`.
- MX: `set routing-options static route 100.70.212.0/30 next-hop 2.2.2.2 resolve`
  + `set protocols bgp group EXABGP-EVPN type internal local-address 201.0.0.7
  family evpn signaling local-as 1234567 loops 2 neighbor 100.70.212.2`.
- ExaBGP conf: 2nd neighbor 201.0.0.7, iBGP local-as/peer-as 1234567,
  local-address 100.70.212.2, outgoing-ttl 64. Session Established (multihop
  transits the RR's IP forwarding; DNOS never parses the RT-6 as BGP).

FINDING (Junos MX 23.4R1.9): RT-6 SMET with malformed flags is PERMISSIVE --
IE-without-v3 (0x0a) and all-version-flags-zero (0x00) are both Import Accepted /
Active (0 hidden), IGMP flags retained verbatim, NO error logged. i.e. Junos does
NOT apply RFC 9251 treat-as-malformed/withdraw for these (same as Q2 IMET EC).

## EVPN RT-7/8 encoders (added 2026-07-15, SW-252580 Q3)

announce.py `_parse_evpn_mcast(words, code)` now shared by code 6 (smet),
7 (join-sync), 8 (leave-sync). Subtypes: `announce evpn join-sync|leave-sync ...`.
RT-7 = SMET + ESI after RD. RT-8 trailer order (as Junos parses it) =
Reserved(4) + Flags(1) + MaxRespTime(1)  <-- NOT Reserved+MaxResp+Flags; getting
this wrong shows up as swapped "IGMP flags" / "Max Response Time" on the MX.
Tokens add: `esi <esi>` (req for 7/8), `max-response-time <n>` (RT-8).
ECs for 7/8: ES-Import (0x0602<6-byte-mac>) matching the target ESI's es-import RT
+ exactly one EVI-RT EC (0x060c<4-oct-AS><2-oct-val> for a 4-octet-AS RT).

FINDING (Junos MX 23.4R1.9): RT-7 and RT-8 with all-version-flags-zero (0x00)
are Import Accepted / Active (0 hidden), flags retained, no error -- same as RT-6.
=> Junos does NOT apply the RFC 9251 'at least one version flag / treat-as-withdraw'
rule to ANY of RT-6/7/8. (SW-252580: Q3 = applies to none; Q1/Q2 also permissive.)
