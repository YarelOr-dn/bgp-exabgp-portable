# BGP Learned Knowledge Rules

This is the detailed companion to the index file. JSON remains the compatibility store
for scripts and test frameworks; this Markdown file is optimized for selective agent reads.

## Critical Rules

### bgptrius_iptables_default_passive

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: Code analysis 2026-03-03: found in services/control/quagga/bgpd/bgp_cpp/bgp_iptables_rules.cpp and bgp_trius/BgpTrius.cpp. Mark 0x65179, NFQUEUE 177 (input) + 178 (output). Updated config_gen.py and exabgp.py to match.
- Rule: DNOS BgpTrius (BGP NSR) installs iptables rules that DROP all TCP port 179 traffic without mark 0x65179. This is built-in (bgp_iptables_rules.cpp, BgpTrius.cpp), NOT configurable, and active on all NSR-enabled devices. External peers like ExaBGP are blocked because BgpTrius NFQUEUE doesn't whitelist them. /BGP tool now defaults to passive=true + listen 179 (PE initiates to us, avoiding the INPUT chain problem). Requires: (1) setcap'd Python at /tmp/python3_bgp (auto-created by exabgp.py), (2) iptables ACCEPT rules on device for our server IP (ephemeral, lost on reboot). config_gen.py updated: passive true, listen 179, outgoing-ttl 64, NO incoming-ttl.
- Examples:
  - Wrong: `passive false; connect 179; incoming-ttl 10;`
  - Right: `passive true; listen 179; outgoing-ttl 64; (no incoming-ttl)`

### device_ip_from_config

- Priority: `CRITICAL`
- Updated: `2026-03-04`
- Source: User correction 2026-03-04: 'that is not the IP of the PE-4 sub-interface, i think that /BGP changes the target address to PE-4 to this after sometime for no reason'
- Rule: bgp_tool.py must extract the actual neighbor IP from the ExaBGP config file (neighbor X.X.X.X line) and store it in session JSON as both peer_ip and device_ip. The old code used DEVICE_DEFAULT_IP (100.70.0.205) which was WRONG for PE-4 (actual: 100.70.0.206 on ge100-18/0/6.999). The scale function also used session peer_ip (which was 'unknown') falling back to .205, generating scale configs targeting a non-existent address. Fixed: _extract_peer_ip_from_config() parses config file, DEVICE_DEFAULT_IP corrected to 100.70.0.206.

### exabgp_afi_must_match_dut_neighbor

- Priority: `CRITICAL`
- Updated: `2026-03-09`
- Source: Root cause analysis 2026-03-09: PE-4 BGP neighbor stats showed 'Notifications: 7 sent, 0 received', 'Opens: 0 sent, 0 received'. Adding common AFIs to ExaBGP config fixed it instantly.
- Rule: ExaBGP family {} block MUST include at least one AFI/SAFI that the DUT's neighbor has configured. Zero common AFIs = DUT sends NOTIFICATION on every connection attempt. Mapping: ipv4-unicast -> 'ipv4 unicast', ipv4-vpn -> 'ipv4 mpls-vpn', ipv4-flowspec -> 'ipv4 flow', ipv6-vpn -> 'ipv6 mpls-vpn', ipv6-flowspec -> 'ipv6 flow'. Check with: run_show_command(device, 'show config protocols bgp <asn> neighbor <ip>'). On 2026-03-09, ExaBGP only had 'ipv4 flow-vpn' (SAFI 134) but PE-4 only had 'ipv4-flowspec' (SAFI 133) -- PE-4 sent 7 NOTIFICATIONs.
- Examples:
  - Wrong: `family { ipv4 flow-vpn; ipv6 flow-vpn; }  -- only SAFI 134, PE-4 has no flow-vpn`
  - Right: `family { ipv4 unicast; ipv4 flow; ipv4 flow-vpn; ipv4 mpls-vpn; ipv6 flow; ipv6 flow-vpn; ipv6 mpls-vpn; }`

### exabgp_env_file_location

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: Root cause analysis 2026-03-03: modified env file to passive=true, port=1179, bind=IP for passive mode experiment. This broke ExaBGP. Restored to safe defaults.
- Rule: ExaBGP env file lives at ~/.local/etc/exabgp/exabgp.env. ExaBGP reads it automatically on startup. Key settings: daemon.drop=false (prevent privilege drop), bgp.passive=false (active mode), tcp.port=179, tcp.bind='' (empty). WARNING: modifying this file with wrong values (passive=true, port=1179, bind=IP) will break ALL ExaBGP sessions. The env file overrides ExaBGP defaults but env vars take priority over the file.

### exabgp_env_passive_conflict

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: Root cause analysis 2026-03-03: session died 3x at ~39min mark. ExaBGP env had passive=true from old workaround. Fixed env + increased hold-time.
- Rule: NEVER set passive=true in exabgp.env when using active mode in neighbor config (passive false). The conflicting settings cause ExaBGP to behave inconsistently with TCP socket management, leading to Hold Timer Expired after ~39 minutes. Safe env defaults: passive=false, port=1790 (non-root safe), bind='' (empty), delay=0, level=DEBUG, packets=false (per-second timer I/O blocks event loop).

### exabgp_internal_cli_crash

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: Root cause analysis 2026-03-03: ExaBGP kept dying with 'Permission denied' on /home/dn/.local/bin/exabgp. Traced to add_api() in process/__init__.py creating internal CLI process, privilege drop to 'nobody', /home/dn 750 blocking access.
- Rule: ExaBGP crashes on startup when BOTH /run/exabgp/exabgp.in AND /run/exabgp/exabgp.out named pipes exist. ExaBGP spawns an internal CLI subprocess that runs '/usr/bin/python3 /home/dn/.local/bin/exabgp cli'. With daemon.drop=true (default), this subprocess runs as 'nobody' user which CANNOT traverse /home/dn/ (permissions 750). The subprocess dies 5 times and ExaBGP terminates. FIX: (1) Only create exabgp.in pipe, never exabgp.out. (2) Set exabgp_daemon_drop=false so ExaBGP stays as 'dn' user. (3) pipe.py updated to delete exabgp.out if found. (4) exabgp.env at ~/.local/etc/exabgp/exabgp.env must have drop=false.
- Examples:
  - Wrong: `ensure_pipes() creates both exabgp.in and exabgp.out; daemon.drop=true (default)`
  - Right: `Only create exabgp.in; set daemon.drop=false in exabgp.env and start_exabgp env dict`

### exabgp_redirect_ip_encoding_fix

- Priority: `CRITICAL`
- Updated: `2026-03-05`
- Source: Root cause analysis 2026-03-05: traced ExaBGP parsing from api_flow -> configuration.partial -> dispatch -> _run -> ParseFlow.route(). The route() function at flow/__init__.py is registered via @ParseFlow.register and is the ACTUAL code path for API pipe flow routes.
- Rule: ExaBGP 5.0.1 has a critical encoding bug for redirect-ip when combined with redirect (redirect-to-rt) in API pipe flow routes. The route() function in exabgp/configuration/flow/__init__.py processes commands sequentially: redirect-ip sets nlri.nexthop=49.49.49.9 correctly, but redirect (action=nexthop-and-attribute) returns NoNextHop and UNCONDITIONALLY overwrites it. Fix: guard with 'if nexthop is not NoNextHop:' before assignment. Also patched: section.py (same guard for config-file parsing), family.py (FlowSpec-VPN SAFI 134 rd_size=8 for correct 12-byte VPN NH format). ALWAYS clear .pyc cache after patching.
- Examples:
  - Wrong: `change.nlri.nexthop = nexthop  # unconditional -- overwrites 49.49.49.9 with NoNextHop from redirect`
  - Right: `if nexthop is not NoNextHop:
    change.nlri.nexthop = nexthop  # only set if redirect-ip provided a real IP`

### mcp_first_for_dut_verification

- Priority: `CRITICAL`
- Updated: `2026-03-09`
- Source: Self-audit 2026-03-09: spent 45+ minutes with paramiko SSH debugging when a single MCP run_show_command would have found the missing static route in 2 seconds. MCP was available the entire time.
- Rule: ALWAYS prefer MCP Network Mapper (run_show_command, get_device_config) over paramiko SSH for DUT verification. MCP is faster (sub-second vs 10-15s for paramiko session setup), more reliable (no PTY/CLI parsing issues), and already available. Use paramiko ONLY as fallback when MCP is unavailable. See cursor rule: bgp-preflight-mcp-verification.mdc.

### nc_z_cannot_distinguish_firewall_vs_missing_route

- Priority: `CRITICAL`
- Updated: `2026-03-09`
- Source: Root cause analysis 2026-03-09: diagnose said 'fortigate_ids_blocked' but real cause was missing static route. ping and SSH worked (management routing) while TCP/179 failed (data plane routing had no return path).
- Rule: nc -z timeout is AMBIGUOUS. It can mean: (1) firewall blocking SYN, (2) DUT has no return route for SYN-ACK, (3) DUT not listening on port 179, (4) network unreachable. bgp_tool.py diagnose reports 'fortigate_ids_blocked' for ALL of these. To disambiguate: use MCP run_show_command to check DUT routing table and interface state. ICMP ping working does NOT prove TCP/179 works -- SSH/ICMP may use different routing (management VRF vs data plane).

### on_session_fail_debug_protocol

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: User instruction 2026-03-03: 'next time the session accidentally fails, run /debug-dnos on PE-4 and on exabgp see if Configuration got changed somehow or the process dies for some reason and created zombie ones'
- Rule: When ExaBGP-PE session FAILS (Hold Timer Expired, Broken TCP, ECONNRESET), BEFORE attempting any fix: 1) Run /debug-dnos on PE-4 to check if BGP config was changed (show config protocols bgp), if any commit happened around crash time (show file traces routing_engine/cli | include commit), and if PE-4 BGP process is healthy. 2) Check ExaBGP side: ps aux for zombie processes, check if config file changed (cat /tmp/exabgp_pe_4.conf), check exabgp.env for unexpected changes, check if another script or process killed/restarted ExaBGP. 3) Check for OTHER devices interfering on the DNAAS bridge domain (show config network-services bridge-domain instance g_mgmt_v999 on DNAAS leaves). DO NOT kill ExaBGP or change config until root cause is identified.

### passive_passive_deadlock

- Priority: `CRITICAL`
- Updated: `2026-03-05`
- Source: Root cause analysis 2026-03-05: overnight session failure. ExaBGP passive + PE-4 passive = both listening, neither connecting. Watchdog restarted 18 times, each restart used same passive config = same deadlock. Fixed by switching ExaBGP to active mode.
- Rule: ExaBGP must ALWAYS use active mode (passive false; connect 179;) when the DUT has passive enabled. If both sides are passive, neither initiates TCP -- permanent deadlock. The watchdog kills ExaBGP after 30s grace thinking it's a SYN storm, but it's actually a TCP deadlock (no SYNs at all). config_gen.py now generates active mode by default. Watchdog detects this deadlock pattern and auto-fixes the config before restart. DNOS CLI has NO native 'ping' command -- use 'clear arp' on device then ping from SERVER side to refresh FortiGate DG ARP.
- Examples:
  - Wrong: `passive true;
    listen 179;`
  - Right: `passive false;
    connect 179;`

### pe1_pe4_dnaas_cleanup

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: User correction + user design confirmation 2026-03-03
- Rule: When switching ExaBGP target device (e.g. PE-4 to PE-1), ALWAYS do FULL cleanup of the OLD device BEFORE setting up the new one. Exact steps: 1) Kill ExaBGP locally. 2) Admin-disable BGP neighbor 100.64.6.134 on OLD device. 3) Remove OLD device's AC from its DNAAS leaf g_mgmt_v999 bridge domain (e.g. 'no interface ge100-0/0/5.999' on DNAAS-LEAF-D16). 4) Only THEN proceed to set up the NEW device (add AC to new leaf BD, configure .999 sub-if, configure BGP neighbor, start ExaBGP). REASON: Both devices share the same OOB IP (100.70.0.205/206) on VLAN 999. If the old device is not fully isolated, it keeps connecting on port 179 and crashes the new device's BGP TCP listener. This caused 1+ hour outages twice on 2026-03-03.

### pe4_tcp_listener_recovery

- Priority: `CRITICAL`
- Updated: `2026-03-03`
- Source: Discovered 2026-03-03: tried admin-disable/enable, clear neighbor 100.64.6.134 -- both failed. Only clear of established RR neighbor recovered listener.
- Rule: PE-4 BGP TCP listener crashes after Hold Timer Expired and port 179 becomes REFUSED. Clearing the ExaBGP neighbor does NOT fix it. Admin-disable/enable does NOT fix it. ONLY fix: clear the RR neighbor (2.2.2.2) via 'clear bgp neighbor 2.2.2.2'. This forces a full BGP process TCP listener restart. Recovery takes ~60-90 seconds after clearing RR. This is a DNOS bug.

### verify_static_route_before_exabgp

- Priority: `CRITICAL`
- Updated: `2026-03-09`
- Source: Root cause analysis 2026-03-09: 'show config protocols static' on PE-4 returned EMPTY. Static route 100.64.0.0/20 was never configured. Adding it instantly fixed TCP/179 connectivity.
- Rule: BEFORE starting ExaBGP, ALWAYS verify the DUT has a static route back to the server (100.64.6.134). Use MCP: run_show_command(device, 'show route 100.64.6.134 | no-more'). Expected: 'Known via static' with next-hop 100.70.0.254. If '% Network not in table', the DUT cannot send SYN-ACKs back -- ExaBGP will NEVER establish regardless of firewall state. This was the #1 root cause of all BGP failures on 2026-03-09, misdiagnosed as FortiGate IDS for 45+ minutes.
- Examples:
  - Wrong: `Start ExaBGP -> nc -z fails -> assume FortiGate IDS -> wait 5+ minutes -> repeat`
  - Right: `run_show_command(device, 'show route 100.64.6.134') -> if missing, add static route -> THEN start ExaBGP`

### watchdog_cron_must_disable_during_recovery

- Priority: `CRITICAL`
- Updated: `2026-03-09`
- Source: Root cause analysis 2026-03-09: recovery script waited 5 minutes but watchdog cron respawned ExaBGP at 30-second mark, refreshing the supposed FortiGate quarantine. Even the nc -z probes during wait periods refreshed it.
- Rule: bgp_watchdog cron runs every 30 seconds (2 crontab entries: at :00 and :30). During ANY recovery attempt that requires ExaBGP to be dead (e.g., FortiGate quarantine wait), MUST disable cron FIRST: 'python3 bgp_watchdog.py --remove-cron'. Otherwise cron respawns ExaBGP within 30s, sending SYNs that refresh any firewall quarantine. Re-enable with '--install-cron' only AFTER session is Established.

## High Rules

### advertised_state_tracking

- Priority: `HIGH`
- Updated: `2026-02-26`
- Source: User request 2026-02-26: BGP tool should have knowledge of what it advertises and document it.
- Rule: Every session now tracks advertised_state in session JSON. route_parser.py parses inject/withdraw into structured fields (type, afi_safi, rd, destination, rt, actions). Summary includes by_type, by_afi_safi, prefix_ranges, rds, route_targets, actions. Capabilities include families, peer_as, hold_time. Always check advertised_state.summary before /BGP status report. Use route_parser.build_advertised_state() to rebuild from injected_routes if missing.

### bgp_status_optimized_flow

- Priority: `HIGH`
- Updated: `2026-02-26`
- Source: Self-audit 2026-02-26: previous /BGP STATUS used 5 rounds (redundant learning.md read, redundant session JSON read, wrong DNOS command). Optimized to 2 rounds with identical output.
- Rule: For /BGP STATUS mode (no args): use exactly 2 rounds. Round 1: 'bgp_tool.py list' (already returns full session data including advertised_summary, selected_afis, routes_injected — do NOT read session JSON separately). Round 2: 'show bgp summary' on each active device via MCP (parallel if multiple). Skip learning.md read (STATUS is read-only). Never use 'show bgp neighbor X summary' (not valid DNOS syntax). Present: path, established AFIs with PfxAccepted/AdjOut, advertised routes from list output.
- Examples:
  - Wrong: `Round 1: read learning.md + list → Round 2: read session JSON → Round 3: wrong show command → Round 4: correct show command`
  - Right: `Round 1: bgp_tool.py list → Round 2: show bgp summary`

### cluster_aware_device_resolver

- Priority: `HIGH`
- Updated: `2026-04-27`
- Source: User request 2026-04-27: '/BGP must be better, like /TEST and /SPIRENT when needeing to find a specific device' -- PE-4 cluster VIP 100.64.4.98 rejected dnroot, active NCC0 100.64.11.96 accepted instantly
- Rule: DNOS clusters in SCALER DB store the cluster mgmt VIP in 'ip' (e.g. PE-4 has ip=100.64.4.98). The VIP's sshd uses a separate password, NOT dnroot/dnroot, so paramiko auth to the VIP FAILS for our agent. Active NCC per-node mgmt IPs (e.g. 100.64.11.96 for kvm108-cl408d-ncc0) accept the universal lab credentials. /BGP MUST run 'bgp_tool.py resolve --device <Device>' BEFORE any device action; this probes candidate IPs (cached active NCC -> VIP -> cluster_ncc_ips[]) via paramiko AUTH and returns the first working IP plus the active NCC hostname. Cache hit ~0.5s, miss ~10s. SCALER DB requires 'is_cluster: true' and 'cluster_ncc_ips': [ncc0_ip, ncc1_ip] for cluster devices. Cache lives in ~/.cursor/bgp-reference/cluster_ncc_cache.json. Use --refresh after a known NCC switchover. Mirrors the 2026-04-27 topology SSH-button fix (per-NCC IP > VIP).
- Examples:

### dnaas_b15_rr_sa2_path

- Priority: `HIGH`
- Updated: `2026-03-10`
- Source: Self-discovered 2026-03-10 during SW-243977 verification on RR-SA-2
- Rule: RR-SA-2 connects to DNAAS via DNAAS-LEAF-B15 (100.64.101.6). Port ge100-0/0/6 is member of bundle-100. The .999 sub-interface (bundle-100.999) was pre-created but admin-disabled. Fix: enable bundle-100.999 + add to g_mgmt_v999 BD. RR-SA-2 inband IP: 100.70.0.205. No secondary IP needed (no ExaBGP session conflict). Verified 2026-03-10.

### dnaas_leaf_credentials

- Priority: `HIGH`
- Updated: `2026-03-10`
- Source: Discovered 2026-03-03, updated 2026-03-10 (B15 added)
- Rule: DNAAS leaves use credentials: sisaev/Drive1234!. Known IPs: DNAAS-LEAF-D16 -> 100.64.101.123, DNAAS-LEAF-B10 -> 100.64.101.3, DNAAS-LEAF-B14 -> 100.64.101.5, DNAAS-LEAF-B15 -> 100.64.101.6. NOT in Network Mapper.

### dnos_afi_no_admin_state

- Priority: `HIGH`
- Updated: `2026-02-17`
- Source: Validation failure on PE-1 2026-02-17: admin-state unknown word under cfg-bgp-neighbor-afi
- Rule: On PE-1 (26.1.0.22), address-family blocks inside BGP neighbor do NOT support admin-state. AFI is implicitly enabled when configured. Only use admin-state at the neighbor level.
- Examples:
  - Wrong: `address-family ipv4-unicast admin-state enabled`
  - Right: `address-family ipv4-unicast (no admin-state)`

### dnos_import_vpn_rt_additive

- Priority: `HIGH`
- Updated: `2026-02-22`
- Source: Self-discovered 2026-02-22: setting just the existing RT resulted in 'no configuration changes'
- Rule: DNOS import-vpn route-target is ADDITIVE. Setting 'import-vpn route-target X' adds X to existing list. To remove, use 'no import-vpn route-target X'. Setting 'import-vpn route-target X,Y' replaces entire list with X,Y.

### dnos_no_ping_command

- Priority: `HIGH`
- Updated: `2026-03-05`
- Source: Discovered 2026-03-05: watchdog used 'run ping 100.70.0.254' which failed silently. Direct test confirmed 'Unknown word: ping' in DNOS CLI.
- Rule: DNOS CLI does NOT have a native 'ping' command. Running 'ping <IP>' in DNOS CLI produces 'Unknown word: ping'. Also 'run ping' is not valid. For ARP refresh after clear arp on device, ping from the SERVER side instead (linux ping). The ICMP echo-reply forces the device to ARP-resolve the DG (FortiGate) for the return path, achieving the same result.

### dnos_show_file_log

- Priority: `HIGH`
- Updated: `2026-03-04`
- Source: Discovered 2026-03-04: queried PE-4 with 'show file log list' and 'show file log routing_engine/system-events.log', confirmed as native DNOS CLI command for historical log viewing without SSH to Linux shell.
- Rule: DNOS historical syslog access uses 'show file log routing_engine/system-events.log | include <pattern>' (PREFERRED over SSH grep). Wildcard 'system-events.log*' searches all rotated logs. Use '| tail N' for recent entries. 'show file log list | include system-events display-headers' lists available log files. Syslog families: BGP, Management, RSVP, ISIS, OSPF, LDP, OAM. Severity levels: local7.info (commits, SSH), local7.notice (BGP UP, state changes), local7.warning (BGP DOWN, FlowSpec rejected, RSVP reroute). Key patterns: BGP_FLOWSPEC_UNSUPPORTED_RULE (warning), BGP_IPV4_NEIGHBOR_ADJACENCY_UP (notice), BGP_IPV4_NEIGHBOR_ADJACENCY_DOWN (warning). Per-daemon traces in /var/log/dn/traces via 'show file traces'. Max 2 pipe operators per command.

### dnos_static_route_nesting

- Priority: `HIGH`
- Updated: `2026-02-17`
- Source: Validation failure on PE-1 2026-02-17: extra ! after next-hop closed protocols before bgp could be entered
- Rule: In DNOS config hierarchy, next-hop X.X.X.X is a LEAF under route block. Do NOT add ! after next-hop. The ! at route level closes the entire route block. Extra ! closes address-family prematurely.
- Examples:
  - Wrong: `next-hop 100.70.0.254
!
!`
  - Right: `next-hop 100.70.0.254
! (closes route block)`

### duplicate_route_count_mismatch

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: User correction 2026-03-01: 'the rules you inject in ipv4 98 and not 100 why?' — 4 old individual routes (2 duplicates) + 96 scale = 98 unique on device.
- Rule: Individual routes (from bgp_tool.py inject) and scale routes (from bgp_tool.py scale) can overlap if they use the same prefix. ExaBGP deduplicates, so the device sees fewer unique routes than the session JSON tracks. Example: 4 individual routes (2 unique) + 96 scale = session says 100, device sees 98. ALWAYS clean up old individual routes before fresh scale injection to get exact counts.

### encoding_bug_affects_ipv4_and_ipv6

- Priority: `HIGH`
- Updated: `2026-02-17`
- Source: Self-discovered 2026-02-17: injected IPv6 flowspec-vpn redirect-ip, PE-1/PE-4 dropped identically to IPv4 test
- Rule: The DNOS FlowSpec-VPN redirect-ip outbound encoding bug (bgp_attr.c → bgp_packet_mpattr_start_v4_flowspec_vpn) affects BOTH IPv4 and IPv6 FlowSpec-VPN routes. IPv6 test with 2001:db8::/48 redirect 2001:db8::fe caused identical session teardown on PE-1/PE-4.

### exabgp_ipv6_flow_works

- Priority: `HIGH`
- Updated: `2026-02-25`
- Source: Self-discovered 2026-02-25: added 'ipv6 flow' to ExaBGP config, session established, 4K IPv6 FlowSpec rules injected and installed in TCAM.
- Rule: ExaBGP 5.0.1 'ipv6 flow' family WORKS. The documented parser bug is resolved (or only affects specific community types). Safe to use for IPv6 FlowSpec SAFI 133. Device must also have ipv6-flowspec configured on the BGP neighbor.

### exabgp_named_pipes

- Priority: `HIGH`
- Updated: `2026-03-03T13:45:00Z`
- Source: root_cause_2026-03-03
- Rule: CRITICAL: Only create exabgp.in pipe. If exabgp.out exists, ExaBGP spawns internal CLI subprocess that crashes (daemon.drop=true -> nobody user -> /home/dn 750 -> Permission denied -> 5 deaths -> ExaBGP terminates). pipe.py now deletes exabgp.out if found. Also set daemon.drop=false in exabgp.env.

### exabgp_pipe_diagnostic

- Priority: `HIGH`
- Updated: `2026-02-25`
- Source: Self-discovered 2026-02-25: 16K routes silently rejected. Only exabgp.out showed 'error' responses.
- Rule: ALWAYS read /run/exabgp/exabgp.out after pipe writes to check for errors. ExaBGP returns 'error' for rejected commands and 'done' for successful ones. Silent failures (no log, no BGP update) are diagnosed this way. Use: timeout 1 cat /run/exabgp/exabgp.out

### flowspec_safi133_flat_format

- Priority: `HIGH`
- Updated: `2026-02-25`
- Source: Self-discovered 2026-02-25: 12K routes injected via pipe with match/then format, ALL silently rejected. Flat format worked immediately.
- Rule: ExaBGP API pipe requires FLAT format for FlowSpec SAFI 133 (non-VPN). Use: 'announce flow route destination <prefix> rate-limit 0'. The match{}/then{} format SILENTLY FAILS via pipe (returns 'error' on exabgp.out but no log entry). ExaBGP auto-detects IPv4/IPv6 from the destination address — no special keyword needed for IPv6.
- Examples:
  - Wrong: `announce flow route match { destination 10.0.0.0/24; } then { rate-limit 0; }`
  - Right: `announce flow route destination 10.0.0.0/24 rate-limit 0`
  - Wrong: `announce flow route destination-ipv6 2001:db8::/48 rate-limit 0`
  - Right: `announce flow route destination 2001:db8::/48 rate-limit 0`

### flowspec_vpn_flat_format

- Priority: `HIGH`
- Updated: `2026-02-16`
- Source: User correction + self-audit 2026-02-16: redirect-ip route wasn't sent; flat format fixed it
- Rule: ExaBGP API pipe requires FLAT format for FlowSpec-VPN routes with rd. Use 'announce flow route rd X destination Y redirect IP extended-community [ target:RT ]'. route_builder.py outputs flat. bgp_tool auto-converts match/then on inject. Do NOT use match { } then { } — ExaBGP tokenizer rejects it.
- Examples:
  - Wrong: `announce flow route rd 2.2.2.2:100 match { destination 10.0.0.0/24; } then { redirect 10.0.0.254; }`
  - Right: `announce flow route rd 2.2.2.2:100 destination 10.0.0.0/24 redirect 10.0.0.254 extended-community [ target:1234567:300 ]`

### flowspec_vpn_rate_limit_flat_format

- Priority: `HIGH`
- Updated: `2026-02-25`
- Source: Self-discovered 2026-02-25: tested and confirmed 12K+4K SAFI 134 routes with rate-limit 0.
- Rule: ExaBGP API pipe accepts SAFI 134 rate-limit in flat format: 'announce flow route rd X destination Y rate-limit 0 extended-community [ target:RT ]'. Works for both IPv4 and IPv6. ExaBGP auto-detects AFI from address format. Avoids the redirect-ip encoding bug entirely.

### flowspec_vpn_vrf_import_rt_matching

- Priority: `HIGH`
- Updated: `2026-02-25`
- Source: Self-discovered 2026-02-25: used RT 300:300 for IPv4 and 1234567:401 for IPv6, both correctly imported into VRF ZULU.
- Rule: SAFI 134 FlowSpec-VPN routes are imported into VRFs based on the VRF's ipv4-flowspec/ipv6-flowspec import-vpn route-target. RT in extended-community must match. On PE-1: VRF ZULU imports IPv4 FlowSpec with RT 300:300,1234567:301 and IPv6 FlowSpec with RT 1234567:401. VRF ALPHA has NO flowspec import-vpn configured.

### fortigate_firewall_identity

- Priority: `HIGH`
- Updated: `2026-03-04`
- Source: Discovered 2026-03-04 via PE-4 ARP table (MAC 00:09:0f:09:00:1a for 100.70.0.254) and server ARP (MAC 00:09:0f:09:00:1e for 100.64.15.254). Same Fortinet OUI prefix confirms same device, two interfaces.
- Rule: The firewall at 100.70.0.254 (inband) / 100.64.15.254 (OOB, our default gateway) is a FortiGate (Fortinet). Identified by ARP MAC OUI 00:09:0f. NOT a DNAAS device. NOT running BgpTrius. It has IDS/IPS that quarantines rapid SYN/RST exchanges on port 179. SSH is available on 100.64.15.254 (admin user). Recovery from IDS block: stop DUT from sending SYNs, wait 2-5 min for quarantine expiry, then restart cleanly.

### ipv6_flowspec_vpn_flat_format

- Priority: `HIGH`
- Updated: `2026-02-17`
- Source: Self-discovered 2026-02-17: successfully injected IPv6 FlowSpec-VPN route, ExaBGP accepted pipe command 'done'
- Rule: ExaBGP pipe accepts IPv6 FlowSpec-VPN redirect-ip in flat format: 'announce flow route rd X destination <ipv6-prefix> redirect <ipv6-addr> extended-community [ target:RT ]'. ExaBGP auto-detects AFI 2 from IPv6 prefix. Requires 'ipv6 flow-vpn' in ExaBGP family config.
- Examples:
  - `announce flow route rd 2.2.2.2:100 destination 2001:db8::/48 redirect 2001:db8::fe extended-community [ target:1234567:300 ]`

### ipv6_flowspec_vpn_safi_134

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: User correction 2026-03-01: 'the SAFI should be 134 for the ipv6 flowspec-vpn routes... you are confused'. Reverted builder to use _flowspec_vpn_route_action.
- Rule: IPv6 FlowSpec-VPN MUST be SAFI 134 (with rd and rt), NOT SAFI 133. ExaBGP correctly detects AFI 2 from IPv6 destination prefix even with rd keyword. The SAFI 133 workaround was WRONG — user corrected this. Use: 'announce flow route rd X destination <ipv6-prefix> rate-limit 0 extended-community [ target:RT ]'. Default RT for IPv6 FlowSpec: 1234567:401 (VRF ZULU ipv6-flowspec import RT).

### nc_z_refreshes_fortigate_quarantine

- Priority: `HIGH`
- Updated: `2026-03-09`
- Source: Root cause analysis 2026-03-09: agent ran nc -z tests at 3, 4, and 5 minute marks during a 7-minute silence period, each one refreshing the supposed quarantine. Already documented in BGP.md but repeatedly violated.
- Rule: nc -z sends a TCP SYN to the target port. If FortiGate IDS is in quarantine for port 179, each nc -z probe refreshes the quarantine timer. Use ICMP ping to check reachability instead. Only use nc -z as a one-shot test AFTER the quarantine should have expired, never repeatedly during the wait period.

### pe1_999_default_vrf

- Priority: `HIGH`
- Updated: `2026-02-22`
- Source: Self-discovered 2026-02-22: default VRF had no route to 100.64.6.134; .999 was in VRF ALPHA
- Rule: PE-1 ge400-0/0/5.999 must be in DEFAULT VRF (not VRF ALPHA) for default-VRF BGP peering with ExaBGP. Move interface: remove VRF ALPHA neighbor first (DNOS won't allow removing interface while used as update-source), then 'no interface ge400-0/0/5.999' from VRF. Add static route and update-source in default VRF.

### per_afi_rt_matching

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: User correction 2026-03-01: 'the ipv6 rules are still not matching any vrf import-vpn route-target on PE-1'. Old routes used IPv4 RT 1234567:301 for IPv6.
- Rule: IPv4 and IPv6 FlowSpec use DIFFERENT import RTs on the VRF. On PE-1 VRF ZULU: ipv4-flowspec import RT = 1234567:301, ipv6-flowspec import RT = 1234567:401. ALWAYS pass the correct per-AFI RT. Default --rt in bgp_tool.py: flowspec-vpn-ipv4 = 1234567:301, flowspec-vpn-ipv6 = 1234567:401. Passing the wrong RT (e.g., IPv4 RT for IPv6 routes) means no VRF will import them.

### preload_mixed_ipv4_ipv6_source_session_drop

- Priority: `HIGH`
- Updated: `2026-03-03`
- Source: Reproduced 2026-03-03: 2x attempts with combined preload both dropped at exactly 325 IPv6 routes. Separate injection (preload IPv4 + pipe IPv6) = 12000 + 4000 success.
- Rule: When preloading 12K+ IPv4 FlowSpec-VPN with source+dest AND IPv6 FlowSpec-VPN with source+dest in a SINGLE preload file, ExaBGP causes BGP session to drop after ~325 IPv6 routes. Workaround: preload IPv4 first (--preload), wait for acceptance, then inject IPv6 via pipe (--fast). IPv6 dest-only preload works fine. The issue is specific to the process API loader with mixed AFI source+dest routes.

### rt_redirect_target_uses_unicast_rt

- Priority: `HIGH`
- Updated: `2026-02-22`
- Source: Self-discovered 2026-02-22: removed 300:300 from flowspec import — route disappeared from VRF but redirect target unchanged. Removing from unicast import triggered the dynamic switch.
- Rule: FlowSpec RT-Redirect target VRF is determined by ipv4-UNICAST import-vpn route-target, NOT ipv4-flowspec. The flowspec import-vpn RT determines which VRFs INSTALL the FlowSpec rule. The redirect action RT resolves against unicast import RTs.
- Examples:
  - Wrong: `Remove RT from ipv4-flowspec import-vpn to change redirect target`
  - Right: `Remove RT from ipv4-unicast import-vpn to change redirect target`

### scale_injection_performance

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: Updated 2026-03-01: Profiled ExaBGP 5.0.1 processing pipeline. reactor.speed and pipe buffer size have no effect. Bottleneck is exabgp.reactor.api.api_flow() -> configuration.partial('flow', line). Preload achieves effective 1967-2000 rps from user perspective.
- Rule: ExaBGP pipe injection is limited to ~184 rps for SAFI 134 routes due to ExaBGP's per-route Python parser (api_flow -> configuration.partial -> tokenizer ~5.5ms each). The bottleneck is NOT I/O, pipe buffer, or reactor speed. Use --preload for 16K+ routes: restarts ExaBGP with routes fed via process API, returns in ~6s. ExaBGP processes routes in background (~87s for 16K). When BGP session comes up, routes are sent in initial burst. For pipe injection, inject_pipe_turbo uses single os.open + bulk os.write (no artificial delays), but is still limited to ~184 rps. For 500-1000 routes, --fast is fine. For 1000+ routes, ALWAYS use --preload.

### scale_injection_tracking

- Priority: `HIGH`
- Updated: `2026-02-26`
- Source: User question 2026-02-26: 'why only 99.99.1.0/24 is tracked and not all?' — cmd_scale was fire-and-forget, never updated session.
- Rule: cmd_scale now tracks all bulk-injected routes in session via scale_injections[] metadata (mode, builder, params, count, timestamp). advertised_state.summary is rebuilt from ALL routes (manual + scale). Individual routes are NOT stored in injected_routes for scale ops (too large). On restart, scale routes are regenerated from builder params and reinjected. list_sessions uses routes_injected field which includes scale counts. Always use bgp_tool.py scale for bulk ops — it tracks properly now.

### scale_source_dest_match

- Priority: `HIGH`
- Updated: `2026-03-03`
- Source: Implemented 2026-03-03: added source prefix support to scale.py builders + bgp_tool.py CLI
- Rule: Scale builders (flowspec-vpn-ipv4/ipv6) now support --base-source and --source-mask args. Routes include both destination and source match. IPv4: base_source=192.168.0.0/24, IPv6: base_source=fd00::/48. Source increments in parallel with destination. Session params store base_source and source_mask for reconstruction on restart.

### scale_withdraw_flag

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: Implemented 2026-03-01: user complained about withdrawal speed. Added --withdraw flag, 100 routes withdrawn in 0.05s.
- Rule: bgp_tool.py scale --withdraw reads scale_injections from session, reconstructs the EXACT format originally injected (even if the builder changed), converts to withdraw, and sends via inject_batch_fast. --keep N retains first N routes. reconstruct_injected_routes handles legacy SAFI 133 injections (no rd in params). ALWAYS use --withdraw instead of ad-hoc withdrawal scripts.

### session_persistence_reinject

- Priority: `HIGH`
- Updated: `2026-02-16`
- Source: User correction 2026-02-16: 'session should run forever, stop only when I tell him; reinject routes after restart'
- Rule: ExaBGP runs indefinitely until /BGP stop. Persisted injected_routes are auto-reinjected on start (seamless restart). Check existing session FIRST before killing orphans — do NOT kill when resuming. Use stable session_id: device_name.lower().replace('-','_').

### tcam_reserved_leak_burst

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: Discovered 2026-03-01: code analysis of FlowspecTcamManager.cpp, FlowspecTable.cpp, FlowspecRuleData.cpp in cheetah_26_1/src/wbox/src/flowspec/
- Rule: FlowspecTcamManager::ReserveQualifiers() increments m_reserved but RollbackRule() (called on write failure) does NOT decrement it. During bulk injection (16K+ rules), phantom m_reserved entries accumulate, causing false 'No more space left in TCAM'. After 400 failures per family (FLOWSPEC_MAX_UNWRITTEN_IN_TABLE=400), HandleRuleFailedWrite() permanently deletes all subsequent rules. No recovery exists (ReshuffleRules skips !IsInstalled). Use slower injection rates or config knob: flowspec_should_validate_resources=0 to bypass. Related: BUG_FLOWSPEC_TCAM_OVERFLOW_NO_RECOVERY (same 400 threshold, different trigger).

### tcam_shared_pool

- Priority: `HIGH`
- Updated: `2026-03-01`
- Source: Updated 2026-03-01: code analysis revealed m_reserved leak. IPv4/IPv6 have separate TCAM managers (FlowspecManager.cpp:66-67).
- Rule: FlowSpec (SAFI 133) and FlowSpec-VPN (SAFI 134) share the SAME TCAM pool on DNOS. Pool is split by IP version only: IPv4 = 12,000 entries, IPv6 = 4,000 entries (separate PMF groups). Check with: show system npu-resources resource-type flowspec. WARNING: bulk injection can trigger false 'out of resources' due to m_reserved leak in FlowspecTcamManager — see BUG_FLOWSPEC_TCAM_RESERVED_LEAK_BURST.

### test_one_route_before_bulk

- Priority: `HIGH`
- Updated: `2026-02-25`
- Source: Self-audit 2026-02-25: wasted 43 seconds injecting 12K routes that all failed due to wrong format.
- Rule: Before any bulk/scale injection, ALWAYS test 1 route first and verify it appears in BGP table on device. Then proceed with bulk. This prevents wasting 30+ seconds injecting routes that will all be silently rejected.

## Medium Rules

### bgp_tool_py_start_background_issue

- Priority: `MEDIUM`
- Updated: `2026-02-17`
- Source: Self-discovered 2026-02-17: bgp_tool.py start returned empty, ExaBGP died immediately. Direct nohup launch worked.
- Rule: bgp_tool.py start may fail to keep ExaBGP alive in background. Workaround: start ExaBGP directly with nohup + env vars (exabgp_daemon_daemonize=false, exabgp_api_pipename=exabgp, etc.) and create session JSON manually. Then use bgp_tool.py inject/withdraw for route operations.

### dnos_local_as_no_prepend

- Priority: `MEDIUM`
- Updated: `2026-02-15T18:00:00Z`
- Source: initial_session
- Rule: When ExaBGP AS (65200) differs from device BGP AS, use 'local-as <peer_as> type no-prepend' on the device neighbor config.

### dnos_send_community_both

- Priority: `MEDIUM`
- Updated: `2026-02-15T18:00:00Z`
- Source: initial_session
- Rule: Required for extended communities (route targets in FlowSpec-VPN). Use 'community-type both' under each address-family.

### dnos_static_route

- Priority: `MEDIUM`
- Updated: `2026-02-15T18:00:00Z`
- Source: initial_session
- Rule: NOT routing-options. DNOS uses 'protocols static address-family ipv4-unicast route'.

### ebgp_multihop_required

- Priority: `MEDIUM`
- Updated: `2026-02-15T18:00:00Z`
- Source: initial_session
- Rule: Peer goes through firewall, not directly connected. Without ebgp-multihop, DNOS rejects with 'eBGP peer not directly connected'.

### exabgp_family_names

- Priority: `MEDIUM`
- Updated: `2026-02-15T18:00:00Z`
- Source: initial_session
- Rule: ExaBGP 5.0.1 uses 'flow' and 'flow-vpn', not 'flowspec' and 'flowspec-vpn'.

### exabgp_ipv6_parser_bug

- Priority: `MEDIUM`
- Updated: `2026-02-16T08:05:00Z`
- Source: rrsa2_afi_fix_2026-02-16
- Rule: Patch 1: ExtendedCommunitiesIPv6 8-byte fallback. Patch 2: TrafficRedirectIPv6 data[2:20].

### use_route_builder_flowspec_vpn

- Priority: `MEDIUM`
- Updated: `2026-02-16`
- Source: Self-audit 2026-02-16: route_builder outputs flat; manual match/then often wrong
- Rule: For FlowSpec-VPN redirect-ip routes, use route_builder.py — it outputs the correct flat format. Example: python3 route_builder.py --type flowspec-vpn --match 'destination 10.0.0.0/24' --rd 2.2.2.2:100 --rt 1234567:300 --redirect-ip 10.0.0.254

## Session History Recent

### 2026-03-05T10:46:00+02:00

- `timestamp`: 2026-03-05T10:46:00+02:00
- `action`: fix_watchdog_route_reinject
- `session_id`: pe_4
- `details`: Fixed gap: watchdog restarted ExaBGP successfully but did not re-inject routes. ExaBGP is stateless across restarts -- routes injected via pipe are one-shot. Added _reinject_routes() to bgp_watchdog.py: reads injected_routes[] from session JSON, deduplicates, waits 4s for BGP ESTABLISHED, writes each route to /run/exabgp/exabgp.in. Two paths: immediate (TCP ESTABLISHED on restart) and deferred (reinject_pending flag checked on next cycle). Manually re-injected combined redirect-ip+redirect-to-rt route, PE-4 confirmed PfxAccepted:1.
- `result`: success
- `route_reinjected`: true
- `files_patched`:
  - bgp_watchdog.py

### 2026-03-05T08:41:00+02:00

- `timestamp`: 2026-03-05T08:41:00+02:00
- `action`: fix_passive_deadlock_and_restart
- `session_id`: pe_4
- `details`: Fixed overnight session failure caused by passive-passive TCP deadlock. ExaBGP was passive (listen 179) + PE-4 had passive enabled = neither side initiated TCP. Watchdog killed ExaBGP 18+ times thinking SYN storm. Fix: 1) config_gen.py default changed to active mode (passive false; connect 179), 2) watchdog updated with deadlock detection + auto-fix, 3) ARP clear logic fixed (ping from server, not DNOS CLI which has no ping command), 4) session brought up in 18s, route auto-reinjected
- `result`: success
- `tcp_established_in_s`: 18
- `route_reinjected`: true

## Investigation Sessions

### 2026-03-04T22:22:00+02:00

- `timestamp`: 2026-03-04T22:22:00+02:00
- `type`: combined_redirect_pipeline_trace
- `device`: PE-4 (YOR_CL_PE-4)
- `image`: 26.1.0.27
- `method`: debug bgp updates-in + fibmgrd traces + NCP wb_agent traces
- `route`: announce flow route rd 4.4.4.4:100 destination 100.100.100.1/32 redirect-ip 49.49.49.9 redirect 1234567:101 extended-community [ target:1234567:300 ]
- `bug_file`: BUG_FLOWSPEC_VPN_COMBINED_REDIRECT_REJECTED.md
- `findings`:
  - bgpd correctly decodes all 3 ext-communities: RT:1234567L:300, flowspec-redirect-ip-nh, flowspec-redirect-vrf-rt:1234567L:101
  - bgpd passes BOTH actions to zebra/fib-manager (should strip redirect-ip per SW-206876)
  - fibmgrd protobuf: FLOWSPEC_RULE_ADD with REDIRECT_IP_NH(nh_oid:0) + REDIRECT_VRF(vrf_id:106)
  - NCP wb_agent: FlowspecRuleData.cpp:255:CheckActionSupport() rejects combination
  - NCP wb_agent log: 'Cannot add redirect next hop rule with redirect vrf'
  - syslog: BGP_FLOWSPEC_UNSUPPORTED_RULE at 22:22:41.388 (2ms after chain done)
  - Secondary: redirect-ip NH shows 0.0.0.0 (nh_oid=0) -- NH not resolved
  - Secondary: rib-manager ERROR on withdraw: destroy_rn_for_nh_tracking Got NULL parameter
- `proven_trace_keywords`:
  - `bgpd_with_debug_updates_in`:
    - rcvd UPDATE w/ attr:
    - flowspec-redirect-ip-nh
    - flowspec-redirect-vrf-rt
    - bgp_update_receive
    - bgp_update_main
    - bgp_chain_done
  - `fibmgrd`:
    - FLOWSPEC_RULE_ADD
    - FLOWSPEC_RULE_DELETE
    - REDIRECT_IP_NH
    - REDIRECT_VRF
    - nh_oid
  - `ncp_wb_agent_flowspec`:
    - AddRuleInternal
    - DeleteRuleInternal
    - CheckActionSupport
    - redirect-ip-nh
    - redirect-vrf
    - Cannot add redirect next hop
  - `rib_manager`:
    - destroy_rn_for_nh_tracking

## Syslog Patterns

### Bgp Flowspec Unsupported Rule

- `severity`: warning
- `meaning`: FlowSpec rule accepted into BGP RIB (PfxAccepted++) but REJECTED at FlowSpec engine -- NOT programmed in NCP/hardware
- `detection`: bgp_tool.py inject auto-checks (SSH 'set logging terminal' + 5s wait). Manual: 'show file log routing_engine/system-events.log | include FLOWSPEC_UNSUPPORTED' (DNOS CLI, PREFERRED). Fallback: SSH to NCC Linux shell 'grep FLOWSPEC_UNSUPPORTED /var/log/syslog'. DNOS has NO 'show logging' command.
- `false_positive_from`: PfxAccepted count and 'show flowspec instance' both show the rule as present -- MISLEADING
- `example`: BGP_FLOWSPEC_UNSUPPORTED_RULE:BGP flowspec IPv4 rule cannot be applied due to unsupported action. Rule NLRI: DstPrefix:=100.100.100.1/32,SrcPrefix:=*, Actions: redirect to next hop|redirect to vrf
- `agent_action`: After ANY FlowSpec inject, check syslog for this message within 5 seconds. Use: 'show file log routing_engine/system-events.log | include FLOWSPEC_UNSUPPORTED' (DNOS CLI, PREFERRED). Fallback: SSH to NCC shell 'grep FLOWSPEC_UNSUPPORTED /var/log/syslog'. If found, warn user that rule was NOT applied despite PfxAccepted showing success.
- `known_triggers`:
  - combined redirect-ip + redirect-to-rt (SW-206876)
  - traffic-rate + redirect-ip (SW-48486)
- `pipeline_trace`:
  - `bgpd_accepts`: rcvd UPDATE w/ attr: ... flowspec-redirect-ip-nh flowspec-redirect-vrf-rt
  - `fibmgrd_passes_both`: FLOWSPEC_RULE_ADD { action { type: REDIRECT_IP_NH nh_oid: 0 } action { type: REDIRECT_VRF } }
  - `ncp_rejects_at`: FlowspecRuleData.cpp:255:CheckActionSupport()
  - `ncp_message`: Cannot add redirect next hop rule with redirect vrf
  - `timing`: syslog fires 2ms after bgpd chain done

## Correction Log

### 2026-02-16

- `what_agent_did`: Injected FlowSpec-VPN route with match { } then { } format
- `what_user_wanted`: Route sent to RR-SA-2
- `rule_learned`: flowspec_vpn_flat_format
- `timestamp`: 2026-02-16

### 2026-02-16

- `what_agent_did`: ExaBGP killed on resume; routes lost on restart
- `what_user_wanted`: Session runs forever; routes persist and reinject on start
- `rule_learned`: session_persistence_reinject
- `timestamp`: 2026-02-16

### 2026-03-01

- `what_agent_did`: Used slow ad-hoc O_NONBLOCK pipe writes for withdrawal (46s for 15804 routes)
- `what_user_wanted`: Fast withdrawal using existing inject_batch_fast mechanism
- `rule_learned`: scale_withdraw_flag
- `timestamp`: 2026-03-01

### 2026-03-01

- `what_agent_did`: Injected IPv6 FlowSpec as SAFI 133 (no rd/rt) as a workaround, claiming ExaBGP forces AFI 1 with rd keyword
- `what_user_wanted`: IPv6 FlowSpec-VPN SAFI 134 routes with correct rd and rt that match VRF import
- `rule_learned`: ipv6_flowspec_vpn_safi_134
- `timestamp`: 2026-03-01

### 2026-03-01

- `what_agent_did`: Used same RT for IPv4 and IPv6 FlowSpec-VPN
- `what_user_wanted`: Per-AFI RT: 1234567:301 for IPv4, 1234567:401 for IPv6
- `rule_learned`: per_afi_rt_matching
- `timestamp`: 2026-03-01

### 2026-03-01

- `what_agent_did`: Injected 96 scale + 4 individual routes (2 duplicates), got 98 unique on device instead of 100
- `what_user_wanted`: Exactly 100 routes on device — clean up old individual routes first
- `rule_learned`: duplicate_route_count_mismatch
- `timestamp`: 2026-03-01

### 2026-03-03

- `what_agent_did`: Killed working ExaBGP process, tried to restart in passive mode, modified exabgp.env with wrong values (passive=true, port=1179), spent 1+ hour debugging cascading issues
- `what_user_wanted`: Diagnose why Hold Timer Expired happened on PE-4 WITHOUT killing ExaBGP. Keep BGP always up.
- `rule_learned`: never_kill_exabgp_to_fix_bgp
- `timestamp`: 2026-03-03

### 2026-03-03

- `what_agent_did`: Created exabgp.out pipe via ensure_pipes(), causing ExaBGP internal CLI crash loop (Permission denied due to daemon.drop=true + /home/dn 750 perms)
- `what_user_wanted`: ExaBGP starts cleanly without internal CLI crashes
- `rule_learned`: exabgp_internal_cli_crash
- `timestamp`: 2026-03-03

### 2026-03-09

- `what_agent_did`: Diagnosed 'FortiGate IDS block' for 45+ min using nc -z timeouts. Never checked DUT routing table. Ran repeated nc -z probes during silence periods. Used paramiko SSH instead of available MCP.
- `what_user_wanted`: Check static route on DUT immediately. Use Network Mapper MCP first. Missing route was the real cause, not FortiGate.
- `rule_learned`: verify_static_route_before_exabgp + nc_z_cannot_distinguish_firewall_vs_missing_route + mcp_first_for_dut_verification
- `timestamp`: 2026-03-09

### 2026-03-09

- `what_agent_did`: ExaBGP config only had ipv4 flow-vpn (SAFI 134). PE-4 only had ipv4-flowspec (SAFI 133). Zero common AFIs. PE-4 sent 7 NOTIFICATIONs.
- `what_user_wanted`: ExaBGP AFIs must match DUT neighbor config. Should have checked before starting.
- `rule_learned`: exabgp_afi_must_match_dut_neighbor
- `timestamp`: 2026-03-09

## Session History

### 2026-03-04T16:21:00

- `timestamp`: 2026-03-04T16:21:00
- `prompt`: Implement fixes: passive enabled on PE-4, FortiGate IDS awareness in watchdog + diagnose
- `session_id`: pe_4
- `device`: PE-4 (YOR_CL_PE-4)
- `outcome`: success -- 3 fixes applied: passive enabled on live PE-4, watchdog FortiGate check, diagnose FortiGate detection
- `routes_injected`: 0
- `self_audit`: 1. Applied passive enabled to PE-4 live config via SSH -- committed without session disruption (BGP stayed Established). 2. Added _is_tcp179_open() to bgp_watchdog.py -- before auto-restarting dead ExaBGP, checks if TCP/179 is reachable; if blocked (FortiGate IDS), skips restart and logs warning. Prevents restart loops that waste time and refresh quarantine. 3. Added _check_fortigate_ids() to bgp_tool.py diagnose -- checks TCP/179 and TCP/22 to peer; if 179 blocked but 22 open, identifies as FortiGate IDS block with recovery steps. Runs BEFORE BgpTrius iptables check. 4. Session verified: TCP ESTAB, 1 PfxAccepted, passive enabled in config.

### 2026-03-04T16:35:00

- `timestamp`: 2026-03-04T16:35:00
- `prompt`: Implement session protection: agent must NEVER kill BGP session unless user explicitly says stop
- `session_id`: pe_4
- `device`: PE-4 (YOR_CL_PE-4)
- `outcome`: success -- 4-layer protection implemented: cursor rule, BGP.md, bgp_tool.py --confirm-kill, learned rules
- `routes_injected`: 0
- `self_audit`: 1. Created ~/.cursor/rules/bgp-session-protection.mdc (alwaysApply:true) -- agent reads this on EVERY prompt regardless of context. Lists exact forbidden actions and exact phrases that constitute explicit stop request. 2. Added SESSION PROTECTION section at top of BGP.md -- first thing agent reads on /BGP invocation. 3. Added --confirm-kill flag to bgp_tool.py stop -- code-level protection. Without flag, stop REFUSES to kill a live ExaBGP and returns error JSON with hint. 4. Added protection to cmd_start -- refuses to start if another session has live ExaBGP (prevents accidental kills during device switch). 5. Updated learned rules: never_kill_exabgp_to_fix_bgp and never_clear_bgp_unless_explicit both strengthened with references to new safeguards. 6. Verified: ran bgp_tool.py stop without --confirm-kill on live pe_4 session, got REFUSED error, session stayed ESTAB.

### 2026-03-04T17:50:00

- `timestamp`: 2026-03-04T17:50:00
- `prompt`: BGP down again (Hold Timer Expired). Found wrong default IP (100.70.0.205 vs actual 100.70.0.206). Fixed code and restarted.
- `session_id`: pe_4
- `device`: PE-4 (YOR_CL_PE-4)
- `outcome`: success -- fixed DEVICE_DEFAULT_IP to 100.70.0.206, added _extract_peer_ip_from_config() to bgp_tool.py, session re-established
- `routes_injected`: 2
- `self_audit`: 1. Session died at 17:35 IST (Hold Timer Expired). ExaBGP was alive but TCP broken -- FortiGate IDS quarantine triggered again. 2. ExaBGP reconnect loop (outgoing-26) was refreshing the quarantine with rapid SYNs. PE-4 passive enabled prevented DUT SYNs but ExaBGP active mode still flooded. 3. Stopped ExaBGP with user permission, waited ~5 min for quarantine expiry. 4. User spotted session metadata showed device_ip=100.70.0.205 -- wrong! PE-4 is 100.70.0.206 on ge100-18/0/6.999. 5. Root cause: config_gen.py DEVICE_DEFAULT_IP hardcoded as .205, bgp_tool.py stored this default in session JSON without parsing the actual ExaBGP config. 6. Fixed: changed default to .206, added _extract_peer_ip_from_config() that parses 'neighbor X.X.X.X' from config file, updated all fallback references. 7. Session restarted, verified ESTAB with correct peer_ip/device_ip=100.70.0.206 in session JSON. 8. REMAINING ISSUE: ExaBGP reconnect is too aggressive when session drops -- needs backoff or FortiGate-aware reconnect throttling to prevent IDS re-trigger.

### 2026-03-05T00:22:00

- `timestamp`: 2026-03-05T00:22:00
- `prompt`: Fixed ExaBGP redirect-ip encoding bug: 49.49.49.9 now correctly encoded in MP_REACH_NLRI NH field
- `session_id`: pe_4
- `device`: PE-4 (YOR_CL_PE-4)
- `outcome`: success -- ExaBGP encoding fix confirmed: redirect-ip-nh:49.49.49.9 on wire and on device
- `routes_injected`: 1
- `route`: announce flow route rd 4.4.4.4:100 destination 100.100.100.1/32 redirect-ip 49.49.49.9 redirect 1234567:101 extended-community [ target:1234567:300 ]
- `self_audit`: ROOT CAUSE FOUND: ExaBGP configuration/flow/__init__.py route() function. redirect-ip correctly parses 49.49.49.9 into nlri.nexthop, but redirect (redirect-to-rt) action returns NoNextHop via nexthop-and-attribute path and unconditionally overwrites nlri.nexthop. Order matters: redirect-ip sets NH, then redirect overwrites it to NoNextHop. FIX: added 'from exabgp.protocol.ip import NoNextHop' and guarded 'if nexthop is not NoNextHop: change.nlri.nexthop = nexthop'. Also patched family.py (SAFI 134 rd_size=8 for 12-byte VPN NH: 8-byte RD + 4-byte IP) and section.py (same guard for config-file parsing). Verification: XRAY CP capture confirmed 49.49.49.9 in MP_REACH_NLRI, PE-4 shows redirect-ip-nh:49.49.49.9, BGP received-routes shows Next hop: 49.49.49.9. HOWEVER: DNOS NCP still rejects the combined redirect-ip + redirect-to-rt per SW-206876 (CheckActionSupport rejection). The encoding fix proves the TOOLING works correctly now; the DNOS spec-vs-implementation gap is the remaining issue.

### 2026-04-27T12:38:51.558883+00:00

- `timestamp`: 2026-04-27T12:38:51.558883+00:00
- `command`: /BGP
- `topic`: cluster_aware_device_resolver
- `summary`: Added bgp_tool.py 'resolve' subcommand + cluster-aware _resolve_device_creds. Probes cached NCC -> VIP -> cluster_ncc_ips via paramiko AUTH (not just TCP/22). Caches winner + active NCC host in ~/.cursor/bgp-reference/cluster_ncc_cache.json. Updated SCALER DB PE-4 entry with cluster_ncc_ips=[100.64.11.96, 100.64.4.122] and aliases=[PE-4, pe-4, pe_4, PE4]. Updated /BGP command file Device Resolution section + bgp-reference/discovery.md Step 0.
- `user_request`: /BGP must be better, like /TEST and /SPIRENT when needeing to find a specific device

## Session History 2026 03 09

### 2026-03-09T12:00:00+02:00

- `timestamp`: 2026-03-09T12:00:00+02:00
- `prompt`: /BGP recovery: fix ExaBGP + PE-4 session -- 3 cascading root causes found
- `session_id`: pe_4
- `device`: PE-4 (YOR_CL_PE-4)
- `outcome`: success -- BGP Established after fixing static route + AFI mismatch + watchdog cron
- `routes_injected`: 0
- `self_audit`: THREE ROOT CAUSES (not one): 1) Watchdog cron respawning ExaBGP every 30s (fix: --remove-cron). 2) Missing static route 100.64.0.0/20 on PE-4 (fix: add via paramiko, commit). 3) ExaBGP AFI mismatch -- only flow-vpn (SAFI 134), PE-4 only has flowspec (SAFI 133) (fix: add ipv4 unicast/flow/mpls-vpn). CRITICAL MISTAKES: A) Wasted 45+ min chasing FortiGate IDS when real cause was missing route. nc -z timeout looks identical for both. B) Never used MCP run_show_command -- it was available and would have found the missing route in 2 seconds. C) Ran nc -z during silence periods, which refreshes the supposed quarantine. D) Used paramiko SSH instead of MCP for show commands. LESSONS ADDED: verify_static_route_before_exabgp, nc_z_cannot_distinguish_firewall_vs_missing_route, exabgp_afi_must_match_dut_neighbor, mcp_first_for_dut_verification, watchdog_cron_must_disable_during_recovery. CURSOR RULE CREATED: bgp-preflight-mcp-verification.mdc.

## Dnaas Path Cache

### Rr Sa 2

- `dnaas_leaf`: DNAAS-LEAF-B15
- `device_bundle`: bundle-100
- `device_999_exists`: true
- `device_999_ip`: 100.70.0.205/24
- `bgp_neighbor_exists`: true
- `bgp_asn`: 123
- `bgp_local_as`: 1234567
- `static_route_exists`: true
- `discovered_at`: 2026-02-15T19:48:00Z
- `dnaas_leaf_ip`: 100.64.101.6
- `dnaas_leaf_creds`: sisaev/Drive1234!

### Yor Pe 1

- `dnaas_leaf`: DNAAS-LEAF-D16
- `dnaas_leaf_ip`: 100.64.101.123
- `dnaas_leaf_creds`: sisaev/Drive1234!
- `device_interface`: ge400-0/0/5
- `leaf_interface`: ge100-0/0/5
- `device_999_interface`: ge400-0/0/5.999
- `device_999_exists`: true
- `device_999_ip`: 100.70.0.205/24
- `bgp_neighbor_exists`: true
- `bgp_asn`: 1234567
- `static_route_exists`: true
- `discovered_at`: 2026-02-17T14:55:00Z
- `note`: DNAAS-LEAF-D16 BD g_mgmt_v999 already had ge100-0/0/5.999 pre-configured

### Yor Cl Pe 4

- `dnaas_leaf`: DNAAS-LEAF-B10
- `dnaas_leaf_ip`: 100.64.101.3
- `dnaas_leaf_creds`: sisaev/Drive1234!
- `device_interface`: ge100-18/0/6
- `leaf_interface`: ge100-0/0/5
- `device_999_interface`: ge100-18/0/6.999
- `device_999_exists`: true
- `device_999_ip`: 100.70.0.206/24
- `bgp_neighbor_exists`: true
- `bgp_asn`: 1234567
- `static_route_exists`: true
- `discovered_at`: 2026-03-03T10:53:00Z
- `note`: Configured DNAAS-LEAF-B10 ge100-0/0/5.999 AC in g_mgmt_v999 BD

## Exabgp Quirks

### orphan_processes_cause_collision

- `id`: orphan_processes_cause_collision
- `description`: Orphaned ExaBGP processes (from killed terminals, crashed agents, or forgotten sessions) all connect to the same peer simultaneously, causing BGP NOTIFICATION 6/7 (Connection Collision Resolution) on every attempt. The session will NEVER establish until all orphans are killed.
- `workaround`: Check for existing active session FIRST. If session exists and ExaBGP alive, return early — do NOT kill. ExaBGP runs indefinitely until /BGP stop. Only kill orphans when starting a FRESH session (no active session for this session_id). Use stable session_id per device: device_name.lower().replace('-','_').

### ipv6_flow_crash

- `id`: ipv6_flow_crash
- `description`: ExaBGP 5.0.1 parser crashes on certain IPv6 FlowSpec extended communities
- `workaround`: Patched: communities.py and traffic.py (TrafficRedirectIPv6)

### no_multihop_keyword

- `id`: no_multihop_keyword
- `description`: ExaBGP 5.0.1 does NOT support 'multihop' keyword in config. It causes exit code 1.
- `workaround`: Do NOT add multihop to ExaBGP config. Only the DNOS device needs ebgp-multihop. ExaBGP handles TTL automatically.

### no_process_section_needed

- `id`: no_process_section_needed
- `description`: ExaBGP 5.x has built-in CLI pipe handler. No explicit process section needed for route injection.
- `workaround`: Omit the process section. Use /run/exabgp/exabgp.in pipe directly for route injection.

### active_mode_connect_179

- `id`: active_mode_connect_179
- `description`: ExaBGP must use passive=false + connect 179 (ACTIVE mode). DUT has 'passive enabled' so DUT never initiates SYN. ExaBGP initiates a single clean SYN. Combined: ExaBGP active + DUT passive = single clean TCP handshake, no SYN storms, no FortiGate IDS trigger. SUPERSEDES: passive_true_listen_179 (caused passive-passive TCP deadlock when both sides listen and neither connects, triggering 18+ watchdog restart loops overnight 2026-03-05).
- `workaround`: Set passive false; connect 179; in ExaBGP config. DUT must have 'passive enabled'. config_gen.py default updated 2026-03-05. Watchdog has _is_exabgp_passive() + _fix_passive_config() auto-detection.

### ttl_outgoing_only

- `id`: ttl_outgoing_only
- `description`: For eBGP multihop, ExaBGP needs outgoing-ttl 64 ONLY. Do NOT use incoming-ttl -- it sets IP_TTL on the socket (not MIN_TTL), causing SYN-ACK to go out with low TTL and be discarded in transit. Note: with active mode (connect 179), ExaBGP initiates the SYN so TTL matters for the outgoing direction. SUPERSEDES: ttl_incoming_outgoing.
- `workaround`: Add outgoing-ttl 64 only. Never add incoming-ttl.

### connect_179_not_listen

- `id`: connect_179_not_listen
- `description`: ExaBGP connects to port 179 on device (active mode). DUT listens (passive enabled). SUPERSEDES: listen_179_not_connect (caused passive-passive deadlock 2026-03-05 when both sides listen).
- `workaround`: Use connect 179 (not listen 179) in ExaBGP config. DUT has passive enabled.

### router_id_local_ip

- `id`: router_id_local_ip
- `description`: Use local-address as router-id for consistency.
- `workaround`: Set router-id to same value as local-address.

### flowspec_vpn_flat_format_required

- `id`: flowspec_vpn_flat_format_required
- `description`: ExaBGP API pipe REQUIRES flat format for FlowSpec-VPN routes with rd. The match{}/then{} section-style wrappers cause parse failure.
- `workaround`: Use FLAT format: 'announce flow route rd X destination Y redirect IP extended-community [ target:RT ]'. route_builder.py outputs flat. bgp_tool auto-converts on inject. Persisted routes reinjected on start (seamless).

### flowspec_safi133_flat_format_required

- `id`: flowspec_safi133_flat_format_required
- `description`: ExaBGP API pipe REQUIRES flat format for FlowSpec SAFI 133 (non-VPN) too. The match{}/then{} format SILENTLY fails — ExaBGP returns 'error' on exabgp.out but writes nothing to log. Routes never sent to peer.
- `workaround`: Use FLAT format: 'announce flow route destination <prefix> <action>'. Example: 'announce flow route destination 10.0.0.0/24 rate-limit 0'. For IPv6: same syntax with IPv6 prefix — ExaBGP auto-detects AFI from address format.

### exabgp_out_pipe_diagnostic

- `id`: exabgp_out_pipe_diagnostic
- `description`: ExaBGP writes 'error' or 'done' to /run/exabgp/exabgp.out for each API pipe command. ALWAYS check this pipe after injection — it's the only way to detect silent failures (no log, no BGP update).
- `workaround`: After writing to exabgp.in, read exabgp.out with: timeout 1 cat /run/exabgp/exabgp.out. 'error' = command rejected. 'done' = accepted. Multiple 'error' = queued failures from batch writes.

### ipv6_flow_family_works

- `id`: ipv6_flow_family_works
- `description`: ExaBGP 5.0.1 'ipv6 flow' family WORKS despite .cursorrules noting a parser bug. Session establishes, routes are accepted and sent to peer. The parser bug may only affect specific community types (patched in our install).
- `workaround`: Safe to use 'ipv6 flow' in ExaBGP family config. No workaround needed.

### pe4_iptables_bgp_block

- `id`: pe4_iptables_bgp_block
- `description`: ROOT CAUSE FOUND: PE-4 NCC container iptables INPUT chain has DROP rules for TCP port 179 (dpt and spt) unless mark 0x65179. NFQUEUE queue 178 daemon supposed to mark legitimate BGP but fails for external peers like ExaBGP. bgpd IS listening on 0.0.0.0:179 inside container. SYN from ExaBGP (dpt:179) dropped by INPUT rule before reaching bgpd.
- `workaround`: RESOLVED: Add iptables ACCEPT rules before DROP rules: iptables -I INPUT 3 -p tcp -s <server_ip> --sport 179 -j ACCEPT; iptables -I INPUT 3 -p tcp -s <server_ip> --dport 179 -j ACCEPT. Rules are ephemeral (lost on reboot). ExaBGP uses active mode (passive false; connect 179;). DUT has passive enabled. bgp_tool.py diagnose --fix auto-applies iptables rules.

### preload_mixed_afi_source_session_drop

- `id`: preload_mixed_afi_source_session_drop
- `description`: Preloading 12K+ IPv4 FlowSpec-VPN (source+dest) combined with IPv6 FlowSpec-VPN (source+dest) in a single process API loader causes BGP session to drop after ~325 IPv6 routes. Consistent across 2 attempts.
- `workaround`: Preload IPv4 first (--preload), wait for BGP establishment and route acceptance, then inject IPv6 via pipe (--fast). Do NOT combine IPv4+IPv6 source+dest routes in a single preload.

## Session Management

### Orphan Cleanup At Start

- `description`: ALWAYS check for and kill orphaned exabgp/socat processes BEFORE starting a new session. Multiple ExaBGP instances cause BGP NOTIFICATION 6/7 (Connection Collision Resolution).
- `learned_from`: session_flap_2026-02-16
- `commands`:
  - pkill -f exabgp
  - pkill -f socat.*exabgp
  - sleep 1
  - pgrep -f exabgp (verify clean)

### Cleanup At Stop

- `description`: When stopping /BGP session, kill ExaBGP process AND all child processes (socat FIFOs). Check for zombies 2 seconds after kill.
- `learned_from`: session_flap_2026-02-16
- `commands`:
  - kill -TERM <pid>
  - sleep 2
  - kill -9 <pid> 2>/dev/null
  - pkill -f socat.*exabgp

### Session Recovery Proof

- `description`: After killing ExaBGP, wait 30s then verify RR↔PE sessions recover. Use: show bgp summary | include Established. If sessions don't recover, check for OTHER orphan ExaBGP processes.
- `learned_from`: xray_encoding_proof_2026-02-16

## Dnos Encoding Bugs

### Flowspec Vpn Redirect Ip Reflection

- `description`: DNOS 26.1.0.22 FlowSpec-VPN redirect-ip outbound UPDATE encoding is broken on ALL devices. Not RR-specific. bgp_attr.c allocates 24-byte NH buffer (IPv6 VPN size) but sets NH_LEN=4 for IPv4. 20 zero bytes bleed into NLRI. Confirmed on RR-SA-2 (reflecting to PEs) AND PE-1 (advertising to RR). Any DNOS device advertising redirect-ip to any BGP peer triggers NOTIFICATION 3/9 from the receiver.
- `affected_component`: bgp_attr.c → bgp_packet_mpattr_start_v4_flowspec_vpn
- `symptom`: Route installs locally on RR (show flowspec ncp 0 shows redirect-ip-nh), but reflected UPDATE to PE is malformed
- `pe_behavior`: PE sends NOTIFICATION 3/9 (UPDATE Message Error, Optional Attribute Error) and tears down session
- `proof_method`: XRAY: run packet-capture ncc interface any count 100 filter-expression "port 179" verbose on RR during inject cycle. Compare NH_LEN=0 (correct, non-redirect) vs NH_LEN=4 with 24-byte buffer (broken, redirect-ip)
- `discovered`: 2026-02-16/17
- `confirmed_on`:
  - RR-SA-2 (reflector)
  - YOR_PE-1 (PE)

## Dnos Tcam Capacity

- `flowspec_pool`: Shared between FlowSpec (SAFI 133) and FlowSpec-VPN (SAFI 134)
- `ipv4_entries`: 12000
- `ipv6_entries`: 4000
- `overflow_behavior`: NCP marks excess rules as 'Not Installed, out of resources' — no crash, no silent drop
- `verification_command`: show system npu-resources resource-type flowspec
- `discovered`: 2026-02-25

## Scale Injection Performance

- `method`: inject_batch_fast via /run/exabgp/exabgp.in pipe
- `batch_size`: 200
- `pipeline_16k_rules_seconds`: 60
- `tool`: bgp_tool.py scale --mode flowspec-ipv4/flowspec-ipv6/flowspec-vpn-ipv4/flowspec-vpn-ipv6 --count N --fast
- `discovered`: 2026-02-25

### Safi 133

- `ipv4_rps`: 377
- `ipv6_rps`: 404

### Safi 134

- `ipv4_rps`: 190
- `ipv6_rps`: 172
- `note`: Slower due to longer route strings with RD/RT/extended-community

### Builders

- scale-flowspec-ipv4 (scale.py)
- scale-flowspec-ipv6 (scale.py)
- scale-flowspec-vpn-ipv4 (scale.py) — defaults: RD 1.1.1.1:200, RT 300:300
- scale-flowspec-vpn-ipv6 (scale.py) — defaults: RD 1.1.1.1:200, RT 1234567:401

## Failed Attempts

### multihop_keyword

- `id`: multihop_keyword
- `config`: multihop 10;
- `error`: ExaBGP exit code 1 on startup
- `resolution`: Removed multihop from ExaBGP config. Only needed on DNOS device.
- `timestamp`: 2026-02-15T19:54:00Z

### traffic_redirect_ipv6

- `id`: traffic_redirect_ipv6
- `config`: TrafficRedirectIPv6.unpack data[2:11]
- `error`: struct.error: unpack requires a buffer of 18 bytes
- `resolution`: Fixed traffic.py: use data[2:20] for unpack, data[:20] for community
- `timestamp`: 2026-02-16T08:04:00Z

### flowspec_safi133_match_then_silent_fail

- `id`: flowspec_safi133_match_then_silent_fail
- `config`: announce flow route match { destination 10.0.0.0/24; } then { rate-limit 0; }
- `error`: ExaBGP returns 'error' on exabgp.out. No log entry, no BGP UPDATE, 0 PfxAccepted. 12K routes wasted.
- `resolution`: Use flat format: 'announce flow route destination 10.0.0.0/24 rate-limit 0'. Also accepted: 'announce flow route { match { destination X; } then { rate-limit 0; } }' (outer braces). But flat is simplest.
- `timestamp`: 2026-02-25T18:30:00Z

### exabgp_4byte_asn_rt_wrong_type

- `id`: exabgp_4byte_asn_rt_wrong_type
- `config`: extended-community target:1234567:300 (ASN > 65535)
- `error`: DNOS shows RT:0.18.214.135:300 instead of RT:1234567:300. 4-byte ASN value interpreted as IPv4 address.
- `resolution`: Fixed parser.py _HEADER: target4 was 0x01,0x02 (IPv4 Type 1), changed to 0x02,0x02 (4-byte ASN Type 2, RFC 5668). Same for origin4.
- `timestamp`: 2026-02-16T16:12:00Z

### exabgp_redirect4_missing

- `id`: exabgp_redirect4_missing
- `config`: extended-community [ redirect:1234567:101 ] (ASN > 65535)
- `error`: ExaBGP ValueError: redirect community only had 2-byte ASN encoding (HL format). 4-byte ASN redirect:1234567:101 silently failed, route never sent to wire.
- `resolution`: Patched parser.py: added redirect4 to _HEADER (0x82,0x08 per RFC 7674), _ENCODE (LH), and auto-upgrade logic. ExaBGP now encodes TrafficRedirectASN4 for 4-byte ASN redirect communities.
- `timestamp`: 2026-03-04T18:10:00Z

### dnos_sw206876_combined_redirect

- `id`: dnos_sw206876_combined_redirect
- `config`: FlowSpec rule with BOTH redirect-ip (Simpson) AND redirect-to-rt in same rule
- `error`: PE-4 syslog: BGP_FLOWSPEC_UNSUPPORTED_RULE: BGP flowspec IPv4 rule cannot be applied due to unsupported action. Actions: redirect to next hop|redirect to vrf. PfxAccepted=1 is MISLEADING -- rule is in BGP RIB but NOT programmed in NCP/hardware. show flowspec shows both actions but they are not applied.
- `resolution`: DNOS limitation (SW-206876). Cannot combine both redirect actions in a single FlowSpec rule. Use separate rules. CRITICAL: PfxAccepted and show flowspec are NOT reliable indicators -- must check syslog via 'set logging terminal' for BGP_FLOWSPEC_UNSUPPORTED_RULE.
- `detection`: After FlowSpec inject: bgp_tool.py auto-checks via SSH 'set logging terminal' + 5s wait. DNOS has NO 'show logging' command. For manual check: 'show file log routing_engine/system-events.log | include FLOWSPEC_UNSUPPORTED' (DNOS CLI, PREFERRED). Fallback: SSH to active NCC Linux shell 'grep FLOWSPEC_UNSUPPORTED /var/log/syslog | tail -5'.
- `timestamp`: 2026-03-04T19:07:00Z

### cluster_device_ssh

- `id`: cluster_device_ssh
- `device_type`: dnos_cluster
- `pattern`: For cluster devices (CL in hostname), SSH must target the ACTIVE NCC hostname (serial number), not the management VIP.
- `example`: PE-4 (YOR_CL_PE-4): ssh dnroot@kvm108-cl408d-ncc1 (active NCC-1), NOT ssh dnroot@100.64.4.98 (VIP rejects with incorrect credentials)
- `note`: Check active NCC: show system components | find NCC. Active NCC has operational: active-up. Use its Serial Number field as SSH hostname.
- `timestamp`: 2026-03-04T18:25:00Z
