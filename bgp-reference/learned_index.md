# BGP Learned Knowledge Index

Last synced: 2026-04-27T12:38:51Z

Read this file first on every command invocation. It is the agent-facing mirror of the
backing JSON learning store. Existing Python tools still read JSON directly.

## Staleness Guard

Before trusting this file, check freshness:

1. Run `python3 ~/.cursor/tools/prune_learning.py --command bgp --check`.
2. If exit code is 1 (stale), run `python3 ~/.cursor/tools/prune_learning.py --command bgp --sync-only` BEFORE reading further.
3. After ANY JSON write-back, you MUST run `python3 ~/.cursor/tools/prune_learning.py --command bgp --sync-only`. This is NOT optional.

Skipping the sync step means you are reading outdated rules and will make wrong decisions.

## Read Protocol

- Always read this file first.
- Read only the matching sections from `learned_rules.md`.
- After any JSON write-back, refresh the Markdown mirror with `python3 ~/.cursor/tools/prune_learning.py --command bgp --sync-only`.

## Critical

- `bgptrius_iptables_default_passive` - DNOS BgpTrius (BGP NSR) installs iptables rules that DROP all TCP port 179 traffic without mark 0x65179.
- `device_ip_from_config` - bgp_tool.py must extract the actual neighbor IP from the ExaBGP config file (neighbor X.X.X.X line) and store it in session JSON as both peer_ip and device_ip.
- `exabgp_afi_must_match_dut_neighbor` - ExaBGP family {} block MUST include at least one AFI/SAFI that the DUT's neighbor has configured.
- `exabgp_env_file_location` - ExaBGP env file lives at ~/.local/etc/exabgp/exabgp.env.
- `exabgp_env_passive_conflict` - NEVER set passive=true in exabgp.env when using active mode in neighbor config (passive false).
- `exabgp_internal_cli_crash` - ExaBGP crashes on startup when BOTH /run/exabgp/exabgp.in AND /run/exabgp/exabgp.out named pipes exist.
- `exabgp_redirect_ip_encoding_fix` - ExaBGP 5.0.1 has a critical encoding bug for redirect-ip when combined with redirect (redirect-to-rt) in API pipe flow routes.
- `mcp_first_for_dut_verification` - ALWAYS prefer MCP Network Mapper (run_show_command, get_device_config) over paramiko SSH for DUT verification.
- `nc_z_cannot_distinguish_firewall_vs_missing_route` - nc -z timeout is AMBIGUOUS.
- `on_session_fail_debug_protocol` - When ExaBGP-PE session FAILS (Hold Timer Expired, Broken TCP, ECONNRESET), BEFORE attempting any fix: 1) Run /debug-dnos on PE-4 to check if BGP config was c...
- `passive_passive_deadlock` - ExaBGP must ALWAYS use active mode (passive false; connect 179;) when the DUT has passive enabled.
- `pe1_pe4_dnaas_cleanup` - When switching ExaBGP target device (e.g.
- `pe4_tcp_listener_recovery` - PE-4 BGP TCP listener crashes after Hold Timer Expired and port 179 becomes REFUSED.
- `verify_static_route_before_exabgp` - BEFORE starting ExaBGP, ALWAYS verify the DUT has a static route back to the server (100.64.6.134).
- `watchdog_cron_must_disable_during_recovery` - bgp_watchdog cron runs every 30 seconds (2 crontab entries: at :00 and :30).

## High

- `advertised_state_tracking` - Every session now tracks advertised_state in session JSON.
- `bgp_status_optimized_flow` - For /BGP STATUS mode (no args): use exactly 2 rounds.
- `cluster_aware_device_resolver` - DNOS clusters in SCALER DB store the cluster mgmt VIP in 'ip' (e.g.
- `dnaas_b15_rr_sa2_path` - RR-SA-2 connects to DNAAS via DNAAS-LEAF-B15 (100.64.101.6).
- `dnaas_leaf_credentials` - DNAAS leaves use credentials: sisaev/Drive1234!.
- `dnos_afi_no_admin_state` - On PE-1 (26.1.0.22), address-family blocks inside BGP neighbor do NOT support admin-state.
- `dnos_import_vpn_rt_additive` - DNOS import-vpn route-target is ADDITIVE.
- `dnos_no_ping_command` - DNOS CLI does NOT have a native 'ping' command.
- `dnos_show_file_log` - DNOS historical syslog access uses 'show file log routing_engine/system-events.log | include <pattern>' (PREFERRED over SSH grep).
- `dnos_static_route_nesting` - In DNOS config hierarchy, next-hop X.X.X.X is a LEAF under route block.
- `duplicate_route_count_mismatch` - Individual routes (from bgp_tool.py inject) and scale routes (from bgp_tool.py scale) can overlap if they use the same prefix.
- `encoding_bug_affects_ipv4_and_ipv6` - The DNOS FlowSpec-VPN redirect-ip outbound encoding bug (bgp_attr.c → bgp_packet_mpattr_start_v4_flowspec_vpn) affects BOTH IPv4 and IPv6 FlowSpec-VPN routes.
- `exabgp_ipv6_flow_works` - ExaBGP 5.0.1 'ipv6 flow' family WORKS.
- `exabgp_named_pipes` - CRITICAL: Only create exabgp.in pipe.
- `exabgp_pipe_diagnostic` - ALWAYS read /run/exabgp/exabgp.out after pipe writes to check for errors.
- `flowspec_safi133_flat_format` - ExaBGP API pipe requires FLAT format for FlowSpec SAFI 133 (non-VPN).
- `flowspec_vpn_flat_format` - ExaBGP API pipe requires FLAT format for FlowSpec-VPN routes with rd.
- `flowspec_vpn_rate_limit_flat_format` - ExaBGP API pipe accepts SAFI 134 rate-limit in flat format: 'announce flow route rd X destination Y rate-limit 0 extended-community [ target:RT ]'.
- `flowspec_vpn_vrf_import_rt_matching` - SAFI 134 FlowSpec-VPN routes are imported into VRFs based on the VRF's ipv4-flowspec/ipv6-flowspec import-vpn route-target.
- `fortigate_firewall_identity` - The firewall at 100.70.0.254 (inband) / 100.64.15.254 (OOB, our default gateway) is a FortiGate (Fortinet).
- `ipv6_flowspec_vpn_flat_format` - ExaBGP pipe accepts IPv6 FlowSpec-VPN redirect-ip in flat format: 'announce flow route rd X destination <ipv6-prefix> redirect <ipv6-addr> extended-community...
- `ipv6_flowspec_vpn_safi_134` - IPv6 FlowSpec-VPN MUST be SAFI 134 (with rd and rt), NOT SAFI 133.
- `nc_z_refreshes_fortigate_quarantine` - nc -z sends a TCP SYN to the target port.
- `pe1_999_default_vrf` - PE-1 ge400-0/0/5.999 must be in DEFAULT VRF (not VRF ALPHA) for default-VRF BGP peering with ExaBGP.
- `per_afi_rt_matching` - IPv4 and IPv6 FlowSpec use DIFFERENT import RTs on the VRF.
- `preload_mixed_ipv4_ipv6_source_session_drop` - When preloading 12K+ IPv4 FlowSpec-VPN with source+dest AND IPv6 FlowSpec-VPN with source+dest in a SINGLE preload file, ExaBGP causes BGP session to drop af...
- `rt_redirect_target_uses_unicast_rt` - FlowSpec RT-Redirect target VRF is determined by ipv4-UNICAST import-vpn route-target, NOT ipv4-flowspec.
- `scale_injection_performance` - ExaBGP pipe injection is limited to ~184 rps for SAFI 134 routes due to ExaBGP's per-route Python parser (api_flow -> configuration.partial -> tokenizer ~5.5...
- `scale_injection_tracking` - cmd_scale now tracks all bulk-injected routes in session via scale_injections[] metadata (mode, builder, params, count, timestamp).
- `scale_source_dest_match` - Scale builders (flowspec-vpn-ipv4/ipv6) now support --base-source and --source-mask args.
- `scale_withdraw_flag` - bgp_tool.py scale --withdraw reads scale_injections from session, reconstructs the EXACT format originally injected (even if the builder changed), converts t...
- `session_persistence_reinject` - ExaBGP runs indefinitely until /BGP stop.
- `tcam_reserved_leak_burst` - FlowspecTcamManager::ReserveQualifiers() increments m_reserved but RollbackRule() (called on write failure) does NOT decrement it.
- `tcam_shared_pool` - FlowSpec (SAFI 133) and FlowSpec-VPN (SAFI 134) share the SAME TCAM pool on DNOS.
- `test_one_route_before_bulk` - Before any bulk/scale injection, ALWAYS test 1 route first and verify it appears in BGP table on device.

## Medium

- `bgp_tool_py_start_background_issue` - bgp_tool.py start may fail to keep ExaBGP alive in background.
- `dnos_local_as_no_prepend` - When ExaBGP AS (65200) differs from device BGP AS, use 'local-as <peer_as> type no-prepend' on the device neighbor config.
- `dnos_send_community_both` - Required for extended communities (route targets in FlowSpec-VPN).
- `dnos_static_route` - NOT routing-options.
- `ebgp_multihop_required` - Peer goes through firewall, not directly connected.
- `exabgp_family_names` - ExaBGP 5.0.1 uses 'flow' and 'flow-vpn', not 'flowspec' and 'flowspec-vpn'.
- `exabgp_ipv6_parser_bug` - Patch 1: ExtendedCommunitiesIPv6 8-byte fallback.
- `use_route_builder_flowspec_vpn` - For FlowSpec-VPN redirect-ip routes, use route_builder.py — it outputs the correct flat format.

## Structured Context

- `Session History Recent` - 2 items
- `Investigation Sessions` - 1 items
- `Syslog Patterns` - 1 keyed entries
- `Correction Log` - 10 items
- `Session History` - 5 items
- `Session History 2026 03 09` - 1 items
- `Dnaas Path Cache` - 3 keyed entries
- `Exabgp Quirks` - 14 items
- `Session Management` - 3 keyed entries
- `Dnos Encoding Bugs` - 1 keyed entries
- `Dnos Tcam Capacity` - 6 keyed entries
- `Scale Injection Performance` - 8 keyed entries
- `Failed Attempts` - 7 items
