# BGP Tool - Route Injection Reference

## Overview

All route injection goes through `bgp_tool.py inject --session-id <id> --route "<exabgp_string>"`.
You can also use `route_builder.py` to generate the ExaBGP string from human-readable arguments.

## Engine Status (2026-02)

- **ExaBGP (patched):** Primary for FlowSpec and FlowSpec-VPN. Patched to accept `rd` and `next-hop` in `announce flow route` via API pipe. Use `bgp_tool.py start` then `inject`.
- **GoBGP:** Parked for flow-vpn (FSM sends TCP FIN after OPEN). Still used for unicast, VPN, EVPN.
- **Scapy:** Malformation testing only (bad-marker, truncated-nlri, etc.).

---

## VPN Route Target Discovery (MANDATORY before VPN injection)

Before injecting ANY VPN route (FlowSpec-VPN, L3VPN, EVPN, VPLS), the agent MUST discover
the import RTs configured on the target device's VRFs. Routes with wrong RTs are silently
discarded by the PE — no error, no log, just 0 PfxAccepted.

### When to Run

Run RT discovery before injecting routes of these types:
- `flowspec-vpn` (SAFI 134) — needs VRF `ipv4-flowspec` or `ipv6-flowspec` import RT
- `l3vpn` (SAFI 128) — needs VRF `ipv4-unicast` or `ipv6-unicast` import RT
- `evpn` (SAFI 70) — needs VRF or BD import RT
- `vpls` (SAFI 65) — needs BD import RT

NOT needed for plain FlowSpec (SAFI 133), unicast, multicast, labeled-unicast, RT-constraint.

### How to Discover

1. Query device config:
   ```
   run_show_command(device, "show config network-services vrf")
   ```
   Or via MCP: `get_device_config(device, section='network-services')`

2. Parse each VRF block for import RTs per address-family:
   ```
   network-services
    vrf <NAME>
     address-family ipv4-flowspec
      import-vpn
      route-target import <RT>      ← FlowSpec-VPN IPv4 import RT
     address-family ipv6-flowspec
      import-vpn
      route-target import <RT>      ← FlowSpec-VPN IPv6 import RT
     address-family ipv4-unicast
      import-vpn
      route-target import <RT>      ← L3VPN / RT-Redirect target RT
   ```

3. Build a VRF→RT map:
   ```
   VRF ZULU:
     ipv4-flowspec import RT: 300:300, 1234567:301
     ipv6-flowspec import RT: 1234567:401
     ipv4-unicast  import RT: 300:300
   VRF ALPHA:
     ipv4-unicast  import RT: 100:100
     (no flowspec import-vpn configured)
   ```

### Present to User via AskQuestion

After discovery, present the VRF→RT map and ask which VRF to target:

```
AskQuestion: "Which VRF should the routes be imported into?"
Options:
  - "VRF ZULU (ipv4-flowspec RT: 300:300, 1234567:301)"
  - "VRF ALPHA (no flowspec import — will need config)"
  - "Custom RT (I'll specify)"
```

If user picks a VRF with no `import-vpn` for the selected AFI, warn:
"VRF ALPHA has no ipv4-flowspec import-vpn configured. Routes won't be imported.
Configure it first?"

### Use the Discovered RT

Once the user selects a VRF, use its import RT as the `extended-community target:` in the
injected route. Override any hardcoded default.

### RT Matching Rules (learned from device behavior)

| Route type | RT must match VRF's... | Notes |
|---|---|---|
| FlowSpec-VPN IPv4 | `ipv4-flowspec` import RT | Determines which VRF installs the rule |
| FlowSpec-VPN IPv6 | `ipv6-flowspec` import RT | Different RT than IPv4 is common |
| L3VPN | `ipv4-unicast` import RT | Standard VPN import |
| RT-Redirect action | `ipv4-unicast` import RT | NOT flowspec RT (learned 2026-02-22) |

### Scale Injection with Discovered RT

For `bgp_tool.py scale --mode flowspec-vpn-ipv4`, pass the discovered RT:
```
bgp_tool.py scale --mode flowspec-vpn-ipv4 --count 12000 --rt <discovered_rt> --fast
```

Do NOT use hardcoded defaults when the device config has been queried.

---

## AFI/SAFI Reference

### IPv4 FlowSpec (AFI 1, SAFI 133)

**ExaBGP family:** `ipv4 flow`

**Announce (FLAT format ONLY via pipe):**
```
announce flow route destination 10.0.0.0/24 rate-limit 0
announce flow route destination 10.0.0.0/24 source 192.168.1.0/24 rate-limit 1000000
```

**Withdraw:**
```
withdraw flow route destination 10.0.0.0/24
withdraw flow route destination 10.0.0.0/24 source 192.168.1.0/24
```

**Match fields:** `destination`, `source`, `protocol`, `port`, `destination-port`, `source-port`, `tcp-flags`, `icmp-type`, `icmp-code`, `fragment`, `packet-length`, `dscp`

**Action fields:** `rate-limit <bps>`, `discard`, `redirect <rd>`, `mark <dscp>`, `sample`, `terminal`

**WARNING:** match{}/then{} format SILENTLY FAILS via ExaBGP pipe (returns 'error' on exabgp.out, no log). Always use flat format.

---

### IPv4 FlowSpec-VPN (AFI 1, SAFI 134)

**ExaBGP family:** `ipv4 flow-vpn`

**DNOS supported encoding:** Simpson draft only (`draft-simpson-idr-flowspec-redirect`). DNOS does NOT support IETF draft `draft-ietf-idr-flowspec-redirect-ip` extended community.

**Redirect-to-IP (Simpson draft — DNOS supported):**
```
announce flow route rd 1.1.1.1:100 destination 10.0.0.0/24 redirect 10.0.0.254 extended-community [ target:1234567:300 ]
```
- Use **FLAT format** (no `match { }` / `then { }`). ExaBGP API pipe rejects section-style when `rd` is present.
- Use `redirect <ip>` (plain IP, no colon) — ExaBGP encodes as TrafficNextHopSimpson + next-hop in NLRI
- DNOS displays as `flowspec-redirect-ip-nh:<ip>`

**Redirect-to-RT (different behavior — redirect to VRF):**
```
announce flow route rd 1.1.1.1:100 match { destination 10.0.0.0/24; } then { redirect 1234567:300; extended-community [ target:1234567:300 ]; }
```
- Use `redirect asn:nn` (AS:NN format) — redirects traffic to VRF that imports that RT

**Rate-limit / discard:**
```
announce flow route rd 4.4.4.4:101 match { destination 10.0.0.0/24; } then { rate-limit 1000000; extended-community [ target:1234567:101 ]; }
```

**Withdraw:**
```
withdraw flow route rd 4.4.4.4:101 match { destination 10.0.0.0/24; }
```

**Key difference from FlowSpec:** Requires `rd` (route distinguisher) and `extended-community target:` (route target). The RD is typically `<router-id>:<vrf-id>` of the originating PE.

**ExaBGP patch:** The `announce flow route rd ...` format requires a patch to ExaBGP (see DEVELOPMENT_GUIDELINES.md). Without it, the API pipe rejects the `rd` keyword.

---

### IPv6 FlowSpec (AFI 2, SAFI 133)

**ExaBGP family:** `ipv6 flow`

**Announce (FLAT format — ExaBGP auto-detects AFI 2 from IPv6 address):**
```
announce flow route destination 2001:db8::/48 rate-limit 0
```

**Withdraw:**
```
withdraw flow route destination 2001:db8::/48
```

No special keyword needed for IPv6 — ExaBGP detects AFI from the destination address format.

---

### IPv6 FlowSpec-VPN (AFI 2, SAFI 134)

**ExaBGP family:** `ipv6 flow-vpn`

**CRITICAL:** This is SAFI 134 (with rd and rt), NOT SAFI 133. ExaBGP correctly detects AFI 2 from the IPv6 destination prefix even with `rd` keyword present. Previous assumption that `rd` forces AFI 1 was WRONG.

**Announce:**
```
announce flow route rd 1.1.1.1:200 destination 2001:db8::/48 rate-limit 0 extended-community [ target:1234567:401 ]
```

**Withdraw:**
```
withdraw flow route rd 1.1.1.1:200 destination 2001:db8::/48
```

**Default RT:** `1234567:401` (VRF ZULU `ipv6-flowspec` import RT on PE-1). IPv6 import RT is DIFFERENT from IPv4 (`1234567:301`). Always use per-AFI RT.

---

### IPv4 Unicast (AFI 1, SAFI 1)

**ExaBGP family:** `ipv4 unicast`

**Announce:**
```
announce route 10.0.0.0/24 next-hop 100.70.0.32
announce route 10.0.0.0/24 next-hop 100.70.0.32 community [ 65000:100 ]
announce route 10.0.0.0/24 next-hop 100.70.0.32 as-path [ 65200 65300 ]
announce route 10.0.0.0/24 next-hop 100.70.0.32 med 100 local-preference 200
```

**Withdraw:**
```
withdraw route 10.0.0.0/24 next-hop 100.70.0.32
```

---

### L3VPN / VPNv4 (AFI 1, SAFI 128)

**ExaBGP family:** `ipv4 mpls-vpn`

**Announce:**
```
announce route rd 4.4.4.4:101 10.0.0.0/24 next-hop 100.70.0.32 extended-community [ target:1234567:101 ] label [ 100 ]
```

**Withdraw:**
```
withdraw route rd 4.4.4.4:101 10.0.0.0/24 next-hop 100.70.0.32
```

---

### EVPN (AFI 25, SAFI 70)

**ExaBGP family:** `l2vpn evpn`

**Type-2 (MAC/IP):**
```
announce evpn mac-advertisement rd 4.4.4.4:101 esi 00:00:00:00:00:00:00:00:00:00 ethernet-tag 0 label 100 mac 00:11:22:33:44:55 ip 10.0.0.1 next-hop 100.70.0.32 extended-community [ target:1234567:101 ]
```

**Type-5 (IP Prefix):**
```
announce evpn ip-prefix rd 4.4.4.4:101 esi 00:00:00:00:00:00:00:00:00:00 ethernet-tag 0 label 100 10.0.0.0/24 next-hop 100.70.0.32 extended-community [ target:1234567:101 ]
```

---

### IPv4 Multicast (AFI 1, SAFI 2)

**ExaBGP family:** `ipv4 multicast`

**Announce:** (multicast prefix 224.0.0.0/4 auto-detected)
```
announce route 224.0.0.0/4 next-hop 100.70.0.32
```

**Withdraw:**
```
withdraw route 224.0.0.0/4 next-hop 100.70.0.32
```

---

### IPv4 Labeled-Unicast (AFI 1, SAFI 4)

**ExaBGP family:** `ipv4 nlri-mpls`

**Announce:**
```
announce route 10.0.0.0/24 next-hop 100.70.0.32 label [ 100 ]
```

**Withdraw:**
```
withdraw route 10.0.0.0/24 next-hop 100.70.0.32 label [ 100 ]
```

---

### L2VPN VPLS (AFI 25, SAFI 65)

**ExaBGP family:** `l2vpn vpls`

**Announce:**
```
announce vpls rd 4.4.4.4:101 endpoint 1 base 100 offset 0 size 10 next-hop 100.70.0.32 extended-community [ target:1234567:101 ]
```

**Withdraw:**
```
withdraw vpls rd 4.4.4.4:101 endpoint 1 base 100 offset 0 size 10 next-hop 100.70.0.32
```

---

### RT-Constraint (AFI 1, SAFI 132)

**ExaBGP family:** `ipv4 rtc`

**Announce:** (next-hop required)
```
announce route-target 1234567:101 next-hop 100.70.0.32
```

**Withdraw:**
```
withdraw route-target 1234567:101
```

---

## Using route_builder.py

For complex routes, use the helper instead of manually crafting strings:

```bash
# FlowSpec
python3 route_builder.py --type flowspec --match "destination 10.0.0.0/24" --action "rate-limit 1000000"

# FlowSpec-VPN
python3 route_builder.py --type flowspec-vpn --rd 4.4.4.4:101 --match "destination 10.0.0.0/24" --action "rate-limit 1000000" --rt 1234567:101

# FlowSpec-VPN redirect-ip (Simpson draft, DNOS supported)
python3 route_builder.py --type flowspec-vpn --rd 1.1.1.1:100 --rt 1234567:300 --match "destination 10.0.0.0/24; source 16.16.16.0/30" --redirect-ip 10.0.0.254

# Unicast
python3 route_builder.py --type unicast --prefix 10.0.0.0/24 --nexthop 100.70.0.32 --community "65000:100"

# L3VPN
python3 route_builder.py --type l3vpn --rd 4.4.4.4:101 --prefix 10.0.0.0/24 --nexthop 100.70.0.32 --rt 1234567:101 --label 100

# Multicast
python3 route_builder.py --type multicast --prefix 224.0.0.0/4 --nexthop 100.70.0.32

# Labeled-Unicast
python3 route_builder.py --type labeled-unicast --prefix 10.0.0.0/24 --nexthop 100.70.0.32 --label 100

# VPLS
python3 route_builder.py --type vpls --rd 4.4.4.4:101 --nexthop 100.70.0.32 --rt 1234567:101

# RT-Constraint
python3 route_builder.py --type rtc --rt 1234567:101 --nexthop 100.70.0.32

# Bulk: inject many prefixes
python3 route_builder.py --type unicast --prefix-range 10.0.0.0/24-10.0.255.0/24 --nexthop 100.70.0.32
```

## Using bgp_tool.py for Injection

```bash
# Single route
python3 bgp_tool.py inject --session-id <id> --route "announce flow route match { destination 10.0.0.0/24; } then { rate-limit 1000000; }"

# From route_builder output
ROUTE=$(python3 route_builder.py --type flowspec --match "destination 10.0.0.0/24" --action "rate-limit 1000000")
python3 bgp_tool.py inject --session-id <id> --route "$ROUTE"

# Withdraw
python3 bgp_tool.py withdraw --session-id <id> --route "withdraw flow route match { destination 10.0.0.0/24; }"
```

## Verification on DNOS Device

After injection, verify the route arrived:

```
show bgp ipv4 flowspec summary           # FlowSpec
show bgp ipv4 flowspec summary       # FlowSpec-VPN
show bgp ipv4 unicast summary            # Unicast
show bgp ipv4 multicast summary          # Multicast
show bgp ipv4 labeled-unicast summary    # Labeled-Unicast
show bgp vpnv4 unicast summary           # L3VPN
show bgp ipv4 rt-constrain summary       # RT-Constraint
show bgp l2vpn evpn summary              # EVPN
show bgp l2vpn vpls summary              # VPLS
```

For detail on a specific route:
```
show bgp ipv4 flowspec detail
show bgp ipv4 flowspec-vpn vrf <vrf-name> detail
```

## Malformed Routes

For intentional malformation testing, use `malform_builder.py`:

```bash
# Bad marker (all zeros instead of all ones)
python3 malform_builder.py --type bad-marker --target-ip <device_ip> --target-port 179

# Truncated NLRI
python3 malform_builder.py --type truncated-nlri --session-id <id>

# Invalid community encoding
python3 malform_builder.py --type bad-community --route "announce route 10.0.0.0/24 next-hop 100.70.0.32"

# Duplicate attributes in UPDATE
python3 malform_builder.py --type duplicate-attr --session-id <id>
```

**WARNING:** Malformed messages may crash the BGP session. Always have cleanup ready.

---

## Advertised State Tracking (route_parser.py)

Every inject/withdraw is parsed into structured data and tracked in `session.advertised_state`.

### What's Tracked

| Field | Description |
|-------|-------------|
| `summary.total_routes` | Count of currently advertised routes |
| `summary.by_type` | Breakdown by route type (flowspec, flowspec-vpn, unicast, l3vpn, evpn, vpls, rtc) |
| `summary.by_afi_safi` | Breakdown by AFI/SAFI (ipv4 flow, ipv4 flow-vpn, etc.) |
| `summary.prefix_ranges` | Summarized prefix ranges (collapsed for bulk) |
| `summary.all_prefixes` | All prefixes (if <= 20, otherwise count) |
| `summary.rds` | All Route Distinguishers in use |
| `summary.route_targets` | All Route Targets (from extended-community target:) |
| `summary.actions` | All FlowSpec actions (rate-limit, redirect-ip, discard) |
| `routes[]` | Each route parsed: type, afi_safi, rd, match fields, actions, RTs, raw |
| `capabilities` | Session capabilities: families, peer_as, hold_time, multihop, target_device |

### Parsed Route Fields (per route)

```json
{
  "type": "flowspec-vpn",
  "afi_safi": "ipv4 flow-vpn",
  "rd": "1.1.1.1:200",
  "match": {"destination": "99.99.1.0/24"},
  "actions": {"rate-limit": "0"},
  "extended_communities": ["target:1234567:301"],
  "route_targets": ["1234567:301"],
  "injected_at": "2026-02-26T09:31:45+00:00"
}
```

### Supported Route Types

| Type | Parser | Key Fields |
|------|--------|------------|
| `flowspec` | `_parse_flowspec` | destination, source, protocol, port, action |
| `flowspec-vpn` | `_parse_flowspec` | + rd, extended-community, route_targets |
| `unicast` | `_parse_unicast_or_vpn` | prefix, next-hop, community, med, as-path |
| `l3vpn` | `_parse_unicast_or_vpn` | + rd, route_targets, labels |
| `evpn` | `_parse_evpn` | rd, esi, mac, ip, ethernet-tag, labels |
| `vpls` | `_parse_vpls` | rd, endpoint, base, offset, size |
| `rt-constraint` | `_parse_rtc` | route_target, next-hop |

### Usage

```python
import route_parser

# Parse a single route
parsed = route_parser.parse_route("announce flow route rd 1.1.1.1:200 destination 99.99.1.0/24 rate-limit 0 extended-community [ target:1234567:301 ]")

# Build full state from injected_routes list
state = route_parser.build_advertised_state(injected_routes, session_data)

# Incremental update on inject
route_parser.update_state_on_inject(state, route_string, injected_at)

# Incremental update on withdraw
route_parser.update_state_on_withdraw(state, withdraw_string)
```

### Agent Usage in /BGP STATUS

When reporting status, **always read `advertised_state.summary`** to know:
- What types of routes are being advertised
- Which prefixes / IP ranges
- Which RDs and RTs (maps to VRFs)
- What actions (rate-limit, redirect, discard)
- Which AFI/SAFIs are in use vs configured

---

## Scale Injection and Withdrawal (bgp_tool.py scale)

### Injection — Preload Mode (recommended for 1K+ routes)

```bash
# 12K IPv4 FlowSpec-VPN — restarts ExaBGP with routes pre-loaded, returns in ~6s
python3 bgp_tool.py scale --session-id pe_1 --mode flowspec-vpn-ipv4 --count 12000 --rt 1234567:301 --preload

# Then add 4K IPv6 (merges with existing 12K IPv4, restarts with 16K total)
python3 bgp_tool.py scale --session-id pe_1 --mode flowspec-vpn-ipv6 --count 4000 --rt 1234567:401 --preload
```

Multiple `--preload` calls accumulate routes across modes. Each call merges
existing scale injections from other modes + any individual routes, writes the
combined set to a file, and restarts ExaBGP with a process API loader.

### Injection — Pipe Mode (for small batches or incremental adds)

```bash
# Small batches (< 500) — per-route pipe write
python3 bgp_tool.py scale --session-id pe_1 --mode flowspec-vpn-ipv4 --count 100 --rt 1234567:301

# Larger batches — turbo pipe (single os.open, bulk os.write)
python3 bgp_tool.py scale --session-id pe_1 --mode flowspec-vpn-ipv4 --count 100 --rt 1234567:301 --fast
```

### Withdrawal

```bash
# Withdraw ALL scale routes for a mode
python3 bgp_tool.py scale --session-id pe_1 --mode flowspec-vpn-ipv4 --withdraw

# Withdraw all EXCEPT first 10 routes
python3 bgp_tool.py scale --session-id pe_1 --mode flowspec-vpn-ipv4 --withdraw --keep 10
```

### Performance

| Method | User-Visible Rate | Actual ExaBGP Rate | Notes |
|--------|------|------|-------|
| `--preload` (process API) | ~2000 rps | ~184 rps (background) | ExaBGP processes in background; CLI returns in ~6s |
| `inject_pipe_turbo` (single pipe, bulk write) | ~184 rps | ~184 rps (blocking) | CLI blocks until ExaBGP processes all routes |
| Legacy `inject_batch` (per-route pipe write) | ~184 rps | ~184 rps | Same rate; more Python overhead |

**ExaBGP bottleneck:** ExaBGP 5.0.1 uses its full config parser
(`api_flow -> configuration.partial -> tokenizer`) for each pipe command.
Per-route parsing costs ~5.5ms (SAFI 134). This is a fundamental Python-speed
limit. `reactor.speed` and pipe buffer size have no effect. The ONLY way to
avoid this is `--preload` (defers processing to background).

### How Withdrawal Works Internally

1. Reads `scale_injections[]` from session JSON for the specified mode
2. Calls `reconstruct_injected_routes(mode, params, count)` to regenerate exact format originally injected
3. Handles legacy injections (e.g., old SAFI 133 IPv6 routes without `rd` in params)
4. Strips action attributes (rate-limit, redirect, extended-community) via `_announce_to_withdraw`
5. Sends via `inject_pipe_turbo` with single pipe open and bulk writes

### Avoiding Count Mismatches

Individual routes (via `bgp_tool.py inject`) and scale routes can overlap if they use the same prefixes. The device deduplicates, causing fewer unique routes than expected. **Always clean up old individual routes before fresh scale injection.**

### Session State Tracking

Scale injections are tracked in `scale_injections[]` with: mode, builder, params (count, rd, rt, base_prefix, mask, action), injected_count, timestamp. Re-preloading the same mode replaces the old entry (no duplicates). Use `_rebuild_advertised_state()` after mixed inject/withdraw operations to ensure counts stay consistent.

---

## FlowSpec Syslog Verification (MANDATORY)

**After injecting ANY FlowSpec route, check device syslog -- PfxAccepted is NOT reliable.**

PE-4 can accept a FlowSpec rule into BGP RIB (`PfxAccepted: 1`) and even display it in
`show flowspec instance` with correct actions, but SILENTLY REJECT it at the FlowSpec engine
level. The ONLY reliable indicator is the absence of `BGP_FLOWSPEC_UNSUPPORTED_RULE` in syslog.

### Verification sequence (after every FlowSpec inject):

**bgp_tool.py does this automatically (unless --skip-syslog):**
```
1. Pre-check: compare actions against KNOWN_UNSUPPORTED_COMBINATIONS (instant)
2. Inject the route via ExaBGP pipe
3. SSH to device active NCC, run "set logging terminal"
4. Wait 5 seconds, read terminal buffer
5. If output contains BGP_FLOWSPEC_UNSUPPORTED_RULE:
   -> status = "injected_but_rejected"
   -> Report the exact syslog message to user
   -> The "Actions:" field shows what combination was unsupported
6. "unset logging terminal" (cleanup)
7. If no syslog match: rule is genuinely installed and programmed
```

**CRITICAL: DNOS has NO `show logging` command.** Do NOT use `show logging | include ...`.
Correct methods: `show file log routing_engine/system-events.log | include <pattern>` (historical, PREFERRED),
`set logging terminal` (real-time), or SSH to Linux shell `grep /var/log/syslog` (fallback only).

### Known unsupported combinations (SW-206876):

| Actions | Syslog message |
|---------|---------------|
| `redirect to next hop\|redirect to vrf` | Combined redirect-ip (Simpson) + redirect-to-rt in same rule |

### Why PfxAccepted lies:

The BGP RIB accepts the FlowSpec NLRI + extended communities as valid BGP data.
`PfxAccepted` increments because the BGP UPDATE was well-formed. But the NCP/hardware
FlowSpec engine evaluates the ACTION COMBINATION and may reject it as unsupported.
This rejection is only logged via syslog, not reflected in BGP counters.

### Data-plane verification after FlowSpec inject

After confirming the rule is installed (no syslog rejection), verify data-plane effect:
1. **`/SPIRENT stream`** -- create traffic matching the FlowSpec NLRI dst IP + correct VLAN
2. **`/XRAY`** -- DP capture on redirect target interface to verify packets arrive
3. **`show flowspec instance vrf <VRF>`** -- check `Match packet counter` with live traffic
