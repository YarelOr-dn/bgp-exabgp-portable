# BGP Peering Tool - Skill

## When to Use

Activate this skill when the user mentions any of:
- BGP peering, BGP session, BGP neighbor
- Route injection, FlowSpec, FlowSpec-VPN
- ExaBGP, route testing, traffic engineering
- DNAAS inband management, VLAN 999
- Configure device, configure devices, route-policy (new language)
- `/BGP` command

## What This Tool Does

Orchestrates end-to-end BGP peering from this server (100.64.6.134) to any DNAAS-connected DNOS device. Uses a 3-mode wizard: STATUS, SETUP, STOP.

## Command Modes

| User input | Mode | Action |
|------------|------|--------|
| `/BGP` (no args) | STATUS | List active sessions, path, established AFIs, advertised routes |
| `/BGP configure` or `/BGP configure <Device>` | CONFIGURE | Configure devices: route-policy (new language), BGP analysis → where to attach (neighbor, AFI, in/out) |
| `/BGP <Device>` | SETUP | Wizard with AskQuestion at each decision (interface, DNAAS, AFI/SAFI, routes) |
| `/BGP stop` | STOP | Admin-disable (default) or full remove (if user says "remove") |

## Reserved IPs

- **ExaBGP side:** `100.70.0.32` (local-address for BGP stays `100.64.6.134`)
- **Device side:** `100.70.0.205` (default on device .999 sub-interface)
- Both overridable by user

## Architecture

```
Server (100.64.6.134) --[OOB]--> Firewall (100.70.0.254) --[Inband]--> DNAAS Fabric --> Target Device
```

- **OOB network:** 100.64.0.0/20 (server management)
- **Inband network:** 100.70.0.0/24 (VLAN 999, bridge-domain `g_mgmt_v999`)
- **Firewall:** Routes between OOB and inband

## Self-Learning (Like /XRAY)

After each BGP operation: **LEARNING FIRST, then ANSWER.** Mandatory self-audit (learning.md). Stores: `~/.cursor/bgp-reference/learned.json` + `patterns.json`.

## Key Files

| File | Purpose |
| `~/.cursor/commands/BGP.md` | Entry point command (only user-facing BGP command) |
| `~/.cursor/bgp-reference/discovery.md` | DNAAS path discovery |
| `~/.cursor/bgp-reference/orchestration.md` | Config generation, apply, rollback |
| `~/.cursor/bgp-reference/route-injection.md` | AFI/SAFI syntax reference |
| `~/.cursor/bgp-reference/cleanup.md` | Cleanup protocol |
| `~/.cursor/bgp-reference/configure.md` | Configure mode: route-policy, BGP analysis, neighbor/AFI/in-out |
| `~/.cursor/bgp-reference/learning.md` | Self-learning system |
| `~/SCALER/FLOWSPEC_VPN/exabgp/bgp_tool.py` | ExaBGP lifecycle manager |
| `~/SCALER/FLOWSPEC_VPN/exabgp/route_builder.py` | Route string generator |
| `~/SCALER/FLOWSPEC_VPN/exabgp/malform_builder.py` | Malformation constructor |

## Wizard Flow (SETUP mode)

1. **Discover path** (discovery.md): LLDP → DNAAS leaf, bundle IDs. Use AskQuestion if multiple interfaces or multiple DNAAS leaves.
2. **Check BD g_mgmt_v999:** If .999 sub-if already in BD, skip. Else create.
3. **Configure device:** .999 sub-if (100.70.0.205/24), static route 100.64.0.0/20 next-hop 100.70.0.254
4. **AskQuestion AFI/SAFI:** Multi-select from 15 DNOS families + "All"
5. **Generate neighbor config:** Dynamic AFI block per selected family (orchestration.md)
6. **Start ExaBGP**, verify ping, verify session
7. **AskQuestion routes:** Inject routes, verify, or done

## Critical Knowledge

### ExaBGP 5.0.1 Specifics
- **Family names:** `ipv4 flow` (not flowspec), `ipv4 flow-vpn` (not flowspec-vpn)
- **IPv6 flow bug:** Parser crashes on certain extended communities. Avoid unless needed.
- **Named pipes:** Must exist at `/run/exabgp/exabgp.{in,out}` before start
- **Process section:** Use `socat` to read from pipe: `run /usr/bin/socat stdout pipe:/run/exabgp/exabgp.in`
- **Hold-time:** Must match DNOS (default 180s)

### DNOS BGP Configuration
- **Hierarchy:** `protocols bgp <asn> neighbor <ip>`
- **ebgp-multihop:** Required -- peer is not directly connected
- **update-source:** Set to the `.999` sub-interface
- **Static route:** `protocols static address-family ipv4-unicast route ...` (NOT `routing-options`)
- **FlowSpec AFI names:** `ipv4-flowspec`, `ipv4-flowspec-vpn` (in DNOS config)
- **send-community:** Use `community-type both` for extended communities

### Stop vs Remove
- **Default stop:** Admin-disable on DNAAS .999 and device neighbor. Config kept for reuse.
- **Explicit remove:** Only when user says "remove" or "delete". Full cleanup.

### DNAAS Fabric
- **Bridge-domain:** `g_mgmt_v999` carries VLAN 999 across leaves
- **Sub-interface:** `bundle-X.999` with `l2-service enabled` and `vlan-id 999`
- **AC (Attachment Circuit):** Added under `network-services bridge-domain instance g_mgmt_v999`

### VPLS (RFC 4761) Support

ExaBGP can inject and withdraw VPLS pseudowire routes to DNOS devices:

**ExaBGP patch:** `announce vpls-pw` / `withdraw vpls-pw` registered in
`~/.local/lib/python3.10/site-packages/exabgp/reactor/api/command/announce.py`

**bgp_tool.py command:**
```
python3 bgp_tool.py vpls --session-id <id> \
  --rd 3.3.3.3:500 --ve-id 3 --base 800000 --offset 1 --size 8 \
  --next-hop 2.2.2.2 --rt 100:100
```

**VPLS NLRI format (BGP AFI 25, SAFI 65):**
- RD (8 bytes) + VE-ID (2 bytes, "endpoint") + Offset (2 bytes) + Size (2 bytes) + Label base (3 bytes, 20-bit)

**L2Info Extended Community (0x800A) -- DNOS bit mapping:**
| Bit | Hex | DNOS flag |
|-----|-----|-----------|
| 1   | 0x02 | C (control-word) |
| 2   | 0x04 | Fr (FAT-receive) |
| 3   | 0x08 | Fs (FAT-send) |

DNOS Seamless-integration requires `C` flag (0x02) to match. Without it: "Control word mismatch".

**PW establishment requirements:**
1. RT must match the EVPN instance import-l2vpn-vpls RT
2. VE-ID must be within the receiving PE's label block size
3. Offset must be 1 (DNOS convention)
4. Next-hop must be MPLS-resolvable (in IGP/LDP). If unreachable, route is `U*` (not best)
5. L2Info EC control byte 0x02 for control-word match
6. Encapsulation type 0x13 (Ethernet VLAN)

**Direct pipe syntax (without bgp_tool.py):**
```
echo "announce vpls-pw rd 3.3.3.3:500 endpoint 3 base 800000 offset 1 size 8 next-hop 2.2.2.2 extended-community [ target:100:100 0x800A130200000000 ]" > /run/exabgp/exabgp.in
```

## Reference

For detailed knowledge, see `REFERENCE.md` in this skill directory.
