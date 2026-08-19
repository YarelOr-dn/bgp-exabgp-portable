# BGP Peering Tool - Reference

Detailed technical reference for the BGP peering tool. Read SKILL.md first for overview.

---

## ExaBGP 5.0.1 Deep Reference

### Configuration Structure

```ini
process announce-routes {
    run /usr/bin/socat stdout pipe:/run/exabgp/exabgp.in;
    encoder text;
}

neighbor <device_ip> {
    router-id <exabgp_ip>;
    local-address <server_ip>;
    local-as <exabgp_as>;
    peer-as <device_as>;
    hold-time 180;
    multihop 10;

    family {
        ipv4 flow;
        ipv4 flow-vpn;
    }

    api {
        processes [ announce-routes ];
    }
}
```

### Family Name Mapping

| Protocol | ExaBGP Family Name | DNOS AFI Name |
|----------|-------------------|---------------|
| IPv4 Unicast | `ipv4 unicast` | `ipv4-unicast` |
| IPv4 FlowSpec | `ipv4 flow` | `ipv4-flowspec` |
| IPv4 FlowSpec-VPN | `ipv4 flow-vpn` | `ipv4-flowspec-vpn` |
| L3VPN (VPNv4) | `ipv4 mpls-vpn` | `vpnv4-unicast` |
| EVPN | `l2vpn evpn` | `l2vpn-evpn` |
| RT-Constraint | `ipv4 rtc` | `ipv4-rt-constraint` |
| IPv6 Unicast | `ipv6 unicast` | `ipv6-unicast` |
| IPv6 FlowSpec | `ipv6 flow` | `ipv6-flowspec` (AVOID - parser bug) |

### Named Pipe Setup

```bash
sudo mkdir -p /run/exabgp
sudo mkfifo /run/exabgp/exabgp.in /run/exabgp/exabgp.out 2>/dev/null
sudo chmod 777 /run/exabgp/exabgp.in /run/exabgp/exabgp.out
```

### Injecting Routes via Pipe

```bash
# Write to named pipe (ExaBGP reads from it)
echo "announce flow route match { destination 10.0.0.0/24; } then { rate-limit 1000000; }" > /run/exabgp/exabgp.in
```

### Common ExaBGP Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `family not configured` | Route AFI/SAFI not in family block | Add the family |
| `connection refused` | Peer not listening on port 179 | Check BGP config on device |
| `hold-time expired` | Keepalive mismatch | Match hold-time (180s) |
| `bad NLRI` | Malformed route string | Check syntax |
| `ipv6 parser crash` | ExaBGP 5.0.1 bug with IPv6 flow | Avoid ipv6 flow families |

---

## DNAAS Architecture Reference

### Network Layout

```
                    ┌─────────────┐
                    │   Server    │
                    │ 100.64.6.134│
                    └──────┬──────┘
                           │ OOB (100.64.0.0/20)
                    ┌──────┴──────┐
                    │  Firewall   │
                    │100.70.0.254 │
                    └──────┬──────┘
                           │ Inband (100.70.0.0/24, VLAN 999)
                    ┌──────┴──────┐
                    │ DNAAS Spine │
                    └──┬──────┬───┘
                 ┌─────┘      └─────┐
          ┌──────┴──────┐   ┌───────┴─────┐
          │ DNAAS Leaf  │   │ DNAAS Leaf  │
          │   B15       │   │   B16       │
          └──────┬──────┘   └───────┬─────┘
                 │                  │
          ┌──────┴──────┐   ┌───────┴─────┐
          │   PE-4      │   │   PE-1      │
          │ Target Dev  │   │             │
          └─────────────┘   └─────────────┘
```

### Bridge-Domain Configuration (DNAAS Leaf)

The bridge-domain `g_mgmt_v999` exists on all DNAAS leaves. We add an AC (Attachment Circuit) for the target device's bundle:

```
interfaces
  bundle-X.999
    admin-state enabled
    description "inband-v999-to-PE-4"
    l2-service enabled
    vlan-id 999
  !
!
network-services
  bridge-domain
    instance g_mgmt_v999
      interface bundle-X.999
      !
    !
  !
!
```

### Target Device Configuration

```
interfaces
  bundle-Y.999
    admin-state enabled
    description "Inband mgmt for BGP peering"
    ipv4-address 100.70.0.201/24
    vlan-id 999
  !
!
protocols
  static
    address-family ipv4-unicast
      route 100.64.0.0/20
        next-hop 100.70.0.254
      !
    !
  !
  bgp <asn>
    neighbor 100.64.6.134
      remote-as 65200
      admin-state enabled
      update-source bundle-Y.999
      ebgp-multihop 10
      local-as <peer_as> type no-prepend
      address-family ipv4-flowspec
        send-community community-type both
        soft-reconfiguration inbound
      !
      address-family ipv4-flowspec-vpn
        send-community community-type both
        soft-reconfiguration inbound
      !
    !
  !
!
```

---

## IP Address Conventions

| Entity | IP | Notes |
|--------|-----|-------|
| Server (OOB) | 100.64.6.134 | ExaBGP `local-address` |
| ExaBGP (Inband) | 100.70.0.32 | User-reserved, default |
| Firewall gateway | 100.70.0.254 | Routes OOB <-> Inband |
| Device inband | 100.70.0.200-250 | Scanned, first free |
| OOB network | 100.64.0.0/20 | Server management |
| Inband network | 100.70.0.0/24 | VLAN 999 |

---

## Session Lifecycle States

```
INIT -> DISCOVERING -> CONFIGURING -> VALIDATING -> APPLYING -> PEERING -> ACTIVE -> CLOSING -> CLOSED
                                                                    |
                                                                    v
                                                                  ERROR
```

- **INIT:** Session created, parsing user intent
- **DISCOVERING:** Running DNAAS path discovery
- **CONFIGURING:** Generating configs for DNAAS leaf, target device, ExaBGP
- **VALIDATING:** Running `validate_config()` on both devices
- **APPLYING:** SSH applying configs (DNAAS leaf first, then device)
- **PEERING:** ExaBGP started, waiting for BGP ESTABLISHED
- **ACTIVE:** Session up, ready for route injection
- **CLOSING:** Running cleanup sequence
- **CLOSED:** All config rolled back, ExaBGP stopped
- **ERROR:** Something failed; partial rollback may be needed

---

## Known Issues and Workarounds

### From Session Discoveries

1. **ebgp-multihop required:** The peering is not directly connected (goes through firewall). Without `ebgp-multihop`, DNOS rejects the session with "eBGP peer not directly connected."

2. **Static route syntax:** DNOS uses `protocols static address-family ipv4-unicast route X/Y next-hop Z` -- NOT `routing-options static`. The `routing-options` hierarchy does not exist in DNOS.

3. **ExaBGP IPv6 flow parser bug:** ExaBGP 5.0.1 crashes when parsing certain IPv6 FlowSpec extended communities. Avoid `ipv6 flow` and `ipv6 flow-vpn` families unless explicitly needed.

4. **Hold-time defaults:** DNOS defaults to 180s hold-time. ExaBGP defaults to 180s too, but explicitly set it to be safe.

5. **ExaBGP family names:** Use `flow` not `flowspec`, `flow-vpn` not `flowspec-vpn`. This is a common mistake.

6. **Named pipes must pre-exist:** ExaBGP won't create `/run/exabgp/exabgp.in` -- you must create them before starting.

7. **local-as with no-prepend:** When the ExaBGP AS (65200) differs from the device's BGP AS, use `local-as <peer_as> type no-prepend` on the device so it accepts the session without prepending its own AS.

8. **Route target encoding:** For FlowSpec-VPN, the RT extended community must be `target:ASN:ID` format. 4-byte ASN uses `target:ASN4:ID` format.
