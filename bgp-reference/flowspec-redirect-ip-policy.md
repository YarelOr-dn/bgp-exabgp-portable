# FlowSpec-VPN: Allow Only redirect-ip (BGP Routing Policy)

When other FlowSpec rules block the redirect-ip rule from installing, use a BGP routing policy to deny blocking rules and allow only redirect-ip.

## DNOS FlowSpec Redirect Types

| Type | Encoding | DNOS support | Policy match |
|------|----------|--------------|--------------|
| **redirect-ip** (Simpson) | Next-hop in MP_REACH_NLRI (sub-type 0x08) | Supported | **CAN match** `extcommunity in ["flowspec-redirect-ip-nh"]` |
| **redirect-vrf-rt** (redirect-to-VRF) | flowspec-redirect-vrf-rt ext-community (0x08) | Supported | CAN match `extcommunity in ["flowspec-redirect-vrf-rt"]` |
| redirect-to-ip (IETF 0x0c) | Extended community | NOT supported | N/A |

**Key insight:** Simpson redirect-ip uses next-hop in NLRI (not 0x0c ext-community), but DNOS internally represents it as extended community `flowspec-redirect-ip-nh:<ip>` in `show bgp flowspec`. The new RPL can match on it.

## Validated Config (commit-check PASSED on RR-SA-2)

### Route-policy (new RPL, one-liner)

```
routing-policy
  route-policy ALLOW_REDIRECT_IP "route-policy ALLOW_REDIRECT_IP() { if (extcommunity in [\"flowspec-redirect-ip-nh\"]) { return allow } return deny }"
!
```

**Syntax rules (validated):**
- `extcommunity in [\"...\"]` — **must use list `[...]` syntax**, bare string fails ("Operator 'in' requires a list or named list")
- Policy body is a quoted string after the policy name
- `()` required on policy name even with no parameters

### BGP attach

```
protocols
  bgp <asn>
    neighbor <ip>
      address-family ipv4-flowspec-vpn
        policy ALLOW_REDIRECT_IP() in
      !
    !
  !
!
```

**Syntax rules (validated):**
- `policy NAME() in` / `policy NAME() out` — correct DNOS syntax
- `import policy-in` — **REJECTED** ("Unknown word: import")
- `export policy-out` — **REJECTED**

### Full validated config (copy-paste ready)

```
routing-policy
  route-policy ALLOW_REDIRECT_IP "route-policy ALLOW_REDIRECT_IP() { if (extcommunity in [\"flowspec-redirect-ip-nh\"]) { return allow } return deny }"
!
protocols
  bgp <asn>
    neighbor <RR_IP>
      address-family ipv4-flowspec-vpn
        policy ALLOW_REDIRECT_IP() in
      !
    !
  !
!
```

## Validation Results (RR-SA-2, 2026-02-16)

| Test | Config | Result |
|------|--------|--------|
| Policy with `extcommunity in [\"flowspec-redirect-ip-nh\"]` | route-policy one-liner | PASSED |
| Policy with bare string `extcommunity in "..."` | route-policy one-liner | FAILED — "requires a list or named list" |
| BGP attach `policy NAME() in` | address-family ipv4-flowspec-vpn | PASSED |
| BGP attach `import policy-in NAME` | address-family ipv4-flowspec-vpn | FAILED — "Unknown word: import" |
| Full config (policy + BGP attach) | routing-policy + protocols | PASSED |

## ExaBGP Encoding (redirect-ip)

`route_builder.py --redirect-ip 10.0.0.254` produces: `redirect 10.0.0.254` (plain IP)
- ExaBGP encodes as TrafficNextHopSimpson (sub-type 0x08 + next-hop in NLRI)
- DNOS accepts and displays as `flowspec-redirect-ip-nh:10.0.0.254`

## Redirect-ip route to lo10 (VRF ALPHA)

```
announce flow route rd 1.1.1.1:100 match { destination 10.0.0.0/24; source 16.16.16.0/30; } then { redirect 10.0.0.254; extended-community [ target:1234567:300 ]; }
```

10.0.0.254 = lo10 in VRF ALPHA. Use `redirect <ip>` (Simpson draft), NOT `redirect asn:nn` (redirect-to-rt).
