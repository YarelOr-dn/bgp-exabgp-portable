# BGP Tool - Device Configuration Mode

When user says "configure", "configure device", "configure devices", or `/BGP configure [Device(s)]`, run the CONFIGURE wizard. This mode adds route-policy (new language) and other BGP config to devices, with correct analysis to determine where to attach policies.

## Triggers

- `/BGP configure` — configure device(s); use AskQuestion to pick device(s)
- `/BGP configure <Device>` — configure single device
- `/BGP configure <Device1> <Device2> ...` — configure multiple devices
- User says "configure device X" or "configure RR-SA-2" in BGP context

---

## Step 1: Resolve Device(s)

1. Use `list_devices` (network-mapper) to get available devices
2. Parse device name(s) from user input
3. **If no device specified:** Use AskQuestion: "Which device(s) to configure?" (allow_multiple=true), options = device names from list_devices
4. **If one device:** Validate it exists in list_devices
5. **If multiple devices:** Validate each, then process in sequence (or AskQuestion: "Configure all at once or one by one?")

---

## Step 2: BGP Analysis (per device)

For each target device, analyze BGP config to understand topology:

1. **Get config:** `get_device_config(device, section='protocols')` or full config
2. **Parse BGP section:** Extract:
   - `protocols bgp <asn>` — local ASN
   - For each `neighbor <ip>`:
     - remote-as
     - address-family blocks: `ipv4-unicast`, `ipv4-flowspec-vpn`, `l2vpn-evpn`, etc.
     - Existing `import policy-in` / `export policy-out` per address-family
3. **Build attachment map:** For each neighbor + AFI, record:
   - neighbor IP, remote-as
   - AFIs with admin-state enabled
   - Current policy-in / policy-out (if any)
4. **Optional:** `run_show_command(device, "show bgp summary")` to confirm which AFIs are Established

---

## Step 3: AskQuestion — What to Configure?

Use AskQuestion: "What would you like to configure?" (allow_multiple=true)

Options:
- **Add route-policy** — Go to Step 4 (route-policy wizard)
- **Modify BGP neighbor** — (future: add AFI, change timers, etc.)
- **Other** — (future: prefix-list, community-list, etc.)

---

## Step 4: Route-Policy Wizard (New Language)

### 4a. Policy Type

Use AskQuestion: "Which route-policy to add?"

Options:
- **ALLOW_REDIRECT_IP** — FlowSpec-VPN: allow only redirect-ip (Simpson `flowspec-redirect-ip-nh`), deny others. See flowspec-redirect-ip-policy.md. Validated on device.
- **Custom** — User provides policy name and body (one-liner format)

If Custom: Prompt for policy name and body. Body must be one-liner. DNOS format: `routing-policy route-policy NAME "route-policy NAME() { ... }"`. BGP attach: `policy NAME() in` / `policy NAME() out`. See dnos-route-policy-new-language.mdc.

### 4b. Where to Attach

Use the **BGP analysis** from Step 2 to build options.

Use AskQuestion: "Where to attach the policy?" (single select or allow_multiple depending on context)

**Format each option:** `Device: neighbor <ip> (remote-as X) — address-family <afi> — import` or `— export`

Example options:
- `RR-SA-2: neighbor 2.2.2.2 (remote-as 65001) — ipv4-flowspec-vpn — import`
- `RR-SA-2: neighbor 100.64.6.134 (remote-as 65200) — ipv4-unicast — export`

**Import vs Export:**
- **import (policy-in):** Filters routes **received from** that neighbor. Use when you want to filter what comes in (e.g. allow only redirect-ip FlowSpec from RR).
- **export (policy-out):** Filters routes **sent to** that neighbor. Use when you want to control what you advertise.

**FlowSpec redirect-ip:** Attach `ALLOW_REDIRECT_IP` as `policy ALLOW_REDIRECT_IP() in` on the neighbor that **sends** FlowSpec-VPN routes (typically the RR). AFI: `ipv4-flowspec-vpn`. Use `policy NAME() in` (NOT `import policy-in` — rejected by DNOS).

### 4c. Generate Config

1. **Routing-policy block** (DNOS format from Jira SW-240559):
```
routing-policy route-policy POLICY_NAME "route-policy POLICY_NAME() { if (condition) { return allow } return deny }"
```

2. **BGP neighbor attach** (DNOS format from Jira SW-240510):
```
protocols
  bgp <asn>
    neighbor <ip>
      address-family <afi>
        policy POLICY_NAME() in
      !
    !
  !
!
```

Or for export: `policy POLICY_NAME() out` (NOT `import policy-in` / `export policy-out`)

3. **Validate:** `validate_config(device, config_text)`
4. **Apply:** Via network-mapper or config_pusher (paste, file upload, load merge)
5. **Store rollback** if applicable

---

## Step 5: Confirm and Apply

1. Show user the generated config (routing-policy + BGP attach)
2. Use AskQuestion: "Apply this config?" Options: Yes, Edit, Cancel
3. If Yes: validate, apply, report success
4. If multiple devices: repeat for each or batch if user prefers

---

## Reference Files

| File | When to Read |
|------|--------------|
| `flowspec-redirect-ip-policy.md` | When adding ALLOW_REDIRECT_IP_ONLY |
| `dnos-route-policy-new-language.mdc` | When generating any route-policy (one-liner format) |
| `orchestration.md` | For config structure, validation |

---

## Summary: Policy Placement Logic

| Policy | Typical attachment | Direction | AFI |
|--------|--------------------|-----------|-----|
| ALLOW_REDIRECT_IP_ONLY | Neighbor that sends FlowSpec (RR, ExaBGP) | import (policy-in) | ipv4-flowspec-vpn |
| Prefix filter | Neighbor receiving/sending prefixes | import or export | ipv4-unicast, ipv4-vpn, etc. |
| Community set | Outbound to peer | export (policy-out) | as needed |

**Never assume.** Use BGP analysis + AskQuestion when multiple neighbors or AFIs exist.

---

## Step 6: Route Injection — Topology-Aware Peering

When the user configures a policy on a PE and wants to test it by advertising routes:

### Understand the Topology

```
ExaBGP  ──BGP──►  RR-SA-2  ──iBGP reflect──►  PE-1
                                                 ↓
                                          policy ALLOW_REDIRECT_IP() in
                                                 ↓
                                          VRF ALPHA (flowspec installed)
```

- **Policy is on PE-1** (inbound from RR neighbor)
- **Routes must come from the RR**, not directly from ExaBGP to PE-1
- **ExaBGP must peer with the RR** so routes are reflected to PE-1

### Peering Logic

| Policy on | Policy direction | Policy filters from | ExaBGP should peer with |
|-----------|-----------------|---------------------|------------------------|
| PE-1 | `in` on neighbor RR | Routes from RR | **RR** (routes reflect to PE-1) |
| PE-1 | `out` on neighbor RR | Routes PE-1 sends to RR | **RR** (to see filtered output) |
| RR | `in` on neighbor ExaBGP | Routes from ExaBGP | **RR** (direct) |

### Rule

**When configuring `policy in` on PE-X toward RR-Y:**
1. ExaBGP peers with **RR-Y** (not PE-X)
2. ExaBGP advertises the route to RR-Y
3. RR-Y reflects to PE-X
4. PE-X's `policy in` filters the route

**Do NOT peer ExaBGP directly with PE-X** unless PE-X has a direct ExaBGP neighbor configured. If the policy filters routes from the RR, the test route must come from the RR.

### Implementation

When `/BGP configure` applies a policy + advertises a route:
1. Identify which neighbor the policy filters from (Step 2 BGP analysis)
2. Check if that neighbor is an RR (same ASN = iBGP, route-reflector-client check)
3. If RR: ensure ExaBGP session peers with that RR, advertise through it
4. If direct eBGP peer: ExaBGP can peer directly with the device
