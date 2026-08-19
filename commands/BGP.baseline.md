---
description: BGP peering and route injection via ExaBGP
---
# BGP - Peering and Route Injection Tool

Orchestrate end-to-end BGP peering from this server to any DNAAS-connected DNOS device. Uses a wizard flow with AskQuestion at every decision point.

## ExaBGP Persistence (CRITICAL)

**ExaBGP runs indefinitely on this server until the user explicitly runs `/BGP stop`.** No timeout, no auto-stop. Do NOT run `bgp_tool.py start` for a different session when the user has an active session they want to keep — the pre-check returns early when session exists and is alive.

**NEVER clear BGP or bring down ExaBGP** unless the user explicitly says "kill", "stop", "bring down", or "clear". Do NOT run `clear bgp neighbor` or otherwise reset the session. Keep BGP always up.

**Session ID convention:** Use stable per-device: `device_name.lower().replace("-","_")` (e.g. RR-SA-2 → `rr_sa2`, PE-4 → `pe_4`). Never use arbitrary IDs like `rr2_clean` or `rr2_redirect` — they cause session churn and kill the user's running session.

**Reset a storming / contended peering → ONLY the DUT session valid:** if the DUT/RR neighbor is stuck in `Connect`/`Active` (its `Up/Down` timer never resets) while `bgp_tool` claims "established", the TRUTH is the DUT (`show bgp l2vpn evpn summary | include <exabgp-ip>`), not ExaBGP's cached state. Causes: (1) a 2nd `active` ExaBGP session with the WRONG `local-as` grabbing the single `local-address→peer:179` socket (RR-SA-2 expects remote-as 65200 → ExaBGP local-as 65200); (2) the cron `bgp_watchdog.py` reviving stale/wrong `active` sessions; (3) the `:179` iptables guard closed; (4) a **FortiGate IDS** in the OOB↔RR path resetting the storming TCP (watchdog log: `[STORM] ... FortiGate IDS`). Fix: close every non-target session (`stop --confirm-kill` → file `closed` so the watchdog drops it), ensure only the target is `active` with matching AS, clean `stop`+`start` (reopens the guard: `Port 179 guard: OPEN` + `BGP TCP ESTABLISHED`), then VERIFY on the DUT (State `Established`, timer reset). If it stays `Connect` with the timer not resetting → path/IDS blocked (infra allowlist needed); stop the session, don't storm. Full procedure: skill `bgp-tool` → "Reset a storming / contended peering".

## Reserved IPs (fixed defaults)

- **ExaBGP side:** `100.70.0.32` (server in mgmt VLAN; local-address for BGP stays `100.64.6.134`)
- **Device side:** `100.70.0.205` (default IP on device .999 sub-interface)
- Both overridable if user specifies another address

## DNOS Command Syntax Validation (MANDATORY)

Before running ANY `run_show_command` or generating ANY device config you haven't used before,
validate it via Network Mapper CLI documentation tools:

| Tool | When to use |
|---|---|
| `search_cli_docs(keyword)` | Verify a show command exists, find correct subcommands |
| `get_cli_doc_section(doc, term)` | Get full syntax for config hierarchies (BGP, VRF, interfaces) |
| `get_cli_guidelines()` | Get style rules and known error patterns before `validate_config` |

**When to validate:**
- STATUS mode: any show command not in the hardcoded tables (e.g., `show bgp summary` is known-good, but `show bgp instance vrf <VRF> summary` should be validated first time)
- SETUP mode: all config blocks before `validate_config` -- use `get_cli_doc_section("NETWORK_PROTOCOLS", "bgp")` for BGP syntax
- CONFIGURE mode: route-policy syntax -- use `search_cli_docs("route-policy")` to verify
- Any command with dynamic arguments (VRF names, neighbor IPs, AFI names)

**For dynamic arguments:** check `~/.cursor/dnos-cli-completions.json` first.
**Full protocol:** `~/.cursor/rules/dnos-cli-completion-protocol.mdc`

---

## Required Context

- **Python tool:** `~/SCALER/FLOWSPEC_VPN/exabgp/bgp_tool.py`
- **Route builder:** `~/SCALER/FLOWSPEC_VPN/exabgp/route_builder.py`
- **ExaBGP:** 5.0.1 (pip-installed)
- **Skill:** `/home/dn/.cursor/skills/bgp-peering-tool/SKILL.md`
- **Network Mapper MCP:** `list_devices`, `get_device_lldp`, `get_device_interfaces`, `get_device_config`, `validate_config`, `run_show_command`, `search_cli_docs`, `get_cli_doc_section`, `get_cli_guidelines`
- **State:** `~/SCALER/FLOWSPEC_VPN/exabgp/sessions/`, `~/SCALER/FLOWSPEC_VPN/exabgp/learned/`
- **Firewall gateway:** `100.70.0.254` (routes OOB 100.64.0.0/20 to inband 100.70.0.0/24)

### MCP dynamic handoff (`dnos_agent_handoff`) -- light touch

**dnos-config** MCP. Call at **SETUP/trigger start**, on **blocker** (session unreachable, FortiGate quarantine), when **routes/evidence** paths are produced, and **final next action**. Does **not** replace ExaBGP session state on disk under `~/SCALER/FLOWSPEC_VPN/exabgp/sessions/`. Never use MCP handoff as an excuse to stop or restart BGP unless the user explicitly asks (workspace BGP protection rules).

---

## Device Resolution: Network Mapper + SCALER DB Fallback

When resolving a device name, use this priority order:

1. **Network Mapper `list_devices`** -- primary source. Match by partial name.
2. **SCALER DB fallback** -- if not found in Network Mapper, check `~/SCALER/db/devices.json`.
   Parse the `devices[]` array and match by `hostname` (partial, case-insensitive).
   If found, use the `ip` field to auto-discover into Network Mapper:
   `discover_device(hostname=<ip>)`, then proceed with the newly discovered device.
3. **Direct IP** -- if user provides an IP address directly, use `discover_device(hostname=<ip>)`.

**SCALER DB format** (`~/SCALER/db/devices.json`):
```json
{
  "devices": [
    {"id": "pe1", "hostname": "PE-1", "ip": "100.64.6.233", "username": "dnroot", "password": "..."}
  ]
}
```

**Why this matters:** Devices may exist in the SCALER database (discovered via the SCALER wizard)
but not yet in Network Mapper. This fallback prevents "device not found" errors and auto-discovers
the device into Network Mapper for future use.

**When to use:** Every device resolution step in SETUP, CONFIGURE, and STATUS modes.

---

## Command Modes

Parse user input to determine mode:

| User input | Mode | Action |
|------------|------|--------|
| `/BGP` (no args) | STATUS | Show current session status, path, established AFIs, advertised routes |
| `/BGP stop` | STOP | Stop ExaBGP locally, admin-disable on DNAAS and device (see cleanup.md) |
| `/BGP configure` or `/BGP configure <Device>` | CONFIGURE | Configure devices: route-policy (new language), BGP analysis to determine where to attach (neighbor, AFI, in/out) |
| `/BGP <Device>` | SETUP | Run setup wizard (or resume if session exists) |

---

## Mode 1: `/BGP` (STATUS)

When user issues `/BGP` with no device name and no "stop":

1. Run `python3 bgp_tool.py list` to get all sessions
2. For each active session (status=active, exabgp_alive=true):
   - Load session JSON
   - Report: session_id, target_device, dnaas_leaf, device_ip (100.70.0.205), path (Server -> Firewall -> DNAAS leaf -> Device)
   - Run `run_show_command(device, "show bgp summary")` to get established AFI/SAFIs
   - Report: selected_afis from session, injected_routes count and list
3. If no active sessions: report "No active BGP session. Use /BGP <Device> to start."
4. Format output clearly: path diagram, established families, advertised routes

### STATUS Table Formatting (Up/Down Clarity)

The raw `Up/Down` field from `show bgp summary` is ambiguous -- it shows a duration but
doesn't say whether the session is UP or DOWN. The `/BGP` status table MUST make this explicit.

**Rules for the status table:**

| BGP State | Status Column | Duration Column | Example |
|-----------|---------------|-----------------|---------|
| `Established` | **UP** | Uptime: `HH:MM:SS` or `XdYhZm` | UP / 01:49:25 |
| `Idle (Admin)` | **DOWN (admin)** | Since disabled: duration or `--` if `never` | DOWN (admin) / 18:54:31 |
| `Idle` | **DOWN** | Down for: `HH:MM:SS` | DOWN / 00:05:12 |
| `Connect` | **DOWN** | Down for: `HH:MM:SS` | DOWN / 00:02:30 |
| `Active` | **DOWN** | Down for: `HH:MM:SS` or `never` if never connected | DOWN / never connected |
| `OpenSent` | **CONNECTING** | Attempting for: `HH:MM:SS` | CONNECTING / 00:00:05 |
| `OpenConfirm` | **CONNECTING** | Attempting for: `HH:MM:SS` | CONNECTING / 00:00:02 |
| `Clearing` | **DOWN** | Clearing for: `HH:MM:SS` | DOWN / 00:00:01 |

**Table format:**

```
| Session | Device | BGP State | Status | Duration | Adv | Rcv | Queued |
|---------|--------|-----------|--------|----------|-----|-----|--------|
| pe_4    | PE-4   | Established    | UP           | 01:49:25   | 0 | 0 | 0 |
| pe_1    | PE-1   | Idle (Admin)   | DOWN (admin) | 18:54:31   | 0 | 0 | 1 |
| rrsa2   | RR-SA-2| Idle (Admin)   | DOWN (admin) | --         | 0 | 0 | 3 |
```

**Key rules:**
- **Status column is mandatory** -- never show raw `Up/Down` without the UP/DOWN qualifier
- **`never`** from device output → show as `--` in Duration column (never connected)
- **Duration meaning changes by status**: UP = uptime, DOWN = time since last state change
- **Queued column** = routes injected locally via ExaBGP but not delivered (session is down)

---

## Mode 2: `/BGP <Device>` (SETUP wizard)

All questions use **AskQuestion** tool. Never assume; always ask when multiple options exist.

### Pre-check

1. Run `python3 ~/.cursor/tools/prune_learning.py --command bgp --check` -- if exit code 1, run `--sync-only` first
2. Read `~/.cursor/bgp-reference/learned_index.md` first, then `~/.cursor/bgp-reference/learning.md`
2. Parse device name from user input (e.g. "RR-SA-2", "PE-4")
3. Check for existing active session for this device: `bgp_tool.py list` + load session JSON
4. **If session exists and ExaBGP alive:** Skip to Step 7 (post-establishment route wizard)

### Step 1: Discover path (discovery.md)

1. Use `list_devices` to match user's device name
2. Use `get_device_lldp(device)` to find DNAAS connections
3. **Multiple physical interfaces to DNAAS?** Use AskQuestion:
   - "Device X has multiple interfaces connecting to DNAAS. Which one to use for .999 sub-interface?"
   - Options: e.g. ["bundle-100 (via ge400-0/0/0 to DNAAS-LEAF-B15)", "bundle-200 (via ge800-0/0/0 to DNAAS-LEAF-B16)"]
4. **Only one interface?** Auto-select, no question
5. **Multiple DNAAS leaves connected?** Use AskQuestion:
   - "Device X connects to multiple DNAAS leaves. Which one?"
   - Options: list leaf names + bundle IDs
6. **Only one DNAAS?** Auto-select, no question
7. Store: target_device, dnaas_leaf, leaf_bundle, device_bundle

### Step 2: Check DNAAS bridge-domain g_mgmt_v999

1. Use `get_device_config(dnaas_leaf)` or `run_show_command(dnaas_leaf, "show config network-services bridge-domain instance g_mgmt_v999")`
2. Check if `bundle-X.999` (leaf bundle facing device) is already in the bridge-domain
3. **If already in BD:** Skip DNAAS config, continue to Step 3
4. **If not in BD:** Generate DNAAS config (orchestration.md), validate, apply

### Step 3: Configure device .999 sub-interface and static route

1. Use device IP `100.70.0.205` (reserved) unless user specified another
2. Generate config: bundle-Y.999 with ipv4-address 100.70.0.205/24, static route 100.64.0.0/20 next-hop 100.70.0.254
3. Check if bundle-Y.999 already exists on device; if yes and has IP, verify no conflict
4. Validate with `validate_config(device, config_text)`
5. Apply via SSH, store rollback in session

### Step 4: AskQuestion - AFI/SAFI selection

Use AskQuestion: "Which address families to enable on the BGP neighbor?" (allow_multiple=true)

Options (15 DNOS families + All):
- ipv4-unicast, ipv6-unicast
- ipv4-flowspec, ipv4-flowspec-vpn, ipv6-flowspec, ipv6-flowspec-vpn
- ipv4-vpn, ipv6-vpn
- ipv4-labeled-unicast, ipv6-labeled-unicast
- ipv4-multicast
- ipv4-rt-constrains
- l2vpn-evpn, l2vpn-vpls
- link-state
- **All** (select all 15)

Store selected_afis in session.

### Step 5: Generate and apply BGP neighbor config

1. Read `~/.cursor/bgp-reference/orchestration.md` for dynamic AFI template
2. Generate neighbor config: each selected AFI gets `address-family <afi>` with `send-community community-type both` and `soft-reconfiguration inbound` and `admin-state enabled`
3. Neighbor IP: 100.64.6.134 (ExaBGP peer - server)
4. Validate, apply, store rollback

### Step 6: Start ExaBGP and verify

1. Generate ExaBGP config with device_ip=100.70.0.205, families from DNOS_TO_EXABGP mapping
2. Run `bgp_tool.py start --config <path> --session-id <id>` where **session_id** = device-based stable ID (e.g. RR-SA-2 → `rr_sa2`, PE-4 → `pe_4`)
3. Verify ping from server to 100.70.0.205
4. Run `run_show_command(device, "show bgp summary")` to confirm Established

### Step 7: Post-establishment route wizard (AskQuestion)

Use AskQuestion: "Session established. What would you like to do?"

Options:
- "Inject routes" -> proceed to Step 7a (RT discovery) then route injection
- "Just verify session" -> Show show bgp summary output
- "Done for now" -> End wizard, session stays open

### Step 7a: VPN RT Discovery (MANDATORY before VPN route injection)

**When user picks "Inject routes" and the route type is VPN (FlowSpec-VPN, L3VPN, EVPN, VPLS):**

1. **Query device VRF config:**
   ```
   run_show_command(device, "show config network-services vrf")
   ```
   Or: `get_device_config(device, section='network-services')`

2. **Parse import RTs per VRF per address-family:**
   Build a map: `{ VRF_NAME: { afi: [import_RTs] } }`
   - `ipv4-flowspec` import RT → for FlowSpec-VPN IPv4
   - `ipv6-flowspec` import RT → for FlowSpec-VPN IPv6
   - `ipv4-unicast` import RT → for L3VPN and RT-Redirect target resolution
   - EVPN/VPLS → their respective import RTs

3. **AskQuestion: "Which VRF should the routes be imported into?"**
   Options built from discovery:
   - "VRF ZULU (ipv4-flowspec RT: 300:300, 1234567:301)"
   - "VRF ALPHA (ipv4-unicast RT: 100:100, no flowspec import)"
   - "Custom RT (I'll specify)"

4. **Warn if VRF has no import-vpn for selected AFI:**
   "VRF ALPHA has no ipv4-flowspec import-vpn. Routes won't be imported. Add it first?"

5. **Use discovered RT in the route:**
   Pass the selected VRF's import RT as `--rt` to `bgp_tool.py` or `route_builder.py`.
   Do NOT fall back to hardcoded defaults when device config has been queried.

**RT matching rules (from learned behavior):**
| Route type | RT must match VRF's... |
|---|---|
| FlowSpec-VPN IPv4 | `ipv4-flowspec` import RT |
| FlowSpec-VPN IPv6 | `ipv6-flowspec` import RT |
| L3VPN | `ipv4-unicast` import RT |
| RT-Redirect action | `ipv4-unicast` import RT (NOT flowspec RT) |

**Skip RT discovery for:** plain FlowSpec (SAFI 133), unicast, multicast, labeled-unicast.

### Step 7b: Route injection

After RT discovery (or skip for non-VPN), use AskQuestion for remaining route parameters
(prefix, match fields, action, count for scale) per route-injection.md.

Use `route_builder.py` + `bgp_tool.py inject` for single routes, or
`bgp_tool.py scale --mode <mode> --rt <discovered_rt> --fast` for bulk.

---

## Mode 3: `/BGP stop` (STOP)

1. Determine which session to stop (if multiple, use AskQuestion or use most recent active)
2. Read `~/.cursor/bgp-reference/cleanup.md`
3. **Default behavior (admin-disable):**
   - Run `bgp_tool.py stop --session-id <id>` (kill ExaBGP locally)
   - On DNAAS: `admin-state disabled` on the .999 sub-interface (do NOT delete)
   - On device: `admin-state disabled` under `protocols bgp <asn> neighbor 100.64.6.134` (do NOT delete neighbor config)
4. **Only if user explicitly said "remove" or "delete":** Full cleanup - remove AC from BD, remove sub-if, remove neighbor, remove static route

---

## Mode 4: `/BGP configure` or `/BGP configure <Device>` (CONFIGURE)

When user says "configure", "configure device", or `/BGP configure [Device(s)]`:

1. Read `~/.cursor/bgp-reference/configure.md` first
2. **Resolve device(s):** `list_devices` → match user input. If none specified, AskQuestion to pick
3. **BGP analysis (per device):** `get_device_config(device, section='protocols')` → parse neighbors, ASNs, address-families per neighbor, existing policy-in/out
4. **AskQuestion:** "What to configure?" → e.g. "Add route-policy"
5. **Route-policy wizard:**
   - AskQuestion: Which policy? (ALLOW_REDIRECT_IP_ONLY, or Custom one-liner)
   - AskQuestion: Where to attach? Options from BGP analysis: `neighbor <ip> — <afi> — import` or `export`
   - Generate: routing-policy block (one-liner, new language) + BGP neighbor attach
6. Validate, apply, report

**Policy placement:** Use BGP analysis to build attachment options. Never assume — AskQuestion when multiple neighbors/AFIs. See configure.md for import vs export logic.

**Route injection peering:** When policy is `in` on PE toward RR, ExaBGP must peer with the **RR** (not PE directly). Route flows: ExaBGP -> RR -> PE (filtered by policy). See configure.md Step 6.

---

## Self-Learning (Like /XRAY)

**After each BGP operation — LEARNING FIRST, then ANSWER:**

1. Run setup / inject / stop / status
2. **WRITE phase** — update learning (see learning.md):
   - Append to `session_history[]`
   - If user corrected: add to `learned_rules[]` and `correction_log[]`
   - **MANDATORY sync** -- run `python3 ~/.cursor/tools/prune_learning.py --command bgp --sync-only` IMMEDIATELY after any JSON write. Skipping this means the next read uses stale rules. Never skip.
   - **MANDATORY self-audit:** Ask yourself: What was slow? What did I miss? What would make next run faster?
3. **THEN present** the report to the user

**Agent read mirrors:** `~/.cursor/bgp-reference/learned_index.md` (always) + `~/.cursor/bgp-reference/learned_rules.md` (matching sections only)

**JSON backing stores:** `~/.cursor/bgp-reference/learned.json` (rules, corrections) + `~/SCALER/FLOWSPEC_VPN/exabgp/learned/patterns.json` (technical patterns). Keep these for script compatibility. After ANY JSON write, you MUST run `python3 ~/.cursor/tools/prune_learning.py --command bgp --sync-only`. Never skip this step.

---

## Agent Reading Pattern

**Before reading: check freshness (fast, ~0.3s):**
- `python3 ~/.cursor/tools/prune_learning.py --command bgp --check` -- if exit 1, sync first

**Always read first:**
1. `~/.cursor/bgp-reference/learned_index.md` — compact rule summary, structured-context map, selective read protocol
2. `~/.cursor/bgp-reference/learning.md` — READ/WRITE phases, self-audit questions

**Read as needed:**
3. `~/.cursor/bgp-reference/learned_rules.md` -- read only the sections that match the current mode, symptom, or AFI/SAFI
4. `~/.cursor/bgp-reference/discovery.md` -- before path discovery
5. `~/.cursor/bgp-reference/orchestration.md` -- when generating config
6. `~/.cursor/bgp-reference/route-injection.md` -- when injecting routes
7. `~/.cursor/bgp-reference/cleanup.md` -- when stopping
8. `~/.cursor/bgp-reference/configure.md` -- when user says "configure" (route-policy, BGP analysis)

---

## Sub-File Summary

| File | When to Read | Content |
|------|--------------|---------|
| `bgp-reference/learned_index.md` | Every invocation, first | Compact rule summary, structured-context map, selective read protocol |
| `bgp-reference/learning.md` | Every invocation | READ/WRITE phases, pattern format |
| `bgp-reference/learned_rules.md` | After index match | Full rules and detailed context, read matching sections only |
| `bgp-reference/discovery.md` | Before path discovery | DNAAS path, AskQuestion for multi-interface/DNAAS |
| `bgp-reference/orchestration.md` | When generating config | Dynamic AFI template, reserved IPs |
| `bgp-reference/route-injection.md` | When injecting routes | AFI/SAFI syntax, route_builder |
| `bgp-reference/cleanup.md` | When stopping | Admin-disable vs remove |
| `bgp-reference/configure.md` | When configure mode | Route-policy (new language), BGP analysis, neighbor/AFI/in-out |

---

## FlowSpec-VPN: redirect-ip vs redirect-to-rt

- **redirect-ip** (Simpson draft): Use `redirect <ip>` (e.g. `redirect 10.0.0.254`). DNOS supported. Redirects traffic to IP next-hop (e.g. lo10).
- **redirect-to-rt**: Use `redirect asn:nn` (e.g. `redirect 1234567:300`). Different behavior — redirects to VRF that imports that RT.
- DNOS does NOT support IETF draft `draft-ietf-idr-flowspec-redirect-ip` extended community. Use Simpson draft only. See `bgp-reference/route-injection.md` and `bgp-reference/flowspec-redirect-ip-policy.md`.

---

## Called by /HA (Cross-Command Integration)

When /HA is running an HA test, it may call /BGP for route operations. Read
`~/.cursor/rules/cross-command-integration.mdc` for the shared protocol.

### Scale Up Routes (before HA test)

/HA may request bulk route injection to meet test requirements (e.g., SW-236398 requires 200 rules).

**How it works:**
1. /HA checks if an active ExaBGP session exists: `bgp_tool.py list`
2. If session exists and is alive, /HA generates routes via `route_builder.py`
3. /HA injects them via `bgp_tool.py inject --session-id <id> --route '<route>'` in a loop
4. /HA verifies on DUT: `show bgp ipv4 flowspec summary` -- PfxAccepted count

**Batch injection pattern (for 200 FlowSpec-VPN rules):**
```python
for i in range(200):
    prefix = f"99.99.{i // 256}.{i % 256}/32"
    route = f"announce flow route rd 1.1.1.1:200 destination {prefix} rate-limit 0 extended-community [ target:1234567:301 ]"
    bgp_tool.py inject --session-id pe_1 --route '{route}'
```

### Report Route Count (during/after HA test)

/HA needs to know how many routes ExaBGP is currently advertising:
- `bgp_tool.py list` -> `advertised_summary.total_routes`
- Compare with DUT `show bgp ipv4 flowspec summary` PfxAccepted

### Withdraw Routes (clean up after test)

/HA may request route withdrawal:
- `bgp_tool.py withdraw --session-id <id> --route '<route>'`
- Or withdraw all: iterate over `injected_routes[]` from session JSON

### Device Identity Check

When /HA asks /BGP to verify session state, /BGP should confirm the DUT hostname matches
the /HA locked device. Read the shared session at `~/SCALER/HA/active_ha_session.json`.

---

## Quick Reference

- **Path:** Server (100.64.6.134) -> Firewall (100.70.0.254) -> DNAAS spine -> DNAAS leaf -> Target device
- **VLAN 999:** Inband management. Bridge-domain `g_mgmt_v999` on DNAAS leaves.
- **Static route:** `protocols static address-family ipv4-unicast route 100.64.0.0/20 next-hop 100.70.0.254`
- **ebgp-multihop:** Required. Default 10.
- **Hold-time:** DNOS default 180s. Match in ExaBGP config.
