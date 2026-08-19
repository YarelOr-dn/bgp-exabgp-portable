# BGP Tool - Cleanup Protocol

## Overview

Two cleanup modes:

- **Default stop** (user says "stop", "close", "end"): Admin-disable only. Keeps config for reuse.
- **Explicit remove** (user says "remove", "delete", "clean up everything"): Full removal of all applied config.

## Default Stop (Admin-Disable + BD Cleanup)

When user stops without saying "remove":

1. **Stop ExaBGP locally:** `bgp_tool.py stop --session-id <id>`
2. **On DNAAS:** Remove AC from bridge-domain, then `admin-state disabled` on the `.999` sub-interface.
3. **On device:** `admin-state disabled` under `protocols bgp <asn> neighbor 100.64.6.134`. Do NOT delete neighbor config.
4. `admin-state disabled` on device `.999` sub-interface (keeps config for reuse).
5. Do NOT remove static route on device (may be reused).
6. Mark session as closed.

Config remains on device; session can be resumed by re-enabling and restarting ExaBGP. DNAAS BD AC must be re-added on resume.

**Default stop commands:**
- DNAAS: `no network-services bridge-domain instance g_mgmt_v999 interface bundle-X.999` + `interfaces bundle-X.999 admin-state disabled`
- Device: `protocols bgp <asn> neighbor 100.64.6.134 admin-state disabled` + `interfaces bundle-Y.999 admin-state disabled`

## Explicit Remove (Full Cleanup)

Only when user explicitly says "remove" or "delete":

1. Stop ExaBGP
2. **Target device:** Remove BGP neighbor, static route, .999 sub-interface (see rollback commands below)
3. **DNAAS leaf:** Remove AC from bridge-domain, remove .999 sub-interface
4. Verify cleanup
5. Mark session as closed

## Session State File

Every session stores its state in `~/SCALER/FLOWSPEC_VPN/exabgp/sessions/<session_id>.json`:

```json
{
  "session_id": "pe4_flowspec_20260215",
  "status": "active",
  "created": "2026-02-15T18:00:00Z",
  "target_device": "PE-4",
  "dnaas_leaf": "DNAAS-LEAF-B15",
  "exabgp_pid": 12345,
  "exabgp_config": "/tmp/exabgp_pe4_flowspec.conf",
  "exabgp_ip": "100.70.0.32",
  "device_ip": "100.70.0.201",
  "applied_configs": {
    "dnaas_leaf": {
      "config_applied": "interfaces\n  bundle-X.999\n  ...",
      "rollback_commands": "no interfaces bundle-X.999\nno network-services bridge-domain instance g_mgmt_v999 interface bundle-X.999"
    },
    "target_device": {
      "config_applied": "interfaces\n  bundle-Y.999\n  ...\nprotocols\n  bgp ...",
      "rollback_commands": "no interfaces bundle-Y.999\nno protocols bgp <asn> neighbor 100.64.6.134\nno protocols static address-family ipv4-unicast route 100.64.0.0/20"
    }
  },
  "injected_routes": [
    "announce flow route rd 4.4.4.4:101 match { destination 10.0.0.0/24; } then { rate-limit 1000000; extended-community [ target:1234567:101 ]; }"
  ]
}
```

## Full Cleanup Sequence (Explicit Remove Only)

### Step 1: Stop ExaBGP

```bash
python3 bgp_tool.py stop --session-id <session_id>
```

This sends SIGTERM to ExaBGP, waits for graceful shutdown (BGP NOTIFICATION sent to peer), then cleans up PID file. If ExaBGP doesn't stop in 10 seconds, SIGKILL.

### Step 2: Rollback Target Device Config (Remove Mode Only)

Use SSH (via network-mapper or paramiko) to remove applied config. Order matters -- remove BGP neighbor first, then static route, then sub-interface:

```
no protocols bgp <asn> neighbor 100.64.6.134
no protocols static address-family ipv4-unicast route 100.64.0.0/20
no interfaces bundle-Y.999
commit
```

**Validation:** Run `show config protocols bgp` and `show config interfaces` on target device. Confirm neighbor and sub-interface are gone.

### Step 3: Rollback DNAAS Leaf Config (Remove Mode Only)

Remove the AC from bridge-domain first, then the sub-interface:

```
no network-services bridge-domain instance g_mgmt_v999 interface bundle-X.999
no interfaces bundle-X.999
commit
```

**Validation:** Run `show config network-services bridge-domain instance g_mgmt_v999` and `show config interfaces`. Confirm AC and sub-interface are gone.

### Step 4: Verify Cleanup

Run on target device:
```
show bgp summary              # Neighbor should be gone
show interfaces bundle-Y.999  # Should not exist
```

Run on DNAAS leaf:
```
show bridge-domain instance g_mgmt_v999  # AC should be gone
show interfaces bundle-X.999             # Should not exist
```

### Step 5: Mark Session Closed

Update `sessions/<session_id>.json`:
```json
{
  "status": "closed",
  "closed_at": "2026-02-15T19:30:00Z",
  "cleanup_result": "success"
}
```

## Emergency Cleanup

If the AI loses context (new conversation, crash, etc.), any agent can recover:

1. Read `~/SCALER/FLOWSPEC_VPN/exabgp/sessions/` for any session with `"status": "active"`
2. Each active session has everything needed: PID, device names, rollback commands
3. Run the graceful cleanup sequence using stored rollback commands
4. No discovery needed -- all info is in the session file

```bash
# Quick check for orphaned sessions
python3 bgp_tool.py list
```

If `bgp_tool.py` shows active sessions but ExaBGP is dead (process not running), just do the device rollback steps.

## Partial Cleanup

If only part of the setup was applied (e.g., DNAAS leaf was configured but device was not):

1. Read `sessions/<id>.json` to see what was actually applied
2. Only rollback what exists -- check `applied_configs` for non-null entries
3. For safety: run `show config` on each device to verify what's actually there before sending rollback commands

## Cleanup on Error

If config apply fails midway:

1. Note which config was successfully applied (DNAAS leaf, target device, or both)
2. Rollback only the successfully applied config
3. Stop ExaBGP if it was started
4. Mark session as `"status": "error"` with `"error_detail": "..."` in session file
5. Report to user what happened and what was cleaned up

## Do NOT Clean Up

- **Existing .999 sub-interfaces** that were there before the session (discovery.md checks for this)
- **Other bridge-domain ACs** -- only remove the one we added
- **Other BGP neighbors** on the target device -- only remove ours (100.64.6.134)
