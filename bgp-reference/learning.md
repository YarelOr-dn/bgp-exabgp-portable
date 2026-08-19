# BGP Tool - Learning Protocol

**Read FIRST on every /BGP invocation.**

**Learning stores:**
- `~/SCALER/FLOWSPEC_VPN/exabgp/learned/patterns.json` — config patterns, DNAAS cache, ExaBGP quirks, failed attempts
- `~/.cursor/bgp-reference/learned.json` — learned rules, correction log, session history (self-audit)

**AskQuestion or terminal prompt:** When /BGP needs user input in Agent mode, run `python3 ~/.cursor/tools/xray_prompt.py --prompt "<question>" --options "<id1>:<label1>,<id2>:<label2>"`. Parse `XRAY_CHOICE:<value>`. Continue.

---

## READ Phase (Every Invocation)

1. Load `patterns.json` — apply when generating config: DNAAS path cache, ExaBGP quirks, failed_attempts
2. Load `learned.json` — if missing, create skeleton and proceed. Apply `learned_rules[]` during setup/inject
3. Rule priority: learned_rules (high confidence) > patterns.json exabgp_quirks > hardcoded defaults

---

## WRITE Phase (BEFORE Presenting Answer)

**CRITICAL ORDER: Learning → then Answer.** Self-audit and learning updates happen AFTER the BGP operation completes, but BEFORE you present the report to the user.

**TRIGGER: ANY BGP-related work, not just /BGP command.** If you debug ExaBGP, fix a BGP session, kill/restart ExaBGP, modify exabgp.env, change pipe.py, or touch ANY file under ~/SCALER/FLOWSPEC_VPN/exabgp/ -- you MUST run the WRITE phase before ending your turn. Do NOT wait for the user to invoke /BGP or ask "where is the self learning." The learning trigger is the WORK, not the command.

**Update in three situations (do not skip ANY):**

### A) After each session completes (setup, inject, stop, status)

Append to `session_history[]`: prompt, resolved params, session_id, device, outcome (success/fail), routes injected.

### B) When the user corrects you (any message)

If the user corrects in **any** message — "use flat format", "session should run forever", "don't kill my session", "the route wasn't sent" — **immediately** update:

1. Add to `learned_rules[]` with `id`, `rule`, `source`, `confidence: "high"`, `examples`
2. Append to `correction_log[]`: what agent did → what user wanted → rule learned
3. Update `patterns.json` exabgp_quirks if it's a technical workaround

### C) MANDATORY self-audit after EVERY session (before presenting)

Even when the user does NOT correct you, ask yourself:

1. **What did I do that was slow or unnecessary?** (e.g., ran full discovery when dnaas_path_cache had the data)
2. **What did I miss that I should have caught?** (e.g., used match/then format when flat was required)
3. **What would make the NEXT similar run faster?** (e.g., always use route_builder for flowspec-vpn)
4. **What new DNOS/ExaBGP behaviors did I discover?** (e.g., route not sent → flat format fix)
5. **Did I use the correct session_id convention?** (device_name.lower().replace("-","_"))

Write findings to `learned_rules[]` (confidence: "medium" for self-discovered) and `session_history[]`. This is NOT optional — self-improvement happens on EVERY session.

---

## learned.json Structure

```json
{
  "version": 1,
  "learned_rules": [
    {
      "id": "flowspec_vpn_flat_format",
      "rule": "ExaBGP API pipe requires FLAT format for FlowSpec-VPN with rd. Use 'announce flow route rd X destination Y redirect IP extended-community [ target:RT ]'. route_builder.py outputs flat. bgp_tool auto-converts on inject.",
      "source": "User correction + self-audit 2026-02-16: route wasn't sent with match/then format",
      "confidence": "high",
      "last_updated": "2026-02-16",
      "examples": [{"wrong": "match { } then { }", "correct": "flat keywords"}]
    }
  ],
  "correction_log": [
    {
      "what_agent_did": "Injected match/then format route",
      "what_user_wanted": "Route sent to RR",
      "rule_learned": "flowspec_vpn_flat_format"
    }
  ],
  "session_history": [
    {
      "timestamp": "2026-02-16T16:09:00",
      "prompt": "/BGP bring peer RR-SA-2 up and advertise redirect-ip",
      "session_id": "rr_sa2",
      "device": "RR-SA-2",
      "outcome": "success",
      "routes_injected": 1,
      "self_audit": "Used flat format; reinject on start worked"
    }
  ],
  "last_updated": "2026-02-16"
}
```

---

## PE-4 Initiation vs ExaBGP Initiation (2026-03-03)

**Discovery:** tcpdump showed PE-4 (100.70.0.206) initiating TCP to server (100.64.6.134):179. Server was sending RST (no listener). So PE-4 and ExaBGP were BOTH trying to initiate; neither was successfully listening for the other.

**passive=true + iptables REDIRECT 179->1179:** ExaBGP listens on 1179. REDIRECT sends 179 traffic to 1179. But reply packets keep source port 1179; PE-4 expects 179. PE-4 sends RST. REDIRECT does NOT rewrite reply source port for the peer's view.

**Fix for passive mode:** Must bind to port 179 directly. Use `authbind --deep` or `setcap cap_net_bind_service=+ep` on Python, then `listen 179`.

**Fix for active mode:** Use `passive=false`. ExaBGP initiates. PE-4 must have working listener (clear bgp neighbor 2.2.2.2 or routing-engine restart to recover listener).

**Authbind for passive mode:** `sudo touch /etc/authbind/byport/179 && sudo chown root:$(id -gn) /etc/authbind/byport/179 && sudo chmod 710 /etc/authbind/byport/179`. Exabgp backend auto-uses authbind when config has `passive true` + `listen 179`.

**SSH-from-BGP-peer hypothesis (2026-03-03):** Investigated. SSH was NOT the cause. Zero SSH connections from server to PE-4 at time of issue.

## ROOT CAUSE: PE-4 iptables Blocking BGP TCP (2026-03-03 - CONFIRMED FIX, updated 2026-03-04)

**Discovery:** PE-4's NCC routing-engine container has iptables INPUT chain rules that DROP all TCP port 179 traffic (both dpt:179 and spt:179) unless packets carry mark 0x65179. The NFQUEUE daemon (queue 178) is supposed to inspect and mark legitimate BGP packets, but was NOT processing our ExaBGP's SYN-ACK responses.

**Proof:**
- `iptables -L INPUT -n` on PE-4 shell showed: `DROP tcp dpt:179 mark match ! 0x65179` and `DROP tcp spt:179 mark match ! 0x65179`
- bgpd WAS listening on 0.0.0.0:179 (confirmed via `ss -tlnp` inside NCC container)
- bgpd's outbound SYN went through OUTPUT chain (MARK set 0x65179) and reached our server
- Our SYN-ACK arrived at PE-4's INPUT chain with mark 0 (incoming packets have no mark) and was DROPPED by rule 4
- BgpTrius traces confirmed: NO "input got rst" for 100.64.6.134 (the SYN-ACK never reached bgpd's socket)
- RST in tcpdump had TTL=63 (PE-4 kernel) -- generated because bgpd's non-blocking connect timed out

**Key diagnostic commands ON PE-4:**
```
run start shell
password: dnroot
iptables -L INPUT -n --line-numbers | head -15
iptables -t filter -L OUTPUT -n --line-numbers | head -10
iptables -t mangle -L INPUT -n --line-numbers
ss -tlnp | grep 179
```

**Fix (runtime iptables, lost on reboot) -- ONLY these 3 rules in filter INPUT:**
```
iptables -I INPUT 3 -p tcp -s 100.64.6.134 --sport 179 -j ACCEPT
iptables -I INPUT 3 -p tcp -s 100.64.6.134 --dport 179 -j ACCEPT
iptables -I INPUT 3 -p tcp -d 100.70.0.206 --dport 179 -j ACCEPT
```

**CRITICAL: What NOT to do (learned 2026-03-04, caused 1+ hour of debugging):**
1. Do NOT add blanket ACCEPT for all port 179 to filter INPUT (`iptables -I INPUT 1 -p tcp --spt 179 -j ACCEPT`). This is unnecessary and bypasses mark checks for ALL peers.
2. Do NOT add blanket ACCEPT for all port 179 to filter OUTPUT. This bypasses NFQUEUE 178 (BgpTrius OUTPUT handler). Without BgpTrius processing outgoing SYNs, bgpd immediately FINs every connection it establishes (BgpTrius connection tracking breaks).
3. Do NOT add ACCEPT rules to mangle INPUT or mangle OUTPUT for ExaBGP. BgpTrius NFQUEUE in mangle MUST process both directions. Our fix only needs to be in filter INPUT (after mangle NFQUEUE processing).
4. Do NOT remove NFQUEUE 177/178 rules. This breaks ALL BGP sessions (2.2.2.2, 50.50.50.2, etc.) with Hold Timer Expired.

**Why only filter INPUT ACCEPT works:**
- BgpTrius NFQUEUE 177 (mangle INPUT) processes the incoming SYN-ACK from ExaBGP
- BgpTrius doesn't recognize ExaBGP, so it passes the packet WITHOUT setting mark 0x65179
- The packet reaches filter INPUT with mark 0x0
- Without our ACCEPT rules, DROP rule fires (mark != 0x65179)
- With our ACCEPT rules at position 3 (before DROP at positions 6-7), the packet is accepted
- BgpTrius NFQUEUE 178 (filter OUTPUT) MUST still process outgoing SYNs for connection tracking

**Symptom of wrong fix (blanket OUTPUT ACCEPT):**
- TCP connection succeeds (SYN, SYN-ACK, ACK)
- bgpd immediately sends FIN (within 129 microseconds) without BGP OPEN
- ExaBGP log shows "incoming-N ... closing connection" rapidly (100+ per minute)
- PE-4 BGP state shows "Idle" with 0 MsgRcvd/MsgSent

**Also required:**
- ExaBGP must run with `passive true; listen 179;` (ExaBGP listens, PE-4 connects to us)
- ExaBGP needs `setcap cap_net_bind_service=+ep` on Python binary to bind port 179 as non-root: `cp /usr/bin/python3.10 /tmp/python3_bgp && sudo setcap 'cap_net_bind_service=+ep' /tmp/python3_bgp`
- Start with: `/tmp/python3_bgp /home/dn/.local/bin/exabgp /tmp/exabgp_pe_4.conf`
- Do NOT use `incoming-ttl` in ExaBGP config -- it sets IP_TTL on the listener socket (not just MINTTL), causing SYN-ACK to go out with low TTL

**Why this affects only ExaBGP (not 2.2.2.2/RR):** The RR (2.2.2.2) is an iBGP peer within the DNOS network. Its BGP traffic goes through standard interfaces with VPP conntrack and proper NFQUEUE processing. ExaBGP (100.64.6.134) is an external peer reaching PE-4 through DNAAS bridge-domain and a firewall gateway -- the NFQUEUE daemon likely doesn't have it in its BGP peer allowlist.

**IMPORTANT: These iptables rules are EPHEMERAL.** They will be lost on NCC restart, routing-engine restart, or device reboot. Re-apply after any such event.

## BgpTrius: Code-Level Source (DNOS Built-In)

The iptables rules are NOT configurable by the user. They are hardcoded in DNOS bgpd as part of BGP NSR (Non-Stop Routing). Active whenever `NSR_ACTIVE` is defined.

**Source files:**
| File | Purpose |
|------|---------|
| `services/control/quagga/bgpd/bgp_cpp/bgp_iptables_rules.cpp` | Defines and installs iptables rules |
| `services/control/quagga/bgpd/bgp_cpp/bgp_iptables_rules.h` | Declares init/clear functions |
| `services/control/quagga/bgpd/bgp_trius/BgpTrius.cpp` | NFQUEUE handler, mark 0x65179, queues 177/178 |
| `services/control/quagga/bgpd/nsrdb/bin/bgpd_standby/bgp_standby_main.cpp` | Standby init of iptables |

**Packet flow through BgpTrius:**
1. Incoming BGP (INPUT): mangle INPUT -> NFQUEUE 177 -> BgpTrius validates -> NF_ACCEPT with mark 0x65179 -> filter INPUT DROP if mark != 0x65179
2. Outgoing BGP (OUTPUT): filter OUTPUT -> NFQUEUE 178 for mark 0 packets -> BgpTrius marks -> POSTROUTING DROP if mark != 0x65179
3. FORWARD (transit): auto-marked 0x65179 (for test/lab scenarios)

**Why ExaBGP is blocked:** BgpTrius sits on NFQUEUE 177 (input). When it receives a SYN-ACK from an "unknown" external peer (one not in bgpd's neighbor table?), it doesn't accept+mark the packet. The packet then hits the DROP rule in filter INPUT.

**Workaround:** Insert ACCEPT rules BEFORE the BgpTrius DROP rules in the filter INPUT chain ONLY. Do NOT modify filter OUTPUT, mangle INPUT, or mangle OUTPUT -- BgpTrius NFQUEUE must process both directions for connection tracking.

**This is NOT CPRL.** CPRL (Control Plane Rate Limiting) is separate -- it operates in the datapath (NCP via PMF TCAM policers), is configurable via `system cprl bgp rate ... burst ...`, and does not use iptables.

## /BGP Tool Code Changes (2026-03-03)

Updated /BGP tool to permanently handle this:

1. **config_gen.py**: Default changed from `passive false; connect 179;` to `passive true; listen 179;`. Removed `incoming-ttl 10` (it sets IP_TTL on socket, not MINTTL). hold_time default 180->600 in both generate_config() and generate_config_with_routes().
2. **exabgp.py**: Auto-detects passive mode + listen 179. Creates setcap'd Python binary at `/tmp/python3_bgp` if missing. Uses it to bind to privileged port 179 as non-root. Falls back to authbind.
3. **iptables on device**: NOT auto-applied (too invasive -- requires SSH to Linux shell). /BGP setup wizard will check and prompt when session stuck in Connect.

### Additional files updated (gap audit 2026-03-03):
4. **bgp_tool.py**: hold_time default 180->600 in CLI arg `--hold-time`, fallback in generate call, and scale mode inline template (was passive false / connect 179 / incoming-ttl 10).
5. **templates/exabgp_conf.j2**: passive true, listen 179, hold-time 600, removed incoming-ttl.
6. **DEVELOPMENT_GUIDELINES.md**: Corrected "Critical ExaBGP Config" section and "Revert if Broken" section.
7. **scapy_tcp.py**: hold_time default 180->600 in both send_update_via_tcp() and send_update_and_hold().
8. **scapy_tcp_tc3_debug.py**: hold_time = 600.
9. **gobgp.py**: hold_time default 180->600 in generate_config() and start().
10. **route_parser.py**: hold_time default 180->600 in session metadata.
11. **patterns.json**: Updated dnos_hold_time pattern from 180 to 600.

12. **bgp_tool.py `diagnose` command (2026-03-03)**: New subcommand that SSHes to device shell, inspects iptables for BgpTrius DROP rules, and optionally applies ACCEPT rules with `--fix`. Auto-resolves device OOB IP and credentials from SCALER DB. Integrated into `/BGP` Step 6 post-start flow.

### FortiGate Firewall Identification (2026-03-04 -- CONFIRMED)

**Discovery:** The "firewall" at 100.70.0.254 is a **FortiGate** (Fortinet). Identified via ARP MAC OUI `00:09:0f` (Fortinet, Inc.) on PE-4's ARP table for ge100-18/0/6.999. It has two interfaces:
- OOB side: `100.64.15.254` (MAC `00:09:0f:09:00:1e`) -- SSH open, our default gateway
- Inband side: `100.70.0.254` (MAC `00:09:0f:09:00:1a`) -- only port 179 open

**FortiGate IDS behavior:** When it sees rapid SYN/RST on TCP/179, it quarantines the traffic. Default quarantine is ~5 minutes, BUT each new SYN refreshes the timer. PE-4's ConnectRetryTimer (120s) kept refreshing the quarantine indefinitely, making it appear permanent.

**Fix: DUT `passive enabled` (2026-03-04 -- MANDATORY for all /BGP setups):**
```
protocols bgp <asn>
  neighbor 100.64.6.134
    passive enabled
  !
!
```
PE-4 never initiates SYNs. ExaBGP initiates. If ExaBGP dies: zero TCP/179 traffic through FortiGate. No IDS trigger. Quarantine expires in 2-3 minutes if previously triggered.

**Three-layer protection (all mandatory):**
1. DUT `passive enabled` -- eliminates SYN flood source
2. Server `bgp_guard.py` -- silently DROPs stray port 179 traffic (no RST)
3. ExaBGP active mode -- single clean SYN/SYN-ACK/ACK handshake

**Recovery from IDS block:**
1. Delete/admin-disable neighbor on DUT (stops SYNs)
2. Wait 2-5 min for FortiGate quarantine to expire
3. Test with `nc -z <device_ip> 179`
4. Re-enable neighbor + start ExaBGP

### Server-side Port 179 Guard (2026-03-04 -- prevents firewall IDS trigger)

**Problem:** When ExaBGP dies (Cursor update, server restart, OOM), the kernel RSTs every incoming SYN on port 179 from PE-4. Rapid SYN/RST exchange triggers the firewall's IDS/rate-limiting, blocking ALL traffic between PE-4 and the server for a cooldown period. This caused 1+ hour of debugging on 2026-03-04.

**Solution:** `bgp_guard.py` manages server-side iptables:
- **Permanent DROP** for port 179 (prevents kernel RST when ExaBGP not running)
- **Temporary ACCEPT** inserted before DROP when ExaBGP is active
- `bgp_tool.py start` calls `bgp_guard.open_port()`, `stop` calls `bgp_guard.close_port()`
- `bgp_watchdog.py` runs via cron every 30s: detects dead ExaBGP, closes guard, auto-restarts

**Files:**
- `bgp_guard.py`: install(), open_port(), close_port(), status()
- `bgp_watchdog.py`: --auto-restart, --status, --install-cron, --remove-cron
- Cron: 2 entries (at 0s and 30s offset) running `bgp_watchdog.py --auto-restart`

**Behavior when ExaBGP dies unexpectedly:**
1. Watchdog detects within 30s (cron interval)
2. Removes ACCEPT rule -- port 179 now silently DROPs (no RST to PE-4)
3. Auto-restarts ExaBGP with same config
4. Re-adds ACCEPT rule if restart succeeds
5. PE-4 reconnects normally within hold-time expiry

**Guard iptables layout:**
```
Rule 1: ACCEPT tcp --dport 179  [bgp_guard_accept -- present when ExaBGP running]
Rule N: DROP   tcp --dport 179  [bgp_guard_drop   -- permanent, prevents RST]
```

### Remaining gaps (partially addressed):
- **Ephemeral iptables on device**: Device-side ACCEPT rules are lost on NCC restart/reboot. **MITIGATED**: `bgp_tool.py diagnose --fix` can now re-apply them automatically. The /BGP agent calls this when session is stuck in Connect.
- **Server-side guard on reboot**: iptables rules lost on server reboot. **MITIGATED**: Watchdog cron will detect dead ExaBGP and close guard within 30s. But DROP rule must be re-installed. Watchdog's first run after boot will install it.
- **sudo for setcap**: If `/tmp/python3_bgp` is lost (server reboot, /tmp cleanup), exabgp.py runs `sudo setcap` which requires sudo password. Current user (dn) has passwordless sudo, but this is environment-dependent.
- **DNOS hold-time mismatch**: DNOS default is 180s. If PE-4's neighbor config still has `hold-time 180`, BGP negotiates min(600,180)=180. Must also update DNOS side to `hold-time 600` for the full benefit.

### BgpTrius Detection Flow (integrated into /BGP Step 6):
```
bgp_tool.py start → wait 15s → bgp_tool.py verify → if tcp != ESTAB:
    → bgp_tool.py diagnose --session-id <id> → reads iptables
    → if bgptrius_detected + drop_179 + no ACCEPT:
        → bgp_tool.py diagnose --session-id <id> --fix → applies ACCEPT rules
        → wait 5s → re-verify tcp state
    → if still not ESTAB: report to user with iptables snippet
```

---

## patterns.json Updates (Technical)

- **dnaas_path_cache:** After successful path discovery
- **exabgp_quirks:** New workarounds (e.g., flat format, session persistence)
- **failed_attempts:** Config that failed, error, resolution
- **session_management:** Orphan cleanup, reinject on start

---

## Conflict Resolution

- Newer rule (by `last_updated`) overrides older for same `id`
- User correction (confidence: high) overrides self-audit (confidence: medium)
- Manual override: User says "use X" → record with `user_override: true`

---

## Pre-Flight Verification (MANDATORY before starting ExaBGP)

See cursor rule `bgp-preflight-mcp-verification.mdc` (alwaysApply: true).

**Before starting ExaBGP or diagnosing a failed session, verify ALL of these via MCP `run_show_command`:**

| # | Check | Command | Pass Condition |
|---|-------|---------|----------------|
| 1 | Static route to server | `show route 100.64.6.134` | "Known via static", next-hop 100.70.0.254 |
| 2 | .999 sub-interface up | `show interfaces ge*-*/0/*.999` | admin UP, oper UP, IP 100.70.0.206/24 |
| 3 | BGP neighbor config | `show config protocols bgp <asn> neighbor 100.64.6.134` | remote-as matches, passive enabled |
| 4 | AFI alignment | (from check 3) | At least one common AFI between DUT and ExaBGP config |

**If MCP is unavailable:** Warn user, fall back to paramiko SSH. Never silently skip.

**Why this exists:** On 2026-03-09, `bgp_tool.py diagnose` reported "FortiGate IDS blocked" for 45+ minutes. The real cause was a missing static route. `nc -z` timeout is ambiguous -- it cannot tell firewall block from missing return route.

---

## Self-Audit Questions (Ask Yourself After Every Session)

Copy these into your reasoning — answer before presenting:

| # | Question |
|---|----------|
| 1 | What did I do that was slow or unnecessary? |
| 2 | What did I miss that I should have caught? |
| 3 | What would make the NEXT similar run faster? |
| 4 | What new DNOS/ExaBGP behaviors did I discover? |
| 5 | Did I use the correct session_id convention (device_name → rr_sa2, pe_4)? |
| 6 | Did I use flat format for ALL FlowSpec (SAFI 133 AND 134)? |
| 7 | Did I preserve/reinject routes on start? |
| 8 | Did I test 1 route FIRST before bulk injection? |
| 9 | Did I check exabgp.out pipe for errors after pipe writes? |
| 10 | Did I run pre-flight MCP checks (static route, interface, AFI) before starting ExaBGP? |
| 11 | Did I use MCP `run_show_command` instead of paramiko when MCP was available? |

Record answers in `session_history[].self_audit` and promote to `learned_rules[]` when actionable.

**AUTOMATIC TRIGGER RULE:** If you touched ExaBGP, bgp_tool.py, pipe.py, exabgp.env, session JSON, or any BGP-related config during the conversation -- even if the user never said /BGP -- you MUST write learning BEFORE presenting your final answer. No exceptions. No waiting for the user to remind you.

---

## Trust / Auto Mode

- First session: Ask confirmation before device commits
- User says "auto" or "trust": Skip confirmation for subsequent applies
- Persist: Optional `learned/trust.json` with `{ "auto_apply": true }` — only if user explicitly enables
