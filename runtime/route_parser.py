#!/usr/bin/env python3
"""
route_parser.py - Parse ExaBGP route strings into structured data.

Parses inject/withdraw commands and maintains an advertised_state
with full knowledge of what's being advertised: prefixes, RDs, RTs,
actions, match fields, AFI/SAFI, target VRFs.
"""

import re
from collections import defaultdict


def parse_route(route_string: str) -> dict:
    """Parse an ExaBGP route string into structured fields.

    Handles:
    - FlowSpec SAFI 133: announce flow route destination <prefix> <action>
    - FlowSpec-VPN SAFI 134: announce flow route rd <RD> destination <prefix> ...
    - Unicast: announce route <prefix> next-hop <ip> ...
    - L3VPN: announce route rd <RD> <prefix> next-hop <ip> ...
    - EVPN: announce evpn mac-advertisement / ip-prefix ...
    - VPLS: announce vpls rd <RD> ...
    - RT-Constraint: announce route-target <RT> next-hop <ip>

    Returns dict with type, afi_safi, and parsed fields.
    """
    s = route_string.strip()

    action = "announce"
    if s.startswith("withdraw "):
        action = "withdraw"
        s = s[len("withdraw "):]
    elif s.startswith("announce "):
        s = s[len("announce "):]

    parsed = {"raw": route_string, "action": action}

    if s.startswith("flow route"):
        _parse_flowspec(s, parsed)
    elif s.startswith("evpn "):
        _parse_evpn(s, parsed)
    elif s.startswith("vpls "):
        _parse_vpls(s, parsed)
    elif s.startswith("route-target "):
        _parse_rtc(s, parsed)
    elif s.startswith("route "):
        _parse_unicast_or_vpn(s, parsed)
    else:
        parsed["type"] = "unknown"
        parsed["afi_safi"] = "unknown"

    return parsed


def _parse_flowspec(s: str, parsed: dict):
    """Parse 'flow route ...' into FlowSpec or FlowSpec-VPN."""
    body = s[len("flow route "):]

    rd = _extract_field(body, "rd")
    if rd:
        parsed["type"] = "flowspec-vpn"
        parsed["rd"] = rd
    else:
        parsed["type"] = "flowspec"

    dest = _extract_field(body, "destination")
    src = _extract_field(body, "source")

    is_ipv6 = False
    if dest and ":" in dest.split("/")[0]:
        is_ipv6 = True
    if src and ":" in src.split("/")[0]:
        is_ipv6 = True

    if rd:
        parsed["afi_safi"] = "ipv6 flow-vpn" if is_ipv6 else "ipv4 flow-vpn"
    else:
        parsed["afi_safi"] = "ipv6 flow" if is_ipv6 else "ipv4 flow"

    match_fields = {}
    if dest:
        match_fields["destination"] = dest
    if src:
        match_fields["source"] = src
    for field in ("protocol", "port", "destination-port", "source-port",
                  "tcp-flags", "icmp-type", "icmp-code", "fragment",
                  "packet-length", "dscp"):
        val = _extract_field(body, field)
        if val:
            match_fields[field] = val

    if _has_match_then(body):
        m = re.search(r'match\s*\{([^}]*)\}', body)
        if m:
            for token in m.group(1).split(";"):
                token = token.strip()
                if not token:
                    continue
                parts = token.split(None, 1)
                if len(parts) == 2:
                    match_fields[parts[0]] = parts[1]

    parsed["match"] = match_fields

    actions = {}

    redirect_ip_val = _extract_field(body, "redirect-ip")
    if redirect_ip_val:
        actions["redirect-ip"] = redirect_ip_val

    redirect_rt = re.search(r'(?<!\w)redirect\s+(\d+:\d+)\b', body)
    if redirect_rt:
        actions["redirect-to-rt"] = redirect_rt.group(1)

    if "redirect-ip" not in actions and "redirect-to-rt" not in actions:
        redirect_val = _extract_field(body, "redirect")
        if redirect_val:
            if ":" in redirect_val and redirect_val.count(":") == 1:
                actions["redirect-to-rt"] = redirect_val
            else:
                actions["redirect-ip"] = redirect_val

    rate_limit = _extract_field(body, "rate-limit")
    if rate_limit is not None:
        actions["rate-limit"] = rate_limit
    if "discard" in body.split():
        actions["discard"] = True

    if _has_match_then(body):
        t = re.search(r'then\s*\{([^}]*)\}', body)
        if t:
            then_body = t.group(1)
            rl = re.search(r'rate-limit\s+(\S+)', then_body)
            if rl:
                actions["rate-limit"] = rl.group(1)
            rd_act = re.search(r'redirect\s+(\S+)', then_body)
            if rd_act:
                val = rd_act.group(1).rstrip(";")
                if ":" in val and val.count(":") == 1:
                    actions["redirect-to-rt"] = val
                else:
                    actions["redirect-ip"] = val
            if "discard" in then_body:
                actions["discard"] = True

    parsed["actions"] = actions

    ecs = _extract_extended_communities(body)
    parsed["extended_communities"] = ecs
    parsed["route_targets"] = [
        ec.replace("target:", "") for ec in ecs if ec.startswith("target:")
    ]


def _parse_unicast_or_vpn(s: str, parsed: dict):
    """Parse 'route ...' into unicast or L3VPN."""
    body = s[len("route "):]

    rd = _extract_field(body, "rd")
    if rd:
        parsed["type"] = "l3vpn"
        parsed["rd"] = rd
    else:
        parsed["type"] = "unicast"

    prefix = _extract_prefix(body, has_rd=bool(rd))
    parsed["prefix"] = prefix

    is_ipv6 = prefix and ":" in prefix.split("/")[0]
    if rd:
        parsed["afi_safi"] = "ipv6 mpls-vpn" if is_ipv6 else "ipv4 mpls-vpn"
    else:
        parsed["afi_safi"] = "ipv6 unicast" if is_ipv6 else "ipv4 unicast"

    nh = _extract_field(body, "next-hop")
    parsed["next_hop"] = nh

    ecs = _extract_extended_communities(body)
    parsed["extended_communities"] = ecs
    parsed["route_targets"] = [
        ec.replace("target:", "") for ec in ecs if ec.startswith("target:")
    ]

    label = _extract_list_field(body, "label")
    if label:
        parsed["labels"] = label

    comm = _extract_list_field(body, "community")
    if comm:
        parsed["communities"] = comm

    lcomm = _extract_list_field(body, "large-community")
    if lcomm:
        parsed["large_communities"] = lcomm

    attrs = {}
    for attr in ("med", "local-preference", "origin"):
        v = _extract_field(body, attr)
        if v:
            attrs[attr] = v
    as_path = _extract_list_field(body, "as-path")
    if as_path:
        attrs["as-path"] = as_path
    if attrs:
        parsed["attributes"] = attrs


def _parse_evpn(s: str, parsed: dict):
    """Parse EVPN routes."""
    parsed["type"] = "evpn"
    parsed["afi_safi"] = "l2vpn evpn"
    if "mac-advertisement" in s:
        parsed["evpn_type"] = "type-2-mac-ip"
    elif "ip-prefix" in s:
        parsed["evpn_type"] = "type-5-ip-prefix"
    else:
        parsed["evpn_type"] = "unknown"

    parsed["rd"] = _extract_field(s, "rd")
    parsed["esi"] = _extract_field(s, "esi")
    parsed["ethernet_tag"] = _extract_field(s, "ethernet-tag")
    parsed["next_hop"] = _extract_field(s, "next-hop")
    ecs = _extract_extended_communities(s)
    parsed["extended_communities"] = ecs
    parsed["route_targets"] = [
        ec.replace("target:", "") for ec in ecs if ec.startswith("target:")
    ]
    label = _extract_list_field(s, "label")
    if label:
        parsed["labels"] = label
    mac = _extract_field(s, "mac")
    if mac:
        parsed["mac"] = mac
    ip = _extract_field(s, "ip")
    if ip:
        parsed["ip"] = ip


def _parse_vpls(s: str, parsed: dict):
    """Parse VPLS routes."""
    parsed["type"] = "vpls"
    parsed["afi_safi"] = "l2vpn vpls"
    parsed["rd"] = _extract_field(s, "rd")
    parsed["endpoint"] = _extract_field(s, "endpoint")
    parsed["base"] = _extract_field(s, "base")
    parsed["offset"] = _extract_field(s, "offset")
    parsed["size"] = _extract_field(s, "size")
    parsed["next_hop"] = _extract_field(s, "next-hop")
    ecs = _extract_extended_communities(s)
    parsed["extended_communities"] = ecs
    parsed["route_targets"] = [
        ec.replace("target:", "") for ec in ecs if ec.startswith("target:")
    ]


def _parse_rtc(s: str, parsed: dict):
    """Parse RT-Constraint routes."""
    parsed["type"] = "rt-constraint"
    parsed["afi_safi"] = "ipv4 rtc"
    m = re.search(r'route-target\s+(\S+)', s)
    if m:
        parsed["route_target"] = m.group(1)
    parsed["next_hop"] = _extract_field(s, "next-hop")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_field(s: str, name: str) -> str | None:
    m = re.search(rf'\b{re.escape(name)}\s+(\S+)', s)
    return m.group(1).rstrip(";") if m else None


def _extract_list_field(s: str, name: str) -> list | None:
    m = re.search(rf'{re.escape(name)}\s+\[([^\]]*)\]', s)
    if m:
        return [v.strip() for v in m.group(1).split() if v.strip()]
    return None


def _extract_extended_communities(s: str) -> list:
    m = re.search(r'extended-community\s+\[([^\]]*)\]', s)
    if m:
        return [v.strip() for v in m.group(1).split() if v.strip()]
    return []


def _extract_prefix(body: str, has_rd: bool = False) -> str | None:
    """Extract the prefix from a unicast/L3VPN route body."""
    if has_rd:
        m = re.search(r'rd\s+\S+\s+(\d[\d.:]+/\d+)', body)
        if m:
            return m.group(1)
    m = re.match(r'(\d[\d.:]+/\d+)', body.strip())
    return m.group(1) if m else None


def _has_match_then(s: str) -> bool:
    return "match" in s and "{" in s


# ---------------------------------------------------------------------------
# Advertised State Management
# ---------------------------------------------------------------------------

def build_advertised_state(injected_routes: list, session_data: dict = None) -> dict:
    """Build a complete advertised_state from a list of injected route entries.

    Args:
        injected_routes: List of dicts with 'route' and 'injected_at' keys
        session_data: Full session dict for capabilities extraction

    Returns:
        Structured advertised_state dict.
    """
    parsed_routes = []
    for entry in injected_routes:
        raw = entry.get("route", entry) if isinstance(entry, dict) else entry
        ts = entry.get("injected_at") if isinstance(entry, dict) else None
        p = parse_route(raw)
        if ts:
            p["injected_at"] = ts
        parsed_routes.append(p)

    summary = _build_summary(parsed_routes)

    capabilities = {}
    if session_data:
        capabilities = {
            "peer_ip": session_data.get("peer_ip"),
            "peer_as": session_data.get("peer_as"),
            "local_as": 65200,
            "local_ip": session_data.get("exabgp_ip", "100.64.6.134"),
            "families": session_data.get("selected_afis", []),
            "ebgp_multihop": 10,
            "hold_time": 600,
            "target_device": session_data.get("target_device"),
            "dnaas_leaf": session_data.get("dnaas_leaf"),
        }

    return {
        "summary": summary,
        "routes": parsed_routes,
        "capabilities": capabilities,
    }


def _build_summary(parsed_routes: list) -> dict:
    """Aggregate parsed routes into a summary."""
    by_type = defaultdict(int)
    by_afi = defaultdict(int)
    prefixes = set()
    rds = set()
    rts = set()
    actions_set = set()

    for r in parsed_routes:
        if r.get("action") == "withdraw":
            continue

        rtype = r.get("type", "unknown")
        afi = r.get("afi_safi", "unknown")
        by_type[rtype] += 1
        by_afi[afi] += 1

        if r.get("match", {}).get("destination"):
            prefixes.add(r["match"]["destination"])
        if r.get("prefix"):
            prefixes.add(r["prefix"])
        if r.get("rd"):
            rds.add(r["rd"])
        for rt in r.get("route_targets", []):
            rts.add(rt)
        for action_name, action_val in r.get("actions", {}).items():
            if action_val is True:
                actions_set.add(action_name)
            else:
                actions_set.add(f"{action_name} {action_val}")

    prefix_ranges = _summarize_prefixes(prefixes) if prefixes else []

    return {
        "total_routes": sum(1 for r in parsed_routes if r.get("action") != "withdraw"),
        "by_type": dict(by_type),
        "by_afi_safi": dict(by_afi),
        "prefix_count": len(prefixes),
        "prefix_ranges": prefix_ranges,
        "all_prefixes": sorted(prefixes) if len(prefixes) <= 20 else f"{len(prefixes)} prefixes (too many to list)",
        "rds": sorted(rds),
        "route_targets": sorted(rts),
        "actions": sorted(actions_set),
    }


def _summarize_prefixes(prefixes: set) -> list:
    """Collapse a set of prefixes into human-readable ranges."""
    if len(prefixes) <= 5:
        return sorted(prefixes)

    import ipaddress
    v4 = []
    v6 = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            pass

    ranges = []
    if v4:
        v4.sort()
        ranges.append(f"{v4[0]} .. {v4[-1]} ({len(v4)} IPv4 prefixes)")
    if v6:
        v6.sort()
        ranges.append(f"{v6[0]} .. {v6[-1]} ({len(v6)} IPv6 prefixes)")
    return ranges


def update_state_on_inject(advertised_state: dict, route_string: str,
                            injected_at: str = None) -> dict:
    """Add a newly injected route to the advertised state."""
    parsed = parse_route(route_string)
    if injected_at:
        parsed["injected_at"] = injected_at

    if "routes" not in advertised_state:
        advertised_state["routes"] = []
    advertised_state["routes"].append(parsed)

    active = [r for r in advertised_state["routes"] if r.get("action") != "withdraw"]
    advertised_state["summary"] = _build_summary(active)
    return advertised_state


def update_state_on_withdraw(advertised_state: dict, route_string: str) -> dict:
    """Remove a withdrawn route from the advertised state.

    Matches by type + key fields (destination, rd, prefix).
    """
    withdrawn = parse_route(route_string)

    remaining = []
    removed = False
    for r in advertised_state.get("routes", []):
        if r.get("action") == "withdraw":
            continue
        if not removed and _routes_match(r, withdrawn):
            removed = True
            continue
        remaining.append(r)

    advertised_state["routes"] = remaining
    advertised_state["summary"] = _build_summary(remaining)
    return advertised_state


def _routes_match(existing: dict, withdrawn: dict) -> bool:
    """Check if two parsed routes refer to the same NLRI."""
    if existing.get("type") != withdrawn.get("type"):
        return False

    if existing.get("type") in ("flowspec", "flowspec-vpn"):
        e_dest = existing.get("match", {}).get("destination")
        w_dest = withdrawn.get("match", {}).get("destination")
        if e_dest != w_dest:
            return False
        if existing.get("rd") != withdrawn.get("rd"):
            return False
        return True

    if existing.get("type") in ("unicast", "l3vpn"):
        if existing.get("prefix") != withdrawn.get("prefix"):
            return False
        if existing.get("rd") != withdrawn.get("rd"):
            return False
        return True

    return existing.get("raw") == withdrawn.get("raw")
