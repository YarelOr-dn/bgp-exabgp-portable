#!/usr/bin/env python3
"""IL DNAAS global-VLAN onboard planner for portable /BGP (dry-run by default)."""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Optional, Tuple

BD_VLAN_RE = re.compile(r"_v(\d+)", re.IGNORECASE)
BD_VLAN_END_RE = re.compile(r"v(\d+)$", re.IGNORECASE)
INSTANCE_RE = re.compile(r"^\s*instance\s+(\S+)\s*$")


def classify_bd_type(bd_name: str) -> Tuple[str, Optional[int]]:
    """Match topology/dnaas_path_discovery.py classify_bd_type (no topology import)."""
    bd_name_lower = (bd_name or "").lower()
    if bd_name_lower.startswith("g_"):
        bd_type = "global"
    elif bd_name_lower.startswith("l_"):
        bd_type = "local"
    else:
        bd_type = "unknown"
    vlan_match = BD_VLAN_RE.search(bd_name or "")
    if not vlan_match:
        vlan_match = BD_VLAN_END_RE.search(bd_name or "")
    global_vlan = int(vlan_match.group(1)) if vlan_match else None
    return bd_type, global_vlan


def parse_vlan_range(text: str) -> Optional[Tuple[int, int]]:
    raw = (text or "").strip().replace(" ", "")
    m = re.match(r"^(\d+)-(\d+)$", raw)
    if not m:
        return None
    lo, hi = int(m.group(1)), int(m.group(2))
    if lo > hi:
        lo, hi = hi, lo
    return lo, hi


def vlan_in_range(vlan: int, range_text: str) -> bool:
    bounds = parse_vlan_range(range_text)
    if bounds is None:
        return False
    lo, hi = bounds
    return lo <= int(vlan) <= hi


def extract_bd_instances(show_text: str) -> list[str]:
    names = []
    for line in (show_text or "").splitlines():
        m = INSTANCE_RE.match(line)
        if m:
            names.append(m.group(1).rstrip("!"))
    return names


def match_global_bds(show_text: str, vlan: int) -> list[dict[str, Any]]:
    hits = []
    for name in extract_bd_instances(show_text):
        bd_type, gv = classify_bd_type(name)
        if bd_type == "global" and gv == int(vlan):
            hits.append({"bd_name": name, "bd_type": bd_type, "global_vlan": gv})
    # also match names that appear only as tokens (pipe-filtered dumps)
    token_re = re.compile(rf"\b(g_\S*_v{int(vlan)})\b", re.IGNORECASE)
    for m in token_re.finditer(show_text or ""):
        name = m.group(1)
        if not any(h["bd_name"] == name for h in hits):
            bd_type, gv = classify_bd_type(name)
            if bd_type == "global" and gv == int(vlan):
                hits.append({"bd_name": name, "bd_type": bd_type, "global_vlan": gv})
    return hits


def plan_dnaas_ac(leaf: str, bundle: str, vlan: int, bd_name: str) -> dict[str, Any]:
    subif = f"{bundle}.{vlan}"
    config = (
        f"interfaces {subif} admin-state enabled\n"
        f"interfaces {subif} description inband-v{vlan}-exabgp\n"
        f"interfaces {subif} l2-service enabled\n"
        f"interfaces {subif} vlan-id {vlan}\n"
        f"network-services bridge-domain instance {bd_name} interface {subif}\n"
    )
    rollback = (
        f"no network-services bridge-domain instance {bd_name} interface {subif}\n"
        f"no interfaces {subif}\n"
    )
    return {
        "device": leaf,
        "subif": subif,
        "bd_name": bd_name,
        "config": config,
        "rollback": rollback,
    }


def plan_dut(device: str, bundle: str, vlan: int, dut_ip: str, prefixlen: int,
             gateway: str, oob_prefix: str, neighbor: str, asn: str, peer_as: str) -> dict[str, Any]:
    subif = f"{bundle}.{vlan}"
    config = (
        f"interfaces {subif} admin-state enabled\n"
        f"interfaces {subif} description Inband BGP peering vlan {vlan}\n"
        f"interfaces {subif} ipv4-address {dut_ip}/{prefixlen}\n"
        f"interfaces {subif} vlan-id {vlan}\n"
        f"protocols static address-family ipv4-unicast route {oob_prefix} next-hop {gateway}\n"
        f"protocols bgp {asn} neighbor {neighbor} remote-as {peer_as}\n"
        f"protocols bgp {asn} neighbor {neighbor} admin-state enabled\n"
        f"protocols bgp {asn} neighbor {neighbor} passive enabled\n"
        f"protocols bgp {asn} neighbor {neighbor} update-source {subif}\n"
        f"protocols bgp {asn} neighbor {neighbor} ebgp-multihop 10\n"
    )
    rollback = (
        f"no protocols bgp {asn} neighbor {neighbor}\n"
        f"no protocols static address-family ipv4-unicast route {oob_prefix}\n"
        f"no interfaces {subif}\n"
    )
    return {
        "device": device,
        "subif": subif,
        "config": config,
        "rollback": rollback,
    }


def onboard_plan(args: dict[str, Any]) -> dict[str, Any]:
    vlan = args.get("vlan")
    vlan_range = str(args.get("vlan_range") or "")
    device = args.get("device")
    try:
        vlan_i = int(vlan)
    except (TypeError, ValueError):
        return {"ok": False, "verdict": "ERROR", "errors": ["vlan must be an integer"]}
    if vlan_range and not vlan_in_range(vlan_i, vlan_range):
        return {
            "ok": False,
            "verdict": "VLAN_OUT_OF_RANGE",
            "errors": [f"vlan {vlan_i} is not in allocated range {vlan_range}"],
        }
    show_text = str(args.get("bd_show_text") or "")
    hits = match_global_bds(show_text, vlan_i) if show_text else []
    requested_bd = args.get("bd_name")
    if requested_bd:
        hits = [h for h in hits if h["bd_name"] == requested_bd] or (
            [{"bd_name": requested_bd, "bd_type": "global", "global_vlan": vlan_i}] if not show_text else hits
        )
    if show_text and not hits:
        return {
            "ok": False,
            "verdict": "NO_BD",
            "errors": [
                f"no IL DNAAS global bridge-domain g_*_v{vlan_i} found; pick another VLAN or abort",
            ],
            "silent_fallback_forbidden": "g_mgmt_v999",
        }
    if len(hits) > 1 and not requested_bd:
        return {
            "ok": True,
            "verdict": "BD_AMBIGUOUS",
            "vlan": vlan_i,
            "candidates": hits,
            "errors": ["multiple global BDs match; AskQuestion to confirm bd_name"],
        }
    bd_name = (requested_bd or (hits[0]["bd_name"] if hits else None))
    if not bd_name:
        return {
            "ok": False,
            "verdict": "NO_BD",
            "errors": ["bd_name required when BD show text is empty"],
        }
    if vlan_i != 999 and bd_name == "g_mgmt_v999":
        return {
            "ok": False,
            "verdict": "FORBIDDEN_FALLBACK",
            "errors": ["will not attach to g_mgmt_v999 unless vlan is 999"],
        }
    leaf = args.get("dnaas_leaf")
    bundle = args.get("bundle")
    dut_bundle = args.get("dut_bundle") or bundle
    deltas = []
    if leaf and bundle:
        deltas.append(plan_dnaas_ac(str(leaf), str(bundle), vlan_i, bd_name))
    if device and dut_bundle and args.get("dut_ip") and args.get("gateway"):
        subnet = str(args.get("subnet") or "24")
        prefixlen = int(subnet.split("/")[-1]) if "/" in str(subnet) else int(subnet)
        deltas.append(plan_dut(
            str(device), str(dut_bundle), vlan_i,
            str(args["dut_ip"]), prefixlen, str(args["gateway"]),
            str(args.get("oob_prefix") or "100.64.0.0/20"),
            str(args.get("neighbor") or "100.64.6.134"),
            str(args.get("asn") or "1234567"),
            str(args.get("peer_as") or "65200"),
        ))
    return {
        "ok": True,
        "verdict": "PREFLIGHT_COLLECTED",
        "vlan": vlan_i,
        "bd_name": bd_name,
        "candidates": hits,
        "leaf": leaf,
        "subif": f"{bundle}.{vlan_i}" if bundle else None,
        "dut_subif": f"{dut_bundle}.{vlan_i}" if dut_bundle else None,
        "dnos_deltas": deltas,
        "execute": False,
        "note": "dry-run only unless execute=true via MCP after user confirm",
    }


def main() -> int:
    p = argparse.ArgumentParser(description="ExaBGP DNAAS onboard planner (dry-run)")
    p.add_argument("--vlan", type=int, required=True)
    p.add_argument("--vlan-range", default="")
    p.add_argument("--device", default="")
    p.add_argument("--bd-name", default="")
    p.add_argument("--bd-show-file", default="")
    p.add_argument("--dnaas-leaf", default="")
    p.add_argument("--bundle", default="")
    p.add_argument("--dut-ip", default="")
    p.add_argument("--gateway", default="")
    p.add_argument("--subnet", default="24")
    args = p.parse_args()
    show = Path_read(args.bd_show_file) if args.bd_show_file else ""
    plan = onboard_plan({
        "vlan": args.vlan,
        "vlan_range": args.vlan_range,
        "device": args.device,
        "bd_name": args.bd_name or None,
        "bd_show_text": show,
        "dnaas_leaf": args.dnaas_leaf or None,
        "bundle": args.bundle or None,
        "dut_ip": args.dut_ip or None,
        "gateway": args.gateway or None,
        "subnet": args.subnet,
    })
    json.dump(plan, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if plan.get("ok") else 1


def Path_read(path: str) -> str:
    from pathlib import Path
    return Path(path).read_text(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    raise SystemExit(main())
