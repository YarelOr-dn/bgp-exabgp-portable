#!/usr/bin/env python3
"""IL DNAAS global-VLAN onboard planner for portable /BGP (dry-run by default)."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
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
        "role": "dnaas_leaf",
        "subif": subif,
        "bd_name": bd_name,
        "config": config,
        "rollback": rollback,
    }


def load_host_defaults() -> dict[str, Any]:
    path = Path(__file__).resolve().parent / "host_defaults.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def il_leaf_names(blob: str) -> list[str]:
    """IL DNAAS leaves only. Do not substring-match HO-DNAAS-LEAF-* as DNAAS-LEAF-*."""
    found = re.findall(r"(?<![A-Za-z0-9-])DNAAS-LEAF-[A-Za-z0-9-]+", blob or "", re.I)
    out = []
    for n in found:
        if n.upper().startswith("HO-"):
            continue
        if n not in out:
            out.append(n)
    return out


def houston_leaf_rejected(name: str) -> bool:
    n = (name or "").upper()
    return n.startswith("HO-") or "HO-DNAAS" in n


def _parse_afis(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [s.strip() for s in str(raw).split(",") if s.strip()]


def plan_dut(device: str, bundle: str, vlan: int, dut_ip: str, prefixlen: int,
             gateway: str, oob_prefix: str, neighbor: str, asn: str, peer_as: str,
             selected_afis: Optional[list[str]] = None) -> dict[str, Any]:
    subif = f"{bundle}.{vlan}"
    lines = [
        f"interfaces {subif} admin-state enabled",
        f"interfaces {subif} description Inband BGP peering vlan {vlan}",
        f"interfaces {subif} ipv4-address {dut_ip}/{prefixlen}",
        f"interfaces {subif} vlan-id {vlan}",
        f"protocols static address-family ipv4-unicast route {oob_prefix} next-hop {gateway}",
        f"protocols bgp {asn} neighbor {neighbor} remote-as {peer_as}",
        f"protocols bgp {asn} neighbor {neighbor} admin-state enabled",
        f"protocols bgp {asn} neighbor {neighbor} passive enabled",
        f"protocols bgp {asn} neighbor {neighbor} update-source {subif}",
        f"protocols bgp {asn} neighbor {neighbor} ebgp-multihop 10",
    ]
    rb_af = []
    for afi in selected_afis or []:
        lines.append(
            f"protocols bgp {asn} neighbor {neighbor} address-family {afi} "
            f"send-community community-type both soft-reconfiguration inbound"
        )
        lines.append(f"protocols bgp {asn} neighbor {neighbor} address-family {afi} admin-state enabled")
        rb_af.append(f"no protocols bgp {asn} neighbor {neighbor} address-family {afi}")
    rollback = (
        "\n".join(rb_af + [
            f"no protocols bgp {asn} neighbor {neighbor}",
            f"no protocols static address-family ipv4-unicast route {oob_prefix}",
            f"no interfaces {subif}",
        ])
        + "\n"
    )
    return {
        "device": device,
        "role": "dut",
        "subif": subif,
        "config": "\n".join(lines) + "\n",
        "rollback": rollback,
        "selected_afis": list(selected_afis or []),
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
    leaf = args.get("dnaas_leaf")
    if not leaf and not show_text and not args.get("bd_name"):
        return {
            "ok": True,
            "verdict": "NEED_DISCOVER",
            "vlan": vlan_i,
            "device": device,
            "errors": ["dnaas_leaf omitted; handler must walk DUT then re-plan"],
        }
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
    if leaf and houston_leaf_rejected(str(leaf)):
        return {
            "ok": False,
            "verdict": "WRONG_LAB",
            "errors": [f"{leaf} looks like Houston DNAAS; IL onboard needs DNAAS-LEAF-B/D* from ~/SCALER/db/devices.json (lab=il)"],
        }
    bundle = args.get("bundle")
    dut_bundle = args.get("dut_bundle") or bundle
    afis = _parse_afis(args.get("selected_afis") or args.get("families"))
    host = load_host_defaults()
    dut_ip = str(args.get("dut_ip") or "").strip()
    gateway = str(args.get("gateway") or "").strip()
    asn = str(args.get("asn") or "").strip()
    missing = []
    if device and dut_bundle and (dut_ip or gateway or asn or args.get("neighbor")):
        if not dut_ip:
            missing.append("dut_ip")
        if not gateway:
            missing.append("gateway (inband next-hop toward ExaBGP, NOT the DUT IP)")
        if not asn:
            missing.append("asn (DUT BGP local ASN; do not use 1234567 unless that is really the DUT)")
    if dut_ip and gateway and dut_ip.split("/")[0] == gateway.split("/")[0]:
        return {
            "ok": False,
            "verdict": "BAD_GATEWAY",
            "errors": [
                f"gateway {gateway} equals dut_ip {dut_ip}; static next-hop must be the inband gateway on the VLAN, not the DUT address",
            ],
        }
    if missing:
        return {
            "ok": False,
            "verdict": "NEED_PARAMS",
            "errors": missing,
            "host_defaults": {k: host.get(k) for k in ("neighbor", "peer_as", "oob_prefix", "lab")},
        }
    neighbor = str(args.get("neighbor") or host.get("neighbor") or "").strip()
    peer_as = str(args.get("peer_as") or host.get("peer_as") or "").strip()
    oob_prefix = str(args.get("oob_prefix") or host.get("oob_prefix") or "").strip()
    deltas = []
    if leaf and bundle:
        deltas.append(plan_dnaas_ac(str(leaf), str(bundle), vlan_i, bd_name))
    if device and dut_bundle and dut_ip and gateway and asn and neighbor and peer_as:
        subnet = str(args.get("subnet") or "24")
        prefixlen = int(subnet.split("/")[-1]) if "/" in str(subnet) else int(subnet)
        deltas.append(plan_dut(
            str(device), str(dut_bundle), vlan_i,
            dut_ip, prefixlen, gateway,
            oob_prefix or "100.64.0.0/20",
            neighbor, asn, peer_as,
            selected_afis=afis,
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
        "selected_afis": afis,
        "execute": False,
        "note": "plan only; MCP execute=true runs host dnos dry_run; confirm_commit=true commits",
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
