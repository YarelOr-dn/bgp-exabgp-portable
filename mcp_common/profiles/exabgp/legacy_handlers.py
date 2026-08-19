"""profiles.exabgp.legacy_handlers - relocated legacy /EXABGP handler
bodies (Phase 5 monolith split).

Relocated VERBATIM out of ``command_profiles.py``. Each function is RE-HOSTED with
``__globals__ = command_profiles.__dict__`` (see profiles/test/legacy_handlers.py
for the rationale), so bare-name lookups -- shared helpers, factory functions,
sibling handlers, stdlib aliases -- and any runtime monkeypatch / reload resolve
DYNAMICALLY against command_profiles at call time. command_profiles imports this
module just before building its HANDLERS dict and re-binds every name in
``MOVED_NAMES``. The served surface stays byte-for-byte identical (gated by
tests/test_split_contract.py). ``from __future__ import annotations`` keeps the
moved signatures lazy.
"""
from __future__ import annotations

import types as _types

from mcp_common import command_profiles as _cp

# Infra names defined above -- used to identify exactly which names below are
# relocated handlers (prefix-independent, so e.g. _ha never grabs _handoff_*).
_INFRA_NAMES = set(globals()) | {"_INFRA_NAMES"}

# === BEGIN RELOCATED HANDLERS ===
def _exabgp_dir() -> Path:
    env = os.environ.get("EXABGP_BGP_TOOL")
    if env:
        return Path(env).resolve().parent
    return Path(BGP_TOOL).resolve().parent


def _exabgp_owner(args: dict[str, Any]) -> str:
    return str(args.get("owner") or os.environ.get("USER") or "unknown").strip()


def _exabgp_lease_mod():
    d = _exabgp_dir()
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import lease as _lease  # type: ignore
    return _lease


def _exabgp_lease_gate(args: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return _exabgp_lease_mod().require_owner(_exabgp_owner(args))
    except Exception as exc:
        return {"ok": False, "verdict": "LEASE_ERROR", "errors": [str(exc)]}


def _exabgp_guarded_start(args: dict[str, Any]) -> dict[str, Any]:
    blocked = _exabgp_lease_gate(args)
    if blocked:
        return blocked
    if args.get("execute") and not args.get("confirmed_no_live_session"):
        return {
            "ok": False,
            "action": "exabgp start",
            "verdict": "BLOCKED_BY_SESSION_PROTECTION",
            "errors": ["confirmed_no_live_session=true is required before start because bgp_tool.py start can disrupt a live ExaBGP session"],
        }
    cmd = [PYTHON, BGP_TOOL, "start"]
    if args.get("device"):
        cmd += ["--device", str(args["device"])]
    families = args.get("selected_afis") or args.get("families")
    if families:
        cmd += ["--selected-afis", str(families)]
    suggested = _next_call("user-exabgp-mcp", "exabgp_verify", {"device": args.get("device"), "format": "both"}, "Verify the session after start.", "read_only")
    return _dry_or_run("exabgp start", cmd, args, timeout=120, mutating=True, suggested_next_call=suggested)

def _exabgp_preflight(args: dict[str, Any]) -> dict[str, Any]:
    device = args.get("device")
    server_ip = args.get("server_ip") or "100.64.6.134"
    neighbor = args.get("neighbor") or server_ip
    bgp_as = args.get("asn") or args.get("bgp_as")
    commands = [
        f"show route {server_ip} | no-more",
        "show interfaces ge*-*/0/*.999 | no-more",
    ]
    if bgp_as:
        commands.append(f"show config protocols bgp {bgp_as} neighbor {neighbor} | no-more")
    else:
        commands.append("show bgp summary | no-more")
    out = _cached_dnos_show(
        device=device,
        commands=commands,
        fmt=args.get("dnos_format", "text"),
        timeout=int(args.get("timeout_sec") or 120),
        ttl_sec=int(args.get("cache_ttl_sec") or 20),
        refresh=bool(args.get("refresh") or args.get("freshness") == "fresh"),
    )
    out.update({"action": "exabgp preflight", "device": device, "server_ip": server_ip, "commands": commands, "verdict": "PREFLIGHT_COLLECTED" if out.get("ok") else "PREFLIGHT_FAILED"})
    out["suggested_next_call"] = _next_call(
        "user-exabgp-mcp",
        "exabgp_verify",
        {"device": device, "format": "text"},
        "Verify the live ExaBGP session after DUT-side preflight passes.",
        "read_only",
    )
    return out

def _exabgp_stop(args: dict[str, Any]) -> dict[str, Any]:
    phrase = str(args.get("explicit_request_text") or "").lower()
    allowed = any(x in phrase for x in ["/bgp stop", "stop the bgp session", "stop exabgp", "kill the bgp session", "kill exabgp", "bring down bgp", "shut down bgp"])
    if not allowed:
        return {
            "ok": False,
            "action": "exabgp stop",
            "verdict": "BLOCKED_BY_SESSION_PROTECTION",
            "errors": ["current user message must explicitly request stopping BGP/ExaBGP"],
        }
    blocked = _exabgp_lease_gate(args)
    if blocked:
        return blocked
    return _dry_or_run("exabgp stop", [PYTHON, BGP_TOOL, "stop"], args, timeout=60, mutating=True, confirm_required=True)

def _exabgp_simple(action: str, verb: str, mutating: bool = False) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if mutating:
            blocked = _exabgp_lease_gate(args)
            if blocked:
                return blocked
        cmd = [PYTHON, BGP_TOOL, verb]
        for key in ("session_id", "file", "route", "prefix", "afi", "count", "device"):
            if args.get(key) is not None:
                cmd += [f"--{key.replace('_', '-')}", str(args[key])]
        return _dry_or_run(action, cmd, args if mutating else {**args, "execute": True}, timeout=120, mutating=mutating)
    return handler

def _exabgp_session_lock(args: dict[str, Any]) -> dict[str, Any]:
    mod = _exabgp_lease_mod()
    owner = _exabgp_owner(args)
    if args.get("acquire") is False:
        st = mod.status()
        st["action"] = "exabgp session lock"
        return st
    return {**mod.acquire(owner, dut=args.get("dut"), ttl_sec=int(args.get("ttl_sec") or 3600), force=bool(args.get("force"))), "action": "exabgp session lock"}

def _exabgp_session_release(args: dict[str, Any]) -> dict[str, Any]:
    mod = _exabgp_lease_mod()
    return {**mod.release(_exabgp_owner(args), force=bool(args.get("force"))), "action": "exabgp session release"}

def _exabgp_atomic_json(path: Path, payload: dict[str, Any]) -> None:
    import tempfile as _tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = _tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _exabgp_walk_leaves(device: str, timeout: int) -> dict[str, Any]:
    d = _exabgp_dir()
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import onboard as _onboard  # type: ignore
    listed = _dnos_tool("dnos_list_devices", {"format": "text"}, timeout=timeout)
    walk = _dnos_tool("dnos_dnaas_walk_from_dut", {"device_name": device, "format": "text"}, timeout=timeout)
    blob = json.dumps({"list": listed, "walk": walk}, default=str)
    leaves = _onboard.il_leaf_names(blob)
    houston = sorted(set(re.findall(r"HO-DNAAS-LEAF[-_A-Za-z0-9]+", blob, re.I)))
    bundles = sorted(set(re.findall(r"bundle-\d+", blob, re.I)))
    return {
        "leaves": leaves,
        "houston_leaves_ignored": houston,
        "bundles": bundles,
        "list_ok": listed.get("ok"),
        "walk_ok": walk.get("ok"),
        "lab": "il",
    }


def _exabgp_dry_ok(result: dict[str, Any]) -> tuple[bool, str]:
    text = json.dumps(result, default=str)
    if "DeviceResolveError" in text:
        return False, "DEVICE_RESOLVE"
    if "not found in" in text.lower() and "devices" in text.lower():
        return False, "DEVICE_RESOLVE"
    low = text.lower()
    if "already exist" in low or "no configuration changes" in low or "unchanged" in low:
        return True, "ALREADY_PRESENT"
    if result.get("ok") is False:
        return False, "DRY_RUN_FAIL"
    return True, "DRY_RUN_OK"


def _exabgp_commit_delta(delta: dict[str, Any], *, dry_run: bool, timeout: int) -> dict[str, Any]:
    return _dnos_tool(
        "dnos_atomic_commit",
        {
            "device_name": delta["device"],
            "config_text": delta["config"],
            "dry_run": bool(dry_run),
            "format": "text",
        },
        timeout=timeout,
    )


def _exabgp_onboard(args: dict[str, Any]) -> dict[str, Any]:
    d = _exabgp_dir()
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import onboard as _onboard  # type: ignore
    vlan = args.get("vlan")
    timeout = int(args.get("timeout_sec") or 120)
    show_text = str(args.get("bd_show_text") or "")
    leaf = args.get("dnaas_leaf")
    device = args.get("device")
    discover = None
    if not leaf and not show_text and device:
        discover = _exabgp_walk_leaves(str(device), timeout)
        leaves = discover["leaves"]
        if not leaves:
            return {
                "ok": False,
                "action": "exabgp onboard",
                "verdict": "NO_LEAF",
                "errors": ["no DNAAS-LEAF found via dnos_list_devices / dnos_dnaas_walk_from_dut"],
                "discover": discover,
            }
        if len(leaves) > 1:
            return {
                "ok": True,
                "action": "exabgp onboard",
                "verdict": "LEAF_AMBIGUOUS",
                "candidates": [{"dnaas_leaf": n} for n in leaves],
                "discover": discover,
                "errors": ["multiple DNAAS leaves; AskQuestion to pick dnaas_leaf"],
            }
        leaf = leaves[0]
        args = {**args, "dnaas_leaf": leaf}
        if not args.get("bundle") and discover["bundles"]:
            args = {**args, "bundle": discover["bundles"][0]}
    if not show_text and leaf:
        out = _cached_dnos_show(
            device=leaf,
            commands=[f'show config network-services bridge-domain | include regex "g_.*_v{int(vlan)}"'],
            fmt=args.get("dnos_format", "text"),
            timeout=timeout,
            ttl_sec=20,
            refresh=True,
        )
        show_text = str((out.get("dnos_result") or out.get("text") or out.get("output") or ""))
        args = {**args, "bd_show_text": show_text}
        args["_dnaas_query"] = {"ok": out.get("ok"), "leaf": leaf}
    plan = _onboard.onboard_plan(args)
    plan["action"] = "exabgp onboard"
    if discover:
        plan["discover"] = discover
    if plan.get("verdict") in {"BD_AMBIGUOUS", "NEED_DISCOVER", "NO_BD", "VLAN_OUT_OF_RANGE", "FORBIDDEN_FALLBACK"}:
        return plan
    next_args = {
        "vlan": vlan,
        "device": args.get("device"),
        "bd_name": plan.get("bd_name"),
        "dnaas_leaf": args.get("dnaas_leaf"),
        "bundle": args.get("bundle"),
        "selected_afis": args.get("selected_afis"),
        "execute": True,
        "format": "text",
    }
    if not args.get("execute"):
        plan["suggested_next_call"] = _next_call(
            "user-exabgp-mcp", "exabgp_onboard",
            next_args,
            "After AskQuestion confirm BD/sub-if, re-call with execute=true (host dry_run).",
            "mutating",
        )
        return plan
    blocked = _exabgp_lease_gate(args)
    if blocked:
        return blocked
    deltas = list(plan.get("dnos_deltas") or [])
    if not deltas:
        return {**plan, "ok": False, "verdict": "NO_DELTAS", "errors": ["no dnos_deltas to dry_run/commit"]}
    ordered = [x for x in deltas if x.get("role") == "dnaas_leaf"] + [x for x in deltas if x.get("role") != "dnaas_leaf"]
    if not args.get("confirm_commit"):
        dry = []
        all_ok = True
        reasons = []
        for delta in ordered:
            result = _exabgp_commit_delta(delta, dry_run=True, timeout=timeout)
            ok, why = _exabgp_dry_ok(result)
            dry.append({"device": delta["device"], "role": delta.get("role"), "result": result, "delta_verdict": why})
            if not ok:
                all_ok = False
                reasons.append(f"{delta['device']}:{why}")
        plan["dry_run"] = dry
        if not all_ok:
            plan["ok"] = False
            plan["verdict"] = "DRY_RUN_FAIL"
            plan["errors"] = [
                "host dnos dry_run did not resolve/apply on IL devices.json",
                *reasons,
                "Use DNAAS-LEAF-B10/B14/B15/D16 (lab=il). Do not use HO-DNAAS-* / Houston devices.houston.json.",
                "DUT asn is required. gateway must be the inband GW, not dut_ip. neighbor defaults to this host 100.64.6.134.",
            ]
            return plan
        plan["ok"] = True
        plan["verdict"] = "DRY_RUN_OK"
        plan["note"] = "host dnos dry_run only; re-call with confirm_commit=true to commit"
        plan["suggested_next_call"] = _next_call(
            "user-exabgp-mcp", "exabgp_onboard",
            {**next_args, "confirm_commit": True, "execute": True},
            "After user confirms dry-run diffs, re-call with confirm_commit=true.",
            "mutating",
        )
        return plan
    committed = []
    leaf_done = None
    for delta in ordered:
        result = _exabgp_commit_delta(delta, dry_run=False, timeout=timeout)
        committed.append({"device": delta["device"], "role": delta.get("role"), "result": result})
        failed = (not result.get("ok")) or ("ERROR" in str(result).upper() and "Overall ERROR" in str(result))
        if failed and delta.get("role") == "dnaas_leaf":
            return {**plan, "ok": False, "verdict": "COMMIT_LEAF_FAILED", "commits": committed}
        if failed:
            if leaf_done and leaf_done.get("rollback"):
                _dnos_tool(
                    "dnos_atomic_commit",
                    {"device_name": leaf_done["device"], "config_text": leaf_done["rollback"], "format": "text"},
                    timeout=timeout,
                )
            return {**plan, "ok": False, "verdict": "COMMIT_DUT_FAILED_LEAF_ROLLED", "commits": committed}
        if delta.get("role") == "dnaas_leaf":
            leaf_done = delta
    rb_path = d / "sessions" / f"onboard_{_exabgp_owner(args)}.json"
    _exabgp_atomic_json(rb_path, {
        "owner": _exabgp_owner(args),
        "vlan": vlan,
        "rollback": [{"device": x["device"], "role": x.get("role"), "rollback": x.get("rollback")} for x in reversed(ordered)],
    })
    plan["ok"] = True
    plan["verdict"] = "COMMITTED"
    plan["commits"] = committed
    plan["rollback_file"] = str(rb_path)
    plan["suggested_next_call"] = _next_call(
        "user-exabgp-mcp", "exabgp_start",
        {"device": args.get("device"), "selected_afis": args.get("selected_afis"), "execute": True, "format": "text"},
        "Start ExaBGP with selected_afis after commit.",
        "mutating",
    )
    return plan

def _exabgp_malform(args: dict[str, Any]) -> dict[str, Any]:
    catalog = [
        "bad-marker", "bad-length", "oversized",
        "truncated-nlri", "bad-afi-safi",
        "duplicate-attr", "bad-origin", "bad-community",
        "bad-extcommunity-0x0c",
    ]
    d = _exabgp_dir()
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    try:
        import malform as _mal  # type: ignore
        catalog = sorted(_mal.MALFORMATIONS.keys())
    except Exception:
        pass
    if args.get("list_types"):
        return {
            "ok": True,
            "action": "exabgp malform",
            "verdict": "CATALOG",
            "types": catalog,
            "note": "Named catalog only. Well-formed inject uses exabgp_inject. EVPN wire tricks: spirent_bgp_raw_update / spirent_raw_frame.",
        }
    mtype = str(args.get("malform_type") or args.get("type") or "")
    if mtype not in catalog:
        return {"ok": False, "action": "exabgp malform", "verdict": "UNKNOWN_TYPE", "errors": [f"unknown type {mtype!r}"], "types": catalog}
    blocked = _exabgp_lease_gate(args)
    if blocked:
        return blocked
    target = args.get("target_ip") or args.get("device")
    if args.get("execute") and not target:
        return {"ok": False, "action": "exabgp malform", "errors": ["target_ip is required to send"]}
    cmd = [PYTHON, BGP_TOOL, "malform", "--type", mtype]
    if target:
        cmd += ["--target-ip", str(target)]
    if args.get("local_as") is not None:
        cmd += ["--local-as", str(args["local_as"])]
    if args.get("peer_as") is not None:
        cmd += ["--peer-as", str(args["peer_as"])]
    return _dry_or_run(
        "exabgp malform",
        cmd,
        args,
        timeout=int(args.get("timeout_sec") or 60),
        mutating=True,
        suggested_next_call=_next_call(
            "user-exabgp-mcp", "exabgp_verify",
            {"device": args.get("device"), "format": "text"},
            "Verify DUT BGP after malform (session may have dropped).",
            "read_only",
        ),
    )

def _exabgp_save(args: dict[str, Any]) -> dict[str, Any]:
    payload = normalize_handoff_payload(args.get("payload") or {
        "user_intent": "BGP session handoff",
        "source_command": "/BGP",
        "active_devices": [args.get("device")] if args.get("device") else [],
        "session": args.get("session_id"),
    })
    return save_handoff(payload, source_command="/BGP", tags=["bgp", "exabgp"])

def _exabgp_route_inventory(args: dict[str, Any]) -> dict[str, Any]:
    roots = [Path("/home/dn/SCALER/FLOWSPEC_VPN/exabgp"), Path("/tmp")]
    patterns = ["*.routes", "*.json", "*.conf"]
    files = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in patterns:
            files.extend(str(p) for p in sorted(root.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)[:20])
    status = _exabgp_simple("exabgp verify", "verify")({"session_id": args.get("session_id"), "device": args.get("device")})
    return {"ok": True, "action": "exabgp route inventory", "verdict": "INVENTORY_READY", "files": files[:50], "status": status}

def _exabgp_session_handoff(args: dict[str, Any]) -> dict[str, Any]:
    payload = normalize_handoff_payload({
        "user_intent": "BGP session handoff",
        "source_command": "/BGP",
        "device": args.get("device"),
        "sessions": [{"session_id": args.get("session_id"), "state": args.get("state")}],
        "next_actions": args.get("next_actions") or [],
        "safety_notes": ["Do not stop or restart ExaBGP unless the current user explicitly requests it."],
    })
    return save_handoff(payload, source_command="/BGP", tags=["bgp", "exabgp"])


def _exabgp_family_mods():
    d = _exabgp_dir()
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import family_registry as _fr  # type: ignore
    import rfc_synthesize as _rs  # type: ignore
    import capability_speaker as _cs  # type: ignore
    return _fr, _rs, _cs


def _exabgp_parse_spec(args: dict[str, Any]) -> dict[str, Any]:
    raw = args.get("spec_json")
    spec: dict[str, Any] = {}
    if isinstance(raw, dict):
        spec = dict(raw)
    elif raw:
        spec = json.loads(str(raw))
    if args.get("name"):
        spec["name"] = args["name"]
    if args.get("afi") is not None:
        spec["afi"] = args["afi"]
    if args.get("safi") is not None:
        spec["safi"] = args["safi"]
    cap = dict(spec.get("capability") or {})
    if args.get("capability_code") is not None:
        cap["code"] = args["capability_code"]
    if args.get("capability_value_hex"):
        cap["value_hex"] = args["capability_value_hex"]
    if cap:
        spec["capability"] = cap
    encs = args.get("nlri_encodings")
    if encs:
        spec["nlri_tlvs"] = [{"name": f"f{i}", "type": i, "encoding": t.strip()} for i, t in enumerate(str(encs).split(",")) if t.strip()]
    if args.get("rfc") or args.get("section"):
        spec["source"] = {"rfc": args.get("rfc"), "section": args.get("section")}
    spec["override"] = bool(args.get("override") or spec.get("override"))
    spec.setdefault("path_attrs", spec.get("path_attrs") or [])
    spec.setdefault("nlri_tlvs", spec.get("nlri_tlvs") or [])
    return spec


def _exabgp_family_register(args: dict[str, Any]) -> dict[str, Any]:
    fr, _rs, _cs = _exabgp_family_mods()
    spec = _exabgp_parse_spec(args)
    owner = _exabgp_owner(args)
    if args.get("publish"):
        out = fr.publish(spec, owner=owner)
    else:
        out = fr.save_draft(spec, owner)
    out["action"] = "exabgp family register"
    out["dnos_af_hint"] = fr.dnos_af_hint(str(spec.get("name") or ""))
    return out


def _exabgp_family_list(args: dict[str, Any]) -> dict[str, Any]:
    fr, _rs, _cs = _exabgp_family_mods()
    out = fr.list_families(_exabgp_owner(args))
    out["action"] = "exabgp family list"
    return out


def _exabgp_family_show(args: dict[str, Any]) -> dict[str, Any]:
    fr, _rs, _cs = _exabgp_family_mods()
    found = fr.get_family(str(args.get("name") or ""), owner=_exabgp_owner(args))
    if not found:
        return {"ok": False, "action": "exabgp family show", "verdict": "NOT_FOUND"}
    return {"ok": True, "action": "exabgp family show", "spec": found}


def _exabgp_family_unregister(args: dict[str, Any]) -> dict[str, Any]:
    fr, _rs, _cs = _exabgp_family_mods()
    out = fr.unregister(str(args.get("name") or ""))
    out["action"] = "exabgp family unregister"
    return out


def _exabgp_rfc_synthesize(args: dict[str, Any]) -> dict[str, Any]:
    _fr, rs, _cs = _exabgp_family_mods()
    spec = _exabgp_parse_spec(args)
    out = rs.stage(spec, _exabgp_owner(args), plugin_src=args.get("plugin_src"), rfc_text=args.get("rfc_text"))
    out["action"] = "exabgp rfc synthesize"
    return out


def _exabgp_capability_probe(args: dict[str, Any]) -> dict[str, Any]:
    fr, _rs, cs = _exabgp_family_mods()
    spec = None
    if args.get("spec_json") or args.get("afi") is not None:
        spec = _exabgp_parse_spec(args)
    elif args.get("name"):
        spec = fr.get_family(str(args["name"]), owner=_exabgp_owner(args))
    if not spec:
        return {"ok": False, "action": "exabgp capability probe", "verdict": "NOT_FOUND", "errors": ["name or spec_json required"]}
    mode = str(args.get("mode") or "dump_only")
    kwargs = {
        "local_as": args.get("local_as") or 65200,
        "router_id": args.get("router_id") or "100.64.6.134",
        "next_hop": args.get("next_hop") or args.get("router_id") or "100.64.6.134",
        "timeout_sec": args.get("timeout_sec") or 8,
    }
    if not args.get("execute") or mode == "dump_only":
        out = cs.dump_frames(spec, **kwargs)
        out["action"] = "exabgp capability probe"
        out["mode"] = "dump_only"
        return out
    blocked = _exabgp_lease_gate(args)
    if blocked:
        return blocked
    if mode == "probe_port":
        out = cs.run_probe_port(spec, **kwargs)
    else:
        target = str(args.get("target_ip") or "")
        if not target:
            return {"ok": False, "action": "exabgp capability probe", "verdict": "ERROR", "errors": ["target_ip required for transient"]}
        out = cs.run_transient(spec, target, **kwargs)
    out["action"] = "exabgp capability probe"
    out["mode"] = mode
    return out


def _exabgp_family_promote(args: dict[str, Any]) -> dict[str, Any]:
    _fr, rs, _cs = _exabgp_family_mods()
    out = rs.promote(str(args.get("name") or ""), _exabgp_owner(args))
    out["action"] = "exabgp family promote"
    return out


# === END RELOCATED HANDLERS ===

# Names of the relocated handlers (everything defined between the markers).
MOVED_NAMES = sorted(_n for _n in list(globals())
                     if _n not in _INFRA_NAMES and not (_n.startswith("__") and _n.endswith("__")))

# Re-host each relocated function onto command_profiles' LIVE module namespace.
for _n in MOVED_NAMES:
    _f = globals()[_n]
    _rehosted = _types.FunctionType(_f.__code__, _cp.__dict__, _f.__name__,
                                    _f.__defaults__, _f.__closure__)
    _rehosted.__kwdefaults__ = _f.__kwdefaults__
    _rehosted.__dict__.update(_f.__dict__)
    _rehosted.__module__ = _f.__module__
    _rehosted.__qualname__ = _f.__qualname__
    _rehosted.__doc__ = _f.__doc__
    globals()[_n] = _rehosted
    setattr(_cp, _n, _rehosted)

if MOVED_NAMES:
    del _n, _f, _rehosted


# === BEGIN VERTICAL HANDLERS (Phase 5 crash-isolation) ===
# This vertical's tool_name -> handler map. Built after re-host so every
# referenced name resolves to its command_profiles-hosted form. command_profiles
# merges this dict defensively (a load failure degrades only this vertical).
HANDLERS = {
    'exabgp_start': _exabgp_guarded_start,
    'exabgp_preflight': _exabgp_preflight,
    'exabgp_stop': _exabgp_stop,
    'exabgp_inject': _exabgp_simple("exabgp inject", "inject", mutating=True),
    'exabgp_withdraw': _exabgp_simple("exabgp withdraw", "withdraw", mutating=True),
    'exabgp_verify': _exabgp_simple("exabgp verify", "verify"),
    'exabgp_diagnose': _exabgp_simple("exabgp diagnose", "diagnose"),
    'exabgp_watchdog_status': _exabgp_simple("exabgp watchdog status", "watchdog-status"),
    'exabgp_route_inventory': _exabgp_route_inventory,
    'exabgp_session_handoff': _exabgp_session_handoff,
    'exabgp_session_save': _exabgp_save,
    'exabgp_session_lock': _exabgp_session_lock,
    'exabgp_session_release': _exabgp_session_release,
    'exabgp_onboard': _exabgp_onboard,
    'exabgp_malform': _exabgp_malform,
    'exabgp_family_register': _exabgp_family_register,
    'exabgp_family_list': _exabgp_family_list,
    'exabgp_family_show': _exabgp_family_show,
    'exabgp_family_unregister': _exabgp_family_unregister,
    'exabgp_rfc_synthesize': _exabgp_rfc_synthesize,
    'exabgp_capability_probe': _exabgp_capability_probe,
    'exabgp_family_promote': _exabgp_family_promote,
}
