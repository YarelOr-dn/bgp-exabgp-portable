#!/usr/bin/env python3
"""RFC-driven BGP family/capability registry. Spec-only JSON; atomic writes."""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import socket
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path(__file__).resolve().parent
FAMILIES_DIR = BASE_DIR / "families"
REGISTRY_FILE = FAMILIES_DIR / "registry.json"
LOCK_FILE = FAMILIES_DIR / "registry.lock"
SESSIONS_DIR = BASE_DIR / "sessions" / "families"
MAX_FRAME = 4096

BUILTIN_FAMILIES: dict[str, dict[str, Any]] = {
    "ipv4-unicast": {"afi": 1, "safi": 1, "capability": {"code": 1}},
    "ipv6-unicast": {"afi": 2, "safi": 1, "capability": {"code": 1}},
    "ipv4-multicast": {"afi": 1, "safi": 2, "capability": {"code": 1}},
    "ipv4-labeled-unicast": {"afi": 1, "safi": 4, "capability": {"code": 1}},
    "ipv6-labeled-unicast": {"afi": 2, "safi": 4, "capability": {"code": 1}},
    "ipv4-vpn": {"afi": 1, "safi": 128, "capability": {"code": 1}},
    "ipv6-vpn": {"afi": 2, "safi": 128, "capability": {"code": 1}},
    "ipv4-rt-constrains": {"afi": 1, "safi": 132, "capability": {"code": 1}},
    "ipv4-flowspec": {"afi": 1, "safi": 133, "capability": {"code": 1}},
    "ipv4-flowspec-vpn": {"afi": 1, "safi": 134, "capability": {"code": 1}},
    "ipv6-flowspec": {"afi": 2, "safi": 133, "capability": {"code": 1}},
    "ipv6-flowspec-vpn": {"afi": 2, "safi": 134, "capability": {"code": 1}},
    "l2vpn-vpls": {"afi": 25, "safi": 65, "capability": {"code": 1}},
    "l2vpn-evpn": {"afi": 25, "safi": 70, "capability": {"code": 1}},
    "link-state": {"afi": 16388, "safi": 71, "capability": {"code": 1}},
}
BUILTIN_CAP_CODES = {1, 2, 65}

ENC_RE = re.compile(
    r"^(u8|u16|u32|hex|ipv4|ipv6|rd|prefix|rt|arg):(.+)$"
)


def _atomic_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name + ".", suffix=".tmp")
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


def encode_rd(rd_str: str) -> bytes:
    parts = rd_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid RD format: {rd_str}")
    try:
        ip_bytes = socket.inet_aton(parts[0])
        nn = int(parts[1])
        return struct.pack("!H", 1) + ip_bytes + struct.pack("!H", nn)
    except (OSError, ValueError, socket.error):
        pass
    asn = int(parts[0])
    nn = int(parts[1])
    if asn <= 65535:
        return struct.pack("!HHI", 0, asn, nn)
    return struct.pack("!HIH", 2, asn, nn)


def encode_rt(rt_str: str) -> bytes:
    parts = rt_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid RT: {rt_str}")
    if "." in parts[0]:
        ip_bytes = socket.inet_aton(parts[0])
        nn = int(parts[1])
        return b"\x01\x02" + ip_bytes + struct.pack("!H", nn)
    asn = int(parts[0])
    nn = int(parts[1])
    if asn <= 65535:
        return b"\x00\x02" + struct.pack("!HI", asn, nn)
    return b"\x02\x02" + struct.pack("!IH", asn, nn)


def encode_prefix(cidr: str) -> bytes:
    net = ipaddress.ip_network(cidr, strict=False)
    plen = net.prefixlen
    packed = net.network_address.packed
    n = (plen + 7) // 8
    return struct.pack("!B", plen) + packed[:n]


def encode_token(token: str, args: Optional[dict[str, Any]] = None) -> bytes:
    m = ENC_RE.match((token or "").strip())
    if not m:
        raise ValueError(f"unknown encoding token: {token!r}")
    kind, raw = m.group(1), m.group(2)
    args = args or {}
    if kind == "arg":
        bound = args.get(raw)
        if bound is None:
            raise ValueError(f"unbound arg:{raw}")
        if isinstance(bound, bytes):
            return bound
        return encode_token(str(bound), args)
    if kind == "u8":
        v = int(raw, 0)
        if not 0 <= v <= 255:
            raise ValueError(f"u8 out of range: {v}")
        return struct.pack("!B", v)
    if kind == "u16":
        v = int(raw, 0)
        if not 0 <= v <= 65535:
            raise ValueError(f"u16 out of range: {v}")
        return struct.pack("!H", v)
    if kind == "u32":
        v = int(raw, 0)
        if not 0 <= v <= 0xFFFFFFFF:
            raise ValueError(f"u32 out of range: {v}")
        return struct.pack("!I", v)
    if kind == "hex":
        h = raw.replace(" ", "").replace(":", "")
        if len(h) % 2:
            raise ValueError(f"hex odd length: {raw}")
        return bytes.fromhex(h)
    if kind == "ipv4":
        return socket.inet_aton(raw)
    if kind == "ipv6":
        return socket.inet_pton(socket.AF_INET6, raw)
    if kind == "rd":
        return encode_rd(raw)
    if kind == "rt":
        return encode_rt(raw)
    if kind == "prefix":
        return encode_prefix(raw)
    raise ValueError(f"unknown encoding token: {token!r}")


def _estimate_size(spec: dict[str, Any]) -> int:
    n = 19 + 10
    cap = spec.get("capability") or {}
    if cap.get("value_hex"):
        try:
            n += 4 + len(bytes.fromhex(str(cap["value_hex"]).replace(" ", "")))
        except ValueError:
            n += 8
    else:
        n += 8
    for tlv in spec.get("nlri_tlvs") or []:
        enc = tlv.get("encoding") or ""
        if enc.startswith("arg:"):
            n += 32
            continue
        try:
            n += len(encode_token(enc))
        except Exception:
            n += 16
    for pa in spec.get("path_attrs") or []:
        vt = pa.get("value_template") or "hex:"
        if vt.startswith("arg:"):
            n += 32
            continue
        try:
            n += 3 + len(encode_token(vt))
        except Exception:
            n += 16
    return n + 64


def validate_spec(spec: dict[str, Any], *, published: Optional[dict[str, Any]] = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(spec, dict):
        return ["spec must be an object"]
    name = str(spec.get("name") or "").strip()
    if not name or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", name):
        errors.append("name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
    try:
        afi = int(spec.get("afi"))
    except (TypeError, ValueError):
        errors.append("afi must be an integer")
        afi = -1
    try:
        safi = int(spec.get("safi"))
    except (TypeError, ValueError):
        errors.append("safi must be an integer")
        safi = -1
    if afi >= 0 and not 0 <= afi <= 65535:
        errors.append(f"afi out of range: {afi}")
    if safi >= 0 and not 0 <= safi <= 255:
        errors.append(f"safi out of range: {safi}")
    cap = spec.get("capability") or {}
    if not isinstance(cap, dict):
        errors.append("capability must be an object")
        cap = {}
    try:
        ccode = int(cap.get("code")) if cap.get("code") is not None else None
    except (TypeError, ValueError):
        errors.append("capability.code must be an integer")
        ccode = None
    if ccode is not None and not 0 <= ccode <= 255:
        errors.append(f"capability.code out of range: {ccode}")
    if cap.get("value_hex"):
        try:
            encode_token("hex:" + str(cap["value_hex"]).replace(" ", ""))
        except Exception as exc:
            errors.append(f"capability.value_hex: {exc}")
    override = bool(spec.get("override"))
    if name in BUILTIN_FAMILIES and not override:
        errors.append(f"name collides with builtin {name} (set override=true)")
    if ccode in BUILTIN_CAP_CODES and ccode not in (1, 2, 65) and not override:
        errors.append(f"capability.code {ccode} collides with builtin")
    for pair_name, b in BUILTIN_FAMILIES.items():
        if afi == b["afi"] and safi == b["safi"] and name != pair_name and not override:
            errors.append(f"(afi,safi)=({afi},{safi}) collides with builtin {pair_name}")
            break
    published = published if published is not None else load_registry().get("families") or {}
    for other_name, other in published.items():
        if other_name == name:
            continue
        if int(other.get("afi", -1)) == afi and int(other.get("safi", -2)) == safi and not override:
            errors.append(f"(afi,safi)=({afi},{safi}) collides with published {other_name}")
    for i, tlv in enumerate(spec.get("nlri_tlvs") or []):
        enc = str((tlv or {}).get("encoding") or "")
        if not ENC_RE.match(enc):
            errors.append(f"nlri_tlvs[{i}].encoding not in closed grammar: {enc!r}")
            continue
        if enc.startswith("arg:"):
            continue
        try:
            encode_token(enc)
        except Exception as exc:
            errors.append(f"nlri_tlvs[{i}].encoding: {exc}")
    for i, pa in enumerate(spec.get("path_attrs") or []):
        vt = str((pa or {}).get("value_template") or "")
        if not ENC_RE.match(vt):
            errors.append(f"path_attrs[{i}].value_template not in closed grammar: {vt!r}")
            continue
        if vt.startswith("arg:"):
            continue
        try:
            encode_token(vt)
        except Exception as exc:
            errors.append(f"path_attrs[{i}].value_template: {exc}")
        try:
            flags = int((pa or {}).get("flags", 0x40))
            tc = int((pa or {}).get("type_code"))
            if not 0 <= flags <= 255 or not 0 <= tc <= 255:
                errors.append(f"path_attrs[{i}] flags/type_code out of range")
        except (TypeError, ValueError):
            errors.append(f"path_attrs[{i}] flags/type_code must be integers")
    est = _estimate_size(spec)
    if est > MAX_FRAME:
        errors.append(f"estimated frame {est} > {MAX_FRAME}")
    return errors


def _lock_ctx():
    FAMILIES_DIR.mkdir(parents=True, exist_ok=True)
    fh = open(LOCK_FILE, "a+", encoding="utf-8")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    return fh


def load_registry() -> dict[str, Any]:
    if not REGISTRY_FILE.exists():
        return {"families": {}, "updated_at": None}
    try:
        data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"families": {}, "updated_at": None}
        data.setdefault("families", {})
        return data
    except (json.JSONDecodeError, OSError):
        return {"families": {}, "updated_at": None}


def save_draft(spec: dict[str, Any], owner: str) -> dict[str, Any]:
    errs = validate_spec(spec)
    if errs:
        return {"ok": False, "verdict": "INVALID_SPEC", "errors": errs}
    owner = str(owner or "unknown").strip()
    spec = {**spec, "owner": owner, "created_at": spec.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    path = SESSIONS_DIR / owner / f"{spec['name']}.json"
    _atomic_write(path, spec)
    return {"ok": True, "verdict": "DRAFT_SAVED", "path": str(path), "spec": spec}


def draft_path(owner: str, name: str) -> Path:
    return SESSIONS_DIR / str(owner) / f"{name}.json"


def load_draft(owner: str, name: str) -> Optional[dict[str, Any]]:
    p = draft_path(owner, name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def publish(spec: dict[str, Any], owner: str | None = None) -> dict[str, Any]:
    lock = _lock_ctx()
    try:
        spec = dict(spec)
        if owner:
            spec["owner"] = owner
        reg = load_registry()
        errs = validate_spec(spec, published=reg.get("families") or {})
        if errs:
            return {"ok": False, "verdict": "INVALID_SPEC", "errors": errs}
        name = spec["name"]
        backup = None
        if REGISTRY_FILE.exists():
            ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            backup = FAMILIES_DIR / f"registry.json.bak_{ts}"
            backup.write_bytes(REGISTRY_FILE.read_bytes())
        families = dict(reg.get("families") or {})
        families[name] = spec
        payload = {"families": families, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _atomic_write(REGISTRY_FILE, payload)
        return {"ok": True, "verdict": "PUBLISHED", "name": name, "backup": str(backup) if backup else None}
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def unregister(name: str) -> dict[str, Any]:
    lock = _lock_ctx()
    try:
        reg = load_registry()
        families = dict(reg.get("families") or {})
        if name not in families:
            return {"ok": False, "verdict": "NOT_FOUND", "errors": [f"no published family {name}"]}
        backup = None
        if REGISTRY_FILE.exists():
            ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            backup = FAMILIES_DIR / f"registry.json.bak_{ts}"
            backup.write_bytes(REGISTRY_FILE.read_bytes())
        families.pop(name)
        payload = {"families": families, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _atomic_write(REGISTRY_FILE, payload)
        return {"ok": True, "verdict": "UNREGISTERED", "name": name, "backup": str(backup) if backup else None}
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def get_family(name: str, owner: str | None = None) -> Optional[dict[str, Any]]:
    if name in BUILTIN_FAMILIES:
        return {"name": name, "builtin": True, **BUILTIN_FAMILIES[name]}
    pub = (load_registry().get("families") or {}).get(name)
    if pub:
        return pub
    if owner:
        return load_draft(owner, name)
    return None


def list_families(owner: str | None = None) -> dict[str, Any]:
    drafts = []
    if owner:
        ddir = SESSIONS_DIR / owner
        if ddir.exists():
            for p in sorted(ddir.glob("*.json")):
                try:
                    drafts.append(json.loads(p.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError):
                    continue
    return {
        "ok": True,
        "builtins": sorted(BUILTIN_FAMILIES),
        "published": load_registry().get("families") or {},
        "drafts": drafts,
    }


def dnos_af_hint(name: str) -> dict[str, Any]:
    """Optional Step-0: whether a verified DNOS AF name exists. Never guesses CLI."""
    import subprocess
    try:
        r = subprocess.run(
            ["python3", str(Path.home() / ".cursor/tools/dnos_cli_cache_lookup.py"), "address-family", name],
            capture_output=True, text=True, timeout=5,
        )
        return {"cache_hit": r.returncode == 0, "output_head": (r.stdout or "")[:400]}
    except Exception as exc:
        return {"cache_hit": False, "error": str(exc)}
