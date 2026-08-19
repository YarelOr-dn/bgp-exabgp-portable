#!/usr/bin/env python3
"""Generic BGP OPEN/UPDATE speaker from a FAMILY_SCHEMA spec.

Modes: dump_only (default, no socket), transient (connect DUT:179),
probe_port (bind ephemeral listener). ExaBGP pipe is documented only --
this module never writes /run/exabgp.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from typing import Any, Optional

from family_registry import MAX_FRAME, encode_token, get_family, validate_spec

BGP_MARKER = b"\xff" * 16
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4
PA_ORIGIN = 1
PA_AS_PATH = 2
PA_MP_REACH_NLRI = 14
AS_TRANS = 23456


def build_header(msg_type: int, payload: bytes, marker: Optional[bytes] = None) -> bytes:
    if marker is None:
        marker = BGP_MARKER
    length = 19 + len(payload)
    return marker + struct.pack("!HB", length, msg_type) + payload


def build_attr(flags: int, type_code: int, value: bytes) -> bytes:
    if len(value) > 255:
        flags |= 0x10
        return struct.pack("!BBH", flags, type_code, len(value)) + value
    return struct.pack("!BBB", flags, type_code, len(value)) + value


def parse_header(msg: bytes) -> dict[str, Any]:
    if len(msg) < 19:
        return {"ok": False, "errors": ["short message"]}
    length = struct.unpack("!H", msg[16:18])[0]
    mtype = msg[18]
    if msg[:16] != BGP_MARKER:
        return {"ok": False, "errors": ["bad marker"], "length": length, "type": mtype}
    if length != len(msg):
        return {"ok": False, "errors": [f"length {length} != {len(msg)}"], "length": length, "type": mtype}
    return {"ok": True, "length": length, "type": mtype, "payload": msg[19:]}


def parse_notification(msg: bytes) -> tuple[Optional[int], Optional[int]]:
    if len(msg) >= 21:
        return msg[19], msg[20]
    return None, None


def _cap_bytes(spec: dict[str, Any], args: Optional[dict[str, Any]] = None) -> bytes:
    cap = spec.get("capability") or {}
    code = int(cap.get("code", 1))
    if cap.get("value_hex"):
        value = encode_token("hex:" + str(cap["value_hex"]).replace(" ", ""), args)
        return struct.pack("!BB", code, len(value)) + value
    if cap.get("template"):
        value = encode_token(str(cap["template"]), args)
        return struct.pack("!BB", code, len(value)) + value
    afi = int(spec["afi"])
    safi = int(spec["safi"])
    # MP-BGP capability (code 1): AFI(2) reserved(1) SAFI(1)
    value = struct.pack("!HBB", afi, 0, safi)
    return struct.pack("!BB", 1 if code == 1 else code, len(value)) + value


def build_open(spec: dict[str, Any], local_as: int, router_id: str,
               hold_time: int = 180, args: Optional[dict[str, Any]] = None) -> bytes:
    version = 4
    my_as = local_as if local_as <= 65535 else AS_TRANS
    cap_mp = _cap_bytes(spec, args)
    cap_rr = struct.pack("!BB", 2, 0)
    cap_as4 = struct.pack("!BBI", 65, 4, local_as)
    caps = cap_mp + cap_rr + cap_as4
    opt = struct.pack("!BB", 2, len(caps)) + caps
    payload = struct.pack("!BHH", version, my_as, hold_time)
    payload += socket.inet_aton(router_id)
    payload += struct.pack("!B", len(opt)) + opt
    return build_header(BGP_OPEN, payload)


def assemble_nlri(spec: dict[str, Any], args: Optional[dict[str, Any]] = None) -> bytes:
    parts = []
    for tlv in spec.get("nlri_tlvs") or []:
        parts.append(encode_token(str(tlv["encoding"]), args))
    return b"".join(parts)


def build_update(spec: dict[str, Any], next_hop: str = "0.0.0.0",
                 args: Optional[dict[str, Any]] = None) -> bytes:
    afi = int(spec["afi"])
    safi = int(spec["safi"])
    nlri = assemble_nlri(spec, args)
    try:
        nh = socket.inet_aton(next_hop)
    except OSError:
        nh = socket.inet_pton(socket.AF_INET6, next_hop)
    mp = struct.pack("!HB", afi, safi) + struct.pack("!B", len(nh)) + nh + b"\x00" + nlri
    attrs = build_attr(0x40, PA_ORIGIN, b"\x00") + build_attr(0x40, PA_AS_PATH, b"")
    attrs += build_attr(0x80, PA_MP_REACH_NLRI, mp)
    for pa in spec.get("path_attrs") or []:
        flags = int(pa.get("flags", 0x40))
        tc = int(pa["type_code"])
        val = encode_token(str(pa["value_template"]), args)
        attrs += build_attr(flags, tc, val)
    payload = struct.pack("!HH", 0, len(attrs)) + attrs
    return build_header(BGP_UPDATE, payload)


def dump_frames(spec: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    errs = validate_spec(spec)
    if errs:
        return {"ok": False, "verdict": "INVALID_SPEC", "errors": errs}
    args = kwargs.get("bind_args") or {}
    local_as = int(kwargs.get("local_as") or 65200)
    rid = str(kwargs.get("router_id") or "100.64.6.134")
    nh = str(kwargs.get("next_hop") or "100.64.6.134")
    open_msg = build_open(spec, local_as, rid, args=args)
    upd = build_update(spec, next_hop=nh, args=args)
    if len(open_msg) > MAX_FRAME or len(upd) > MAX_FRAME:
        return {"ok": False, "verdict": "FRAME_TOO_LARGE",
                "errors": [f"open={len(open_msg)} update={len(upd)} max={MAX_FRAME}"]}
    po = parse_header(open_msg)
    pu = parse_header(upd)
    return {
        "ok": po.get("ok") and pu.get("ok"),
        "verdict": "DUMP_OK" if po.get("ok") and pu.get("ok") else "REPARSE_FAIL",
        "open_hex": open_msg.hex(),
        "update_hex": upd.hex(),
        "open_len": len(open_msg),
        "update_len": len(upd),
        "open_parse": po,
        "update_parse": pu,
        "exabgp_pipe_note": "per-family ExaBGP patch is advanced/manual; this speaker never writes the ExaBGP pipe",
    }


class MsgReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def next_msg(self, timeout: float = 2.0) -> Optional[bytes]:
        self.sock.settimeout(timeout)
        while True:
            if len(self.buf) >= 19:
                length = struct.unpack("!H", self.buf[16:18])[0]
                if length < 19 or length > 4096:
                    return None
                if len(self.buf) >= length:
                    msg = self.buf[:length]
                    self.buf = self.buf[length:]
                    return msg
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None
            self.buf += chunk


def _speak(sock: socket.socket, spec: dict[str, Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    dumped = dump_frames(spec, **kwargs)
    if not dumped.get("ok"):
        return dumped
    open_msg = bytes.fromhex(dumped["open_hex"])
    upd = bytes.fromhex(dumped["update_hex"])
    sock.sendall(open_msg)
    reader = MsgReader(sock)
    replies = []
    for _ in range(4):
        msg = reader.next_msg(timeout=float(kwargs.get("timeout_sec") or 3))
        if not msg:
            break
        parsed = parse_header(msg)
        rec: dict[str, Any] = {"hex": msg.hex(), "parse": parsed}
        if parsed.get("type") == BGP_NOTIFICATION:
            rec["notification"] = parse_notification(msg)
        replies.append(rec)
        if parsed.get("type") == BGP_NOTIFICATION:
            break
        if parsed.get("type") == BGP_KEEPALIVE:
            sock.sendall(upd)
            sock.sendall(build_header(BGP_KEEPALIVE, b""))
    return {**dumped, "ok": True, "verdict": "PROBED", "replies": replies}


def run_transient(spec: dict[str, Any], target_ip: str, target_port: int = 179, **kwargs: Any) -> dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(kwargs.get("timeout_sec") or 8))
    try:
        sock.connect((target_ip, int(target_port)))
        return _speak(sock, spec, kwargs)
    except OSError as exc:
        return {"ok": False, "verdict": "CONNECT_FAIL", "errors": [str(exc)]}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run_probe_port(spec: dict[str, Any], bind_ip: str = "127.0.0.1", bind_port: int = 0, **kwargs: Any) -> dict[str, Any]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, int(bind_port)))
    srv.listen(1)
    srv.settimeout(float(kwargs.get("listen_timeout_sec") or 15))
    port = srv.getsockname()[1]
    dumped = dump_frames(spec, **kwargs)
    try:
        conn, addr = srv.accept()
        try:
            out = _speak(conn, spec, kwargs)
            out["peer"] = f"{addr[0]}:{addr[1]}"
            out["listen_port"] = port
            return out
        finally:
            conn.close()
    except socket.timeout:
        return {**dumped, "ok": False, "verdict": "LISTEN_TIMEOUT", "listen_port": port, "errors": ["no inbound connect"]}
    finally:
        srv.close()


def resolve_spec(name_or_spec: Any, owner: str | None = None) -> dict[str, Any]:
    if isinstance(name_or_spec, dict):
        return name_or_spec
    found = get_family(str(name_or_spec), owner=owner)
    if not found:
        raise KeyError(f"unknown family {name_or_spec}")
    return found


def main() -> int:
    p = argparse.ArgumentParser(description="RFC family capability speaker")
    p.add_argument("--spec", required=True, help="JSON spec file or published name")
    p.add_argument("--dump-only", action="store_true")
    p.add_argument("--mode", choices=["dump_only", "transient", "probe_port"], default="dump_only")
    p.add_argument("--target-ip", default="")
    p.add_argument("--local-as", type=int, default=65200)
    p.add_argument("--router-id", default="100.64.6.134")
    args = p.parse_args()
    path = args.spec
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
    else:
        spec = resolve_spec(path)
    if args.dump_only or args.mode == "dump_only":
        out = dump_frames(spec, local_as=args.local_as, router_id=args.router_id)
    elif args.mode == "transient":
        out = run_transient(spec, args.target_ip, local_as=args.local_as, router_id=args.router_id)
    else:
        out = run_probe_port(spec, local_as=args.local_as, router_id=args.router_id)
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
