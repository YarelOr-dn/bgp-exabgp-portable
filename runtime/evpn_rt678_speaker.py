#!/usr/bin/env python3
"""
evpn_rt678_speaker.py - Persistent raw BGP-EVPN speaker for RT-6/7/8 (mal)injection.

WHY THIS EXISTS
    Stock ExaBGP 4.0.2 only encodes EVPN RT-1..5 (mac/ip-prefix/ethernet-ad/
    ethernet-segment); it CANNOT emit RT-6 (SMET), RT-7 (IGMP Join Sync) or
    RT-8 (IGMP Leave Sync), and it will not emit deliberately MALFORMED NLRI.
    STC on this Houston Lab Server build has no RT-6/7/8 objects either.
    So to inject (and malform) RT-6/7/8 into a DNOS DUT we hand-craft the NLRI
    at the byte level and speak BGP ourselves, keeping the session alive with a
    KEEPALIVE loop so the DUT retains + displays the routes.

    This is a NEW, self-owned BGP session (BGP tripwire safe: it never touches
    the protected /BGP ExaBGP :179 injector, which lives on a different host).

SCOPE
    - OPEN with L2VPN-EVPN (AFI 25 / SAFI 70) + 4-octet-ASN capabilities.
    - Optional phantom all-active ESI: RT-4 (Ethernet Segment) + RT-1 (A-D)
      so the DUT can correlate RT-7/8 to a multihomed ES.
    - RT-6 / RT-7 / RT-8 encoders (RFC 7432 + RFC 9251).
    - Per-route MALFORM knobs (see MALFORMS below).
    - Persistent: KEEPALIVE loop until --duration elapses or peer NOTIFIES.

Reuses the byte primitives style of malform/_common.py but stays standalone so
it runs on the Ubuntu-18.04 host (Python 3.6+) with no ExaBGP import.
"""

import argparse
import socket
import struct
import sys
import time

# ---- BGP constants ---------------------------------------------------------
BGP_MARKER = b"\xff" * 16
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

AFI_L2VPN = 25
SAFI_EVPN = 70

PA_ORIGIN = 1
PA_AS_PATH = 2
PA_EXT_COMMUNITY = 16
PA_MP_REACH_NLRI = 14

AS_TRANS = 23456

MALFORMS = {
    "none": "well-formed reference route",
    "bad_nlri_len": "NLRI length octet declares more bytes than present",
    "bad_flags": "IGMP flags octet set to illegal 0xFF",
    "bad_grp_len": "multicast-group length octet = 255 but only 4 bytes follow",
    "bad_src_len": "multicast-source length octet = 255 but 0 bytes follow",
    "trailing_junk": "extra junk bytes appended inside the NLRI value",
    "illegal_route_type": "route-type code forced to 0x63 (99, undefined)",
    "bad_ext_comm": "append a 7-byte (non 8-aligned) extended community",
    "dup_evi_rt": "duplicate EVI-RT extended community",
    "zero_len_nlri": "NLRI length octet = 0",
}


# ---- low-level encoders ----------------------------------------------------
def build_header(msg_type, payload, marker=None):
    if marker is None:
        marker = BGP_MARKER
    length = 19 + len(payload)
    return marker + struct.pack("!HB", length, msg_type) + payload


def build_attr(flags, type_code, value):
    if len(value) > 255:
        flags |= 0x10  # extended length
        return struct.pack("!BBH", flags, type_code, len(value)) + value
    return struct.pack("!BBB", flags, type_code, len(value)) + value


def encode_rd(rd_str):
    """RD (8 bytes). ip:nn -> type1; asn:nn -> type0 (<=65535) or type2 (4-byte).

    NOTE: a dotted admin field is an IPv4 RD; a bare number is an ASN.
    socket.inet_aton() is deliberately NOT used to classify because it happily
    accepts a bare integer (e.g. '1234567') as a packed address.
    """
    a, b = rd_str.split(":")
    nn = int(b)
    if "." in a:
        return struct.pack("!H", 1) + socket.inet_aton(a) + struct.pack("!H", nn)
    asn = int(a)
    if asn <= 65535:
        return struct.pack("!HHI", 0, asn, nn)
    return struct.pack("!HIH", 2, asn, nn)


def encode_esi(esi_str):
    """9-octet ESI value -> 10-byte ESI (type octet + 9 value octets).

    Accepts 'aa:bb:...' (9 or 10 hex octets) or a plain hex string.
    Convention here: caller passes the 9-octet VALUE; we prepend type 0x00.
    If 10 octets are given we use them verbatim.
    """
    parts = esi_str.replace("-", ":").split(":")
    octets = bytes(int(p, 16) for p in parts)
    if len(octets) == 10:
        return octets
    if len(octets) == 9:
        return b"\x00" + octets
    raise ValueError("ESI must be 9 or 10 octets, got %d" % len(octets))


def esi_import_mac(esi10):
    """ES-Import RT value = high-order 6 bytes of the 9-octet ESI value."""
    return esi10[1:7]


# ---- extended communities (8 bytes each) -----------------------------------
def ec_route_target(rt_str):
    """target:AS:val -> RT extended community (8 bytes).

    A dotted admin field is an IPv4-address RT (type 0x01); a bare number is an
    ASN RT: 2-byte-AS -> type 0x00, 4-byte-AS -> type 0x02. Do NOT use
    inet_aton() to classify (it accepts a bare int like '1234567' as an IP).
    """
    a, b = rt_str.split(":")
    val = int(b)
    if "." in a:
        return struct.pack("!BB", 0x01, 0x02) + socket.inet_aton(a) + struct.pack("!H", val)
    asn = int(a)
    if asn <= 65535:
        return struct.pack("!BBHI", 0x00, 0x02, asn, val)
    return struct.pack("!BBIH", 0x02, 0x02, asn, val)


def ec_es_import(esi10):
    return struct.pack("!BB", 0x06, 0x02) + esi_import_mac(esi10)


def ec_esi_label(single_active=False, label=0):
    flags = 0x01 if single_active else 0x00
    lbl = struct.pack("!I", label << 4)[1:]
    return struct.pack("!BBB", 0x06, 0x01, flags) + b"\x00\x00" + lbl


def ec_encap_vxlan():
    # type 0x03 subtype 0x0c, tunnel-type 8 = VXLAN
    return struct.pack("!BB", 0x03, 0x0c) + b"\x00\x00\x00\x00" + struct.pack("!H", 8)


# ---- EVPN NLRI encoders ----------------------------------------------------
def _grp_field(ip, length_override=None):
    b = socket.inet_aton(ip)
    ln = 32 if length_override is None else length_override
    return struct.pack("!B", ln) + b


def _src_field(ip, length_override=None):
    if ip in (None, "", "0.0.0.0", "*"):
        ln = 0 if length_override is None else length_override
        return struct.pack("!B", ln)
    b = socket.inet_aton(ip)
    ln = 32 if length_override is None else length_override
    return struct.pack("!B", ln) + b


def _orig_field(ip):
    return struct.pack("!B", 32) + socket.inet_aton(ip)


def wrap_nlri(route_type, value, malform=None):
    """Prepend [route-type][length] to a route-type-specific value."""
    m = malform or "none"
    rt = 0x63 if m == "illegal_route_type" else route_type
    ln = len(value)
    if m == "bad_nlri_len":
        ln = len(value) + 5
    elif m == "zero_len_nlri":
        ln = 0
    return struct.pack("!BB", rt, ln) + value


def nlri_rt4_es(rd, esi10, orig_ip):
    return wrap_nlri(4, encode_rd(rd) + esi10 + _orig_field(orig_ip))


def nlri_rt1_ad(rd, esi10, eth_tag, label):
    lbl = struct.pack("!I", label << 4)[1:]
    return wrap_nlri(1, encode_rd(rd) + esi10 + struct.pack("!I", eth_tag) + lbl)


def _mcast_common(eth_tag, src, grp, orig_ip, flags, malform):
    src_lo = 255 if malform == "bad_src_len" else None
    grp_lo = 255 if malform == "bad_grp_len" else None
    fl = 0xFF if malform == "bad_flags" else flags
    body = (
        struct.pack("!I", eth_tag)
        + _src_field(src, src_lo)
        + _grp_field(grp, grp_lo)
        + _orig_field(orig_ip)
        + struct.pack("!B", fl)
    )
    if malform == "trailing_junk":
        body += b"\xde\xad\xbe\xef"
    return body


def nlri_rt6_smet(rd, eth_tag, src, grp, orig_ip, flags=0x02, malform=None):
    value = encode_rd(rd) + _mcast_common(eth_tag, src, grp, orig_ip, flags, malform)
    return wrap_nlri(6, value, malform)


def nlri_rt7_join(rd, esi10, eth_tag, src, grp, orig_ip, flags=0x02, malform=None):
    value = (
        encode_rd(rd)
        + esi10
        + _mcast_common(eth_tag, src, grp, orig_ip, flags, malform)
    )
    return wrap_nlri(7, value, malform)


def nlri_rt8_leave(rd, esi10, eth_tag, src, grp, orig_ip, flags=0x02, malform=None):
    value = (
        encode_rd(rd)
        + esi10
        + _mcast_common(eth_tag, src, grp, orig_ip, flags, malform)
    )
    return wrap_nlri(8, value, malform)


# ---- MP_REACH + UPDATE assembly --------------------------------------------
def build_update(nlri_bytes, next_hop, ext_comms, malform=None):
    """One UPDATE carrying one or more concatenated EVPN NLRIs + path attrs."""
    mp = struct.pack("!HB", AFI_L2VPN, SAFI_EVPN)
    nh = socket.inet_aton(next_hop)
    mp += struct.pack("!B", len(nh)) + nh
    mp += b"\x00"  # reserved SNPA
    mp += nlri_bytes
    mp_attr = build_attr(0x80, PA_MP_REACH_NLRI, mp)

    origin = build_attr(0x40, PA_ORIGIN, b"\x00")  # IGP
    as_path = build_attr(0x40, PA_AS_PATH, b"")     # empty (iBGP-style)

    ec_value = b"".join(ext_comms)
    if malform == "dup_evi_rt" and ext_comms:
        ec_value += ext_comms[0]
    if malform == "bad_ext_comm":
        ec_value += b"\x06\x02\x00\x00\x00\x00\x00"  # 7 bytes, non 8-aligned
    ec_attr = build_attr(0xC0, PA_EXT_COMMUNITY, ec_value)

    attrs = origin + as_path + mp_attr + ec_attr
    payload = struct.pack("!HH", 0, len(attrs)) + attrs
    return build_header(BGP_UPDATE, payload)


# ---- OPEN / session --------------------------------------------------------
def build_open(local_as, hold_time, router_id):
    version = 4
    my_as = local_as if local_as <= 65535 else AS_TRANS
    cap_mp = struct.pack("!BBHBB", 1, 4, AFI_L2VPN, 0, SAFI_EVPN)
    cap_rr = struct.pack("!BB", 2, 0)
    cap_as4 = struct.pack("!BBI", 65, 4, local_as)
    caps = cap_mp + cap_rr + cap_as4
    opt = struct.pack("!BB", 2, len(caps)) + caps
    payload = struct.pack("!BHH", version, my_as, hold_time)
    payload += socket.inet_aton(router_id)
    payload += struct.pack("!B", len(opt)) + opt
    return build_header(BGP_OPEN, payload)


class MsgReader(object):
    """Buffer TCP bytes and yield complete BGP messages (marker+len+type+body)."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def next_msg(self, timeout=1.0):
        self.sock.settimeout(timeout)
        while True:
            if len(self.buf) >= 19:
                length = struct.unpack("!H", self.buf[16:18])[0]
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


def msg_type(msg):
    return msg[18] if len(msg) >= 19 else None


def parse_notification(msg):
    if len(msg) >= 21:
        return msg[19], msg[20]
    return None, None


def run(args):
    log = lambda *a: print("[speaker]", *a, flush=True)

    esi10 = encode_esi(args.esi)
    evi_rt = ec_route_target(args.evi_rt)

    # Build the route set --------------------------------------------------
    updates = []
    if args.phantom:
        rt4 = nlri_rt4_es(args.es_rd, esi10, args.orig_ip)
        rt1_es = nlri_rt1_ad(args.es_rd, esi10, 0xFFFFFFFF, 0)
        rt1_evi = nlri_rt1_ad(args.evi_rd, esi10, 0, args.vni)
        updates.append(("RT-4 ES", build_update(
            rt4, args.next_hop,
            [ec_es_import(esi10), evi_rt, ec_encap_vxlan()])))
        updates.append(("RT-1 A-D per-ES", build_update(
            rt1_es, args.next_hop,
            [evi_rt, ec_encap_vxlan(), ec_esi_label(False, 0)])))
        updates.append(("RT-1 A-D per-EVI", build_update(
            rt1_evi, args.next_hop, [evi_rt, ec_encap_vxlan()])))

    types = args.route_types.split(",")
    if "6" in types:
        n = nlri_rt6_smet(args.evi_rd, args.eth_tag, args.source, args.group,
                          args.orig_ip, malform=args.malform)
        updates.append(("RT-6 SMET [%s]" % args.malform,
                        build_update(n, args.next_hop, [evi_rt, ec_encap_vxlan()],
                                     malform=args.malform)))
    if "7" in types:
        n = nlri_rt7_join(args.evi_rd, esi10, args.eth_tag, args.source, args.group,
                          args.orig_ip, malform=args.malform)
        updates.append(("RT-7 JoinSync [%s]" % args.malform,
                        build_update(n, args.next_hop,
                                     [ec_es_import(esi10), evi_rt, ec_encap_vxlan()],
                                     malform=args.malform)))
    if "8" in types:
        n = nlri_rt8_leave(args.evi_rd, esi10, args.eth_tag, args.source, args.group,
                           args.orig_ip, malform=args.malform)
        updates.append(("RT-8 LeaveSync [%s]" % args.malform,
                        build_update(n, args.next_hop,
                                     [ec_es_import(esi10), evi_rt, ec_encap_vxlan()],
                                     malform=args.malform)))

    if args.dump_only:
        for name, u in updates:
            log("%-22s %d bytes: %s" % (name, len(u), u.hex()))
        return 0

    # Connect --------------------------------------------------------------
    log("connect %s:%d local-as %d peer-as %d rid %s" % (
        args.peer, args.port, args.local_as, args.peer_as, args.router_id))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    if args.local_address:
        sock.bind((args.local_address, 0))
    sock.connect((args.peer, args.port))
    reader = MsgReader(sock)

    sock.sendall(build_open(args.local_as, args.hold_time, args.router_id))
    log("-> OPEN")

    established = False
    got_peer_open = False
    deadline = time.time() + 20
    while time.time() < deadline and not established:
        msg = reader.next_msg(timeout=2.0)
        if msg is None:
            continue
        t = msg_type(msg)
        if t == BGP_OPEN:
            got_peer_open = True
            log("<- OPEN")
            sock.sendall(build_header(BGP_KEEPALIVE, b""))
            log("-> KEEPALIVE")
        elif t == BGP_KEEPALIVE:
            log("<- KEEPALIVE")
            if got_peer_open:
                established = True
        elif t == BGP_NOTIFICATION:
            c, s = parse_notification(msg)
            log("<- NOTIFICATION code=%s subcode=%s (session refused)" % (c, s))
            sock.close()
            return 2

    if not established:
        log("ERROR: session did not establish")
        sock.close()
        return 3
    log("STATE: Established")

    # Inject ---------------------------------------------------------------
    for name, u in updates:
        sock.sendall(u)
        log("-> UPDATE %s (%d bytes)" % (name, len(u)))
        time.sleep(0.3)

    # Keepalive loop -------------------------------------------------------
    log("holding session for %ds (keepalive every %ds); Ctrl-C to stop"
        % (args.duration, max(1, args.hold_time // 3)))
    ka_interval = max(1, args.hold_time // 3)
    last_ka = time.time()
    end = time.time() + args.duration
    result = 0
    try:
        while time.time() < end:
            if time.time() - last_ka >= ka_interval:
                sock.sendall(build_header(BGP_KEEPALIVE, b""))
                last_ka = time.time()
            msg = reader.next_msg(timeout=1.0)
            if msg is None:
                continue
            t = msg_type(msg)
            if t == BGP_NOTIFICATION:
                c, s = parse_notification(msg)
                log("<- NOTIFICATION code=%s subcode=%s (peer tore down AFTER inject)"
                    % (c, s))
                result = 4
                break
            elif t == BGP_UPDATE:
                log("<- UPDATE (%d bytes) from peer" % len(msg))
            elif t == BGP_KEEPALIVE:
                pass
    except KeyboardInterrupt:
        log("interrupted; closing")
    finally:
        sock.close()
    log("done (result=%d)" % result)
    return result


def build_parser():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--peer", required=True, help="DUT neighbor IP (BGP peer)")
    p.add_argument("--port", type=int, default=179)
    p.add_argument("--local-address", help="source IP to bind (ens3f0.<vlan>)")
    p.add_argument("--local-as", type=int, required=True)
    p.add_argument("--peer-as", type=int, required=True)
    p.add_argument("--router-id", required=True)
    p.add_argument("--next-hop", required=True, help="EVPN next-hop (usually local-address)")
    p.add_argument("--hold-time", type=int, default=180)
    p.add_argument("--duration", type=int, default=300, help="seconds to hold session")

    p.add_argument("--evi-rd", default="99.99.99.99:2001", help="EVI RD for RT-1/6/7/8")
    p.add_argument("--es-rd", default="99.99.99.99:0", help="ES RD for RT-4/RT-1-per-ES")
    p.add_argument("--evi-rt", default="1234567:2001", help="target:AS:val")
    p.add_argument("--esi", default="00:00:00:00:00:00:00:00:02:16",
                   help="9- or 10-octet ESI value")
    p.add_argument("--vni", type=int, default=2001)
    p.add_argument("--eth-tag", type=int, default=0)
    p.add_argument("--group", default="239.1.1.1")
    p.add_argument("--source", default="0.0.0.0", help="'0.0.0.0'/'*' = (*,G)")
    p.add_argument("--orig-ip", default=None,
                   help="originating router IP in NLRI (default = next-hop)")

    p.add_argument("--route-types", default="6,7,8", help="comma list of 6,7,8")
    p.add_argument("--phantom", action="store_true",
                   help="also inject RT-4 + RT-1 phantom all-active ESI")
    p.add_argument("--malform", default="none", choices=list(MALFORMS.keys()))
    p.add_argument("--dump-only", action="store_true",
                   help="print hex of the crafted UPDATEs and exit (no connect)")
    return p


def main():
    args = build_parser().parse_args()
    if args.orig_ip is None:
        args.orig_ip = args.next_hop
    if args.malform != "none":
        print("[speaker] MALFORM=%s : %s" % (args.malform, MALFORMS[args.malform]),
              flush=True)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
