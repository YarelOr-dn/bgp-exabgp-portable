"""Extended community malformations: IETF 0x0c (DNOS rejects)."""

import socket
import struct

from . import register
from ._common import (
    BGP_UPDATE,
    PA_EXT_COMMUNITY,
    PA_MP_REACH_NLRI,
    build_bgp_header,
    build_attr,
    encode_rd,
    encode_flowspec_nlri,
)


@register("bad-extcommunity-0x0c")
def bad_extcommunity_0x0c(rd: str = "1.1.1.1:100", redirect_ip: str = "10.0.0.230", **kwargs) -> bytes:
    """UPDATE with IETF redirect-ip ext-community (0x0c) - DNOS rejects. Negative test."""
    ip_bytes = socket.inet_aton(redirect_ip)
    ietf_extcomm = bytes([0x80, 0x0c]) + ip_bytes + b"\x00\x00"

    attr = build_attr(0xC0, PA_EXT_COMMUNITY, ietf_extcomm)

    fs_nlri = encode_flowspec_nlri("10.0.0.0/24")
    rd_bytes = encode_rd(rd)
    nlri_with_rd = rd_bytes + fs_nlri
    nlri_block = struct.pack("!B", len(nlri_with_rd)) + nlri_with_rd

    mp_reach = struct.pack("!HBB", 1, 134, 4)
    mp_reach += socket.inet_aton("0.0.0.0")
    mp_reach += b"\x00" + nlri_block

    mp_attr = build_attr(0xC0, PA_MP_REACH_NLRI, mp_reach)
    origin = build_attr(0x40, 1, b"\x00")
    as_path = build_attr(0x40, 2, b"")

    attrs = origin + as_path + attr + mp_attr
    payload = struct.pack("!HH", 0, len(attrs)) + attrs
    return build_bgp_header(BGP_UPDATE, payload)
