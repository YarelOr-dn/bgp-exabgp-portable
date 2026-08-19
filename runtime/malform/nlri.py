"""NLRI-level malformations: truncated-nlri, bad-afi-safi."""

import socket
import struct

from . import register
from ._common import (
    BGP_UPDATE,
    AFI_IPV4,
    SAFI_FLOWSPEC_VPN,
    PA_MP_REACH_NLRI,
    build_bgp_header,
    build_attr,
    encode_rd,
)


@register("truncated-nlri")
def truncated_nlri(rd: str = "1.1.1.1:100", **kwargs) -> bytes:
    """UPDATE with truncated FlowSpec NLRI - claims 20 bytes but only sends 5."""
    rd_bytes = encode_rd(rd)
    mp_reach = struct.pack("!HBB", AFI_IPV4, SAFI_FLOWSPEC_VPN, 4)
    mp_reach += socket.inet_aton("10.0.0.1")
    mp_reach += b"\x00"
    mp_reach += struct.pack("!B", 20)
    mp_reach += rd_bytes[:5]

    attr = build_attr(0xC0, PA_MP_REACH_NLRI, mp_reach)
    payload = struct.pack("!HH", 0, len(attr)) + attr
    return build_bgp_header(BGP_UPDATE, payload)


@register("bad-afi-safi")
def bad_afi_safi(**kwargs) -> bytes:
    """UPDATE with invalid AFI/SAFI in MP_REACH_NLRI."""
    origin_attr = build_attr(0x40, 1, b"\x00")
    aspath_attr = build_attr(0x40, 2, b"")

    mp_reach_data = struct.pack("!HB", 999, 255)
    mp_reach_data += struct.pack("!B", 4) + socket.inet_aton("100.70.0.32")
    mp_reach_data += struct.pack("!B", 0)
    mp_reach_attr = build_attr(0x90, 14, mp_reach_data)

    attrs = origin_attr + aspath_attr + mp_reach_attr
    path_attrs = struct.pack("!H", len(attrs)) + attrs
    payload = struct.pack("!H", 0) + path_attrs
    return build_bgp_header(BGP_UPDATE, payload)
