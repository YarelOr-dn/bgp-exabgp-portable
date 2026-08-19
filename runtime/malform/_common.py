"""Shared BGP encoding primitives for malformation builders."""

import socket
import struct
from typing import Optional, Tuple

BGP_MARKER = b"\xff" * 16
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

AFI_IPV4 = 1
SAFI_FLOWSPEC_VPN = 134

FS_DEST_PREFIX = 1
FS_SRC_PREFIX = 2

PA_ORIGIN = 1
PA_AS_PATH = 2
PA_EXT_COMMUNITY = 16
PA_MP_REACH_NLRI = 14


def build_bgp_header(msg_type: int, payload: bytes, marker=None) -> bytes:
    """Build BGP message with 16-byte marker + 2-byte length + 1-byte type."""
    if marker is None:
        marker = BGP_MARKER
    length = 19 + len(payload)
    return marker + struct.pack("!HB", length, msg_type) + payload


def build_attr(flags: int, type_code: int, value: bytes) -> bytes:
    """Build a BGP path attribute."""
    if len(value) > 255:
        flags |= 0x10
        return struct.pack("!BBH", flags, type_code, len(value)) + value
    return struct.pack("!BBB", flags, type_code, len(value)) + value


def encode_rd(rd_str: str) -> bytes:
    """Encode Route Distinguisher (8 bytes)."""
    parts = rd_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid RD format: {rd_str}")
    try:
        socket.inet_aton(parts[0])
        ip_bytes = socket.inet_aton(parts[0])
        nn = int(parts[1])
        return struct.pack("!H", 1) + ip_bytes + struct.pack("!H", nn)
    except socket.error:
        pass
    asn = int(parts[0])
    nn = int(parts[1])
    if asn <= 65535:
        return struct.pack("!HHI", 0, asn, nn)
    return struct.pack("!HIH", 2, asn, nn)


def encode_flowspec_nlri(dest_prefix: Optional[str] = None, src_prefix: Optional[str] = None) -> bytes:
    """Encode FlowSpec NLRI (match rules). Returns NLRI bytes WITHOUT length prefix."""
    nlri = b""
    if dest_prefix:
        ip_str, plen_str = dest_prefix.split("/")
        plen = int(plen_str)
        ip_bytes = socket.inet_aton(ip_str)
        num_octets = (plen + 7) // 8
        nlri += struct.pack("!BB", FS_DEST_PREFIX, plen) + ip_bytes[:num_octets]
    if src_prefix:
        ip_str, plen_str = src_prefix.split("/")
        plen = int(plen_str)
        ip_bytes = socket.inet_aton(ip_str)
        num_octets = (plen + 7) // 8
        nlri += struct.pack("!BB", FS_SRC_PREFIX, plen) + ip_bytes[:num_octets]
    return nlri
