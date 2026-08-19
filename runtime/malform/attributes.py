"""Path attribute malformations: duplicate-attr, bad-origin, bad-community."""

import socket
import struct

from . import register
from ._common import BGP_UPDATE, build_bgp_header, build_attr


def _origin_attr(value: int) -> bytes:
    return build_attr(0x40, 1, struct.pack("!B", value))


def _aspath_attr() -> bytes:
    return build_attr(0x40, 2, b"")


def _nexthop_attr(ip: str = "100.70.0.32") -> bytes:
    return build_attr(0x40, 3, socket.inet_aton(ip))


@register("duplicate-attr")
def duplicate_attr(**kwargs) -> bytes:
    """UPDATE with duplicate path attributes (two ORIGIN)."""
    origin1 = _origin_attr(0)
    origin2 = _origin_attr(1)
    as_path = _aspath_attr()
    attrs = origin1 + origin2 + as_path
    payload = struct.pack("!HH", 0, len(attrs)) + attrs
    return build_bgp_header(BGP_UPDATE, payload)


@register("bad-origin")
def bad_origin(**kwargs) -> bytes:
    """UPDATE with invalid ORIGIN value (5, valid range 0-2)."""
    origin_attr = _origin_attr(5)
    as_path = _aspath_attr()
    nexthop = _nexthop_attr()
    attrs = origin_attr + as_path + nexthop
    path_attrs = struct.pack("!H", len(attrs)) + attrs
    nlri = struct.pack("!B", 24) + b"\x0a\x00\x00"
    payload = struct.pack("!HH", 0, len(path_attrs)) + path_attrs + nlri
    return build_bgp_header(BGP_UPDATE, payload)


@register("bad-community")
def bad_community(**kwargs) -> bytes:
    """UPDATE with non-4-byte-aligned COMMUNITY attribute."""
    origin_attr = build_attr(0x40, 1, b"\x00")
    aspath_attr = build_attr(0x40, 2, b"")
    nexthop_attr = build_attr(0x40, 3, socket.inet_aton("100.70.0.32"))
    community_attr = struct.pack("!BBB", 0xC0, 8, 3) + b"\xff\xfe\x01"

    attrs = origin_attr + aspath_attr + nexthop_attr + community_attr
    path_attrs = struct.pack("!H", len(attrs)) + attrs
    nlri = struct.pack("!B", 24) + b"\x0a\x00\x00"
    payload = struct.pack("!HH", 0, len(path_attrs)) + path_attrs + nlri
    return build_bgp_header(BGP_UPDATE, payload)
