"""Header-level malformations: bad-marker, bad-length, oversized."""

import struct

from . import register
from ._common import BGP_MARKER, BGP_KEEPALIVE, BGP_UPDATE, build_bgp_header


@register("bad-marker")
def bad_marker(**kwargs) -> bytes:
    """BGP message with incorrect marker (not all 0xFF)."""
    bad = b"\xff" * 15 + b"\x00"
    keepalive = struct.pack("!HB", 19, BGP_KEEPALIVE)
    return bad + keepalive


@register("bad-length")
def bad_length(**kwargs) -> bytes:
    """BGP message with wrong length field."""
    return BGP_MARKER + struct.pack("!HB", 1000, BGP_KEEPALIVE)


@register("oversized")
def oversized(**kwargs) -> bytes:
    """BGP message exceeding 4096 bytes."""
    junk = b"\x00" * 5000
    return BGP_MARKER + struct.pack("!HB", 19 + len(junk), BGP_UPDATE) + junk
