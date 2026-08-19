"""Next-hop variations: unreachable, self, third-party."""

from . import register_attr


@register_attr("nexthop-self")
def self_hop(prefix: str, **kwargs) -> str:
    """ExaBGP route with next-hop self (0.0.0.0)."""
    return f"announce route {prefix} next-hop self"


@register_attr("nexthop-unreachable")
def unreachable(prefix: str, **kwargs) -> str:
    """ExaBGP route with unreachable next-hop (for testing)."""
    return f"announce route {prefix} next-hop 0.0.0.0"


@register_attr("nexthop-third-party")
def third_party(prefix: str, nexthop: str, **kwargs) -> str:
    """ExaBGP route with third-party next-hop."""
    return f"announce route {prefix} next-hop {nexthop}"
