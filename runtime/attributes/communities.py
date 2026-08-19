"""Community variations: standard, extended, large community."""

from . import register_attr


@register_attr("community-standard")
def standard(prefix: str, nexthop: str, community: str = "12345:67890", **kwargs) -> str:
    """ExaBGP route with standard COMMUNITY attribute."""
    return f"announce route {prefix} next-hop {nexthop} community [ {community} ]"


@register_attr("community-extended")
def extended(prefix: str, nexthop: str, rt: str = "1234567:300", **kwargs) -> str:
    """ExaBGP route with extended community (Route Target)."""
    return f"announce route {prefix} next-hop {nexthop} extended-community [ target:{rt} ]"


@register_attr("community-large")
def large(prefix: str, nexthop: str, large_comm: str = "1234567:1234567:999", **kwargs) -> str:
    """ExaBGP route with large community (if supported)."""
    return f"announce route {prefix} next-hop {nexthop} large-community [ {large_comm} ]"
