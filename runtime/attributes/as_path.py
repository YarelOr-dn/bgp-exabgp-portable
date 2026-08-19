"""AS path variations: prepend, loops, confederation, 4-byte AS."""

from . import register_attr


@register_attr("as-path-prepend")
def prepend(prefix: str, nexthop: str, prepend_as: int = 65000, prepend_count: int = 3, **kwargs) -> str:
    """ExaBGP route with AS path prepending."""
    as_list = " ".join(str(prepend_as) for _ in range(prepend_count))
    return f"announce route {prefix} next-hop {nexthop} as-path [ {as_list} ]"


@register_attr("as-path-loop")
def loop(prefix: str, nexthop: str, target_as: int = 65001, **kwargs) -> str:
    """ExaBGP route with AS loop (target AS appears multiple times)."""
    return f"announce route {prefix} next-hop {nexthop} as-path [ {target_as} {target_as} {target_as} ]"


@register_attr("as-path-4byte")
def as4byte(prefix: str, nexthop: str, asn: int = 1234567, **kwargs) -> str:
    """ExaBGP route with 4-byte AS in path."""
    return f"announce route {prefix} next-hop {nexthop} as-path [ {asn} ]"
