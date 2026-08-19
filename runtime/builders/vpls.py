"""L2VPN VPLS SAFI 65 - ExaBGP route strings."""

from . import register


@register("vpls")
def build(args):
    """Build L2VPN VPLS announce string."""
    rd = args.rd or "4.4.4.4:101"
    endpoint = getattr(args, "vpls_endpoint", None) or "1"
    base = getattr(args, "vpls_base", None) or "100"
    offset = getattr(args, "vpls_offset", None) or "0"
    size = getattr(args, "vpls_size", None) or "10"
    nexthop = args.nexthop or "100.70.0.32"
    rt = getattr(args, "rt", None)

    route = (
        f"announce vpls rd {rd} endpoint {endpoint} base {base} "
        f"offset {offset} size {size} next-hop {nexthop}"
    )
    if rt:
        route += f" extended-community [ target:{rt} ]"
    return route
