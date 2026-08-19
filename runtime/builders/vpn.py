"""L3VPN / VPNv4 SAFI 128 - ExaBGP route strings."""

from . import register


@register("l3vpn")
def build(args):
    """Build L3VPN / VPNv4 announce string."""
    rd = args.rd
    prefix = args.prefix
    nexthop = args.nexthop or "100.70.0.32"
    rt = args.rt
    label = args.label or "100"

    if not rd:
        raise ValueError("--rd required for l3vpn")
    if not prefix:
        raise ValueError("--prefix required for l3vpn")
    if not rt:
        raise ValueError("--rt required for l3vpn (route target)")

    return (
        f"announce route rd {rd} {prefix} next-hop {nexthop} "
        f"extended-community [ target:{rt} ] label [ {label} ]"
    )
