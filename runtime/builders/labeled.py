"""IPv4 Labeled-Unicast SAFI 4 - ExaBGP route strings."""

from . import register


@register("labeled-unicast")
def build(args):
    """Build IPv4 Labeled-Unicast (nlri-mpls) announce string."""
    prefix = args.prefix
    nexthop = args.nexthop or "100.70.0.32"
    label = args.label or "100"

    if not prefix:
        raise ValueError("--prefix required for labeled-unicast (e.g., '10.0.0.0/24')")

    return f"announce route {prefix} next-hop {nexthop} label [ {label} ]"
