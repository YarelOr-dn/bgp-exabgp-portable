"""IPv4 Multicast SAFI 2 - ExaBGP route strings."""

from . import register


@register("multicast")
def build(args):
    """Build IPv4 Multicast announce string."""
    prefix = getattr(args, "prefix", None) or "224.0.0.0/4"
    nexthop = args.nexthop or "100.70.0.32"
    return f"announce route {prefix} next-hop {nexthop}"
