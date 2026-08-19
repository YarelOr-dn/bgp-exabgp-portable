"""RT-Constraint SAFI 132 - ExaBGP route strings."""

from . import register


@register("rtc")
def build(args):
    """Build RT-Constraint announce string."""
    rt = args.rt
    nexthop = args.nexthop or "100.70.0.32"

    if not rt:
        raise ValueError("--rt required for rtc (e.g., '1234567:101')")

    return f"announce route-target {rt} next-hop {nexthop}"
