"""IPv4 Unicast SAFI 1 - ExaBGP route strings."""

from . import register


@register("unicast")
def build(args):
    """Build IPv4 Unicast announce string."""
    prefix = args.prefix
    nexthop = args.nexthop or "100.70.0.32"

    if not prefix:
        raise ValueError("--prefix required for unicast (e.g., '10.0.0.0/24')")

    route = f"announce route {prefix} next-hop {nexthop}"

    if getattr(args, "community", None):
        route += f" community [ {args.community} ]"
    if getattr(args, "as_path", None):
        route += f" as-path [ {args.as_path} ]"
    if getattr(args, "med", None):
        route += f" med {args.med}"
    if getattr(args, "local_pref", None):
        route += f" local-preference {args.local_pref}"

    return route
