"""EVPN Type-2 and Type-5 - ExaBGP route strings."""

from . import register


@register("evpn-type2")
def build_type2(args):
    """Build EVPN Type-2 (MAC/IP) announce string."""
    rd = args.rd
    mac = getattr(args, "mac", None) or "00:11:22:33:44:55"
    ip_addr = getattr(args, "evpn_ip", None) or ""
    nexthop = args.nexthop or "100.70.0.32"
    rt = args.rt
    label = args.label or "100"
    esi = getattr(args, "esi", None) or "00:00:00:00:00:00:00:00:00:00"
    etag = getattr(args, "ethernet_tag", None) or "0"

    if not rd:
        raise ValueError("--rd required for evpn-type2")
    if not rt:
        raise ValueError("--rt required for evpn-type2")

    route = (
        f"announce evpn mac-advertisement rd {rd} esi {esi} "
        f"ethernet-tag {etag} label {label} mac {mac}"
    )
    if ip_addr:
        route += f" ip {ip_addr}"
    route += f" next-hop {nexthop} extended-community [ target:{rt} ]"

    return route


@register("evpn-type5")
def build_type5(args):
    """Build EVPN Type-5 (IP Prefix) announce string."""
    rd = args.rd
    prefix = args.prefix
    nexthop = args.nexthop or "100.70.0.32"
    rt = args.rt
    label = args.label or "100"
    esi = getattr(args, "esi", None) or "00:00:00:00:00:00:00:00:00:00"
    etag = getattr(args, "ethernet_tag", None) or "0"

    if not rd:
        raise ValueError("--rd required for evpn-type5")
    if not prefix:
        raise ValueError("--prefix required for evpn-type5")
    if not rt:
        raise ValueError("--rt required for evpn-type5")

    return (
        f"announce evpn ip-prefix rd {rd} esi {esi} "
        f"ethernet-tag {etag} label {label} {prefix} "
        f"next-hop {nexthop} extended-community [ target:{rt} ]"
    )
