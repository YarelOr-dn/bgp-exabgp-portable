#!/usr/bin/env python3
"""
builders/ - Plugin registry for ExaBGP route string generators.

Each module registers its builders via @register("name").
"""

import ipaddress

BUILDERS = {}


def register(name):
    """Decorator to register a builder function."""
    def decorator(func):
        BUILDERS[name] = func
        return func
    return decorator


def to_withdraw(announce_str):
    """Convert an announce string to a withdraw string."""
    if announce_str.startswith("announce"):
        return announce_str.replace("announce", "withdraw", 1)
    return f"withdraw {announce_str}"


def generate_prefix_range(prefix_range_str, nexthop, builder_func, args):
    """Generate multiple routes from a prefix range like 10.0.0.0/24-10.0.9.0/24."""
    parts = prefix_range_str.split("-")
    if len(parts) != 2:
        raise ValueError("--prefix-range format: START/MASK-END/MASK (e.g., 10.0.0.0/24-10.0.9.0/24)")

    start_net = ipaddress.ip_network(parts[0].strip(), strict=False)
    end_net = ipaddress.ip_network(parts[1].strip(), strict=False)

    routes = []
    current = int(start_net.network_address)
    end = int(end_net.network_address)
    mask = start_net.prefixlen

    while current <= end:
        prefix = f"{ipaddress.IPv4Address(current)}/{mask}"
        args.prefix = prefix
        route = builder_func(args)
        routes.append(route)
        current += 2 ** (32 - mask)

    return routes


# Import all builder modules to trigger registration
from . import flowspec
from . import flowspec_vpn
from . import unicast
from . import vpn
from . import evpn
from . import vpls
from . import rtc
from . import multicast
from . import labeled
from . import scale
