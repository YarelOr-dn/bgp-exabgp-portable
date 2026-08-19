#!/usr/bin/env python3
"""
route_builder.py - Multi-AFI/SAFI Route String Generator for ExaBGP

Thin wrapper over builders/ plugin package.
Generates ExaBGP-format announce/withdraw strings from human-readable arguments.

Supported types: flowspec, flowspec-vpn, unicast, multicast, labeled-unicast,
l3vpn, evpn-type2, evpn-type5, vpls, rtc

Usage:
    python3 route_builder.py --type flowspec --match "destination 10.0.0.0/24" --action "rate-limit 1000000"
    python3 route_builder.py --type flowspec-vpn --rd 4.4.4.4:101 --match "destination 10.0.0.0/24" --redirect-ip 10.0.0.230 --rt 1234567:101
    python3 route_builder.py --type unicast --prefix 10.0.0.0/24 --nexthop 100.70.0.32
"""

import argparse
import json
import sys

from builders import BUILDERS, generate_prefix_range, to_withdraw


def main():
    parser = argparse.ArgumentParser(
        description="Route Builder - Generate ExaBGP route strings"
    )
    parser.add_argument("--type", required=True,
                        choices=list(BUILDERS.keys()),
                        help="Route type")
    parser.add_argument("--withdraw", action="store_true",
                        help="Generate withdraw instead of announce")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")

    # Common
    parser.add_argument("--prefix", help="IP prefix (e.g., 10.0.0.0/24)")
    parser.add_argument("--prefix-range", help="Prefix range (e.g., 10.0.0.0/24-10.0.9.0/24)")
    parser.add_argument("--nexthop", help="Next-hop IP (default: 100.70.0.32)")
    parser.add_argument("--rd", help="Route Distinguisher (e.g., 4.4.4.4:101)")
    parser.add_argument("--rt", help="Route Target (e.g., 1234567:101)")
    parser.add_argument("--label", help="MPLS label (default: 100)")

    # FlowSpec
    parser.add_argument("--match", help="FlowSpec match clause (e.g., 'destination 10.0.0.0/24')")
    parser.add_argument("--action", help="FlowSpec action (e.g., 'rate-limit 1000000')")
    parser.add_argument("--redirect-ip", dest="redirect_ip", help="Redirect to IP (Simpson draft, DNOS supported)")

    # Unicast optional
    parser.add_argument("--community", help="Community string (e.g., '65000:100')")
    parser.add_argument("--as-path", help="AS path (e.g., '65200 65300')")
    parser.add_argument("--med", help="MED value")
    parser.add_argument("--local-pref", help="Local preference")

    # EVPN
    parser.add_argument("--mac", help="MAC address for EVPN Type-2")
    parser.add_argument("--evpn-ip", help="IP for EVPN Type-2")
    parser.add_argument("--esi", help="ESI (default: all zeros)")
    parser.add_argument("--ethernet-tag", help="Ethernet tag (default: 0)")

    # VPLS
    parser.add_argument("--vpls-endpoint", help="VPLS endpoint ID (default: 1)")
    parser.add_argument("--vpls-base", help="VPLS label base (default: 100)")
    parser.add_argument("--vpls-offset", help="VPLS block offset (default: 0)")
    parser.add_argument("--vpls-size", help="VPLS block size (default: 10)")

    args = parser.parse_args()

    builder = BUILDERS[args.type]

    try:
        if args.prefix_range:
            routes = generate_prefix_range(args.prefix_range, args.nexthop, builder, args)
            if args.withdraw:
                routes = [to_withdraw(r) for r in routes]
            if args.json:
                print(json.dumps({"routes": routes, "count": len(routes)}, indent=2))
            else:
                for route in routes:
                    print(route)
            return

        route = builder(args)
        if args.withdraw:
            route = to_withdraw(route)

        if args.json:
            print(json.dumps({"route": route}))
        else:
            print(route)

    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
