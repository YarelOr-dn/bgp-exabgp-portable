#!/usr/bin/env python3
"""
config_gen.py - ExaBGP configuration generation

Handles: template + inline config generation, DNOS/ExaBGP family mapping.
"""

from pathlib import Path

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"

# Reserved IPs (overridable by user)
DEVICE_DEFAULT_IP = "100.70.0.206"
EXABGP_DEFAULT_IP = "100.70.0.32"

# DNOS address-family name -> ExaBGP family string
DNOS_TO_EXABGP = {
    "ipv4-unicast": "ipv4 unicast",
    "ipv6-unicast": "ipv6 unicast",
    "ipv4-flowspec": "ipv4 flow",
    "ipv4-flowspec-vpn": "ipv4 flow-vpn",
    "ipv6-flowspec": "ipv6 flow",
    "ipv6-flowspec-vpn": "ipv6 flow-vpn",
    "ipv4-vpn": "ipv4 mpls-vpn",
    "ipv6-vpn": "ipv6 mpls-vpn",
    "ipv4-labeled-unicast": "ipv4 nlri-mpls",
    "ipv6-labeled-unicast": "ipv6 nlri-mpls",
    "ipv4-multicast": "ipv4 multicast",
    "ipv4-rt-constrains": "ipv4 rtc",
    "l2vpn-evpn": "l2vpn evpn",
    "l2vpn-vpls": "l2vpn vpls",
    "link-state": "bgp-ls bgp-ls",
}

# Reverse: ExaBGP family string -> DNOS address-family name
EXABGP_TO_DNOS = {v: k for k, v in DNOS_TO_EXABGP.items()}

# All 15 ExaBGP families for full DNOS support
ALL_EXABGP_FAMILIES = [
    "ipv4 unicast", "ipv6 unicast",
    "ipv4 flow", "ipv4 flow-vpn", "ipv6 flow", "ipv6 flow-vpn",
    "ipv4 mpls-vpn", "ipv6 mpls-vpn",
    "ipv4 nlri-mpls", "ipv6 nlri-mpls",
    "ipv4 multicast",
    "ipv4 rtc",
    "l2vpn evpn", "l2vpn vpls",
    "bgp-ls bgp-ls",
]


def generate_config(session_id, device_ip, peer_as, local_as=65200,
                    local_address="100.64.6.134", router_id=None,
                    families=None, hold_time=180, ebgp_multihop=10):
    """Generate ExaBGP config from template or inline."""
    if families is None:
        families = ALL_EXABGP_FAMILIES.copy()
    if router_id is None:
        router_id = local_address

    families = [DNOS_TO_EXABGP.get(f, f) for f in families]

    template_path = TEMPLATES_DIR / "exabgp_conf.j2"

    if template_path.exists():
        try:
            from jinja2 import Template
            with open(template_path) as f:
                tmpl = Template(f.read())
            config = tmpl.render(
                device_ip=device_ip,
                router_id=router_id,
                local_address=local_address,
                local_as=local_as,
                peer_as=peer_as,
                hold_time=hold_time,
                ebgp_multihop=ebgp_multihop,
                families=families,
            )
        except ImportError:
            config = _generate_config_inline(
                device_ip, peer_as, local_as, local_address,
                router_id, families, hold_time, ebgp_multihop
            )
    else:
        config = _generate_config_inline(
            device_ip, peer_as, local_as, local_address,
            router_id, families, hold_time, ebgp_multihop
        )

    config_path = Path(f"/tmp/exabgp_{session_id}.conf")
    with open(config_path, "w") as f:
        f.write(config)
    return str(config_path)


def _generate_config_inline(device_ip, peer_as, local_as, local_address,
                            router_id, families, hold_time, ebgp_multihop,
                            static_flow_routes=None):
    """Generate ExaBGP config without Jinja2.

    ExaBGP active mode: initiates TCP to the device. Device has passive enabled
    (FortiGate IDS protection) so it never initiates SYNs. BgpTrius iptables on
    the device must have ACCEPT rules for our IP (added by bgp_tool.py diagnose --fix).
    Do NOT use incoming-ttl (sets IP_TTL on socket, not MIN_TTL).

    static_flow_routes: list of ExaBGP announce strings to embed as static flow
    routes. They are parsed at config load and sent on session establishment,
    bypassing the pipe API bottleneck entirely.
    """
    family_lines = "\n".join(f"        {fam};" for fam in families)

    static_block = ""
    if static_flow_routes:
        route_lines = []
        for r in static_flow_routes:
            line = r.replace("announce flow route ", "", 1) if r.startswith("announce flow route ") else r
            route_lines.append(f"            {line};")
        routes_str = "\n".join(route_lines)
        static_block = f"""
    static {{
        flow {{
{routes_str}
        }}
    }}
"""

    return f"""process pipe-reader {{
    run /usr/bin/socat stdout pipe:/run/exabgp/exabgp.in;
    encoder text;
}}

neighbor {device_ip} {{
    router-id {router_id};
    local-address {local_address};
    local-as {local_as};
    peer-as {peer_as};
    hold-time {hold_time};
    passive false;
    connect 179;
    outgoing-ttl 64;

    family {{
{family_lines}
    }}
{static_block}
    api {{
        processes [ pipe-reader ];
    }}
}}
"""


def generate_config_with_routes(session_id, device_ip, peer_as, local_as=65200,
                                local_address="100.64.6.134", router_id=None,
                                families=None, hold_time=180, ebgp_multihop=10,
                                static_flow_routes=None):
    """Generate ExaBGP config with pre-loaded static flow routes.

    Routes are embedded in the config as static flow definitions. ExaBGP parses
    them at startup and advertises them on session establishment -- much faster
    than pipe injection for bulk routes (thousands per second vs ~183 rps).
    """
    if families is None:
        families = ALL_EXABGP_FAMILIES.copy()
    if router_id is None:
        router_id = local_address

    families = [DNOS_TO_EXABGP.get(f, f) for f in families]

    config = _generate_config_inline(
        device_ip, peer_as, local_as, local_address,
        router_id, families, hold_time, ebgp_multihop,
        static_flow_routes=static_flow_routes,
    )

    config_path = Path(f"/tmp/exabgp_{session_id}.conf")
    with open(config_path, "w") as f:
        f.write(config)
    return str(config_path)
