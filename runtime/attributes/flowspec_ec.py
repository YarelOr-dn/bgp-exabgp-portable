"""FlowSpec extended community variations: traffic-rate, redirect, marking, sampling."""

from . import register_attr


@register_attr("ec-simpson-0x08")
def simpson(rd: str, rt: str, redirect_ip: str, dest_prefix: str = "10.0.0.0/24", **kwargs) -> str:
    """FlowSpec-VPN with Simpson redirect-ip (0x08) - DNOS supported."""
    return (
        f"announce flow route rd {rd} destination {dest_prefix} "
        f"redirect {redirect_ip} extended-community [ target:{rt} ]"
    )


@register_attr("ec-traffic-rate")
def traffic_rate(rd: str, rt: str, rate: int = 1000000, dest_prefix: str = "10.0.0.0/24", **kwargs) -> str:
    """FlowSpec-VPN with traffic-rate extended community."""
    return (
        f"announce flow route rd {rd} destination {dest_prefix} "
        f"rate-limit {rate} extended-community [ target:{rt} ]"
    )


@register_attr("ec-traffic-action")
def traffic_action(rd: str, rt: str, dest_prefix: str = "10.0.0.0/24", **kwargs) -> str:
    """FlowSpec-VPN with traffic-action (sample/discard)."""
    return (
        f"announce flow route rd {rd} destination {dest_prefix} "
        f"discard extended-community [ target:{rt} ]"
    )
