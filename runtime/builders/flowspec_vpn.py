"""FlowSpec-VPN SAFI 134 - ExaBGP flat format, Simpson redirect-ip."""

from . import register


@register("flowspec-vpn")
def build(args):
    """Build FlowSpec-VPN announce string. Uses FLAT format for ExaBGP API pipe."""
    rd = args.rd
    match_str = args.match
    rt = args.rt
    if getattr(args, "redirect_ip", None):
        action_str = f"redirect {args.redirect_ip}"
    else:
        action_str = args.action or "rate-limit 0"

    if not rd:
        raise ValueError("--rd required for flowspec-vpn (e.g., '4.4.4.4:101')")
    if not match_str:
        raise ValueError("--match required for flowspec-vpn")
    if not rt:
        raise ValueError("--rt required for flowspec-vpn (route target, e.g., '1234567:101')")

    match_flat = match_str.strip().rstrip(";").replace(";", " ")
    action_flat = action_str.strip().rstrip(";").replace(";", " ")
    return f"announce flow route rd {rd} {match_flat} {action_flat} extended-community [ target:{rt} ]"
