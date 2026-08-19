"""FlowSpec SAFI 133 - ExaBGP route strings."""

from . import register


@register("flowspec")
def build(args):
    """Build FlowSpec announce string."""
    match_str = args.match
    action_str = args.action or "rate-limit 0"

    if not match_str:
        raise ValueError("--match required for flowspec (e.g., 'destination 10.0.0.0/24')")

    match_parts = []
    for part in match_str.split(";"):
        part = part.strip()
        if part:
            if not part.endswith(";"):
                part += ";"
            match_parts.append(part)
    match_block = " ".join(match_parts)

    action_parts = []
    for part in action_str.split(";"):
        part = part.strip()
        if part:
            if not part.endswith(";"):
                part += ";"
            action_parts.append(part)
    action_block = " ".join(action_parts)

    return f"announce flow route match {{ {match_block} }} then {{ {action_block} }}"
