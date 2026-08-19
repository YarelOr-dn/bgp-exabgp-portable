"""MED and LOCAL_PREF variations."""

from . import register_attr


@register_attr("med-variations")
def med(prefix: str, nexthop: str, med_value: int = 100, **kwargs) -> str:
    """ExaBGP route with MED (multi-exit discriminator)."""
    return f"announce route {prefix} next-hop {nexthop} med {med_value}"


@register_attr("local-pref-high")
def local_pref_high(prefix: str, nexthop: str, local_pref: int = 200, **kwargs) -> str:
    """ExaBGP route with high LOCAL_PREF."""
    return f"announce route {prefix} next-hop {nexthop} local-preference {local_pref}"


@register_attr("local-pref-low")
def local_pref_low(prefix: str, nexthop: str, local_pref: int = 50, **kwargs) -> str:
    """ExaBGP route with low LOCAL_PREF."""
    return f"announce route {prefix} next-hop {nexthop} local-preference {local_pref}"
