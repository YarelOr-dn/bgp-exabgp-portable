#!/usr/bin/env python3
"""
malform/ - Plugin registry for BGP malformation builders.

Each module registers malformation types via @register("name").
"""

MALFORMATIONS = {}
DESCRIPTIONS = {}


def register(name, description=None):
    """Decorator to register a malformation builder."""

    def decorator(func):
        MALFORMATIONS[name] = func
        DESCRIPTIONS[name] = description or func.__doc__ or name
        return func

    return decorator


def build(malform_type: str, **kwargs) -> bytes:
    """Build malformed message bytes by type name."""
    builder = MALFORMATIONS.get(malform_type)
    if not builder:
        raise ValueError(f"Unknown malform type: {malform_type}. Available: {list(MALFORMATIONS.keys())}")
    return builder(**kwargs)


# Import to trigger registration
from . import header
from . import nlri
from . import attributes
from . import extcommunity
from . import sender
