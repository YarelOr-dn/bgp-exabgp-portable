"""Attribute testing lab - BGP attribute and extended community variations."""

ATTRIBUTE_TESTS = {}
DESCRIPTIONS = {}


def register_attr(name, description=None):
    """Decorator to register an attribute test builder."""

    def decorator(func):
        ATTRIBUTE_TESTS[name] = func
        DESCRIPTIONS[name] = description or func.__doc__ or name
        return func

    return decorator


def build(test_name: str, **kwargs):
    """Build route/UPDATE for attribute test by name."""
    builder = ATTRIBUTE_TESTS.get(test_name)
    if not builder:
        raise ValueError(f"Unknown attribute test: {test_name}. Available: {list(ATTRIBUTE_TESTS.keys())}")
    return builder(**kwargs)


# Import to trigger registration
from . import communities
from . import as_path
from . import med_locpref
from . import flowspec_ec
from . import next_hop
