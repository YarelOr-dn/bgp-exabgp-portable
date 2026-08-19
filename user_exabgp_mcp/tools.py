"""Tool facade for user-exabgp-mcp."""
from __future__ import annotations

import importlib
import logging
import py_compile
import sys
from pathlib import Path
from threading import RLock
from types import ModuleType

PROFILE = 'exabgp'
_LOG = logging.getLogger("user-exabgp-mcp.tools")
_LOCK = RLock()
_PROFILES: ModuleType = importlib.import_module("mcp_common.command_profiles")
_PROFILES_PATH = Path(_PROFILES.__file__ or "")
_PROFILES_MTIME_NS = _PROFILES_PATH.stat().st_mtime_ns if _PROFILES_PATH.exists() else 0


def _profiles_module() -> ModuleType:
    global _PROFILES, _PROFILES_MTIME_NS
    if not _PROFILES_PATH.exists():
        return _PROFILES
    mtime_ns = _PROFILES_PATH.stat().st_mtime_ns
    if mtime_ns <= _PROFILES_MTIME_NS:
        return _PROFILES
    with _LOCK:
        mtime_ns = _PROFILES_PATH.stat().st_mtime_ns
        if mtime_ns <= _PROFILES_MTIME_NS:
            return _PROFILES
        try:
            py_compile.compile(str(_PROFILES_PATH), doraise=True)
            crashguard = sys.modules.get("mcp_common.crashguard")
            if crashguard is not None:
                importlib.reload(crashguard)
            _PROFILES = importlib.reload(_PROFILES)
            _PROFILES_MTIME_NS = mtime_ns
            _LOG.info("hot-reloaded %s", _PROFILES_PATH)
        except Exception:
            _LOG.exception("failed to hot-reload %s; keeping previous module", _PROFILES_PATH)
        return _PROFILES

def get_tool_definitions():
    return _profiles_module().get_tool_definitions(PROFILE)

def handle_tool_call(name: str, arguments: dict):
    return _profiles_module().handle_tool_call(PROFILE, name, arguments)
