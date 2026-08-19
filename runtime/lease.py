#!/usr/bin/env python3
"""Single-instance ExaBGP lease (one :179 listener). Atomic JSON writes."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
LEASES_DIR = BASE_DIR / "leases"
LEASE_FILE = LEASES_DIR / "active.json"


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".lease_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read() -> dict[str, Any]:
    if not LEASE_FILE.exists():
        return {}
    try:
        return json.loads(LEASE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _pid_alive(pid: Any) -> bool:
    try:
        p = int(pid)
    except (TypeError, ValueError):
        return False
    if p <= 0:
        return False
    try:
        os.kill(p, 0)
        return True
    except OSError:
        return False


def status() -> dict[str, Any]:
    cur = _read()
    if not cur.get("active"):
        return {"ok": True, "verdict": "AVAILABLE", "current": cur or None, "path": str(LEASE_FILE)}
    age = max(0, int(time.time()) - int(cur.get("updated_at") or 0))
    ttl = int(cur.get("ttl_sec") or 3600)
    stale = age > ttl and not _pid_alive(cur.get("pid"))
    return {
        "ok": True,
        "verdict": "STALE" if stale else "HELD",
        "current": cur,
        "path": str(LEASE_FILE),
        "age_sec": age,
        "holder_pid_alive": _pid_alive(cur.get("pid")),
    }


def acquire(owner: str, dut: str | None = None, ttl_sec: int = 3600, force: bool = False) -> dict[str, Any]:
    owner = str(owner or "").strip()
    if not owner:
        return {"ok": False, "verdict": "ERROR", "errors": ["owner is required"]}
    cur = _read()
    if cur.get("active") and not force:
        same = str(cur.get("owner") or "") == owner
        age = max(0, int(time.time()) - int(cur.get("updated_at") or 0))
        ttl = int(cur.get("ttl_sec") or 3600)
        stale = age > ttl and not _pid_alive(cur.get("pid"))
        if not same and not stale:
            return {
                "ok": False,
                "verdict": "DEVICE_BUSY",
                "errors": [f"ExaBGP lease held by {cur.get('owner')}"],
                "current": cur,
                "path": str(LEASE_FILE),
            }
    payload = {
        "active": True,
        "owner": owner,
        "dut": dut,
        "updated_at": int(time.time()),
        "ttl_sec": int(ttl_sec),
        "pid": os.getpid(),
    }
    _atomic_write(LEASE_FILE, payload)
    return {"ok": True, "verdict": "LOCK_ACQUIRED", "payload": payload, "path": str(LEASE_FILE)}


def release(owner: str, force: bool = False) -> dict[str, Any]:
    owner = str(owner or "").strip()
    cur = _read()
    if not cur.get("active"):
        return {"ok": True, "verdict": "AVAILABLE", "current": cur or None}
    if not force and str(cur.get("owner") or "") != owner:
        return {
            "ok": False,
            "verdict": "DEVICE_BUSY",
            "errors": [f"lease owned by {cur.get('owner')}, not {owner}"],
            "current": cur,
        }
    payload = {"active": False, "released_by": owner or cur.get("owner"), "updated_at": int(time.time())}
    _atomic_write(LEASE_FILE, payload)
    return {"ok": True, "verdict": "LOCK_RELEASED", "payload": payload}


def require_owner(owner: str) -> dict[str, Any] | None:
    """Return an error dict if owner does not hold the active lease, else None."""
    cur = _read()
    if not cur.get("active"):
        return {
            "ok": False,
            "verdict": "NO_LEASE",
            "errors": ["acquire exabgp_session_lock before mutating ExaBGP"],
        }
    if str(cur.get("owner") or "") != str(owner or "").strip():
        return {
            "ok": False,
            "verdict": "DEVICE_BUSY",
            "errors": [f"ExaBGP lease held by {cur.get('owner')}"],
            "current": cur,
        }
    return None
