#!/usr/bin/env python3
"""Stage RFC-synthesized family specs; AST-then-sandbox gates; optional auto-publish."""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import capability_speaker
import family_registry as fr

QUEUE_DIR = fr.SESSIONS_DIR / "_queue"
ALLOWED_IMPORTS = {"struct", "socket", "typing"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "getattr", "open", "setattr", "delattr"}
FORBIDDEN_ATTR_ROOTS = {"os", "sys", "subprocess", "builtins", "ctypes", "importlib"}
DUNDER_PREFIX = "__"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ast_reject(plugin_src: str) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(plugin_src)
    except SyntaxError as exc:
        return [f"syntax: {exc}"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in ALLOWED_IMPORTS:
                    errors.append(f"import not allowed: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod not in ALLOWED_IMPORTS:
                errors.append(f"from-import not allowed: {node.module}")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = None
            if isinstance(fn, ast.Name):
                name = fn.id
            elif isinstance(fn, ast.Attribute):
                name = fn.attr
            if name in FORBIDDEN_CALLS:
                errors.append(f"forbidden call: {name}")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in FORBIDDEN_ATTR_ROOTS:
                errors.append(f"forbidden attribute root: {node.value.id}.{node.attr}")
            if isinstance(node.attr, str) and node.attr.startswith(DUNDER_PREFIX):
                errors.append(f"forbidden dunder attr: {node.attr}")
        elif isinstance(node, ast.Name) and node.id.startswith(DUNDER_PREFIX) and node.id not in ("__name__", "__doc__"):
            errors.append(f"forbidden dunder name: {node.id}")
    return errors


_SANDBOX_RUNNER = r'''
import socket, sys, json, importlib.util, resource
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024, 64 * 1024 * 1024))
def _nosock(*a, **k):
    raise RuntimeError("socket disabled in sandbox")
socket.socket = _nosock  # type: ignore
path = sys.argv[1]
spec = json.loads(sys.argv[2])
mod_name = "_family_plugin"
spec_obj = importlib.util.spec_from_file_location(mod_name, path)
mod = importlib.util.module_from_spec(spec_obj)
spec_obj.loader.exec_module(mod)
if hasattr(mod, "dump_only"):
    out = mod.dump_only(spec)
elif hasattr(mod, "build"):
    out = {"ok": True, "built": True}
else:
    out = {"ok": True, "imported": True}
print(json.dumps(out if isinstance(out, dict) else {"ok": True}))
'''


def sandbox_import(plugin_src: str, spec: dict[str, Any], timeout_sec: int = 5) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        plugin = Path(td) / "plugin.py"
        plugin.write_text(plugin_src, encoding="utf-8")
        runner = Path(td) / "runner.py"
        runner.write_text(_SANDBOX_RUNNER, encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-S", str(runner), str(plugin), json.dumps(spec)],
                capture_output=True, text=True, timeout=timeout_sec,
                env={"PYTHONPATH": "", "PATH": os.environ.get("PATH", "/usr/bin")},
                cwd=td,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "errors": ["sandbox timeout"]}
        if proc.returncode != 0:
            return {"ok": False, "errors": [(proc.stderr or proc.stdout or "sandbox fail")[:800]]}
        try:
            return json.loads(proc.stdout.strip() or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "errors": ["sandbox non-json stdout"]}


def stage(candidate_spec: dict[str, Any], owner: str, plugin_src: Optional[str] = None,
          rfc_text: Optional[str] = None) -> dict[str, Any]:
    gates: list[dict[str, Any]] = []
    spec = dict(candidate_spec)
    spec.setdefault("owner", owner)
    spec.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if rfc_text and not spec.get("source"):
        spec["source"] = {"rfc": "pasted", "section": "user"}

    verrs = fr.validate_spec(spec)
    gates.append({"gate": "validate_spec", "ok": not verrs, "errors": verrs})
    if verrs:
        return {"ok": False, "verdict": "REJECTED", "failing_gate": "validate_spec", "gates": gates, "errors": verrs}

    if plugin_src:
        aerrs = ast_reject(plugin_src)
        gates.append({"gate": "ast_reject", "ok": not aerrs, "errors": aerrs})
        if aerrs:
            return {"ok": False, "verdict": "REJECTED", "failing_gate": "ast_reject", "gates": gates, "errors": aerrs}
        sbox = sandbox_import(plugin_src, spec)
        sok = bool(sbox.get("ok"))
        gates.append({"gate": "sandbox_import", "ok": sok, "errors": sbox.get("errors") or []})
        if not sok:
            return {"ok": False, "verdict": "REJECTED", "failing_gate": "sandbox_import", "gates": gates, "errors": sbox.get("errors")}
    else:
        gates.append({"gate": "ast_reject", "ok": True, "skipped": "spec-only"})
        gates.append({"gate": "sandbox_import", "ok": True, "skipped": "spec-only"})

    dumped = capability_speaker.dump_frames(spec)
    dok = bool(dumped.get("ok"))
    gates.append({"gate": "dump_and_reparse", "ok": dok, "errors": dumped.get("errors") or []})
    if not dok:
        return {"ok": False, "verdict": "REJECTED", "failing_gate": "dump_and_reparse", "gates": gates, "errors": dumped.get("errors"), "dump": dumped}

    size_ok = dumped.get("open_len", 0) <= fr.MAX_FRAME and dumped.get("update_len", 0) <= fr.MAX_FRAME
    gates.append({"gate": "frame_size", "ok": size_ok, "open_len": dumped.get("open_len"), "update_len": dumped.get("update_len")})
    if not size_ok:
        return {"ok": False, "verdict": "REJECTED", "failing_gate": "frame_size", "gates": gates}

    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    qpath = QUEUE_DIR / f"{owner}_{spec['name']}.json"
    payload = {"spec": spec, "owner": owner, "plugin_src": plugin_src, "dump": {
        "open_hex": dumped.get("open_hex"), "update_hex": dumped.get("update_hex"),
        "open_len": dumped.get("open_len"), "update_len": dumped.get("update_len"),
    }}
    _atomic_write_text(qpath, json.dumps(payload, indent=2) + "\n")
    draft = fr.save_draft(spec, owner)
    return decision(spec, owner, gates, dump=dumped, queue_path=str(qpath), draft=draft)


def decision(spec: dict[str, Any], owner: str, gates: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    auto = os.environ.get("BGP_FAMILY_AUTOPUBLISH", "").strip() in ("1", "true", "TRUE", "yes")
    if auto:
        pub = fr.publish(spec, owner=owner)
        return {
            "ok": bool(pub.get("ok")),
            "verdict": "AUTO_PUBLISHED" if pub.get("ok") else "REJECTED",
            "gates": gates,
            "publish": pub,
            **extra,
        }
    return {"ok": True, "verdict": "QUEUED_FOR_REVIEW", "gates": gates, **extra}


def promote(name: str, owner: str) -> dict[str, Any]:
    spec = fr.load_draft(owner, name)
    qpath = QUEUE_DIR / f"{owner}_{name}.json"
    if spec is None and qpath.exists():
        spec = json.loads(qpath.read_text(encoding="utf-8")).get("spec")
    if not spec:
        return {"ok": False, "verdict": "NOT_FOUND", "errors": [f"no draft/queue for {owner}/{name}"]}
    return fr.publish(spec, owner=owner)
