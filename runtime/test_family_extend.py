#!/usr/bin/env python3
"""Unit tests for RFC family registry, speaker dump, and synthesize gates."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capability_speaker as cs
import family_registry as fr
import rfc_synthesize as rs

SAMPLE = {
    "name": "exp-afi99",
    "afi": 99,
    "safi": 99,
    "capability": {"code": 99, "value_hex": "00630063"},
    "nlri_tlvs": [
        {"name": "rd", "type": 0, "encoding": "rd:65000:1"},
        {"name": "tag", "type": 1, "encoding": "u32:1"},
    ],
    "path_attrs": [{"flags": 64, "type_code": 1, "value_template": "hex:00"}],
    "source": {"rfc": "experimental", "section": "test"},
    "override": False,
}


def _tmp_reg():
    d = Path(tempfile.mkdtemp())
    fr.FAMILIES_DIR = d / "families"
    fr.REGISTRY_FILE = fr.FAMILIES_DIR / "registry.json"
    fr.LOCK_FILE = fr.FAMILIES_DIR / "registry.lock"
    fr.SESSIONS_DIR = d / "sessions"
    rs.QUEUE_DIR = fr.SESSIONS_DIR / "_queue"
    fr.FAMILIES_DIR.mkdir(parents=True)
    return d


def test_validate():
    assert fr.validate_spec(SAMPLE) == []
    bad_afi = {**SAMPLE, "afi": 999999}
    assert any("afi out of range" in e for e in fr.validate_spec(bad_afi))
    bad_enc = {**SAMPLE, "nlri_tlvs": [{"name": "x", "type": 0, "encoding": "foo:bar"}]}
    assert any("closed grammar" in e for e in fr.validate_spec(bad_enc))
    collide = {**SAMPLE, "name": "other", "afi": 1, "safi": 1}
    assert any("collides" in e for e in fr.validate_spec(collide))


def test_dump_no_socket():
    called = {"n": 0}
    real = cs.socket.socket

    def boom(*a, **k):
        called["n"] += 1
        raise AssertionError("socket must not be used in dump_only")

    cs.socket.socket = boom  # type: ignore
    try:
        out = cs.dump_frames(SAMPLE)
        assert out["ok"] and out["verdict"] == "DUMP_OK"
        assert out["open_hex"].startswith("f" * 32)
        po = cs.parse_header(bytes.fromhex(out["open_hex"]))
        pu = cs.parse_header(bytes.fromhex(out["update_hex"]))
        assert po["ok"] and pu["ok"]
        assert called["n"] == 0
    finally:
        cs.socket.socket = real


def test_publish_lock():
    _tmp_reg()
    a = {**SAMPLE, "name": "fam-a", "safi": 90}
    b = {**SAMPLE, "name": "fam-b", "safi": 91}
    errs = []

    def one(spec):
        r = fr.publish(spec, owner="t")
        if not r.get("ok"):
            errs.append(r)

    t1 = threading.Thread(target=one, args=(a,))
    t2 = threading.Thread(target=one, args=(b,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert not errs
    families = fr.load_registry()["families"]
    assert "fam-a" in families and "fam-b" in families
    json.loads(fr.REGISTRY_FILE.read_text())
    u = fr.unregister("fam-a")
    assert u["ok"] and u.get("backup")
    assert "fam-a" not in fr.load_registry()["families"]
    assert Path(u["backup"]).exists()


def test_gates():
    _tmp_reg()
    os.environ.pop("BGP_FAMILY_AUTOPUBLISH", None)
    bad_plugin = "import os\ndef dump_only(spec):\n    return {'ok': True}\n"
    r = rs.stage(SAMPLE, "alice", plugin_src=bad_plugin)
    assert r["verdict"] == "REJECTED" and r["failing_gate"] == "ast_reject"
    eval_plugin = "def dump_only(spec):\n    return eval('1')\n"
    r2 = rs.stage(SAMPLE, "alice", plugin_src=eval_plugin)
    assert r2["failing_gate"] == "ast_reject"
    bad_spec = {**SAMPLE, "nlri_tlvs": [{"name": "x", "type": 0, "encoding": "foo:bar"}]}
    r3 = rs.stage(bad_spec, "alice")
    assert r3["failing_gate"] == "validate_spec"
    r4 = rs.stage(SAMPLE, "alice")
    assert r4["verdict"] == "QUEUED_FOR_REVIEW"
    assert "exp-afi99" not in fr.load_registry()["families"]
    os.environ["BGP_FAMILY_AUTOPUBLISH"] = "1"
    spec2 = {**SAMPLE, "name": "exp-afi98", "safi": 98}
    r5 = rs.stage(spec2, "alice")
    assert r5["verdict"] == "AUTO_PUBLISHED"
    assert "exp-afi98" in fr.load_registry()["families"]
    os.environ.pop("BGP_FAMILY_AUTOPUBLISH", None)
    promo = rs.promote("exp-afi99", "alice")
    assert promo.get("ok")
    assert "exp-afi99" in fr.load_registry()["families"]


if __name__ == "__main__":
    test_validate()
    test_dump_no_socket()
    test_publish_lock()
    test_gates()
    print("[OK] family extend unit tests")
