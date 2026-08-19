#!/usr/bin/env python3
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lease
import onboard


def test_classify():
    assert onboard.classify_bd_type("g_mgmt_v999") == ("global", 999)
    assert onboard.classify_bd_type("g_foo_v2100") == ("global", 2100)
    assert onboard.classify_bd_type("l_bar_v10")[0] == "local"


def test_range():
    assert onboard.vlan_in_range(2100, "2100-2199")
    assert not onboard.vlan_in_range(999, "2100-2199")
    plan = onboard.onboard_plan({"vlan": 999, "vlan_range": "2100-2199"})
    assert plan["verdict"] == "VLAN_OUT_OF_RANGE"


def test_no_silent_999():
    plan = onboard.onboard_plan({
        "vlan": 2100,
        "bd_name": "g_mgmt_v999",
        "bd_show_text": "instance g_foo_v2100\n",
    })
    assert plan["verdict"] == "FORBIDDEN_FALLBACK"


def test_match_and_plan():
    show = "instance g_user_v2100\n"
    plan = onboard.onboard_plan({
        "vlan": 2100,
        "vlan_range": "2100-2199",
        "bd_show_text": show,
        "dnaas_leaf": "DNAAS-LEAF-X",
        "bundle": "bundle-100",
        "device": "PE-X",
        "dut_ip": "10.1.1.10",
        "gateway": "10.1.1.1",
        "subnet": "24",
        "asn": "65001",
    })
    assert plan["ok"] and plan["bd_name"] == "g_user_v2100"
    assert plan["subif"] == "bundle-100.2100"
    assert "g_mgmt_v999" not in json.dumps(plan)
    assert plan.get("execute") is False


def test_need_discover():
    plan = onboard.onboard_plan({"vlan": 2100, "vlan_range": "2100-2199", "device": "PE-X"})
    assert plan["verdict"] == "NEED_DISCOVER"


def test_selected_afis_on_dut():
    plan = onboard.onboard_plan({
        "vlan": 2100,
        "vlan_range": "2100-2199",
        "bd_show_text": "instance g_user_v2100\n",
        "dnaas_leaf": "DNAAS-LEAF-X",
        "bundle": "bundle-100",
        "device": "PE-X",
        "dut_ip": "10.1.1.10",
        "gateway": "10.1.1.1",
        "selected_afis": "l2vpn-evpn,ipv4-unicast",
        "asn": "65001",
    })
    dut = [d for d in plan["dnos_deltas"] if d.get("role") == "dut"][0]
    assert "address-family l2vpn-evpn" in dut["config"]
    assert "address-family ipv4-unicast" in dut["config"]
    assert "g_mgmt_v999" not in json.dumps(plan)


def test_reject_dut_as_gateway():
    plan = onboard.onboard_plan({
        "vlan": 1205,
        "bd_name": "g_user_v1205",
        "dnaas_leaf": "DNAAS-LEAF-B15",
        "bundle": "ge100-0/0/9",
        "device": "PE-X",
        "dut_ip": "201.44.205.1",
        "gateway": "201.44.205.1",
        "asn": "65001",
    })
    assert plan["verdict"] == "BAD_GATEWAY"


def test_reject_houston_leaf():
    plan = onboard.onboard_plan({
        "vlan": 1205,
        "bd_name": "g_user_v1205",
        "dnaas_leaf": "HO-DNAAS-LEAF-C05-2",
        "bundle": "ge100-0/0/9",
    })
    assert plan["verdict"] == "WRONG_LAB"


def test_il_leaf_filter():
    blob = "HO-DNAAS-LEAF-C05-2 DNAAS-LEAF-B15 DNAAS-LEAF-B14"
    names = onboard.il_leaf_names(blob)
    assert names == ["DNAAS-LEAF-B15", "DNAAS-LEAF-B14"]
    assert "DNAAS-LEAF-C05-2" not in names


def test_need_asn():
    plan = onboard.onboard_plan({
        "vlan": 2100,
        "bd_name": "g_user_v2100",
        "dnaas_leaf": "DNAAS-LEAF-B15",
        "bundle": "bundle-100",
        "device": "PE-X",
        "dut_ip": "10.1.1.10",
        "gateway": "10.1.1.1",
    })
    assert plan["verdict"] == "NEED_PARAMS"
    assert any("asn" in e for e in plan["errors"])


def test_lease(tmp_path=None):
    orig = lease.LEASE_FILE
    d = Path(tempfile.mkdtemp())
    lease.LEASE_FILE = d / "active.json"
    lease.LEASES_DIR = d
    try:
        a = lease.acquire("alice", dut="PE-1")
        assert a["ok"]
        b = lease.acquire("bob", dut="PE-2")
        assert not b["ok"] and b["verdict"] == "DEVICE_BUSY"
        g = lease.require_owner("bob")
        assert g and g["verdict"] == "DEVICE_BUSY"
        assert lease.require_owner("alice") is None
        r = lease.release("alice")
        assert r["ok"]
        c = lease.acquire("bob")
        assert c["ok"]
    finally:
        lease.LEASE_FILE = orig


if __name__ == "__main__":
    test_classify()
    test_range()
    test_no_silent_999()
    test_match_and_plan()
    test_need_discover()
    test_selected_afis_on_dut()
    test_reject_dut_as_gateway()
    test_reject_houston_leaf()
    test_il_leaf_filter()
    test_need_asn()
    test_lease()
    print("[OK] onboard+lease unit tests")
