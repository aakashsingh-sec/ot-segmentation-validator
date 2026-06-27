"""
tests/test_rules.py — pytest coverage for the rule engine in rules.py.

Each test gets a fresh, isolated SQLite file via the `test_db` fixture
(monkeypatches db.DB_PATH to a path under pytest's tmp_path, then calls
db.reset_db()) so tests never share state and never touch the real
data/ot_segmentation.db. `topology` layers a small, reusable asset/conduit
set on top of that empty database; individual tests add only the flows
relevant to what they're checking.

Run with: py -3.11 -m pytest tests/test_rules.py -v
"""

import json

import pytest

import config
import db
import rules


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """An empty, isolated database for one test."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.reset_db()
    yield


@pytest.fixture
def topology(test_db):
    """A small fixed topology shared by every test below.

    Z-SUPERVISORY <-> Z-OPERATIONS <-> Z-DMZ <-> Z-ENTERPRISE are wired with
    permissive (wildcard) conduits; everything else is deliberately left
    without a conduit so cross-zone flows that should be flagged are.
    """
    db.insert_assets(
        [
            {"name": "PLC-01", "type": "PLC", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "High", "scan_sensitivity": False},
            {"name": "PLC-02", "type": "PLC", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "High", "scan_sensitivity": False},
            {"name": "HMI-01", "type": "HMI", "purdue_level": 2, "zone": "Z-SUPERVISORY", "criticality": "Medium", "scan_sensitivity": False},
            {"name": "HIST-01", "type": "Historian", "purdue_level": 3, "zone": "Z-OPERATIONS", "criticality": "Medium", "scan_sensitivity": False},
            {"name": "ENT-01", "type": "Server", "purdue_level": 4, "zone": "Z-ENTERPRISE", "criticality": "Low", "scan_sensitivity": False},
            {"name": "UNKNOWN-ZONE-01", "type": "PLC", "purdue_level": None, "zone": None, "criticality": "Medium", "scan_sensitivity": False},
            {"name": "SAFETY-PLC-01", "type": "SIS", "purdue_level": 1, "zone": "Z-SAFETY", "criticality": "Safety", "scan_sensitivity": True},
            {"name": "BRIDGE-01", "type": "Gateway", "purdue_level": 3, "zone": "Z-OPERATIONS", "criticality": "Medium", "scan_sensitivity": False},
            {"name": "DMZ-JUMP-01", "type": "Jumphost", "purdue_level": 3.5, "zone": "Z-DMZ", "criticality": "Medium", "scan_sensitivity": False},
            {"name": "OPS-SVC-01", "type": "Server", "purdue_level": 3, "zone": "Z-OPERATIONS", "criticality": "Medium", "scan_sensitivity": False},
        ]
    )
    db.insert_conduits(
        [
            {"src_zone": "Z-SUPERVISORY", "dst_zone": "Z-OPERATIONS", "allowed_protocols": "*", "allowed_ports": "*", "direction": "bi", "description": "supervisory-ops link"},
            {"src_zone": "Z-OPERATIONS", "dst_zone": "Z-DMZ", "allowed_protocols": "*", "allowed_ports": "*", "direction": "bi", "description": "ops-dmz"},
            {"src_zone": "Z-DMZ", "dst_zone": "Z-ENTERPRISE", "allowed_protocols": "*", "allowed_ports": "*", "direction": "bi", "description": "dmz-enterprise"},
        ]
    )


def _seed_assessment(flows: list) -> int:
    assessment_id = db.create_assessment("Test assessment", "2026-06-01", "2026-06-27")
    db.insert_flows(flows, assessment_id)
    return assessment_id


def _violations_by_pair(assessment_id: int) -> dict:
    return {(v["src_asset"], v["dst_asset"]): v for v in db.get_violations(assessment_id)}


def test_clean_intra_zone_flow_not_flagged(topology):
    """Same-zone Modbus traffic is normal OT traffic and should be silent."""
    assessment_id = _seed_assessment(
        [{"src_asset": "PLC-01", "dst_asset": "PLC-02", "port": 502, "protocol": "Modbus", "flow_count": 10}]
    )
    rules.evaluate_assessment(assessment_id)
    assert _violations_by_pair(assessment_id) == {}


def test_clean_permitted_cross_zone_flow_not_flagged(topology):
    """A cross-zone flow covered by an explicit conduit should also be silent."""
    assessment_id = _seed_assessment(
        [{"src_asset": "HMI-01", "dst_asset": "HIST-01", "port": 1234, "protocol": "HistorianSync", "flow_count": 5}]
    )
    rules.evaluate_assessment(assessment_id)
    assert _violations_by_pair(assessment_id) == {}


def test_incomplete_inventory_short_circuits_other_rules(topology):
    """A flow touching an asset with no zone/level yields exactly one loud
    finding — INCOMPLETE_INVENTORY — and nothing else, because no other rule
    can be evaluated without that information.
    """
    assessment_id = _seed_assessment(
        [{"src_asset": "HMI-01", "dst_asset": "UNKNOWN-ZONE-01", "port": 502, "protocol": "Modbus", "flow_count": 1}]
    )
    rules.evaluate_assessment(assessment_id)
    violation = _violations_by_pair(assessment_id)[("HMI-01", "UNKNOWN-ZONE-01")]
    assert violation["rule_id"] == "INCOMPLETE_INVENTORY"
    assert json.loads(violation["contributing_rules"]) == []


def test_shadow_asset_detected(topology):
    """A flow naming a device that's neither in inventory nor external-shaped
    is an undocumented (shadow) asset.
    """
    assessment_id = _seed_assessment(
        [{"src_asset": "HMI-01", "dst_asset": "GHOST-DEVICE-01", "port": 80, "protocol": "HTTP", "flow_count": 1}]
    )
    rules.evaluate_assessment(assessment_id)
    violation = _violations_by_pair(assessment_id)[("HMI-01", "GHOST-DEVICE-01")]
    assert violation["rule_id"] == "SHADOW_ASSET"


def test_multi_rule_flow_picks_highest_precedence_headline(topology):
    """A direct Level 1 -> Level 4 Modbus flow trips DMZ_BYPASS, NO_CONDUIT,
    LEVEL_SKIP, and INSECURE_PROTO_CROSS_ZONE all at once. All four land at
    the same (un-escalated) severity, so DMZ_BYPASS — precedence 1 — must be
    the single headline row; the rest become contributing_rules, not
    separate violations.
    """
    assessment_id = _seed_assessment(
        [{"src_asset": "PLC-01", "dst_asset": "ENT-01", "port": 502, "protocol": "Modbus", "flow_count": 2}]
    )
    rules.evaluate_assessment(assessment_id)
    violation = _violations_by_pair(assessment_id)[("PLC-01", "ENT-01")]
    assert violation["rule_id"] == "DMZ_BYPASS"
    assert set(json.loads(violation["contributing_rules"])) == {
        "NO_CONDUIT",
        "LEVEL_SKIP",
        "INSECURE_PROTO_CROSS_ZONE",
    }


def test_severity_escalates_for_safety_destination(topology):
    """NO_CONDUIT's base severity is High; escalate_severity bumps it to
    Critical because the destination's criticality is Safety. The
    scan-sensitivity note must also be appended since the destination is
    flagged scan_sensitivity=True.
    """
    assessment_id = _seed_assessment(
        [{"src_asset": "PLC-01", "dst_asset": "SAFETY-PLC-01", "port": 9999, "protocol": "Modbus", "flow_count": 1}]
    )
    rules.evaluate_assessment(assessment_id)
    violation = _violations_by_pair(assessment_id)[("PLC-01", "SAFETY-PLC-01")]
    assert violation["rule_id"] == "NO_CONDUIT"
    assert violation["severity"] == "Critical"
    assert config.SCAN_SENSITIVITY_NOTE in violation["remediation"]


def test_dual_homed_bridge_detected(topology):
    """BRIDGE-01 receives from Z-CONTROL and separately sends to
    Z-ENTERPRISE, with no conduit directly joining those two zones — it is
    relaying traffic between them outside any approved path. Both legs of
    that relay should carry DUAL_HOMED_BRIDGE.
    """
    assessment_id = _seed_assessment(
        [
            {"src_asset": "PLC-02", "dst_asset": "BRIDGE-01", "port": 1234, "protocol": "HistorianSync", "flow_count": 1},
            {"src_asset": "BRIDGE-01", "dst_asset": "ENT-01", "port": 443, "protocol": "HTTPS", "flow_count": 1},
        ]
    )
    rules.evaluate_assessment(assessment_id)
    by_pair = _violations_by_pair(assessment_id)
    for pair in (("PLC-02", "BRIDGE-01"), ("BRIDGE-01", "ENT-01")):
        rule_ids = {by_pair[pair]["rule_id"]} | set(json.loads(by_pair[pair]["contributing_rules"]))
        assert "DUAL_HOMED_BRIDGE" in rule_ids, f"expected DUAL_HOMED_BRIDGE for {pair}, got {rule_ids}"


def test_dual_homed_bridge_allowlist_excludes_dmz_broker(topology):
    """DMZ-JUMP-01 relays Z-OPERATIONS <-> Z-ENTERPRISE traffic exactly like
    BRIDGE-01 does above — but it's on config.DUAL_HOMED_ALLOWLIST because
    that is its documented job. Both legs should be completely clean.
    """
    assessment_id = _seed_assessment(
        [
            {"src_asset": "OPS-SVC-01", "dst_asset": "DMZ-JUMP-01", "port": 3389, "protocol": "RDP", "flow_count": 1},
            {"src_asset": "DMZ-JUMP-01", "dst_asset": "ENT-01", "port": 3389, "protocol": "RDP", "flow_count": 1},
        ]
    )
    rules.evaluate_assessment(assessment_id)
    assert _violations_by_pair(assessment_id) == {}


def test_rerunning_engine_does_not_double_count(topology):
    """Re-running the engine on the same assessment (e.g. after a data fix)
    must replace prior violations, never add to them.
    """
    assessment_id = _seed_assessment(
        [{"src_asset": "PLC-01", "dst_asset": "ENT-01", "port": 502, "protocol": "Modbus", "flow_count": 2}]
    )
    first = rules.evaluate_assessment(assessment_id)
    second = rules.evaluate_assessment(assessment_id)
    assert first["violations_found"] == second["violations_found"]
    assert len(db.get_violations(assessment_id)) == first["violations_found"]
