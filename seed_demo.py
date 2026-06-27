"""
seed_demo.py — synthetic demo topology loader (airport + jet-fuel-farm OT
estate).

Populates the persistent SQLite database with a fabricated ~35-asset OT
network spanning an airport's baggage handling, airfield ground lighting,
building management, physical security, and fuel farm systems, then creates
two assessments that demonstrate how the tool tracks drift over time:

- Assessment A ("Baseline – Q1"): the network as it stood at first
  assessment. Carries 6 of 8 planted violations: V1, V2, V3, V4, V5, V7.
- Assessment B ("Re-assessment – Q2"), three months later: V3 has been
  resolved (the HMI's generic-internet HTTPS egress was removed); V6 and V8
  are new (an undocumented device talking to a baggage PLC, and a
  building-management system reaching a fuel RTU on the wrong port).

Comparing A and B is the intended demonstration of the tool's value over a
one-off scan: 1 resolved finding, 2 new findings, 1 newly-appeared
undocumented asset — drift a single snapshot would never show.

ALL data in this module is fabricated for demonstration. No real device
names, IP addresses, vendors, or network topology appear anywhere in this
file. This module only ever writes to the local SQLite file at db.DB_PATH;
it does not scan, probe, or otherwise touch a network or device.

Run directly to (re)seed local data/ot_segmentation.db:
    py -3.11 seed_demo.py
"""

import db
import rules

# ---------------------------------------------------------------------------
# Assets — 35 rows across the 10 zones in config.ZONES.
#
# INET-VENDOR-01 and INET-GENERIC-01 are deliberately inserted as real asset
# rows at Purdue level 5 / Z-EXTERNAL, rather than left out of inventory to
# be picked up by rules._looks_external's IPv4/IPv6-shape heuristic. That
# heuristic exists for traffic naming a bare IP that was never documented;
# these two are *known, named* external endpoints (a vendor remote-access
# point and a generic internet egress), so they belong in inventory like
# any other asset — which is also what lets ZONE_LEVEL_MISMATCH and the
# Purdue-tiered graph (grapher.py) place them correctly instead of treating
# them as undocumented.
#
# AMS-01 is intentionally seeded with purdue_level=2 while sitting in
# Z-OPERATIONS (canonical level 3) — a deliberate, persistent inventory
# inconsistency. This is V7: an asset whose declared Purdue level disagrees
# with its declared zone, present unresolved in both assessments below.
# ---------------------------------------------------------------------------
ASSETS = [
    # Z-FIELD (Level 0) — field instrumentation
    {"name": "SENS-FUEL-PT-01", "type": "pressure transmitter", "purdue_level": 0, "zone": "Z-FIELD", "criticality": "Medium", "scan_sensitivity": True},
    {"name": "SENS-FUEL-LT-01", "type": "tank level transmitter", "purdue_level": 0, "zone": "Z-FIELD", "criticality": "Medium", "scan_sensitivity": True},
    {"name": "SENS-FUEL-FT-01", "type": "custody flow meter", "purdue_level": 0, "zone": "Z-FIELD", "criticality": "High", "scan_sensitivity": True},
    {"name": "SENS-BHS-PE-01", "type": "baggage photo-eye", "purdue_level": 0, "zone": "Z-FIELD", "criticality": "Low", "scan_sensitivity": True},
    {"name": "SENS-AGL-FB-01", "type": "lighting feedback sensor", "purdue_level": 0, "zone": "Z-FIELD", "criticality": "Medium", "scan_sensitivity": True},

    # Z-CONTROL (Level 1) — PLCs / RTUs
    {"name": "PLC-BHS-01", "type": "baggage sortation PLC (S7comm)", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "Medium", "scan_sensitivity": True},
    {"name": "PLC-BHS-02", "type": "baggage sortation PLC (S7comm)", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "Medium", "scan_sensitivity": True},
    {"name": "PLC-JETBRIDGE-01", "type": "jet bridge PLC", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "Low", "scan_sensitivity": False},
    {"name": "RTU-FUEL-01", "type": "fuel pump/valve RTU (Modbus)", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "High", "scan_sensitivity": True},
    {"name": "RTU-FUEL-02", "type": "hydrant pit RTU (DNP3)", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "High", "scan_sensitivity": True},
    {"name": "CCR-AGL-01", "type": "airfield lighting regulator ctrl", "purdue_level": 1, "zone": "Z-CONTROL", "criticality": "High", "scan_sensitivity": True},

    # Z-SAFETY (Level 1) — SIS / ESD / F&G. Most restrictive zone: only a
    # uni, read-only monitoring conduit reaches it (see CONDUITS below).
    {"name": "SIS-FUEL-ESD-01", "type": "emergency shutdown controller", "purdue_level": 1, "zone": "Z-SAFETY", "criticality": "Safety", "scan_sensitivity": True},
    {"name": "SIS-FUEL-FG-01", "type": "fire & gas controller", "purdue_level": 1, "zone": "Z-SAFETY", "criticality": "Safety", "scan_sensitivity": True},

    # Z-SUPERVISORY (Level 2) — SCADA / HMI / DCS
    {"name": "SCADA-FUEL-01", "type": "fuel SCADA server", "purdue_level": 2, "zone": "Z-SUPERVISORY", "criticality": "High", "scan_sensitivity": False},
    {"name": "HMI-FUEL-01", "type": "fuel HMI", "purdue_level": 2, "zone": "Z-SUPERVISORY", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "HMI-AGL-01", "type": "lighting HMI (tower)", "purdue_level": 2, "zone": "Z-SUPERVISORY", "criticality": "High", "scan_sensitivity": False},
    {"name": "DCS-BHS-01", "type": "baggage DCS/supervisory", "purdue_level": 2, "zone": "Z-SUPERVISORY", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "OPC-SRV-01", "type": "OPC-UA aggregation server", "purdue_level": 2, "zone": "Z-SUPERVISORY", "criticality": "Medium", "scan_sensitivity": False},

    # Z-BMS (Level 2) — building management
    {"name": "BMS-01", "type": "building management (BACnet)", "purdue_level": 2, "zone": "Z-BMS", "criticality": "Low", "scan_sensitivity": False},

    # Z-PHYSEC (Level 2) — CCTV / access control
    {"name": "CCTV-NVR-01", "type": "network video recorder", "purdue_level": 2, "zone": "Z-PHYSEC", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "CAM-TERMINAL-01", "type": "IP camera (terminal)", "purdue_level": 2, "zone": "Z-PHYSEC", "criticality": "Low", "scan_sensitivity": True},
    {"name": "CAM-FUEL-01", "type": "IP camera (fuel farm)", "purdue_level": 2, "zone": "Z-PHYSEC", "criticality": "Low", "scan_sensitivity": True},
    {"name": "ACS-01", "type": "access control server", "purdue_level": 2, "zone": "Z-PHYSEC", "criticality": "Medium", "scan_sensitivity": False},

    # Z-OPERATIONS (Level 3) — historian / EWS / asset management
    {"name": "HIST-01", "type": "process historian (PI)", "purdue_level": 3, "zone": "Z-OPERATIONS", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "EWS-01", "type": "engineering workstation", "purdue_level": 3, "zone": "Z-OPERATIONS", "criticality": "High", "scan_sensitivity": False},
    {"name": "AMS-01", "type": "asset management server", "purdue_level": 2, "zone": "Z-OPERATIONS", "criticality": "Low", "scan_sensitivity": False},  # V7 — see module docstring

    # Z-DMZ (Level 3.5) — jump host, patch/AV, historian replication
    {"name": "DMZ-JUMP-01", "type": "jump/bastion host", "purdue_level": 3.5, "zone": "Z-DMZ", "criticality": "High", "scan_sensitivity": False},
    {"name": "DMZ-HIST-REP-01", "type": "replication historian", "purdue_level": 3.5, "zone": "Z-DMZ", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "DMZ-PATCH-01", "type": "patch/AV server", "purdue_level": 3.5, "zone": "Z-DMZ", "criticality": "Medium", "scan_sensitivity": False},

    # Z-ENTERPRISE (Level 4) — AD / email / ERP / corporate workstations
    {"name": "AD-01", "type": "domain controller", "purdue_level": 4, "zone": "Z-ENTERPRISE", "criticality": "High", "scan_sensitivity": False},
    {"name": "MAIL-01", "type": "email server", "purdue_level": 4, "zone": "Z-ENTERPRISE", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "ERP-01", "type": "enterprise app / business dashboard", "purdue_level": 4, "zone": "Z-ENTERPRISE", "criticality": "Medium", "scan_sensitivity": False},
    {"name": "WS-CORP-01", "type": "corporate workstation", "purdue_level": 4, "zone": "Z-ENTERPRISE", "criticality": "Low", "scan_sensitivity": False},

    # Z-EXTERNAL (Level 5) — vendor remote access + generic internet egress.
    # Criticality "Low": these are not internal assets to escalate findings
    # against; the source doc lists them as "n/a" but the schema requires a
    # concrete value, and neither planted violation depends on this value
    # (V1's escalation comes from RTU-FUEL-01's criticality as destination;
    # V3's OT_INTERNET_ROUTE base severity is already High with no
    # escalation needed).
    {"name": "INET-VENDOR-01", "type": "vendor remote endpoint", "purdue_level": 5, "zone": "Z-EXTERNAL", "criticality": "Low", "scan_sensitivity": False},
    {"name": "INET-GENERIC-01", "type": "internet", "purdue_level": 5, "zone": "Z-EXTERNAL", "criticality": "Low", "scan_sensitivity": False},
]

# ---------------------------------------------------------------------------
# Conduits — the 9 legitimate, documented paths. Everything else is
# deliberately left without a conduit so the planted violations (which all
# cross zones with no conduit covering them) are genuinely undocumented
# crossings, not an artifact of incomplete conduit data.
# ---------------------------------------------------------------------------
CONDUITS = [
    {"src_zone": "Z-OPERATIONS", "dst_zone": "Z-DMZ", "allowed_protocols": "OPC-UA,Historian", "allowed_ports": "4840", "direction": "uni", "description": "Historian push to replication"},
    {"src_zone": "Z-DMZ", "dst_zone": "Z-ENTERPRISE", "allowed_protocols": "HTTPS", "allowed_ports": "443", "direction": "uni", "description": "Replication to business dashboard"},
    {"src_zone": "Z-ENTERPRISE", "dst_zone": "Z-DMZ", "allowed_protocols": "RDP", "allowed_ports": "3389", "direction": "uni", "description": "Remote access lands on the jump host only"},
    {"src_zone": "Z-DMZ", "dst_zone": "Z-OPERATIONS", "allowed_protocols": "RDP", "allowed_ports": "3389", "direction": "uni", "description": "Jump host to engineering workstation"},
    {"src_zone": "Z-DMZ", "dst_zone": "Z-CONTROL", "allowed_protocols": "HTTPS", "allowed_ports": "443", "direction": "uni", "description": "Patch/AV distribution"},
    {"src_zone": "Z-DMZ", "dst_zone": "Z-SUPERVISORY", "allowed_protocols": "HTTPS", "allowed_ports": "443", "direction": "uni", "description": "Patch/AV distribution"},
    {"src_zone": "Z-SUPERVISORY", "dst_zone": "Z-CONTROL", "allowed_protocols": "Modbus,S7comm,DNP3", "allowed_ports": "502,102,20000", "direction": "bi", "description": "Normal SCADA<->PLC"},
    {"src_zone": "Z-CONTROL", "dst_zone": "Z-FIELD", "allowed_protocols": "Modbus,DNP3", "allowed_ports": "502,20000", "direction": "bi", "description": "PLC<->field IO"},
    {"src_zone": "Z-SUPERVISORY", "dst_zone": "Z-SAFETY", "allowed_protocols": "Modbus", "allowed_ports": "502", "direction": "uni", "description": "Read-only monitoring of the SIS — nothing may write to or route through Z-SAFETY"},
]

# ---------------------------------------------------------------------------
# Clean flows — present in both assessments, should never trip a rule.
# Keeps the topology graph mostly grey so the planted violations stand out.
# ---------------------------------------------------------------------------
CLEAN_FLOWS = [
    ("SCADA-FUEL-01", "RTU-FUEL-01", 502, "Modbus"),
    ("SCADA-FUEL-01", "RTU-FUEL-02", 20000, "DNP3"),
    ("HMI-FUEL-01", "SCADA-FUEL-01", 443, "HTTPS"),
    ("DCS-BHS-01", "PLC-BHS-01", 102, "S7comm"),
    ("DCS-BHS-01", "PLC-BHS-02", 102, "S7comm"),
    ("PLC-BHS-01", "SENS-BHS-PE-01", 502, "Modbus"),
    ("RTU-FUEL-01", "SENS-FUEL-PT-01", 502, "Modbus"),
    ("CCR-AGL-01", "SENS-AGL-FB-01", 502, "Modbus"),
    ("HMI-AGL-01", "CCR-AGL-01", 502, "Modbus"),
    ("SCADA-FUEL-01", "SIS-FUEL-ESD-01", 502, "Modbus"),       # read-only monitor, permitted
    ("HIST-01", "DMZ-HIST-REP-01", 4840, "OPC-UA"),            # push up, conduit
    ("DMZ-HIST-REP-01", "ERP-01", 443, "HTTPS"),               # conduit
    ("WS-CORP-01", "DMZ-JUMP-01", 3389, "RDP"),                # conduit
    ("DMZ-JUMP-01", "EWS-01", 3389, "RDP"),                    # conduit
    ("DMZ-PATCH-01", "SCADA-FUEL-01", 443, "HTTPS"),           # conduit, patching
    ("CCTV-NVR-01", "CAM-TERMINAL-01", 554, "RTSP"),           # intra Z-PHYSEC
    ("CCTV-NVR-01", "CAM-FUEL-01", 554, "RTSP"),               # intra Z-PHYSEC
    ("ACS-01", "CCTV-NVR-01", 443, "HTTPS"),                   # intra Z-PHYSEC
]

# ---------------------------------------------------------------------------
# Planted violations — the story. Each maps to a real-world ICS incident.
#
# A note on headlines: V1 and V3 both involve an OT asset (Level ≤3)
# reaching Z-EXTERNAL (Level 5) with no DMZ in between. The engine's
# DMZ_BYPASS rule treats "reaching Level ≥4" as a boundary crossing
# regardless of whether the far side is the enterprise zone or the
# internet, and DMZ_BYPASS has the highest tie-break precedence — so both
# V1 and V3 headline as DMZ_BYPASS. OT_INTERNET_ROUTE still fires on both
# and is recorded as a contributing_rule, so the internet-reachability
# finding is never lost, just not the headline. This was verified directly
# against the rule engine rather than assumed; see the Block 7 validation
# notes for the empirical check.
# ---------------------------------------------------------------------------
VIOLATION_FLOWS = {
    # V1 — vendor remote-access path straight into the control zone,
    # skipping the DMZ entirely. Modeled on the 2015 Ukraine grid attack
    # (compromised vendor VPN access used to reach ICS directly).
    "V1": {"src_asset": "INET-VENDOR-01", "dst_asset": "RTU-FUEL-01", "port": 3389, "protocol": "RDP"},

    # V2 — an engineering workstation reaching the safety controller across
    # zones; Z-SAFETY's only conduit is the read-only supervisory monitor,
    # not this. Modeled on TRITON/TRISIS.
    "V2": {"src_asset": "EWS-01", "dst_asset": "SIS-FUEL-ESD-01", "port": 502, "protocol": "Modbus"},

    # V3 — a supervisory HMI with an outbound route straight to the
    # internet. Modeled on the Oldsmar water-treatment incident. Present
    # only in Assessment A; resolved by Assessment B.
    "V3": {"src_asset": "HMI-FUEL-01", "dst_asset": "INET-GENERIC-01", "port": 443, "protocol": "HTTPS"},

    # V4 — cleartext Modbus crossing straight from enterprise into the
    # supervisory zone with no permitting conduit.
    "V4": {"src_asset": "ERP-01", "dst_asset": "SCADA-FUEL-01", "port": 502, "protocol": "Modbus"},

    # V5 — the operations historian bridging IT/OT directly (HIST-01 ->
    # ERP-01) instead of going through the DMZ replication path the
    # conduits actually authorize (HIST-01 -> DMZ-HIST-REP-01 -> ERP-01).
    "V5": {"src_asset": "HIST-01", "dst_asset": "ERP-01", "port": 443, "protocol": "HTTPS"},

    # V6 — a device that talks to a baggage-handling PLC but was never
    # added to inventory. Appears only in Assessment B: a newly discovered
    # rogue device between assessments.
    "V6": {"src_asset": "UNKNOWN-DEV-01", "dst_asset": "PLC-BHS-02", "port": 502, "protocol": "Modbus"},

    # V7 — touches AMS-01, whose Purdue level disagrees with its own
    # declared zone (see ASSETS above). Persists, unresolved, in both
    # assessments.
    "V7": {"src_asset": "EWS-01", "dst_asset": "AMS-01", "port": 443, "protocol": "HTTPS"},

    # V8 — protocol and port disagree (Modbus declared, but observed on
    # RDP's port 3389) — a possible tunnel or masquerade. New in
    # Assessment B.
    "V8": {"src_asset": "BMS-01", "dst_asset": "RTU-FUEL-01", "port": 3389, "protocol": "Modbus"},
}

BASELINE_VIOLATION_KEYS = ["V1", "V2", "V3", "V4", "V5", "V7"]
REASSESSMENT_VIOLATION_KEYS = ["V1", "V2", "V4", "V5", "V6", "V7", "V8"]


def _flow_rows(violation_keys: list[str]) -> list[dict]:
    """CLEAN_FLOWS plus the selected violation flows, as db.insert_flows rows."""
    rows = [
        {"src_asset": src, "dst_asset": dst, "port": port, "protocol": protocol, "flow_count": 1}
        for (src, dst, port, protocol) in CLEAN_FLOWS
    ]
    for key in violation_keys:
        rows.append({**VIOLATION_FLOWS[key], "flow_count": 1})
    return rows


def seed_demo() -> dict:
    """Reset the database and load the full demo topology plus two
    assessments. Safe to call repeatedly — db.reset_db() drops and
    recreates every table first, so re-seeding never leaves stale rows
    behind or double-counts violations.
    """
    db.reset_db()
    db.insert_assets(ASSETS)
    db.insert_conduits(CONDUITS)

    baseline_id = db.create_assessment("Baseline – Q1", "2026-01-01", "2026-01-31")
    db.insert_flows(_flow_rows(BASELINE_VIOLATION_KEYS), baseline_id)
    baseline_result = rules.evaluate_assessment(baseline_id)

    reassessment_id = db.create_assessment("Re-assessment – Q2", "2026-04-01", "2026-04-30")
    db.insert_flows(_flow_rows(REASSESSMENT_VIOLATION_KEYS), reassessment_id)
    reassessment_result = rules.evaluate_assessment(reassessment_id)

    return {"baseline": baseline_result, "reassessment": reassessment_result}


if __name__ == "__main__":
    summary = seed_demo()
    print("Demo data loaded (synthetic — no real device or network data).")
    for key in ("baseline", "reassessment"):
        result = summary[key]
        print(
            f"  {key} (assessment_id={result['assessment_id']}): "
            f"{result['flows_evaluated']} flows evaluated, "
            f"{result['violations_found']} violations found"
        )
