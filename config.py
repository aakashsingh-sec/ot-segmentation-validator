"""
config.py — constants only, no logic.

This module is the single source of truth for the Purdue model, protocol
reference data, IEC 62443 / MITRE ATT&CK for ICS mappings, and the rule
engine's metadata table. `rules.py` iterates `RULES`; adding a new rule means
adding one dict here and one function in `rules.py` — nothing else changes.

Reference verification: IEC 62443-3-3 clause numbers and MITRE ATT&CK for ICS
technique IDs below come from
`P4_Reference_Mappings_and_Demo_Network.md` (Singh's verified pass against
the standard and the live ATT&CK for ICS matrix, June 2026). Re-verify both
against current sources before publishing the README mapping table, in case
either has been revised since.
"""

# ---------------------------------------------------------------------------
# Purdue levels
# ---------------------------------------------------------------------------
# Level 5 is a pseudo-level for anything outside the operator's own network
# (internet, vendor remote-access endpoints) so that every flow — even one
# leaving the estate entirely — resolves to a zone and a level instead of
# falling through every rule silently.
PURDUE_LEVELS = {
    0:   {"label": "Level 0 — Field Devices",        "color": "#8B4513"},
    1:   {"label": "Level 1 — Basic Control",         "color": "#D2691E"},
    2:   {"label": "Level 2 — Supervisory Control",   "color": "#DAA520"},
    3:   {"label": "Level 3 — Site Operations",       "color": "#2E8B57"},
    3.5: {"label": "Level 3.5 — IT/OT DMZ",            "color": "#4682B4"},
    4:   {"label": "Level 4 — Enterprise",            "color": "#6A5ACD"},
    5:   {"label": "Level 5 — External / Internet",   "color": "#A9A9A9"},
}

# Canonical zone -> Purdue level map. Used by ZONE_LEVEL_MISMATCH to flag an
# asset whose declared purdue_level disagrees with the level its declared
# zone is supposed to sit at. EXTERNAL is the pseudo-zone for L5.
ZONES = {
    "Z-FIELD":       {"name": "Field instrumentation",      "purdue_level": 0},
    "Z-SAFETY":      {"name": "Fuel safety (ESD + F&G)",     "purdue_level": 1},
    "Z-CONTROL":     {"name": "Process control",            "purdue_level": 1},
    "Z-SUPERVISORY": {"name": "Supervisory control",         "purdue_level": 2},
    "Z-PHYSEC":      {"name": "Physical security",          "purdue_level": 2},
    "Z-BMS":         {"name": "Building management",        "purdue_level": 2},
    "Z-OPERATIONS":  {"name": "Site operations",             "purdue_level": 3},
    "Z-DMZ":         {"name": "IT/OT DMZ",                   "purdue_level": 3.5},
    "Z-ENTERPRISE":  {"name": "Enterprise",                  "purdue_level": 4},
    "Z-EXTERNAL":    {"name": "External / internet",         "purdue_level": 5},
}
EXTERNAL_ZONE = "Z-EXTERNAL"
DMZ_LEVEL = 3.5

# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------
# Insecure-by-design OT protocols (no auth/encryption in their plain form).
# DNP3-SA (Secure Authentication) is the secure variant and is intentionally
# NOT in this set. OPC-UA has a secure transport mode and is also excluded —
# do not flag it.
INSECURE_PROTOCOLS = {
    "Modbus",
    "Modbus/TCP",
    "DNP3",
    "S7comm",
    "EtherNet/IP",
    "PROFINET",
    "BACnet",
    "OPC-DA",
}

# Expected port per protocol, used by PROTO_PORT_MISMATCH. Protocols not
# listed here (e.g. RTSP, proprietary historian links) are skipped by that
# rule rather than guessed at.
WELL_KNOWN_PORTS = {
    "Modbus": 502,
    "Modbus/TCP": 502,
    "DNP3": 20000,
    "DNP3-SA": 20000,
    "S7comm": 102,
    "IEC61850-MMS": 102,
    "OPC-UA": 4840,
    "BACnet": 47808,
    "RDP": 3389,
    "HTTP": 80,
    "HTTPS": 443,
}

# ---------------------------------------------------------------------------
# IEC 62443-3-3 references
# ---------------------------------------------------------------------------
# Verified against P4_Reference_Mappings_and_Demo_Network.md. Singh: give
# these one more pass against your physical 62443-3-3 copy before the README
# ships, in case of edition differences.
IEC62443_REFS = {
    "DMZ_BYPASS": "FR5 — SR 5.1 (Network Segmentation), SR 5.2 (Zone Boundary Protection)",
    "NO_CONDUIT": "FR5 — SR 5.1 (Network Segmentation); conduit concept per IEC 62443-3-2",
    "LEVEL_SKIP": "FR5 — SR 5.1 (Network Segmentation)",
    "OT_INTERNET_ROUTE": "FR5 — SR 5.2 (Zone Boundary Protection); FR4 — SR 4.1 (Information Confidentiality)",
    "INSECURE_PROTO_CROSS_ZONE": "FR1 — SR 1.1/1.2 (Identification & Authentication); FR4 — SR 4.1 (Confidentiality); FR3 — SR 3.1 (Communication Integrity)",
    "DUAL_HOMED_BRIDGE": "FR5 — SR 5.1 (Network Segmentation), SR 5.2 (Zone Boundary Protection)",
    "SHADOW_ASSET": "FR5 — SR 5.2 (asset outside defined zone boundary)",
    "ZONE_LEVEL_MISMATCH": "IEC 62443-2-1 (zone definition / CSMS consistency)",
    "PROTO_PORT_MISMATCH": "FR5 — SR 5.2 (anomalous boundary traffic)",
    "INCOMPLETE_INVENTORY": "FR5 — SR 5.1 (cannot evaluate flow — missing zone/level)",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK for ICS references
# ---------------------------------------------------------------------------
# Verified technique IDs from P4_Reference_Mappings_and_Demo_Network.md.
# Four rule_ids are architectural/inventory-hygiene findings rather than a
# single attacker technique, so they map to None on purpose — a missing
# mapping here would be a bug, an explicit None is a documented choice.
ATTACK_ICS_MAP = {
    "DMZ_BYPASS": "External Remote Services (T0822)",
    "NO_CONDUIT": None,
    "LEVEL_SKIP": None,
    "OT_INTERNET_ROUTE": "Internet Accessible Device (T0883)",
    "INSECURE_PROTO_CROSS_ZONE": "Adversary-in-the-Middle (T0830)",
    "DUAL_HOMED_BRIDGE": "Remote Services (T0886)",
    "SHADOW_ASSET": "Rogue Master (T0848)",
    "ZONE_LEVEL_MISMATCH": None,
    "PROTO_PORT_MISMATCH": "Commonly Used Port (T0885)",
    "INCOMPLETE_INVENTORY": None,
}

# Context note (not a rule, not tied to a rule_id) attached to any finding
# that touches a scan_sensitivity=true asset. T0814 is MITRE's own citation
# for why fragile ICS devices should not be actively probed.
SCAN_SENSITIVITY_NOTE = (
    "validate passively; active scanning contraindicated — Denial of Service "
    "(T0814): some ICS devices become unresponsive to even a simple ping sweep."
)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
SEVERITY_BANDS = ["Low", "Medium", "High", "Critical"]
SEVERITY_ORDER = {band: i for i, band in enumerate(SEVERITY_BANDS)}

# Base severity per rule, before any escalation.
SEVERITY_WEIGHTS = {
    "INCOMPLETE_INVENTORY": "High",
    "DMZ_BYPASS": "High",
    "NO_CONDUIT": "High",
    "LEVEL_SKIP": "High",
    "OT_INTERNET_ROUTE": "High",
    "INSECURE_PROTO_CROSS_ZONE": "Medium",
    "DUAL_HOMED_BRIDGE": "High",
    "SHADOW_ASSET": "High",
    "ZONE_LEVEL_MISMATCH": "Medium",
    "PROTO_PORT_MISMATCH": "Medium",
}

# A destination asset at one of these criticality levels bumps the finding's
# severity up by one band (capped at Critical). "Safety" covers SIS/ESD/F&G.
ESCALATION_CRITICALITIES = {"High", "Safety"}
ESCALATION_BANDS = 1


def escalate_severity(base_severity: str, dest_criticality: str | None) -> str:
    """Bump `base_severity` by ESCALATION_BANDS if dest_criticality warrants it.

    Pure function, capped at the top of SEVERITY_BANDS. Kept here (not in
    rules.py) so severity math lives next to the table it reads from.
    """
    if dest_criticality not in ESCALATION_CRITICALITIES:
        return base_severity
    idx = SEVERITY_ORDER[base_severity] + ESCALATION_BANDS
    idx = min(idx, len(SEVERITY_BANDS) - 1)
    return SEVERITY_BANDS[idx]


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------
# The engine in rules.py iterates this list. A new rule = one new dict here
# + one new function there. Nothing else needs to change.
RULES = [
    {
        "id": "INCOMPLETE_INVENTORY",
        "label": "Incomplete inventory",
        "iec_ref": IEC62443_REFS["INCOMPLETE_INVENTORY"],
        "attack_ref": ATTACK_ICS_MAP["INCOMPLETE_INVENTORY"],
        "base_severity": SEVERITY_WEIGHTS["INCOMPLETE_INVENTORY"],
        "precedence": 10,
        "description": (
            "One or both endpoints of this flow are missing a zone or "
            "Purdue level in inventory, so the flow cannot be evaluated "
            "against any segmentation rule."
        ),
        "remediation": (
            "Complete the asset record (zone and Purdue level) before this "
            "flow can be validated. Treat as an inventory-hygiene gap, not "
            "a cleared flow."
        ),
    },
    {
        "id": "DMZ_BYPASS",
        "label": "DMZ bypass",
        "iec_ref": IEC62443_REFS["DMZ_BYPASS"],
        "attack_ref": ATTACK_ICS_MAP["DMZ_BYPASS"],
        "base_severity": SEVERITY_WEIGHTS["DMZ_BYPASS"],
        "precedence": 1,
        "description": (
            "A flow crosses the IT/OT boundary (Level ≤3 to Level ≥4, or "
            "vice versa) without terminating in the Level 3.5 DMZ. OT-to-DMZ "
            "pushes are fine; enterprise reaching past the DMZ into OT is not."
        ),
        "remediation": (
            "Route this traffic through the DMZ broker/jump host. No direct "
            "IT-to-OT or OT-to-IT path should skip Level 3.5."
        ),
    },
    {
        "id": "NO_CONDUIT",
        "label": "No permitting conduit",
        "iec_ref": IEC62443_REFS["NO_CONDUIT"],
        "attack_ref": ATTACK_ICS_MAP["NO_CONDUIT"],
        "base_severity": SEVERITY_WEIGHTS["NO_CONDUIT"],
        "precedence": 2,
        "description": (
            "A cross-zone flow exists with no defined conduit permitting "
            "that exact protocol, port, and direction between the two zones."
        ),
        "remediation": (
            "Either add an explicit conduit authorizing this exact "
            "protocol/port/direction, or block the flow at the zone boundary."
        ),
    },
    {
        "id": "OT_INTERNET_ROUTE",
        "label": "OT-to-internet route",
        "iec_ref": IEC62443_REFS["OT_INTERNET_ROUTE"],
        "attack_ref": ATTACK_ICS_MAP["OT_INTERNET_ROUTE"],
        "base_severity": SEVERITY_WEIGHTS["OT_INTERNET_ROUTE"],
        "precedence": 3,
        "description": (
            "An OT asset (Level 0-3) has a flow reaching Level 5 "
            "(internet/external), meaning it is internet-accessible or "
            "internet-reaching."
        ),
        "remediation": (
            "Remove the direct route. Any internet-facing requirement "
            "should terminate in the DMZ or enterprise zone, never on the "
            "OT asset itself."
        ),
    },
    {
        "id": "DUAL_HOMED_BRIDGE",
        "label": "Dual-homed bridge",
        "iec_ref": IEC62443_REFS["DUAL_HOMED_BRIDGE"],
        "attack_ref": ATTACK_ICS_MAP["DUAL_HOMED_BRIDGE"],
        "base_severity": SEVERITY_WEIGHTS["DUAL_HOMED_BRIDGE"],
        "precedence": 4,
        "description": (
            "An asset has flows touching two or more zones with no conduit "
            "between those zones, meaning the asset itself is bridging "
            "zones outside any approved path."
        ),
        "remediation": (
            "Confirm whether this asset is a legitimate spanning device "
            "(add to the DMZ-broker allowlist in config) or split its "
            "interfaces so it no longer bridges zones directly."
        ),
    },
    {
        "id": "LEVEL_SKIP",
        "label": "Purdue level skip",
        "iec_ref": IEC62443_REFS["LEVEL_SKIP"],
        "attack_ref": ATTACK_ICS_MAP["LEVEL_SKIP"],
        "base_severity": SEVERITY_WEIGHTS["LEVEL_SKIP"],
        "precedence": 5,
        "description": (
            "A flow spans two or more Purdue levels without passing through "
            "the intermediate tier(s)."
        ),
        "remediation": (
            "Insert an intermediate hop (e.g. supervisory or DMZ tier) or "
            "justify and document the direct path explicitly."
        ),
    },
    {
        "id": "SHADOW_ASSET",
        "label": "Shadow asset",
        "iec_ref": IEC62443_REFS["SHADOW_ASSET"],
        "attack_ref": ATTACK_ICS_MAP["SHADOW_ASSET"],
        "base_severity": SEVERITY_WEIGHTS["SHADOW_ASSET"],
        "precedence": 6,
        "description": (
            "A flow references a device that is not in the asset inventory "
            "and is not the external pseudo-zone — an undocumented device "
            "on the network."
        ),
        "remediation": (
            "Identify the device and add it to inventory with a zone and "
            "Purdue level, or confirm it should be removed from the network."
        ),
    },
    {
        "id": "INSECURE_PROTO_CROSS_ZONE",
        "label": "Insecure protocol crossing a zone",
        "iec_ref": IEC62443_REFS["INSECURE_PROTO_CROSS_ZONE"],
        "attack_ref": ATTACK_ICS_MAP["INSECURE_PROTO_CROSS_ZONE"],
        "base_severity": SEVERITY_WEIGHTS["INSECURE_PROTO_CROSS_ZONE"],
        "precedence": 7,
        "description": (
            "An unauthenticated/unencrypted OT protocol (e.g. Modbus, "
            "S7comm, plain DNP3) crosses a zone boundary. The same protocol "
            "used inside one zone is normal and is not flagged."
        ),
        "remediation": (
            "Terminate the insecure protocol at the zone boundary and "
            "proxy/encapsulate it (e.g. via a secure gateway) for any "
            "cross-zone need."
        ),
    },
    {
        "id": "PROTO_PORT_MISMATCH",
        "label": "Protocol/port mismatch",
        "iec_ref": IEC62443_REFS["PROTO_PORT_MISMATCH"],
        "attack_ref": ATTACK_ICS_MAP["PROTO_PORT_MISMATCH"],
        "base_severity": SEVERITY_WEIGHTS["PROTO_PORT_MISMATCH"],
        "precedence": 8,
        "description": (
            "The flow's declared protocol does not match the port it was "
            "observed on (per WELL_KNOWN_PORTS), suggesting tunneling, "
            "masquerading, or a data-entry error."
        ),
        "remediation": (
            "Confirm what is actually running on this port. If it is "
            "intentional tunneling, document it as a conduit; if not, "
            "investigate as a possible masquerade."
        ),
    },
    {
        "id": "ZONE_LEVEL_MISMATCH",
        "label": "Zone/level mismatch",
        "iec_ref": IEC62443_REFS["ZONE_LEVEL_MISMATCH"],
        "attack_ref": ATTACK_ICS_MAP["ZONE_LEVEL_MISMATCH"],
        "base_severity": SEVERITY_WEIGHTS["ZONE_LEVEL_MISMATCH"],
        "precedence": 9,
        "description": (
            "An asset's declared Purdue level does not match the canonical "
            "level of its declared zone — an inventory/zone-definition "
            "consistency problem rather than a traffic finding."
        ),
        "remediation": (
            "Correct the asset's zone or Purdue level so the two agree; "
            "audit how the mismatch was introduced."
        ),
    },
]

# Lower number wins a tie. Severity (post-escalation) is the primary sort
# key when multiple rules fire on the same flow; this list only breaks ties
# between rules that land on the same final severity. See rules.py
# `pick_headline()` for the implementation.
RULE_PRECEDENCE = {rule["id"]: rule["precedence"] for rule in RULES}

# Assets that legitimately bridge zones on purpose (e.g. a DMZ broker that is
# *meant* to have legs in two zones) are excluded from DUAL_HOMED_BRIDGE.
DUAL_HOMED_ALLOWLIST = {
    "DMZ-JUMP-01",
    "DMZ-HIST-REP-01",
    "DMZ-PATCH-01",
}
