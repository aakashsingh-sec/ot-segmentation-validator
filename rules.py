"""
rules.py — the segmentation rule engine.

Reads the persistent asset/conduit topology plus one assessment's flows,
evaluates every flow against the 10 rules defined in config.RULES, and
writes one violation row per flow that trips at least one rule.

Design summary (see config.py for the rule metadata table):
- INCOMPLETE_INVENTORY short-circuits everything else for a flow: if either
  endpoint is a known asset but is missing a zone or Purdue level, that is
  the only finding emitted for that flow. There is nothing else to validate
  against an unknown zone/level.
- SHADOW_ASSET fires when an endpoint is neither a known asset nor something
  that looks like an external (internet/vendor) address — i.e. an
  undocumented device.
- A flow endpoint that looks like a bare IPv4/IPv6 address and is not in
  inventory is treated as the external pseudo-zone (Z-EXTERNAL, level 5),
  not as a shadow asset — that is how OT_INTERNET_ROUTE and DMZ_BYPASS see
  genuinely external traffic.
- Every other rule is evaluated independently per flow; a flow can trip
  several rules at once. The headline finding (the one row written to
  `violations`) is whichever candidate has the highest severity *after*
  escalation; ties are broken by config.RULE_PRECEDENCE (lower wins). The
  rest are recorded as `contributing_rules` so nothing is silently dropped.
- DUAL_HOMED_BRIDGE is the one rule that isn't a property of a single flow:
  it asks whether an asset is the *only* path between two zones that have
  no conduit of their own. That requires looking at all of an asset's
  flows together, so it's computed once per assessment before the
  per-flow loop, not inside it.
"""

import json
import re
from collections import defaultdict

import config
import db

RULES_BY_ID = {rule["id"]: rule for rule in config.RULES}

# Loose IPv4/IPv6 shape check. This is intentionally not a strict validator —
# its only job is to distinguish "looks like a raw network address" (treat as
# external) from "looks like a hostname/tag" (treat as a possible shadow
# asset) for names that aren't already in inventory.
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]*:[0-9a-fA-F:]*$")


def _looks_external(name: str) -> bool:
    if _IPV4_RE.match(name):
        octets = name.split(".")
        return all(0 <= int(o) <= 255 for o in octets)
    if ":" in name and _IPV6_RE.match(name):
        return True
    return False


# ---------------------------------------------------------------------------
# Topology loading
# ---------------------------------------------------------------------------
def _build_asset_map(asset_rows) -> dict:
    """name -> {zone, purdue_level, criticality, scan_sensitivity}"""
    assets = {}
    for row in asset_rows:
        assets[row["name"]] = {
            "zone": row["zone"],
            "purdue_level": row["purdue_level"],
            "criticality": row["criticality"],
            "scan_sensitivity": bool(row["scan_sensitivity"]),
        }
    return assets


def _build_conduit_index(conduit_rows) -> dict:
    """(src_zone, dst_zone) -> list of conduit rows.

    A 'bi' conduit is indexed under both orderings; a 'uni' conduit only
    under its declared direction.
    """
    index = defaultdict(list)
    for row in conduit_rows:
        index[(row["src_zone"], row["dst_zone"])].append(row)
        if row["direction"] == "bi":
            index[(row["dst_zone"], row["src_zone"])].append(row)
    return index


def _parse_port_field(field: str) -> set | None:
    """Return None for a wildcard ('*'), else the concrete set of allowed ports."""
    field = field.strip()
    if field == "*":
        return None
    ports = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return ports


def _conduit_permits(src_zone, dst_zone, protocol, port, conduit_index) -> bool:
    for conduit in conduit_index.get((src_zone, dst_zone), []):
        protocols = {p.strip() for p in conduit["allowed_protocols"].split(",") if p.strip()}
        if protocol not in protocols and "*" not in protocols:
            continue
        allowed_ports = _parse_port_field(conduit["allowed_ports"])
        if allowed_ports is None or port in allowed_ports:
            return True
    return False


def _conduit_zone_pair_exists(zone_a, zone_b, conduit_index) -> bool:
    return bool(conduit_index.get((zone_a, zone_b))) or bool(conduit_index.get((zone_b, zone_a)))


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------
def _resolve_endpoint(name: str, assets: dict) -> dict:
    """Classify one flow endpoint as known / external / shadow / incomplete."""
    if name in assets:
        info = assets[name]
        if info["zone"] is None or info["purdue_level"] is None:
            status = "incomplete"
        else:
            status = "known"
        return {
            "name": name,
            "status": status,
            "zone": info["zone"],
            "level": info["purdue_level"],
            "criticality": info["criticality"],
            "scan_sensitivity": info["scan_sensitivity"],
        }
    if _looks_external(name):
        return {
            "name": name,
            "status": "external",
            "zone": config.EXTERNAL_ZONE,
            "level": 5,
            "criticality": None,
            "scan_sensitivity": False,
        }
    return {
        "name": name,
        "status": "shadow",
        "zone": None,
        "level": None,
        "criticality": None,
        "scan_sensitivity": False,
    }


# ---------------------------------------------------------------------------
# DUAL_HOMED_BRIDGE — computed once per assessment, not per flow
# ---------------------------------------------------------------------------
def _compute_bridge_assets(flows, assets, conduit_index) -> set:
    """Assets that genuinely relay traffic between two zones with no conduit
    of their own — i.e. the asset receives from zone A *and* separately
    sends to a different zone B, and nothing authorizes a direct A<->B path.

    Deliberately direction-aware: a pure sink (an enterprise server that
    only ever receives from several zones) or a pure source (a device that
    only ever sends to several zones) is not bridging anything — it's just
    popular. Bridging requires both an inbound leg and an outbound leg into
    different zones, which is what actually lets traffic hop A -> asset -> B
    outside any approved conduit.
    """
    inbound = defaultdict(set)   # asset -> zones of flows where it's the destination
    outbound = defaultdict(set)  # asset -> zones of flows where it's the source
    for flow in flows:
        src_zone = assets.get(flow["src_asset"], {}).get("zone")
        dst_zone = assets.get(flow["dst_asset"], {}).get("zone")
        if src_zone and dst_zone and src_zone != dst_zone:
            outbound[flow["src_asset"]].add(dst_zone)
            inbound[flow["dst_asset"]].add(src_zone)

    bridges = set()
    for asset_name in set(inbound) | set(outbound):
        if asset_name in config.DUAL_HOMED_ALLOWLIST:
            continue
        relay_pairs = {
            (a, b)
            for a in inbound.get(asset_name, set())
            for b in outbound.get(asset_name, set())
            if a != b
        }
        if any(not _conduit_zone_pair_exists(a, b, conduit_index) for a, b in relay_pairs):
            bridges.add(asset_name)
    return bridges


# ---------------------------------------------------------------------------
# Per-flow rule candidates
# ---------------------------------------------------------------------------
# Purdue levels in tier order (3.5 sits between 3 and 4). Used by LEVEL_SKIP
# to measure "how many tiers does this flow jump", not just numeric distance.
_LEVEL_ORDER = sorted(config.PURDUE_LEVELS.keys())
_LEVEL_INDEX = {level: i for i, level in enumerate(_LEVEL_ORDER)}


def _candidate(rule_id: str) -> dict:
    return {"rule_id": rule_id, "base_severity": RULES_BY_ID[rule_id]["base_severity"]}


def _evaluate_flow(flow, src, dst, bridge_assets, conduit_index) -> list:
    """Return the list of rule candidates this flow trips, in no particular
    order. Severity escalation and headline selection happen in the caller.
    """
    # INCOMPLETE_INVENTORY short-circuits every other rule for this flow.
    if src["status"] == "incomplete" or dst["status"] == "incomplete":
        return [_candidate("INCOMPLETE_INVENTORY")]

    candidates = []

    if src["status"] == "shadow" or dst["status"] == "shadow":
        candidates.append(_candidate("SHADOW_ASSET"))

    # ZONE_LEVEL_MISMATCH: an asset's declared level disagrees with the
    # canonical level of its declared zone. Checked on both known endpoints
    # independently of whatever else this flow trips.
    for endpoint in (src, dst):
        if endpoint["status"] != "known":
            continue
        canonical = config.ZONES.get(endpoint["zone"], {}).get("purdue_level")
        if canonical is not None and canonical != endpoint["level"]:
            candidates.append(_candidate("ZONE_LEVEL_MISMATCH"))
            break  # one finding per flow is enough; both endpoints would be redundant

    have_topology = (
        src["zone"] is not None
        and dst["zone"] is not None
        and src["level"] is not None
        and dst["level"] is not None
    )

    if have_topology:
        src_zone, dst_zone = src["zone"], dst["zone"]
        src_level, dst_level = src["level"], dst["level"]

        crosses_zone = src_zone != dst_zone

        # DMZ_BYPASS: IT/OT boundary crossed directly, skipping Level 3.5.
        boundary_crossed = (src_level <= 3 and dst_level >= 4) or (
            src_level >= 4 and dst_level <= 3
        )
        if boundary_crossed and config.DMZ_LEVEL not in (src_level, dst_level):
            candidates.append(_candidate("DMZ_BYPASS"))

        # OT_INTERNET_ROUTE: an OT asset (Level 0-3) reaching Level 5.
        if (src_level <= 3 and dst_level == 5) or (dst_level <= 3 and src_level == 5):
            candidates.append(_candidate("OT_INTERNET_ROUTE"))

        # NO_CONDUIT: a cross-zone flow with no conduit authorizing this
        # exact protocol/port/direction between the two zones. Computed
        # before LEVEL_SKIP/INSECURE_PROTO_CROSS_ZONE below because both of
        # those reuse it: a conduit is the organization's explicit, on-the-
        # record decision to allow this exact protocol on this exact zone
        # pair (a supervisory-to-field Modbus link, a dedicated DMZ patch
        # conduit that deliberately skips a tier). Once that authorization
        # exists, re-flagging the same crossing under a different rule name
        # is noise, not a finding — these two rules exist to catch tier
        # skips and insecure protocols that *aren't* accounted for by any
        # conduit at all.
        conduit_ok = _conduit_permits(
            src_zone, dst_zone, flow["protocol"], flow["port"], conduit_index
        )
        if crosses_zone and not conduit_ok:
            candidates.append(_candidate("NO_CONDUIT"))

        # LEVEL_SKIP: the flow jumps more than one tier in Purdue order,
        # and no conduit specifically authorizes this protocol/zone pair.
        if src_level != dst_level and not conduit_ok:
            tier_gap = abs(_LEVEL_INDEX[src_level] - _LEVEL_INDEX[dst_level])
            if tier_gap > 1:
                candidates.append(_candidate("LEVEL_SKIP"))

        # INSECURE_PROTO_CROSS_ZONE: an unauthenticated OT protocol leaving
        # its own zone with no conduit covering it. The same protocol used
        # inside one zone, or covered by an explicit conduit crossing zones,
        # is the organization's documented, accepted use and is not flagged.
        if crosses_zone and not conduit_ok and flow["protocol"] in config.INSECURE_PROTOCOLS:
            candidates.append(_candidate("INSECURE_PROTO_CROSS_ZONE"))

        # DUAL_HOMED_BRIDGE: precomputed once per assessment, but the asset
        # being *somewhere* in bridge_assets is not enough to flag *this*
        # flow. An asset can legitimately touch several zones for several
        # independent, individually-conduited reasons (a busy supervisory
        # server controlling its own PLCs while also accepting DMZ patch
        # traffic, say) — that does not make every one of its conduit-
        # permitted flows part of the bridging behavior. This rule is only
        # about the leg(s) that have no conduit of their own; a flow that
        # already has an explicit conduit permitting it is never one of
        # those legs, regardless of what else the asset happens to touch.
        if (
            crosses_zone
            and not conduit_ok
            and (flow["src_asset"] in bridge_assets or flow["dst_asset"] in bridge_assets)
        ):
            candidates.append(_candidate("DUAL_HOMED_BRIDGE"))

    # PROTO_PORT_MISMATCH: independent of zone topology — just protocol vs
    # the port it was actually observed on. Protocols absent from
    # WELL_KNOWN_PORTS are not guessed at and are skipped.
    expected_port = config.WELL_KNOWN_PORTS.get(flow["protocol"])
    if expected_port is not None and flow["port"] != expected_port:
        candidates.append(_candidate("PROTO_PORT_MISMATCH"))

    return candidates


def _pick_headline(candidates: list) -> tuple:
    """Highest final severity wins; ties broken by RULE_PRECEDENCE (lower
    number wins). Returns (headline_candidate, [contributing_rule_ids]).
    """
    ordered = sorted(
        candidates,
        key=lambda c: (-config.SEVERITY_ORDER[c["severity"]], config.RULE_PRECEDENCE[c["rule_id"]]),
    )
    headline = ordered[0]
    contributing = [c["rule_id"] for c in ordered[1:]]
    return headline, contributing


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def evaluate_assessment(assessment_id: int) -> dict:
    """Run every rule against every flow in one assessment and persist the
    results. Always clears prior violations for this assessment first, so
    re-running the engine after a data fix never double-counts.
    """
    assets = _build_asset_map(db.get_all_assets())
    conduit_index = _build_conduit_index(db.get_all_conduits())
    flows = db.get_flows(assessment_id)

    bridge_assets = _compute_bridge_assets(flows, assets, conduit_index)

    violations_to_insert = []
    severity_counts = {band: 0 for band in config.SEVERITY_BANDS}

    for flow in flows:
        src = _resolve_endpoint(flow["src_asset"], assets)
        dst = _resolve_endpoint(flow["dst_asset"], assets)

        candidates = _evaluate_flow(flow, src, dst, bridge_assets, conduit_index)
        if not candidates:
            continue

        # Escalate every candidate by the destination asset's criticality
        # before picking a headline — a Low-severity finding landing on a
        # Safety-critical destination should outrank a Medium one that doesn't.
        for candidate in candidates:
            candidate["severity"] = config.escalate_severity(
                candidate["base_severity"], dst["criticality"]
            )

        headline, contributing = _pick_headline(candidates)
        rule_meta = RULES_BY_ID[headline["rule_id"]]

        remediation = rule_meta["remediation"]
        if src["scan_sensitivity"] or dst["scan_sensitivity"]:
            remediation = f"{remediation}\n\n{config.SCAN_SENSITIVITY_NOTE}"

        violations_to_insert.append(
            {
                "flow_id": flow["id"],
                "rule_id": headline["rule_id"],
                "contributing_rules": json.dumps(contributing),
                "iec62443_ref": rule_meta["iec_ref"],
                "attack_ref": rule_meta["attack_ref"],
                "severity": headline["severity"],
                "remediation": remediation,
            }
        )
        severity_counts[headline["severity"]] += 1

    db.clear_violations(assessment_id)
    if violations_to_insert:
        db.insert_violations(violations_to_insert, assessment_id)

    return {
        "assessment_id": assessment_id,
        "flows_evaluated": len(flows),
        "violations_found": len(violations_to_insert),
        "severity_counts": severity_counts,
    }
