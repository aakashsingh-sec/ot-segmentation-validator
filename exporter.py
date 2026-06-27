"""
exporter.py — CSV export of violations and asset inventory.

Security note — CSV formula injection: a cell value beginning with =, +, -,
@, a tab, or a carriage return is interpreted as a formula by Excel/Sheets
when the file is opened, not as plain text. Every string cell written by
this module goes through `_sanitize_cell`, which prefixes a leading single
quote onto any value starting with one of those characters. That quote
forces spreadsheet apps to render the cell as literal text while leaving
the value itself unchanged for any other consumer (a script reading the
CSV back with `csv.reader` sees the same leading quote character, which is
the accepted tradeoff for this mitigation — see OWASP's CSV Injection
guidance). This module never builds a cell value via string formatting that
skips this step.

All data here comes from already-validated rows in the local SQLite
database (assets/zones validated by loader.py at import time, asset names
restricted to loader.ASSET_NAME_RE's plain charset). The sanitization in
this module is a second, independent layer — it does not rely on that
upstream validation holding for every field (e.g. free-text remediation
strings are not charset-restricted) before treating an export as safe.

Uses Python's `csv` module exclusively — no manual comma-joining anywhere,
so quoting of embedded commas/quotes/newlines is handled correctly by the
standard library rather than by hand.
"""

import csv
import io
import json

import db

# Leading characters that a spreadsheet application treats as the start of
# a formula rather than literal text.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(value) -> str:
    """Stringify one cell and neutralize a leading formula-trigger character."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in _FORMULA_TRIGGER_CHARS:
        return "'" + text
    return text


def export_violations_csv(assessment_id: int) -> str:
    """Return the full violations report for one assessment as CSV text.

    One row per violation, joined with its source flow's endpoints/protocol
    (db.get_violations already does this join) and the parent assessment's
    label and time window.
    """
    assessment = db.get_assessment(assessment_id)
    violations = db.get_violations(assessment_id)

    label = assessment["label"] if assessment else ""
    window_start = assessment["time_window_start"] if assessment else ""
    window_end = assessment["time_window_end"] if assessment else ""

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "assessment_label",
            "time_window_start",
            "time_window_end",
            "src_asset",
            "dst_asset",
            "port",
            "protocol",
            "flow_count",
            "rule_id",
            "severity",
            "status",
            "contributing_rules",
            "iec62443_ref",
            "attack_ref",
            "remediation",
            "detected_at",
        ]
    )
    for violation in violations:
        contributing = ", ".join(json.loads(violation["contributing_rules"]))
        writer.writerow(
            [
                _sanitize_cell(label),
                _sanitize_cell(window_start),
                _sanitize_cell(window_end),
                _sanitize_cell(violation["src_asset"]),
                _sanitize_cell(violation["dst_asset"]),
                violation["port"],
                _sanitize_cell(violation["protocol"]),
                violation["flow_count"],
                _sanitize_cell(violation["rule_id"]),
                _sanitize_cell(violation["severity"]),
                _sanitize_cell(violation["status"]),
                _sanitize_cell(contributing),
                _sanitize_cell(violation["iec62443_ref"]),
                _sanitize_cell(violation["attack_ref"]),
                _sanitize_cell(violation["remediation"]),
                _sanitize_cell(violation["detected_at"]),
            ]
        )
    return buffer.getvalue()


def export_assets_csv() -> str:
    """Return the full asset inventory (persistent, not assessment-scoped) as CSV text."""
    assets = db.get_all_assets()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "type", "purdue_level", "zone", "criticality", "scan_sensitivity"])
    for asset in assets:
        writer.writerow(
            [
                _sanitize_cell(asset["name"]),
                _sanitize_cell(asset["type"]),
                asset["purdue_level"] if asset["purdue_level"] is not None else "",
                _sanitize_cell(asset["zone"]) if asset["zone"] is not None else "",
                _sanitize_cell(asset["criticality"]),
                "true" if asset["scan_sensitivity"] else "false",
            ]
        )
    return buffer.getvalue()
