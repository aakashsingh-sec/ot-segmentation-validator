"""
loader.py — validated, hostile-input-safe import of assets and flows.

Every byte that enters this module is treated as untrusted. The guard order
is deliberate: cheap structural checks (size, archive signature, encoding,
nesting depth) run before anything is fully parsed, so a hostile file is
rejected before it can do real work. Only after that does row-level
validation run, which skips individual bad rows (logged with a reason)
rather than failing the whole file — except for a few conditions (duplicate
asset names, zero valid rows) that are serious enough to reject the entire
import outright. See each function's docstring for which behavior applies.

Nothing here ever calls `eval`. JSON goes through `json.loads` only.
"""

import csv
import io
import json
import os
import re
import sqlite3

import config
import db

MAX_ROWS = 5000
MAX_COLUMNS = 20
MAX_FIELD_LENGTH = 500
MAX_JSON_DEPTH = 12

ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]+$")
ALLOWED_CRITICALITY = {"Low", "Medium", "High", "Safety"}
ALLOWED_PURDUE_LEVELS = set(config.PURDUE_LEVELS.keys())
REQUIRED_ASSET_COLUMNS = {"name", "type", "purdue_level", "zone", "criticality", "scan_sensitivity"}
REQUIRED_FLOW_COLUMNS = {"src_asset", "dst_asset", "port", "protocol"}

ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"


class LoaderError(Exception):
    """Raised when an entire file is rejected outright (not a per-row skip)."""


class LoadReport:
    """Result of one import: how many rows landed, and why others didn't."""

    def __init__(self):
        self.imported = 0
        self.skipped: list[dict] = []

    def skip(self, row_number: int, reason: str) -> None:
        self.skipped.append({"row": row_number, "reason": reason})

    def to_dict(self) -> dict:
        return {"imported": self.imported, "skipped": self.skipped}


# ---------------------------------------------------------------------------
# Pre-parse guards — run before any real parsing happens
# ---------------------------------------------------------------------------
def _max_upload_bytes() -> int:
    mb = float(os.getenv("MAX_UPLOAD_MB", "5"))
    return int(mb * 1024 * 1024)


def _check_not_archive(raw: bytes) -> None:
    if raw.startswith(ZIP_MAGIC) or raw.startswith(GZIP_MAGIC):
        raise LoaderError(
            "Archive files (zip/gz) are not accepted. Upload a plain CSV or JSON file."
        )


def _decode_utf8(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise LoaderError("File is not valid UTF-8 text.")
    text = text.lstrip("﻿")  # strip a leading BOM
    text = text.replace("\x00", "")  # strip embedded null bytes
    return text


def _check_json_depth(text: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Reject deeply-nested JSON before json.loads ever sees it.

    This is a character-level bracket-depth scan, not a real parser — it
    intentionally runs *before* full parsing so a pathologically nested
    payload (the classic small-file JSON-bomb) is rejected on a single pass
    instead of being handed to the recursive-descent JSON decoder first.
    """
    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                raise LoaderError(f"JSON nesting exceeds the limit of {max_depth} levels.")
        elif ch in "}]":
            depth -= 1


def _pre_parse_guard(raw: bytes, filename: str) -> str:
    max_bytes = _max_upload_bytes()
    if len(raw) > max_bytes:
        raise LoaderError(f"File exceeds the {max_bytes // (1024 * 1024)} MB upload limit.")
    _check_not_archive(raw)
    text = _decode_utf8(raw)
    if filename.lower().endswith(".json"):
        _check_json_depth(text)
    return text


# ---------------------------------------------------------------------------
# Row extraction — CSV and JSON both reduce to a list of (row_number, dict)
# ---------------------------------------------------------------------------
def _parse_csv_rows(text: str) -> list[tuple[int, dict]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise LoaderError("File has no header row.")
    if len(reader.fieldnames) > MAX_COLUMNS:
        raise LoaderError(f"Too many columns (limit {MAX_COLUMNS}).")
    rows = []
    for line_number, row in enumerate(reader, start=2):  # row 1 is the header
        if line_number - 1 > MAX_ROWS:
            raise LoaderError(f"File exceeds the {MAX_ROWS}-row limit.")
        rows.append((line_number, row))
    return rows


def _parse_json_rows(text: str) -> list[tuple[int, dict]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"Malformed JSON: {exc}")
    if not isinstance(data, list):
        raise LoaderError("JSON file must contain a list of row objects.")
    if len(data) > MAX_ROWS:
        raise LoaderError(f"File exceeds the {MAX_ROWS}-row limit.")
    rows = []
    for index, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            raise LoaderError(f"Row {index} is not a JSON object.")
        if len(row) > MAX_COLUMNS:
            raise LoaderError(f"Row {index} has too many fields (limit {MAX_COLUMNS}).")
        rows.append((index, row))
    return rows


def _parse_rows(text: str, filename: str) -> list[tuple[int, dict]]:
    if filename.lower().endswith(".json"):
        return _parse_json_rows(text)
    return _parse_csv_rows(text)


def _check_field_lengths(row: dict) -> str | None:
    for key, value in row.items():
        if value is not None and len(str(value)) > MAX_FIELD_LENGTH:
            return f"field '{key}' exceeds {MAX_FIELD_LENGTH} characters"
    return None


def _valid_name(name: str) -> bool:
    return bool(name) and len(name) <= MAX_FIELD_LENGTH and bool(ASSET_NAME_RE.match(name))


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------
def _normalize_asset_row(row_number: int, row: dict, report: LoadReport) -> dict | None:
    missing = REQUIRED_ASSET_COLUMNS - row.keys()
    if missing:
        report.skip(row_number, f"missing required column(s): {sorted(missing)}")
        return None

    length_issue = _check_field_lengths(row)
    if length_issue:
        report.skip(row_number, length_issue)
        return None

    name = str(row["name"]).strip()
    if not _valid_name(name):
        report.skip(row_number, f"asset name '{name[:40]}' contains disallowed characters")
        return None

    # purdue_level and zone may be intentionally blank — an asset whose name
    # is known but hasn't been classified yet. A *non-blank but invalid*
    # value (garbage text, a level not in the allowed set) is still a hard
    # skip: that's a data error, not an honest "unknown".
    raw_level = str(row["purdue_level"]).strip()
    if raw_level == "":
        purdue_level = None
    else:
        try:
            purdue_level = float(raw_level)
        except ValueError:
            report.skip(row_number, f"purdue_level '{raw_level}' is not numeric")
            return None
        if purdue_level not in ALLOWED_PURDUE_LEVELS:
            report.skip(
                row_number,
                f"purdue_level {purdue_level} is not one of {sorted(ALLOWED_PURDUE_LEVELS)}",
            )
            return None

    criticality = str(row["criticality"]).strip()
    if criticality not in ALLOWED_CRITICALITY:
        report.skip(row_number, f"criticality '{criticality}' not in {sorted(ALLOWED_CRITICALITY)}")
        return None

    zone = str(row["zone"]).strip() or None

    asset_type = str(row["type"]).strip()
    scan_sensitivity = _to_bool(row.get("scan_sensitivity", False))

    return {
        "name": name,
        "type": asset_type,
        "purdue_level": purdue_level,
        "zone": zone,
        "criticality": criticality,
        "scan_sensitivity": scan_sensitivity,
    }


def import_assets(raw: bytes, filename: str) -> LoadReport:
    """Import an asset inventory file.

    A duplicate asset name — whether repeated within this file or already
    present in the database — rejects the entire import with a clear error.
    Inventory-hygiene problems like that are surfaced loudly, never papered
    over by a silent overwrite.
    """
    text = _pre_parse_guard(raw, filename)
    rows = _parse_rows(text, filename)

    report = LoadReport()
    seen_names: set[str] = set()
    valid_rows: list[dict] = []

    for row_number, row in rows:
        normalized = _normalize_asset_row(row_number, row, report)
        if normalized is None:
            continue
        if normalized["name"] in seen_names:
            raise LoaderError(
                f"Duplicate asset name '{normalized['name']}' within the uploaded file "
                f"(row {row_number}). Remove the duplicate and re-upload."
            )
        seen_names.add(normalized["name"])
        valid_rows.append(normalized)

    if not valid_rows:
        raise LoaderError("No valid asset rows found in the file.")

    try:
        db.insert_assets(valid_rows)
    except sqlite3.IntegrityError:
        raise LoaderError(
            "One or more asset names already exist in inventory. Duplicate names are "
            "rejected, not overwritten — rename or remove them and re-upload."
        )

    report.imported = len(valid_rows)
    return report


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------
def _normalize_flow_row(row_number: int, row: dict, report: LoadReport) -> dict | None:
    missing = REQUIRED_FLOW_COLUMNS - row.keys()
    if missing:
        report.skip(row_number, f"missing required column(s): {sorted(missing)}")
        return None

    length_issue = _check_field_lengths(row)
    if length_issue:
        report.skip(row_number, length_issue)
        return None

    src = str(row["src_asset"]).strip()
    dst = str(row["dst_asset"]).strip()
    if not _valid_name(src):
        report.skip(row_number, f"src_asset '{src[:40]}' contains disallowed characters")
        return None
    if not _valid_name(dst):
        report.skip(row_number, f"dst_asset '{dst[:40]}' contains disallowed characters")
        return None

    try:
        port = int(row["port"])
    except (TypeError, ValueError):
        report.skip(row_number, f"port '{row['port']}' is not an integer")
        return None
    if not (0 <= port <= 65535):
        report.skip(row_number, f"port {port} out of range")
        return None

    protocol = str(row["protocol"]).strip()
    if not protocol:
        report.skip(row_number, "protocol is empty")
        return None

    try:
        flow_count = int(row.get("flow_count", 1) or 1)
    except (TypeError, ValueError):
        flow_count = 1
    flow_count = max(flow_count, 1)

    return {"src_asset": src, "dst_asset": dst, "port": port, "protocol": protocol, "flow_count": flow_count}


def _collapse_flows(rows: list[dict]) -> list[dict]:
    """Collapse identical (src, dst, port, protocol) rows into one with a
    summed flow_count. Direction matters: A->B and B->A are different keys
    and are never merged with each other.
    """
    collapsed: dict[tuple, dict] = {}
    for row in rows:
        key = (row["src_asset"], row["dst_asset"], row["port"], row["protocol"])
        if key in collapsed:
            collapsed[key]["flow_count"] += row["flow_count"]
        else:
            collapsed[key] = dict(row)
    return list(collapsed.values())


def import_flows(raw: bytes, filename: str, assessment_id: int) -> LoadReport:
    """Import a flow-export file for an existing assessment.

    Flow endpoints are validated for shape (charset, length) only — never
    checked against the asset inventory here. A flow naming a device that
    isn't in inventory is stored as-is; that's exactly the case
    rules.SHADOW_ASSET exists to flag, and rejecting it at import time would
    hide the finding instead of producing it.
    """
    text = _pre_parse_guard(raw, filename)
    rows = _parse_rows(text, filename)

    report = LoadReport()
    valid_rows: list[dict] = []
    for row_number, row in rows:
        normalized = _normalize_flow_row(row_number, row, report)
        if normalized is None:
            continue
        valid_rows.append(normalized)

    collapsed = _collapse_flows(valid_rows)
    if not collapsed:
        raise LoaderError("No valid flow rows found in the file.")

    db.insert_flows(collapsed, assessment_id)
    report.imported = len(collapsed)
    return report


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def import_assessment(
    label: str,
    time_window_start: str,
    time_window_end: str,
    flows_raw: bytes,
    flows_filename: str,
    assets_raw: bytes | None = None,
    assets_filename: str | None = None,
) -> dict:
    """Create an assessment row, optionally load new/updated assets, then
    load the flow export and tie it to that assessment.

    Assets are optional on a re-import — you may only have a fresh flow
    export against an inventory that hasn't changed. Flows are required: an
    assessment with no flows has nothing for the rule engine to evaluate.
    """
    assessment_id = db.create_assessment(label, time_window_start, time_window_end)

    asset_report = None
    if assets_raw is not None:
        asset_report = import_assets(assets_raw, assets_filename or "assets.csv")

    flow_report = import_flows(flows_raw, flows_filename, assessment_id)

    return {
        "assessment_id": assessment_id,
        "assets": asset_report.to_dict() if asset_report else None,
        "flows": flow_report.to_dict(),
    }
