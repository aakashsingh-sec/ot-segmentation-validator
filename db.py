"""
db.py — SQLite access layer. Offline, local-file only, fully parameterized.

Design notes:
- Every connection enables `PRAGMA foreign_keys = ON` (SQLite has it off by
  default per-connection, so this must happen every time, not just once).
- `flows.src_asset` / `flows.dst_asset` are plain TEXT, NOT foreign keys
  into `assets`. That is deliberate: a flow can legitimately reference a
  device that is not yet in inventory (a shadow asset) or the external
  pseudo-zone, and the loader must accept that without the database
  rejecting the row. SHADOW_ASSET detection happens in rules.py, not via a
  constraint violation here.
- All SQL below uses `?` placeholders for values. Table/column names and
  PRAGMA statements are always literals written directly in this file —
  never built from input or config — per the project's security posture.
- `assets`, `conduits`, and `assessments` are NOT scoped to a single
  assessment; they are the persistent inventory/topology. `flows` and
  `violations` ARE scoped via `assessment_id`, which is how Tab 5
  (compare assessments) and re-running the engine without double-counting
  both work.
"""

import os
import sqlite3
from contextlib import contextmanager

from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "data/ot_segmentation.db")


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """Open a connection with foreign keys enforced and Row access by name."""
    _ensure_parent_dir(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def transaction():
    """Yield a connection inside a single commit/rollback transaction."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# purdue_level and zone are nullable on purpose: a partially-known asset
# (name known, classification not yet done) is a real inventory state, not
# a malformed one. rules.INCOMPLETE_INVENTORY is exactly the rule that
# surfaces a flow touching one of these rows — see rules.py.
SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    name             TEXT PRIMARY KEY,
    type             TEXT NOT NULL,
    purdue_level     REAL,
    zone             TEXT,
    criticality      TEXT NOT NULL,
    scan_sensitivity INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS conduits (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    src_zone          TEXT NOT NULL,
    dst_zone          TEXT NOT NULL,
    allowed_protocols TEXT NOT NULL,
    allowed_ports     TEXT NOT NULL,
    direction         TEXT NOT NULL CHECK (direction IN ('uni', 'bi')),
    description       TEXT
);

CREATE TABLE IF NOT EXISTS assessments (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    label              TEXT NOT NULL,
    time_window_start  TEXT NOT NULL,
    time_window_end    TEXT NOT NULL,
    imported_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS flows (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    src_asset      TEXT NOT NULL,
    dst_asset      TEXT NOT NULL,
    port           INTEGER NOT NULL,
    protocol       TEXT NOT NULL,
    flow_count     INTEGER NOT NULL DEFAULT 1,
    assessment_id  INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS violations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id             INTEGER REFERENCES flows(id) ON DELETE CASCADE,
    rule_id             TEXT NOT NULL,
    contributing_rules  TEXT NOT NULL DEFAULT '[]',
    iec62443_ref        TEXT,
    attack_ref          TEXT,
    severity            TEXT NOT NULL,
    remediation         TEXT,
    status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'accepted')),
    accepted_note       TEXT,
    assessment_id       INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    detected_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_flows_assessment ON flows(assessment_id);
CREATE INDEX IF NOT EXISTS idx_violations_assessment ON violations(assessment_id);
"""


# Every statement below is a hardcoded literal — never built from input,
# config, or a loop over a name list — so a "grep for f-string / .format()
# SQL" audit comes back clean by construction, not by convention.
def reset_db() -> None:
    """Drop and recreate every table. Used by tests and 'clear & reseed'."""
    with transaction() as conn:
        conn.execute("DROP TABLE IF EXISTS violations")
        conn.execute("DROP TABLE IF EXISTS flows")
        conn.execute("DROP TABLE IF EXISTS assessments")
        conn.execute("DROP TABLE IF EXISTS conduits")
        conn.execute("DROP TABLE IF EXISTS assets")
        conn.executescript(SCHEMA)


def init_db() -> None:
    """Create tables if they don't exist yet. Safe to call on every startup."""
    with transaction() as conn:
        conn.executescript(SCHEMA)


def purge_all() -> None:
    """Wipe every row from every table. Leaves the schema intact.

    This is the 'clear sensitive real data after use' control: once a real
    assessment is no longer needed, this removes all topology/violation data
    from the local DB without requiring the file itself to be deleted.
    """
    with transaction() as conn:
        conn.execute("DELETE FROM violations")
        conn.execute("DELETE FROM flows")
        conn.execute("DELETE FROM assessments")
        conn.execute("DELETE FROM conduits")
        conn.execute("DELETE FROM assets")
        conn.execute("DELETE FROM sqlite_sequence")


def clear_violations(assessment_id: int) -> None:
    """Delete violations for one assessment so the engine can re-run clean."""
    with transaction() as conn:
        conn.execute(
            "DELETE FROM violations WHERE assessment_id = ?", (assessment_id,)
        )


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------
def create_assessment(label: str, time_window_start: str, time_window_end: str) -> int:
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO assessments (label, time_window_start, time_window_end) "
            "VALUES (?, ?, ?)",
            (label, time_window_start, time_window_end),
        )
        return cur.lastrowid


def list_assessments() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM assessments ORDER BY imported_at ASC, id ASC"
        ).fetchall()


def get_assessment(assessment_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()


# ---------------------------------------------------------------------------
# Assets (persistent inventory — not scoped to an assessment)
# ---------------------------------------------------------------------------
def insert_assets(rows: list[dict]) -> None:
    """Bulk-insert assets. Caller (loader.py) has already de-duplicated and
    validated; a name collision here raises sqlite3.IntegrityError, which the
    loader translates into a clear 'duplicate asset name' message.
    """
    with transaction() as conn:
        conn.executemany(
            "INSERT INTO assets (name, type, purdue_level, zone, criticality, scan_sensitivity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    r["name"],
                    r["type"],
                    r["purdue_level"],
                    r["zone"],
                    r["criticality"],
                    int(bool(r.get("scan_sensitivity", False))),
                )
                for r in rows
            ],
        )


def get_all_assets() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM assets ORDER BY name ASC").fetchall()


def asset_exists(name: str) -> bool:
    with get_connection() as conn:
        row = conn.execute("SELECT 1 FROM assets WHERE name = ?", (name,)).fetchone()
        return row is not None


# ---------------------------------------------------------------------------
# Conduits (persistent topology — not scoped to an assessment)
# ---------------------------------------------------------------------------
def insert_conduits(rows: list[dict]) -> None:
    with transaction() as conn:
        conn.executemany(
            "INSERT INTO conduits (src_zone, dst_zone, allowed_protocols, allowed_ports, direction, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    r["src_zone"],
                    r["dst_zone"],
                    r["allowed_protocols"],
                    r["allowed_ports"],
                    r["direction"],
                    r.get("description", ""),
                )
                for r in rows
            ],
        )


def get_all_conduits() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM conduits ORDER BY id ASC").fetchall()


def clear_conduits() -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM conduits")


def clear_assets() -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM assets")


# ---------------------------------------------------------------------------
# Flows (scoped to an assessment)
# ---------------------------------------------------------------------------
def insert_flows(rows: list[dict], assessment_id: int) -> None:
    with transaction() as conn:
        conn.executemany(
            "INSERT INTO flows (src_asset, dst_asset, port, protocol, flow_count, assessment_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    r["src_asset"],
                    r["dst_asset"],
                    r["port"],
                    r["protocol"],
                    r.get("flow_count", 1),
                    assessment_id,
                )
                for r in rows
            ],
        )


def get_flows(assessment_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM flows WHERE assessment_id = ? ORDER BY id ASC",
            (assessment_id,),
        ).fetchall()


def clear_flows(assessment_id: int) -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM flows WHERE assessment_id = ?", (assessment_id,))


# ---------------------------------------------------------------------------
# Violations (scoped to an assessment)
# ---------------------------------------------------------------------------
def insert_violations(rows: list[dict], assessment_id: int) -> None:
    with transaction() as conn:
        conn.executemany(
            "INSERT INTO violations "
            "(flow_id, rule_id, contributing_rules, iec62443_ref, attack_ref, "
            " severity, remediation, status, assessment_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)",
            [
                (
                    r["flow_id"],
                    r["rule_id"],
                    r.get("contributing_rules", "[]"),
                    r.get("iec62443_ref"),
                    r.get("attack_ref"),
                    r["severity"],
                    r.get("remediation"),
                    assessment_id,
                )
                for r in rows
            ],
        )


def get_violations(assessment_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT v.*, f.src_asset, f.dst_asset, f.port, f.protocol, f.flow_count "
            "FROM violations v "
            "JOIN flows f ON f.id = v.flow_id "
            "WHERE v.assessment_id = ? "
            "ORDER BY v.id ASC",
            (assessment_id,),
        ).fetchall()


def set_violation_status(violation_id: int, status: str, note: str | None = None) -> None:
    if status not in ("open", "accepted"):
        raise ValueError("status must be 'open' or 'accepted'")
    with transaction() as conn:
        conn.execute(
            "UPDATE violations SET status = ?, accepted_note = ? WHERE id = ?",
            (status, note, violation_id),
        )
