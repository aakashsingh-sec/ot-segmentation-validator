# OT Network Segmentation Validator

A small, offline tool that checks whether an OT (operational technology)
network's actual traffic respects its documented zone-and-conduit
segmentation, per the Purdue Enterprise Reference Architecture and the
IEC 62443-3-3 / 62443-3-2 zone-and-conduit model.

You give it an asset inventory (name, type, Purdue level, zone, criticality)
and a flow export (who talked to whom, on what port/protocol). It tells you
which flows cross a zone boundary with no documented conduit authorizing
that exact protocol/port/direction, which devices aren't in inventory at
all, which assets disagree with their own zone's canonical Purdue level,
and a few other segmentation-hygiene problems — each with a severity, a
remediation note, and a citation back to the specific IEC 62443
requirement and MITRE ATT&CK for ICS technique it relates to.

## What this tool is not

- It does not scan, probe, or otherwise touch any device or network. It
  only reads files you give it (a CSV/JSON inventory export, a CSV/JSON
  flow export) and a local SQLite database.
- It ships with **synthetic demo data only**. Every asset name, IP-shaped
  string, and flow in `seed_demo.py` is fabricated for this project — none
  of it describes a real network.
- It is not a substitute for a real segmentation assessment, a penetration
  test, or a 62443 conformance audit. Treat its findings as a starting
  point for an analyst to investigate, not a verdict.

## How it thinks about a network

- **Purdue levels** (0 through 4, plus 3.5 for the IT/OT DMZ) describe how
  far a device sits from the process floor. A pseudo-level 5 ("External")
  covers anything outside the operator's own network — the internet, a
  vendor's remote-access endpoint — so that even a flow leaving the estate
  entirely resolves to a zone and a level instead of falling through every
  rule silently.
- **Zones** group assets that share a trust boundary (`Z-FIELD`,
  `Z-CONTROL`, `Z-SAFETY`, `Z-SUPERVISORY`, `Z-OPERATIONS`, `Z-DMZ`,
  `Z-ENTERPRISE`, plus site-specific zones like `Z-PHYSEC`/`Z-BMS` and the
  external pseudo-zone `Z-EXTERNAL`). Each zone has one canonical Purdue
  level.
- **Conduits** are the organization's explicit, documented, accepted-risk
  authorization for traffic between two zones — one exact combination of
  zone pair, protocol, port, and direction. A conduit is a *decision*, not
  an absence of risk: once it exists, the rules whose job is "does this
  crossing carry *unaddressed* risk" stop firing on flows it covers.

## The rule engine

`rules.py` evaluates every flow in an assessment against the table below.
A flow can trip several rules at once; the highest-severity one becomes
the headline finding and the rest are recorded as `contributing_rules` so
nothing is silently dropped. `INCOMPLETE_INVENTORY` is the one exception —
if either endpoint is missing a zone or Purdue level, that is the *only*
finding for that flow, because nothing else can be evaluated without that
information.

| Rule | What it catches | Base severity | IEC 62443 ref | ATT&CK for ICS |
|---|---|---|---|---|
| `INCOMPLETE_INVENTORY` | Endpoint known but missing zone/Purdue level | High | FR5 — SR 5.1 | — |
| `DMZ_BYPASS` | IT/OT boundary crossed directly, skipping the Level 3.5 DMZ | High | FR5 — SR 5.1/5.2 | External Remote Services (T0822) |
| `NO_CONDUIT` | Cross-zone flow with no conduit authorizing that protocol/port/direction | High | FR5 — SR 5.1 | — |
| `OT_INTERNET_ROUTE` | OT asset (Level 0–3) with a flow reaching Level 5 (internet/external) | High | FR5 — SR 5.2; FR4 — SR 4.1 | Internet Accessible Device (T0883) |
| `DUAL_HOMED_BRIDGE` | An asset relays traffic between two zones that have no conduit of their own | High | FR5 — SR 5.1/5.2 | Remote Services (T0886) |
| `LEVEL_SKIP` | A flow spans more than one Purdue tier with no covering conduit | High | FR5 — SR 5.1 | — |
| `SHADOW_ASSET` | Flow endpoint isn't in inventory and isn't external-shaped — an undocumented device | High | FR5 — SR 5.2 | Rogue Master (T0848) |
| `INSECURE_PROTO_CROSS_ZONE` | An unauthenticated OT protocol (Modbus, S7comm, plain DNP3, …) crosses a zone with no covering conduit | Medium | FR1 — SR 1.1/1.2; FR3 — SR 3.1; FR4 — SR 4.1 | Adversary-in-the-Middle (T0830) |
| `PROTO_PORT_MISMATCH` | Declared protocol doesn't match the port it was observed on | Medium | FR5 — SR 5.2 | Commonly Used Port (T0885) |
| `ZONE_LEVEL_MISMATCH` | Asset's declared Purdue level disagrees with its declared zone's canonical level | Medium | IEC 62443-2-1 | — |

Severity escalates one band (capped at Critical) when the destination
asset's criticality is `High` or `Safety`. Findings touching a
`scan_sensitivity=true` asset carry an explicit "do not actively scan this"
note, citing MITRE's Denial of Service (T0814) rationale.

IEC 62443-3-3 clause numbers and ATT&CK for ICS technique IDs were checked
against the standard and the live ATT&CK for ICS matrix as of June 2026
(see `config.py`'s header comment) — re-verify both before relying on this
mapping in a real assessment, in case either has been revised since.

## Setup

Requires Python 3.11.

```
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

`.env.example` lists the two settings `.env` needs; fill them in (these are
sensible local defaults):

```
DB_PATH=data/ot_segmentation.db
MAX_UPLOAD_MB=5
```

Before shipping or relying on this in any real capacity, run:

```
pip-audit
```

against the pinned `requirements.txt` and review any findings.

## Running it

```
py -3.11 -m streamlit run app.py
```

The sidebar has a **Load synthetic demo data** button — it loads two
linked assessments (`Baseline – Q1` and `Re-assessment – Q2`) so you can
see a populated topology, a violations list, and the **Compare
Assessments** tab's drift detection without supplying your own files. The
same data can be loaded from the command line:

```
py -3.11 seed_demo.py
```

To import your own data instead: go to the **Import** tab, give the
assessment a label and time window, and upload a flow export (required)
and, optionally, an asset inventory (CSV or JSON; column requirements are
enforced by `loader.py` and listed in its docstring). Every row is
validated before anything reaches the database — malformed rows are
skipped and reported with a reason, not silently dropped.

## Running the tests

```
py -3.11 -m pytest tests/ -v
```

## Project layout

| File | Block | Purpose |
|---|---|---|
| `config.py` | 1 | Purdue levels, zones, protocol reference data, IEC 62443/ATT&CK mappings, rule metadata table |
| `db.py` | 2 | SQLite schema and all parameterized data access |
| `loader.py` | 3 | Hostile-input-safe CSV/JSON import of assets and flows |
| `rules.py` | 4 | The segmentation rule engine |
| `tests/test_rules.py` | 5 | pytest coverage for the rule engine |
| `grapher.py` | 6 | Purdue-tiered topology graph (networkx layout, Plotly render) |
| `seed_demo.py` | 7 | Synthetic two-assessment demo dataset and loader |
| `exporter.py` | 8 | Formula-injection-safe CSV export of violations and inventory |
| `app.py` | 9 | Streamlit UI |

## Security posture

- Every SQL statement is parameterized; table/column names and PRAGMA
  statements are hardcoded literals, never built from input or config.
- `.env` and the database file are gitignored from the first commit and
  never logged in full — `app.py`'s log file (`logs/app.log`, also
  gitignored) records error summaries, not full payloads.
- Every externally-sourced file goes through `loader.py`'s guard pipeline
  before any of its content is trusted: a charset allowlist, a size cap, a
  row cap, a column cap, a max field length, a JSON nesting-depth limit,
  UTF-8-only decoding with BOM/null-byte stripping, and an outright
  rejection of zip/gzip archives.
- CSV exports (`exporter.py`) neutralize any cell beginning with `=`, `+`,
  `-`, `@`, a tab, or a carriage return, so a malicious field value can't
  execute as a formula when the file is opened in Excel/Sheets.
- `app.py` never passes `unsafe_allow_html=True` anywhere; tables render
  through `st.dataframe` (including pandas Styler for severity coloring),
  and Plotly hover/labels are plain text.
- Errors shown to the user are short, pre-written, non-sensitive messages.
  Full exception detail (including anything that might contain a stack
  trace or filesystem path) goes only to the gitignored log file.
- The tool never scans, pings, or otherwise touches a device — every code
  path either reads local files/database or writes to the local database.
- Findings are never silenced: a flow that trips multiple rules keeps every
  one of them (headline plus `contributing_rules`), and re-running the
  engine replaces an assessment's prior violations rather than silently
  merging with them.

## Screenshots

`screenshots/` is reserved for UI captures (topology view, violations
table, compare-assessments drift) taken from a running instance — add them
there and reference them here once you've run the app locally; none are
checked in yet.

## License

See `LICENSE`.
