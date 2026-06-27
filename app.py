"""
app.py — Streamlit UI for the OT Network Segmentation Validator.

This is the only module that talks to Streamlit. It is a thin layer over
loader.py / rules.py / grapher.py / exporter.py / db.py — no segmentation
logic lives here, only display and form handling.

Security notes specific to this module:
- `unsafe_allow_html` is never set anywhere in this file. Tables go through
  `st.dataframe` (including pandas Styler objects for severity coloring),
  which renders cell values as text, not as page HTML — that is what makes
  Styler usage here safe without `unsafe_allow_html`. Plotly hover/labels
  are built as plain text by grapher.py already.
- This tool is ingest-only: every code path here either reads from the local
  SQLite database or hands an uploaded file to loader.py for validation.
  Nothing in this file opens a socket, pings a host, or otherwise touches a
  device on the network.
- Errors shown to the user are always a short, pre-written, non-sensitive
  message. `loader.LoaderError` messages are safe to show as-is (loader.py
  crafts them to never include a stack trace or filesystem path). Any other
  exception is logged in full to `logs/app.log` (gitignored) and the UI only
  ever sees a generic "something went wrong, check the log" message.
- Findings are never hidden: every tab that lists violations shows all of
  them (optionally filtered by the user, never silently dropped), and the
  rule engine's own no-silent-failure design (see rules.py) is unaffected by
  anything in this file.
"""

import json
import logging
import os
from datetime import date

import pandas as pd
import streamlit as st

import config
import db
import exporter
import grapher
import loader
import rules
import seed_demo

# ---------------------------------------------------------------------------
# Logging — full detail to a gitignored file, never to the screen.
# ---------------------------------------------------------------------------
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ot_validator")

st.set_page_config(page_title="OT Network Segmentation Validator", layout="wide")

db.init_db()

SEVERITY_ROW_COLORS = {
    "Critical": "#8B0000",
    "High": "#E03C31",
    "Medium": "#FF8C00",
    "Low": "#B8860B",
}


def _style_by_severity(df: pd.DataFrame):
    """Color each row by its severity column. Returned as a pandas Styler,
    passed straight to st.dataframe — no HTML string is ever built by hand.
    """

    def _row_style(row):
        color = SEVERITY_ROW_COLORS.get(row["severity"], "#444444")
        return [f"background-color: {color}; color: white"] * len(row)

    return df.style.apply(_row_style, axis=1)


def _assessment_labels(assessments) -> list:
    return [
        f"#{a['id']} — {a['label']} ({a['time_window_start']} to {a['time_window_end']})"
        for a in assessments
    ]


# ---------------------------------------------------------------------------
# Sidebar — disclaimer, demo/housekeeping actions, active assessment picker.
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("OT Segmentation Validator")
    st.caption(
        "IEC 62443 zone & conduit validation, offline. Ingest-only — this "
        "tool never scans or touches a device. All demo data is synthetic."
    )

    with st.expander("Demo data / housekeeping"):
        if st.button("Load synthetic demo data"):
            try:
                summary = seed_demo.seed_demo()
                logger.info("Demo data loaded: %s", summary)
                st.success("Synthetic demo data loaded (two assessments).")
                st.rerun()
            except Exception:
                logger.exception("Failed to load demo data")
                st.error("Could not load demo data. Check logs/app.log for details.")

        st.divider()
        confirm_purge = st.checkbox("I understand this deletes all local data")
        if st.button("Purge all local data", disabled=not confirm_purge):
            db.purge_all()
            logger.info("All local data purged via UI action.")
            st.success("All local data purged.")
            st.rerun()

    st.divider()
    assessments = db.list_assessments()
    if assessments:
        index = st.selectbox(
            "Active assessment",
            options=range(len(assessments)),
            format_func=lambda i: _assessment_labels(assessments)[i],
        )
        active_assessment_id = assessments[index]["id"]
    else:
        st.info("No assessments yet. Load demo data or import one in the Import tab.")
        active_assessment_id = None

# ---------------------------------------------------------------------------
# Main tabs
# ---------------------------------------------------------------------------
tab_import, tab_topology, tab_violations, tab_compare, tab_assets, tab_conduits, tab_rules = st.tabs(
    ["Import", "Topology", "Violations", "Compare Assessments", "Asset Inventory", "Conduits", "Rule Reference"]
)

# --- Import -----------------------------------------------------------------
with tab_import:
    st.subheader("New assessment")
    st.caption(
        "Upload a flow export (required) and, optionally, an updated asset "
        "inventory. CSV or JSON only — every row is validated by loader.py "
        "before anything is written to the database."
    )
    with st.form("import_form", clear_on_submit=False):
        label = st.text_input("Assessment label")
        col_start, col_end = st.columns(2)
        with col_start:
            window_start = st.date_input("Time window start", value=date.today())
        with col_end:
            window_end = st.date_input("Time window end", value=date.today())
        assets_file = st.file_uploader("Asset inventory (optional)", type=["csv", "json"])
        flows_file = st.file_uploader("Flow export (required)", type=["csv", "json"])
        submitted = st.form_submit_button("Import")

    if submitted:
        if not label.strip():
            st.error("Assessment label is required.")
        elif flows_file is None:
            st.error("A flow export file is required.")
        else:
            try:
                result = loader.import_assessment(
                    label=label.strip(),
                    time_window_start=str(window_start),
                    time_window_end=str(window_end),
                    flows_raw=flows_file.getvalue(),
                    flows_filename=flows_file.name,
                    assets_raw=assets_file.getvalue() if assets_file else None,
                    assets_filename=assets_file.name if assets_file else None,
                )
                eval_summary = rules.evaluate_assessment(result["assessment_id"])
                logger.info("Imported assessment %s: %s", result["assessment_id"], eval_summary)

                st.success(
                    f"Assessment #{result['assessment_id']} imported and evaluated: "
                    f"{eval_summary['flows_evaluated']} flows evaluated, "
                    f"{eval_summary['violations_found']} violation(s) found."
                )
                if result["assets"]:
                    st.write(f"Asset rows imported: {result['assets']['imported']}")
                    if result["assets"]["skipped"]:
                        st.warning(f"{len(result['assets']['skipped'])} asset row(s) skipped:")
                        st.dataframe(pd.DataFrame(result["assets"]["skipped"]), use_container_width=True)
                if result["flows"]["skipped"]:
                    st.warning(f"{len(result['flows']['skipped'])} flow row(s) skipped:")
                    st.dataframe(pd.DataFrame(result["flows"]["skipped"]), use_container_width=True)
                st.rerun()
            except loader.LoaderError as exc:
                # loader.py crafts these messages to be safe to show as-is —
                # never a stack trace, never a filesystem path.
                logger.warning("Import rejected: %s", exc)
                st.error(str(exc))
            except Exception:
                logger.exception("Unexpected error during import")
                st.error("Something went wrong processing that file. Check logs/app.log for details.")

# --- Topology -----------------------------------------------------------------
with tab_topology:
    if active_assessment_id is None:
        st.info("No assessment selected.")
    else:
        figure = grapher.build_topology_figure(
            db.get_all_assets(),
            db.get_flows(active_assessment_id),
            db.get_violations(active_assessment_id),
        )
        st.plotly_chart(figure, use_container_width=True)

# --- Violations -----------------------------------------------------------------
with tab_violations:
    if active_assessment_id is None:
        st.info("No assessment selected.")
    else:
        violations = db.get_violations(active_assessment_id)
        if not violations:
            st.success("No violations recorded for this assessment.")
        else:
            df = pd.DataFrame([dict(v) for v in violations])
            df["contributing_rules"] = df["contributing_rules"].apply(
                lambda raw: ", ".join(json.loads(raw))
            )
            display_columns = [
                "id", "src_asset", "dst_asset", "rule_id", "severity", "status",
                "contributing_rules", "iec62443_ref", "attack_ref", "remediation",
            ]

            chosen_severities = st.multiselect(
                "Filter by severity", config.SEVERITY_BANDS, default=config.SEVERITY_BANDS
            )
            filtered = df[df["severity"].isin(chosen_severities)]
            st.dataframe(
                _style_by_severity(filtered[display_columns]),
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Download violations CSV",
                data=exporter.export_violations_csv(active_assessment_id),
                file_name=f"violations_assessment_{active_assessment_id}.csv",
                mime="text/csv",
            )

            st.divider()
            st.caption("Mark a violation as accepted risk (with a note), or reopen one.")
            violation_ids = [v["id"] for v in violations]
            selected_violation_id = st.selectbox("Violation ID", violation_ids)
            note = st.text_input("Note (required to accept)")
            col_accept, col_reopen = st.columns(2)
            with col_accept:
                if st.button("Mark accepted"):
                    if not note.strip():
                        st.error("A note is required to accept a violation.")
                    else:
                        db.set_violation_status(selected_violation_id, "accepted", note.strip())
                        logger.info("Violation %s marked accepted", selected_violation_id)
                        st.rerun()
            with col_reopen:
                if st.button("Reopen"):
                    db.set_violation_status(selected_violation_id, "open", None)
                    logger.info("Violation %s reopened", selected_violation_id)
                    st.rerun()

# --- Compare Assessments -----------------------------------------------------------------
with tab_compare:
    all_assessments = db.list_assessments()
    if len(all_assessments) < 2:
        st.info("Need at least two assessments to compare.")
    else:
        labels = _assessment_labels(all_assessments)
        idx_a = st.selectbox(
            "Baseline assessment", range(len(all_assessments)), format_func=lambda i: labels[i], key="cmp_a"
        )
        idx_b = st.selectbox(
            "Comparison assessment",
            range(len(all_assessments)),
            format_func=lambda i: labels[i],
            index=min(1, len(all_assessments) - 1),
            key="cmp_b",
        )

        if idx_a == idx_b:
            st.warning("Choose two different assessments to compare.")
        else:
            id_a = all_assessments[idx_a]["id"]
            id_b = all_assessments[idx_b]["id"]

            flows_a = db.get_flows(id_a)
            flows_b = db.get_flows(id_b)
            violations_a = db.get_violations(id_a)
            violations_b = db.get_violations(id_b)

            def _flow_key(row):
                return (row["src_asset"], row["dst_asset"], row["port"], row["protocol"])

            by_key_a = {_flow_key(v): v for v in violations_a}
            by_key_b = {_flow_key(v): v for v in violations_b}

            resolved_keys = by_key_a.keys() - by_key_b.keys()
            new_keys = by_key_b.keys() - by_key_a.keys()

            endpoints_a = {name for f in flows_a for name in (f["src_asset"], f["dst_asset"])}
            endpoints_b = {name for f in flows_b for name in (f["src_asset"], f["dst_asset"])}
            new_endpoints = endpoints_b - endpoints_a

            col1, col2, col3 = st.columns(3)
            col1.metric("Resolved violations", len(resolved_keys))
            col2.metric("New violations", len(new_keys))
            col3.metric("New endpoints observed", len(new_endpoints))

            display_cols = ["src_asset", "dst_asset", "rule_id", "severity"]
            if resolved_keys:
                st.write("Resolved (present in baseline, gone in comparison):")
                st.dataframe(
                    pd.DataFrame([dict(by_key_a[k]) for k in resolved_keys])[display_cols],
                    use_container_width=True,
                    hide_index=True,
                )
            if new_keys:
                st.write("New (absent in baseline, present in comparison):")
                st.dataframe(
                    pd.DataFrame([dict(by_key_b[k]) for k in new_keys])[display_cols],
                    use_container_width=True,
                    hide_index=True,
                )
            if new_endpoints:
                st.write("New endpoints observed in the comparison assessment:")
                st.dataframe(
                    pd.DataFrame({"endpoint": sorted(new_endpoints)}),
                    use_container_width=True,
                    hide_index=True,
                )
            if not (resolved_keys or new_keys or new_endpoints):
                st.success("No drift between these two assessments.")

# --- Asset Inventory -----------------------------------------------------------------
with tab_assets:
    all_assets = db.get_all_assets()
    if not all_assets:
        st.info("No assets in inventory yet.")
    else:
        df = pd.DataFrame([dict(a) for a in all_assets])
        df["scan_sensitivity"] = df["scan_sensitivity"].astype(bool)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download asset inventory CSV",
            data=exporter.export_assets_csv(),
            file_name="asset_inventory.csv",
            mime="text/csv",
        )

# --- Conduits -----------------------------------------------------------------
with tab_conduits:
    all_conduits = db.get_all_conduits()
    if not all_conduits:
        st.info("No conduits defined yet.")
    else:
        st.dataframe(
            pd.DataFrame([dict(c) for c in all_conduits]), use_container_width=True, hide_index=True
        )
    st.caption(
        "Conduits are the documented, accepted topology and are not currently "
        "importable through file upload — they are maintained directly (see "
        "seed_demo.py for the demo set)."
    )

# --- Rule Reference -----------------------------------------------------------------
with tab_rules:
    st.caption("Every rule the engine evaluates, with its IEC 62443 and MITRE ATT&CK for ICS mapping.")
    rules_df = pd.DataFrame(config.RULES)[
        ["id", "label", "base_severity", "precedence", "iec_ref", "attack_ref", "description", "remediation"]
    ]
    st.dataframe(rules_df, use_container_width=True, hide_index=True)
