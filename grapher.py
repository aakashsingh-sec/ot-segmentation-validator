"""
grapher.py — Purdue-tiered topology graph (networkx layout + Plotly render).

Builds a directed graph of assets and flows, lays it out with one
horizontal band per Purdue level (Level 0 at the bottom, External/Internet
at the top, matching the conventional Purdue pyramid), and renders it with
Plotly. Violations color and thicken their edge; everything else renders as
a thin neutral line so the eye goes straight to what's wrong.

Security notes:
- All node/edge labels come from asset and flow names that loader.py has
  already restricted to a plain charset allowlist (see loader.ASSET_NAME_RE)
  before they ever reach the database, so nothing here can inject markup.
  Hover text is still built from plain strings only — no field is ever
  passed through unescaped beyond Plotly's own `<br>` line-break convention,
  which Plotly renders as text, not as page HTML.
- This module never calls Streamlit, so `unsafe_allow_html` doesn't apply
  here; app.py is responsible for passing this figure to `st.plotly_chart`
  without any HTML wrapper.
"""

import re

import networkx as nx
import plotly.graph_objects as go

import config

# Endpoints that aren't in inventory but look like a raw IPv4/IPv6 address
# are treated as external (Level 5) rather than as an undocumented device —
# mirrors rules._looks_external exactly, kept as a small local copy so this
# module has no dependency on the rule engine's internals.
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]*:[0-9a-fA-F:]*$")


def _looks_external(name: str) -> bool:
    if _IPV4_RE.match(name):
        return all(0 <= int(octet) <= 255 for octet in name.split("."))
    if ":" in name and _IPV6_RE.match(name):
        return True
    return False


# A synthetic layer below "Level 0" for nodes nothing else can place: assets
# with a name but no zone/level (incomplete inventory) and true shadow
# assets (not in inventory, not external-shaped). Drawn below the pyramid
# rather than mixed into it, since neither has an honest Purdue level.
UNCLASSIFIED_LAYER = -1
UNCLASSIFIED_COLOR = "#777777"
UNCLASSIFIED_LABEL = "Unclassified (no zone/level, or undocumented)"

SEVERITY_EDGE_COLORS = {
    "Low": "#F5C518",
    "Medium": "#FF8C00",
    "High": "#E03C31",
    "Critical": "#8B0000",
}
CLEAN_EDGE_COLOR = "#B0B0B0"

SHADOW_BORDER_COLOR = "#E03C31"


def _node_style(name: str, asset_map: dict) -> dict:
    """Resolve one flow endpoint to its layer, fill color, and a 'kind' used
    to decide whether it gets a warning border (shadow/incomplete).
    """
    if name in asset_map:
        info = asset_map[name]
        if info["zone"] is None or info["purdue_level"] is None:
            return {
                "layer": UNCLASSIFIED_LAYER,
                "color": UNCLASSIFIED_COLOR,
                "kind": "incomplete",
                "zone": info["zone"],
                "level": info["purdue_level"],
                "criticality": info["criticality"],
            }
        return {
            "layer": info["purdue_level"],
            "color": config.PURDUE_LEVELS[info["purdue_level"]]["color"],
            "kind": "known",
            "zone": info["zone"],
            "level": info["purdue_level"],
            "criticality": info["criticality"],
        }
    if _looks_external(name):
        return {
            "layer": 5,
            "color": config.PURDUE_LEVELS[5]["color"],
            "kind": "external",
            "zone": config.EXTERNAL_ZONE,
            "level": 5,
            "criticality": None,
        }
    return {
        "layer": UNCLASSIFIED_LAYER,
        "color": UNCLASSIFIED_COLOR,
        "kind": "shadow",
        "zone": None,
        "level": None,
        "criticality": None,
    }


def build_graph(asset_rows, flow_rows) -> nx.DiGraph:
    """One node per asset/endpoint referenced by a flow, one edge per flow.

    Assets are added first, in name order, so node insertion order — and
    therefore the resulting layout — is the same on every run regardless of
    dict/set iteration order elsewhere in the process.
    """
    asset_map = {row["name"]: row for row in asset_rows}
    graph = nx.DiGraph()

    for name in sorted(asset_map):
        style = _node_style(name, asset_map)
        graph.add_node(name, **style)

    for flow in flow_rows:
        for name in (flow["src_asset"], flow["dst_asset"]):
            if not graph.has_node(name):
                graph.add_node(name, **_node_style(name, asset_map))
        graph.add_edge(
            flow["src_asset"],
            flow["dst_asset"],
            flow_id=flow["id"],
            port=flow["port"],
            protocol=flow["protocol"],
            flow_count=flow["flow_count"],
        )

    return graph


def _layer_label(layer) -> str:
    if layer == UNCLASSIFIED_LAYER:
        return UNCLASSIFIED_LABEL
    return config.PURDUE_LEVELS[layer]["label"]


def _node_hover_text(name: str, data: dict) -> str:
    lines = [name]
    if data["kind"] == "shadow":
        lines.append("Shadow asset — not in inventory")
    elif data["kind"] == "incomplete":
        lines.append("Incomplete inventory — missing zone or Purdue level")
    else:
        lines.append(f"Zone: {data['zone']}")
        lines.append(f"Purdue level: {data['level']}")
        if data["criticality"]:
            lines.append(f"Criticality: {data['criticality']}")
    return "<br>".join(lines)


def _edge_hover_text(src: str, dst: str, edge_data: dict, violation) -> str:
    lines = [
        f"{src} -> {dst}",
        f"Protocol: {edge_data['protocol']}  Port: {edge_data['port']}",
        f"Flow count: {edge_data['flow_count']}",
    ]
    if violation is not None:
        lines.append(f"Finding: {violation['rule_id']} ({violation['severity']})")
    return "<br>".join(lines)


def build_topology_figure(asset_rows, flow_rows, violation_rows=None) -> go.Figure:
    """Render the Purdue-tiered topology graph for one assessment.

    `violation_rows` (from db.get_violations) is optional — pass None to
    render a clean topology view with no severity coloring at all.
    """
    graph = build_graph(asset_rows, flow_rows)

    violation_by_flow_id = {}
    if violation_rows:
        for violation in violation_rows:
            violation_by_flow_id[violation["flow_id"]] = violation

    # horizontal bands, one per layer, Level 0 at the bottom like the
    # conventional Purdue pyramid (multipartite_layout's default puts the
    # first-sorted layer first; negating the layer value before layout and
    # flipping the axis label achieves the bottom-up order without needing
    # any randomness — the layout is fully deterministic by construction).
    for _, data in graph.nodes(data=True):
        data["_layout_layer"] = -data["layer"]

    if graph.number_of_nodes() == 0:
        return go.Figure().update_layout(
            title="No assets or flows to display for this assessment.",
            xaxis={"visible": False},
            yaxis={"visible": False},
        )

    positions = nx.multipartite_layout(graph, subset_key="_layout_layer", align="horizontal")

    # Plotly draws one line style per trace, so flows that share a severity
    # (or lack one) are grouped into a single trace rather than one trace per
    # edge — keeps the figure small even on a busy demo network. A separate,
    # invisible marker trace at each edge's midpoint carries the per-flow
    # hover text, since Plotly line traces can't show per-segment hover.
    midpoint_x, midpoint_y, midpoint_text = [], [], []
    groups = {}
    for src, dst, edge_data in graph.edges(data=True):
        x0, y0 = positions[src]
        x1, y1 = positions[dst]
        violation = violation_by_flow_id.get(edge_data["flow_id"])
        key = "clean" if violation is None else violation["severity"]
        groups.setdefault(key, {"x": [], "y": []})
        groups[key]["x"] += [x0, x1, None]
        groups[key]["y"] += [y0, y1, None]

        midpoint_x.append((x0 + x1) / 2)
        midpoint_y.append((y0 + y1) / 2)
        midpoint_text.append(_edge_hover_text(src, dst, edge_data, violation))

    edge_traces = []
    for key, coords in groups.items():
        color = CLEAN_EDGE_COLOR if key == "clean" else SEVERITY_EDGE_COLORS[key]
        width = 1.5 if key == "clean" else 3
        edge_traces.append(
            go.Scatter(
                x=coords["x"],
                y=coords["y"],
                mode="lines",
                line={"color": color, "width": width},
                hoverinfo="skip",
                name="Clean flow" if key == "clean" else f"{key} finding",
                showlegend=True,
            )
        )

    edge_hover_trace = go.Scatter(
        x=midpoint_x,
        y=midpoint_y,
        mode="markers",
        marker={"size": 8, "opacity": 0},
        hoverinfo="text",
        hovertext=midpoint_text,
        showlegend=False,
    )

    node_x, node_y, node_text, node_hover, node_color, node_border = [], [], [], [], [], []
    for name, data in graph.nodes(data=True):
        x, y = positions[name]
        node_x.append(x)
        node_y.append(y)
        node_text.append(name)
        node_hover.append(_node_hover_text(name, data))
        node_color.append(data["color"])
        node_border.append(SHADOW_BORDER_COLOR if data["kind"] in ("shadow", "incomplete") else "#FFFFFF")

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_text,
        textposition="top center",
        textfont={"size": 10},
        hoverinfo="text",
        hovertext=node_hover,
        marker={
            "size": 16,
            "color": node_color,
            "line": {"color": node_border, "width": 2},
        },
        showlegend=False,
        name="Assets",
    )

    figure = go.Figure(data=edge_traces + [edge_hover_trace, node_trace])

    layer_values = sorted({data["layer"] for _, data in graph.nodes(data=True)})
    annotations = []
    for layer in layer_values:
        sample_node = next(n for n in graph.nodes() if graph.nodes[n]["layer"] == layer)
        y = positions[sample_node][1]
        annotations.append(
            {
                "x": -1.15,
                "y": y,
                "xref": "x",
                "yref": "y",
                "text": _layer_label(layer),
                "showarrow": False,
                "xanchor": "right",
                "font": {"size": 11},
            }
        )

    figure.update_layout(
        title="OT network topology — Purdue levels (Level 0 at bottom)",
        xaxis={"visible": False},
        yaxis={"visible": False},
        margin={"l": 160, "r": 20, "t": 50, "b": 20},
        legend={"orientation": "h", "yanchor": "bottom", "y": -0.1},
        annotations=annotations,
        plot_bgcolor="white",
    )

    return figure
