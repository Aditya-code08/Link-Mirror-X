"""LinkMirror X — SIH26106 investigation dashboard.

Restores the original LinkMirror chart/graph experience while keeping the new
multi-vector forensic features. Email forensics and LinkMirror Direct remain
separate top-level tabs. The original threat-graph section is restored as its
own dedicated tab, and the original score/severity/URL charts plus animated
trust/fusion pies are available again.
"""
from __future__ import annotations

import base64
import html
import io
import os
import tempfile
import time
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import streamlit as st
import streamlit.components.v1 as components
from PIL import Image

from case.case_manager import process_email, analyze_standalone_url
from correlation.correlation_engine import (
    CaseIndicators, build_attack_path, build_campaign_dna, build_threat_graph,
    find_shared_infrastructure,
)
from intelligence.domain_intel import lookup_ip
from intelligence.sibling_predictor import predict_siblings
from reporting.report_generator import generate_case_report
from engine.linkmirror_engine import (
    analyze_screenshot_against_refs, decide_trust, fused_score,
)
from core.risk_engine import assess_case_risk
from provenance.origin_trace import explain_result

BASE = Path(__file__).resolve().parent
DEMO_DIR = BASE / "demo_data" / "emails"
REF_DIR = BASE / "reference_images"
CAPTURED_DIR = BASE / "captured_screenshots"

st.set_page_config(page_title="LinkMirror X Forensics", page_icon="🪞", layout="wide")

SEVERITY_COLOR = {
    "critical": "#ef5350", "high": "#ef5350", "medium": "#fb8c00",
    "warning": "#fb8c00", "low": "#2e7d32", "info": "#2979FF",
}
VERDICT_COLOR_MAP = {
    "green": "#2e7d32", "red": "#ef5350", "orange": "#fb8c00", "blue": "#1976d2",
}


def set_bg_gif(path: Path):
    if not path.exists():
        return
    data = base64.b64encode(path.read_bytes()).decode()
    st.markdown(
        f'''<style>
        [data-testid="stAppViewContainer"]{{background-color:#000;background-image:url("data:image/gif;base64,{data}");background-size:cover;background-position:center;background-attachment:fixed;background-repeat:no-repeat}}
        [data-testid="stHeader"]{{background:transparent}}
        [data-testid="stSidebar"]{{display:none}}
        [data-testid="collapsedControl"]{{display:none}}
        #MainMenu,footer,[data-testid="stStatusWidget"]{{visibility:hidden;height:0}}
        [data-testid="stDecoration"]{{display:none}}
        </style>''',
        unsafe_allow_html=True,
    )


def inject_theme():
    st.markdown('''<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');
    html,body,[class*="css"]{font-family:Poppins,sans-serif;color:#dbe9ff}
    .header{padding:18px 22px;background:linear-gradient(90deg,#081426,#071a2b);border:1px solid rgba(41,121,255,.16);border-radius:14px;margin-bottom:14px}
    .title{font-size:28px;font-weight:700;color:#5ca7ff}.sub{font-size:13px;color:#9fbbe8}
    .panel{background:rgba(7,16,38,.93);border:1px solid rgba(41,121,255,.12);border-radius:12px;padding:14px 16px;margin-bottom:12px}
    .hero{background:linear-gradient(135deg,rgba(7,16,38,.97),rgba(9,28,50,.94));border:1px solid rgba(41,121,255,.20);border-radius:14px;padding:18px;margin-bottom:12px}
    .hero h2{margin:0;color:#dbe9ff}.muted{color:#9fbbe8;font-size:12px}.pill{display:inline-block;padding:3px 8px;border-radius:20px;font-size:11px;font-weight:600;background:#0b1a2b;margin-right:5px}
    .metric{background:#0b1a2b;border:1px solid rgba(41,121,255,.10);border-radius:10px;padding:10px 12px;text-align:center}.metric .v{font-size:23px;font-weight:700}.metric .l{font-size:11px;color:#9fbbe8}
    .finding{background:#0b1a2b;border-radius:8px;padding:10px 12px;margin:6px 0;border-left:4px solid #2979FF}
    .riskbar{height:10px;border-radius:8px;background:#17243a;overflow:hidden;margin:8px 0 12px}.riskfill{height:100%;border-radius:8px}
    .section{font-size:19px;font-weight:700;margin:8px 0 12px}
    .path{display:flex;gap:8px;overflow-x:auto;padding:8px 0}.step{min-width:150px;background:#0b1a2b;border:1px solid rgba(41,121,255,.12);border-radius:10px;padding:10px}.arrow{align-self:center;color:#2979FF;font-size:20px}
    .statrow{display:flex;gap:8px;flex-wrap:wrap}.chip{padding:6px 9px;border-radius:8px;background:#0b1a2b;border:1px solid rgba(41,121,255,.13);font-size:12px}
    .chart-shell{background:rgba(7,16,38,.78);border:1px solid rgba(41,121,255,.10);border-radius:12px;padding:8px;margin:4px 0 12px}
    .chart-shell img{max-width:100%;height:auto;border-radius:10px}
    @keyframes fadeInUp{from{opacity:0;transform:translateY(16px) scale(.99)}to{opacity:1;transform:translateY(0) scale(1)}}
    .fade-in{animation:fadeInUp .55s cubic-bezier(.2,.7,.3,1) both}
    </style>''', unsafe_allow_html=True)


def metric(label, value):
    st.markdown(
        f'<div class="metric"><div class="v">{html.escape(str(value))}</div><div class="l">{html.escape(label)}</div></div>',
        unsafe_allow_html=True,
    )


def risk_banner(score: float, level: str, subtitle: str = ""):
    color = SEVERITY_COLOR.get(level, "#2979FF")
    width = max(0, min(100, score))
    st.markdown(
        f'''<div class="hero" style="border-left:5px solid {color}">
        <h2>Risk Assessment</h2>
        <span class="pill">{html.escape(level.upper())}</span><span class="pill">{score:.0f}/100</span>
        <div class="riskbar"><div class="riskfill" style="width:{width}%;background:{color}"></div></div>
        <div class="muted">{html.escape(subtitle)}</div>
        </div>''',
        unsafe_allow_html=True,
    )



def fig_to_img_tag(fig, css_class="fade-in", delay=0.0) -> str:
    """Legacy helper retained for compatibility with older rendering paths."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    data = base64.b64encode(buf.getvalue()).decode("utf-8")
    style = f'animation-delay:{delay}s;' if delay else ''
    return f'<div class="chart-shell {css_class}" style="{style}"><img src="data:image/png;base64,{data}" /></div>'


def _prepare_axes(fig, ax):
    fig.patch.set_facecolor("#071026")
    ax.set_facecolor("#071026")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(colors="#9fbbe8", labelsize=9)
    ax.xaxis.label.set_color("#9fbbe8")
    ax.yaxis.label.set_color("#9fbbe8")
    return fig, ax


def _graph_header(title: str, subtitle: str, key: str):
    c1, c2 = st.columns([6, 1])
    with c1:
        st.markdown(
            f"<div style='font-weight:700;color:#dbe9ff;font-size:14px'>{html.escape(title)}</div>"
            f"<div class='muted'>{html.escape(subtitle)}</div>",
            unsafe_allow_html=True,
        )
    with c2:
        replay = st.button("↻ Replay", key=f"replay-{key}", use_container_width=True)
    animate = replay or not st.session_state.get(f"_graph_seen_{key}", False)
    if animate:
        st.session_state[f"_graph_seen_{key}"] = True
    return animate


def _show_frame(placeholder, fig):
    placeholder.pyplot(fig, use_container_width=True)
    plt.close(fig)


def _should_animate(key: str, replay: bool) -> bool:
    animate = replay or not st.session_state.get(f"_graph_seen_{key}", False)
    st.session_state[f"_graph_seen_{key}"] = True
    return animate


def animated_bar_chart(labels, values, title, ylabel="Score", higher_is_risk=False, key="bar", height=430):
    vals = [float(v) for v in values]
    maxv = max(100.0, max(vals, default=0.0))
    animate = _graph_header(title, f"{ylabel} · animated rise", key)
    placeholder = st.empty()

    fig, ax = plt.subplots(figsize=(6.8, max(3.0, height / 115)))
    _prepare_axes(fig, ax)
    x = np.arange(len(vals))
    ax.set_ylim(0, maxv)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels([str(l)[:18] for l in labels], color="#9fbbe8", fontsize=9)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.grid(axis="y", color="#1d3556", alpha=0.8, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title(title, color="#dbe9ff", fontsize=12, pad=10)
    bar_colors = [
        "#ef5350" if (v >= 70 if higher_is_risk else v < 40)
        else "#fb8c00" if (v >= 40 if higher_is_risk else v < 70)
        else "#2e7d32" for v in vals
    ]
    bars = ax.bar(x, [0.0] * len(vals), color=bar_colors, width=0.52, alpha=0.95)
    value_labels = [ax.text(0, 0, "", ha="center", va="bottom", color="#dbe9ff", fontsize=9, fontweight="600") for _ in vals]
    fig.tight_layout()

    steps = 18 if animate else 1
    for step in range(1, steps + 1):
        progress = step / steps
        ease = 1 - (1 - progress) ** 3
        for i, (bar, actual) in enumerate(zip(bars, vals)):
            shown = actual * ease
            bar.set_height(shown)
            value_labels[i].set_position((bar.get_x() + bar.get_width() / 2, min(maxv * 0.98, shown + maxv * 0.025)))
            value_labels[i].set_text(f"{actual:.0f}" if progress > 0.94 else "")
        _show_frame(placeholder, fig)
        if animate and step < steps:
            time.sleep(0.016)
    plt.close(fig)


def animated_pie(score, title="TrustScore", size=3.0, risk=False, key=None):
    key = key or f"pie-{title.lower().replace(' ', '-') }"
    val = max(0.0, min(100.0, float(score)))
    animate = _graph_header(title, f"animated growth · {val:.0f}%", key)
    placeholder = st.empty()

    fig, ax = plt.subplots(figsize=(size, size))
    fig.patch.set_facecolor("#071026")
    ax.set_facecolor("#071026")
    color = "#ef5350" if (risk and val >= 75) else "#fb8c00" if (risk and val >= 50) else "#5ca7ff"
    wedges, _ = ax.pie([0.0, 100.0], colors=[color, "#17243a"], startangle=90,
                       counterclock=False, wedgeprops=dict(width=0.34, edgecolor="#0b1a2b"))
    center = ax.text(0, 0.02, "0%", ha="center", va="center", fontsize=22, color="white", fontweight="700")
    ax.text(0, -0.20, "Risk" if risk else "Trust", ha="center", va="center", fontsize=9, color="#9fbbe8")
    ax.set_title(title, color="#dbe9ff", fontsize=12, pad=10)
    ax.axis("equal")
    fig.tight_layout()

    steps = 24 if animate else 1
    for step in range(1, steps + 1):
        progress = step / steps
        ease = 1 - (1 - progress) ** 3
        shown = val * ease
        wedges[0].set_theta1(90 - shown * 3.6)
        wedges[0].set_theta2(90)
        wedges[1].set_theta1(90 - 360)
        wedges[1].set_theta2(90 - shown * 3.6)
        center.set_text(f"{val:.0f}%" if progress > 0.92 else f"{shown:.0f}%")
        _show_frame(placeholder, fig)
        if animate and step < steps:
            time.sleep(0.012)
    plt.close(fig)


def animated_line_chart(labels, values, title, ylabel="Score", key="line", height=430):
    vals = [float(v) for v in values]
    animate = _graph_header(title, f"{ylabel} · animated draw", key)
    placeholder = st.empty()
    fig, ax = plt.subplots(figsize=(6.8, max(3.0, height / 115)))
    _prepare_axes(fig, ax)
    x = np.arange(len(vals))
    ax.set_ylim(0, max(100.0, max(vals, default=0.0)))
    ax.set_xlim(-0.5, max(0.5, len(vals) - 0.5))
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels([str(l)[:16] for l in labels], color="#9fbbe8", fontsize=9)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.grid(axis="y", color="#1d3556", alpha=0.8, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title(title, color="#dbe9ff", fontsize=12, pad=10)
    line, = ax.plot([], [], color="#5ca7ff", linewidth=3.0, marker="o", markersize=5)
    value_labels = [ax.text(xi, yi + 4, f"{yi:.0f}", ha="center", va="bottom", color="#dbe9ff", fontsize=9) for xi, yi in zip(x, vals)]
    for label in value_labels:
        label.set_visible(False)
    fig.tight_layout()
    steps = max(12, len(vals) * 5) if animate else 1
    for step in range(1, steps + 1):
        progress = step / steps
        if not vals:
            vx, vy = [], []
        else:
            scaled = progress * len(vals)
            count = min(len(vals), max(1, int(np.ceil(scaled))))
            frac = max(0.0, min(1.0, scaled - (count - 1)))
            vx = x[:count]
            vy = vals[:count].copy()
            if count == 1:
                vy[0] = vals[0] * frac
            elif count < len(vals):
                vy[-1] = vals[count - 1] * frac
        line.set_data(vx, vy)
        if len(vx) == len(vals):
            for label in value_labels:
                label.set_visible(True)
        _show_frame(placeholder, fig)
        if animate and step < steps:
            time.sleep(0.012)
    plt.close(fig)


def animated_severity_breakdown(header_findings, key="severity"):
    counts = {"high": 0, "warning": 0, "info": 0}
    for f in header_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    animated_bar_chart(list(counts), list(counts.values()), "Header finding severity", "Count", higher_is_risk=True, key=key, height=390)


def animated_threat_graph(threat_graph, key="threat-graph", height=560):
    """Threat graph with decongested spacing (scales with node count),
    a colour legend instead of repeating each node's type as text, and
    the same reveal animation as before: nodes appear first, then all
    connections grow together."""
    G = nx.Graph()
    color_map = {"case":"#2979FF", "domain":"#ef5350", "ip":"#fb8c00", "email":"#9fbbe8", "attachment":"#9c6cff", "url":"#00bcd4"}
    badge_map = {"case":"C", "domain":"D", "ip":"I", "email":"E", "attachment":"A", "url":"U"}
    for n in threat_graph.nodes:
        G.add_node(n.id, label=n.label, type=n.type)
    for e in threat_graph.edges:
        G.add_edge(e.source, e.target, relation=e.relation)

    animate = _graph_header("Threat correlation graph", "nodes appear first; connections grow together", key)
    placeholder = st.empty()
    if not G.nodes:
        fig, ax = plt.subplots(figsize=(8, 4.8))
        _prepare_axes(fig, ax); ax.text(0.5,0.5,"No data yet",ha="center",va="center",color="#dbe9ff"); ax.axis("off")
        _show_frame(placeholder, fig); plt.close(fig); return

    n_total = len(G.nodes)
    dense, very_dense = n_total > 20, n_total > 40

    # Lay out each connected component on its own, with spacing that grows
    # with that component's OWN size (a big cluster needs more room than a
    # 2-node pair), then pack components using their real footprint so
    # large and small clusters never collide.
    comps = sorted(nx.connected_components(G), key=len, reverse=True)
    comp_layouts = []
    for comp in comps:
        sub = G.subgraph(comp); n = len(sub)
        if n == 1:
            sub_pos = {next(iter(sub.nodes)): (0.0, 0.0)}
        elif n == 2:
            ns = list(sub.nodes); sub_pos = {ns[0]: (-1.1, 0.0), ns[1]: (1.1, 0.0)}
        else:
            k = 2.2 + 0.28 * np.sqrt(n)
            scale = np.sqrt(n) * 1.9
            sub_pos = nx.spring_layout(sub, seed=42, k=k, scale=scale, iterations=400)
        xs = [p[0] for p in sub_pos.values()]; ys = [p[1] for p in sub_pos.values()]
        w = (max(xs) - min(xs)) if len(xs) > 1 else 1.0
        h = (max(ys) - min(ys)) if len(ys) > 1 else 1.0
        comp_layouts.append({"pos": sub_pos, "w": w, "h": h})

    MARGIN, MAX_ROW_WIDTH = 2.6, 26.0
    pos = {}
    cursor_x = cursor_y = row_h = 0.0
    for comp, layout in zip(comps, comp_layouts):
        cell_w, cell_h = layout["w"] + MARGIN, layout["h"] + MARGIN
        if cursor_x + cell_w > MAX_ROW_WIDTH and cursor_x > 0:
            cursor_y -= row_h + MARGIN
            cursor_x, row_h = 0.0, 0.0
        ox, oy = cursor_x + cell_w / 2, cursor_y
        for n_id, (x, y) in layout["pos"].items():
            pos[n_id] = (x + ox, y + oy)
        cursor_x += cell_w
        row_h = max(row_h, cell_h)

    xs = [p[0] for p in pos.values()]; ys = [p[1] for p in pos.values()]
    xmin, xmax = min(xs) - 1.8, max(xs) + 1.8
    ymin, ymax = min(ys) - 1.6, max(ys) + 2.2
    nodes = list(G.nodes(data=True)); edges = list(G.edges(data=True))

    # Figure size is driven mainly by node count (not just by the layout's
    # own span) -- this is what actually buys more breathing room per node
    # once Streamlit fits the image to the container width.
    figw = float(np.clip(9 + 0.16 * n_total, 9, 22))
    figh = float(np.clip(6 + 0.11 * n_total, 6, max(6, height / 95)))
    marker_s = 620 if not dense else (420 if not very_dense else 320)
    node_font = 7.5 if not dense else 6.5
    label_font = 7.6 if not dense else (6.6 if not very_dense else 6.0)
    max_label_len = 22 if not dense else (16 if not very_dense else 13)
    show_relations = len(edges) <= 20  # dense graphs skip edge-relation text to cut clutter

    fig, ax = plt.subplots(figsize=(figw, figh))
    _prepare_axes(fig, ax); ax.set_xlim(xmin, xmax); ax.set_ylim(ymin, ymax); ax.axis("off")
    ax.set_title("Threat graph — shared infrastructure", color="#dbe9ff", fontsize=12, pad=8)

    # Legend in axes-fraction coordinates so it never clips, regardless of graph size.
    legend_items = sorted(set(d.get("type") for _, d in nodes))
    n_leg = max(len(legend_items), 1)
    for j, t in enumerate(legend_items):
        lx = 0.02 + j * (0.94 / n_leg)
        ax.scatter([lx], [0.985], s=160, c=[color_map.get(t, "#888")], edgecolors="#0b1a2b",
                   linewidths=1.0, zorder=5, transform=ax.transAxes, clip_on=False)
        ax.text(lx + 0.018, 0.985, t.capitalize(), ha="left", va="center", color="#dbe9ff",
                fontsize=9, zorder=5, transform=ax.transAxes, clip_on=False)

    node_artists={}; badge_artists={}; label_artists={}
    offsets = [(-0.0,-1), (0.0,1), (0.55,-0.75), (-0.55,-0.75)]
    for i,(n,d) in enumerate(nodes):
        x,y=pos[n]
        node_artists[n]=ax.scatter([x],[y],s=marker_s,c=[color_map.get(d.get("type"),"#888")],edgecolors="#0b1a2b",linewidths=1.4,zorder=3,visible=False)
        badge_artists[n]=ax.text(x,y,badge_map.get(d.get("type"),"?"),ha="center",va="center",color="white",fontsize=node_font,fontweight="700",zorder=4,visible=False)
        label=str(d.get("label",n)); label=label if len(label)<=max_label_len else label[:max_label_len]+"…"
        dx, ydir = offsets[i % len(offsets)]
        ly = y + ydir*0.62; va = "top" if ydir < 0 else "bottom"
        label_artists[n]=ax.text(x+dx*0.9, ly, label, ha="center", va=va, color="#dbe9ff", fontsize=label_font, zorder=4, visible=False)

    edge_artists=[]; relation_artists=[]
    for u,v,d in edges:
        x1,y1=pos[u]; x2,y2=pos[v]
        line,=ax.plot([x1,x1],[y1,y1],color="#2979FF",linewidth=1.3 if very_dense else 1.8,alpha=0.5 if very_dense else 0.68,zorder=1)
        rel=ax.text((x1+x2)/2,(y1+y2)/2+0.14,str(d.get("relation","")) if show_relations else "",ha="center",va="bottom",color="#6486ad",fontsize=6.3,zorder=2,visible=False)
        edge_artists.append((u,v,line)); relation_artists.append(rel)
    fig.tight_layout()

    if not animate:
        for n,_ in nodes:
            node_artists[n].set_visible(True); badge_artists[n].set_visible(True); label_artists[n].set_visible(True)
        for (u,v,line),rel in zip(edge_artists,relation_artists):
            x1,y1=pos[u]; x2,y2=pos[v]; line.set_data([x1,x2],[y1,y2]); rel.set_visible(show_relations)
        _show_frame(placeholder,fig); plt.close(fig); return

    # Nodes: quick reveal, using only a few frames for speed.
    node_steps=min(max(len(nodes),1),6)
    for step in range(1,node_steps+1):
        count=int(np.ceil(len(nodes)*step/node_steps))
        for i,(n,_) in enumerate(nodes):
            vis=i<count; node_artists[n].set_visible(vis); badge_artists[n].set_visible(vis); label_artists[n].set_visible(vis)
        _show_frame(placeholder,fig)
        if step<node_steps: time.sleep(0.014)

    # Edges: ALL connections grow simultaneously.
    edge_steps=10 if edges else 1
    for step in range(1,edge_steps+1):
        progress=step/edge_steps
        ease=1-(1-progress)**3
        for (u,v,line),rel in zip(edge_artists,relation_artists):
            x1,y1=pos[u]; x2,y2=pos[v]
            line.set_data([x1, x1+(x2-x1)*ease], [y1, y1+(y2-y1)*ease])
            rel.set_visible(progress>0.9 and show_relations)
        _show_frame(placeholder,fig)
        if step<edge_steps: time.sleep(0.014)
    plt.close(fig)


def current_case_indicators():
    return [CaseIndicators(c.case_id, c.parsed.subject, c.indicators) for c in st.session_state.cases]


def refresh_case_risks():
    """Recompute case risk using current cross-case relationships too."""
    cases = current_case_indicators()
    shared = find_shared_infrastructure(cases) if len(cases) >= 2 else {}
    for c in st.session_state.cases:
        other_related = set()
        for ids in shared.values():
            if c.case_id in ids:
                other_related.update(x for x in ids if x != c.case_id)
        c.shared_relationships = len(other_related)
        c.risk = assess_case_risk(
            c.header_findings,
            c.url_analyses,
            c.attachment_findings,
            len(c.qr_findings),
            c.shared_relationships,
        )


set_bg_gif(BASE / "linkmirror_bg.gif")
inject_theme()
st.markdown(
    '<div class="header"><span style="font-size:38px">🪞</span> <span class="title">LinkMirror X Forensics</span><br>'
    '<span class="sub">SIH26106 — AI-assisted email threat investigation, quishing detection, infrastructure correlation & forensic reporting</span></div>',
    unsafe_allow_html=True,
)

if "cases" not in st.session_state:
    st.session_state.cases = []
if "direct_result" not in st.session_state:
    st.session_state.direct_result = None
if "visual_analysis" not in st.session_state:
    st.session_state.visual_analysis = None
if "last_url_score" not in st.session_state:
    st.session_state.last_url_score = None
if "last_img_score" not in st.session_state:
    st.session_state.last_img_score = None
if "last_img_best" not in st.session_state:
    st.session_state.last_img_best = None

main_tabs = st.tabs([
    "🔎 Email Forensics", "🕸 Threat Graph", "📊 Analytics", "🪞 LinkMirror Direct", "🧬 Campaigns", "📄 Reports", "🧭 Sibling Prediction"
])

# -----------------------------------------------------------------------------
# EMAIL FORENSICS
# -----------------------------------------------------------------------------
with main_tabs[0]:
    st.markdown(
        '<div class="hero"><h2>🔎 Email Forensics</h2><div class="muted">Upload an .eml to create a forensic case and automatically pivot through headers, URLs, QR destinations, attachments and infrastructure.</div></div>',
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns([1.1, 1.8, 1])
    with c1:
        load_demo = st.button("📥 Load demo cases", use_container_width=True, disabled=not DEMO_DIR.exists())
    with c2:
        upload = st.file_uploader("Upload .eml", type=["eml"], label_visibility="collapsed", key="eml_upload")
    with c3:
        process = st.button("⬆ Process email", use_container_width=True, disabled=upload is None)
    clear = st.button("🗑 Clear cases", use_container_width=True, disabled=not st.session_state.cases)

    if load_demo:
        st.session_state.cases = []
        for pth in sorted(DEMO_DIR.glob("*.eml")):
            try:
                st.session_state.cases.append(process_email(str(pth), str(REF_DIR), str(CAPTURED_DIR)))
            except Exception as e:
                st.error(f"{pth.name}: {e}")
        refresh_case_risks()
    if process and upload:
        fd, tmp = tempfile.mkstemp(suffix=".eml")
        os.close(fd)
        Path(tmp).write_bytes(upload.getvalue())
        try:
            st.session_state.cases.append(process_email(tmp, str(REF_DIR), str(CAPTURED_DIR)))
            refresh_case_risks()
            st.success(f"Processed {upload.name}")
        except Exception as e:
            st.error(f"Processing failed: {e}")
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if clear:
        st.session_state.cases = []
        st.rerun()

    if not st.session_state.cases:
        st.info("No cases loaded yet. Use the controls above or the demo dataset.")
    else:
        refresh_case_risks()
        total_urls = sum(len(c.indicators.urls) for c in st.session_state.cases)
        total_qr = sum(len(c.indicators.qr_urls) for c in st.session_state.cases)
        total_att = sum(len(c.parsed.attachments) for c in st.session_state.cases)
        cols = st.columns(5)
        stats = [len(st.session_state.cases), total_urls, total_qr, total_att,
                 sum(c.highest_severity in ("critical", "high") for c in st.session_state.cases)]
        for col, label, value in zip(cols, ["Cases", "URLs", "QR URLs", "Attachments", "Critical/High"], stats):
            with col:
                metric(label, value)

        case_idx = st.selectbox(
            "Select forensic case", range(len(st.session_state.cases)),
            format_func=lambda i: f"{st.session_state.cases[i].parsed.subject} — {st.session_state.cases[i].case_id}",
        )
        case = st.session_state.cases[case_idx]
        risk = case.risk.score if case.risk else 0
        level = case.risk.level if case.risk else "pending"
        risk_banner(risk, level, f"{case.parsed.from_address} · Case {case.case_id}")

        etabs = st.tabs(["📋 Investigation", "📈 Case Analytics"])
        with etabs[0]:
            st.markdown('<div class="panel"><div class="section">Evidence Summary</div>', unsafe_allow_html=True)
            st.markdown('<div class="statrow">' + ''.join(
                f'<span class="chip">{html.escape(x)}</span>' for x in [
                    f"Header findings: {len(case.header_findings)}",
                    f"URLs: {len(case.indicators.urls)}",
                    f"QR destinations: {len(case.indicators.qr_urls)}",
                    f"Attachments: {len(case.parsed.attachments)}",
                    f"Related cases: {case.shared_relationships}",
                ]) + '</div></div>', unsafe_allow_html=True)

            st.markdown('<div class="section">Detailed Findings</div>', unsafe_allow_html=True)
            subtabs = st.tabs(["Identity & Headers", "URLs + QR", "Attachments", "Infrastructure", "Attack Path", "🧭 Origin Trace"])
            with subtabs[0]:
                a, b = st.columns(2)
                with a:
                    st.write("**From:**", case.parsed.from_address or "Unknown")
                    st.write("**Display name:**", case.parsed.from_display_name or "Unknown")
                    st.write("**Reply-To:**", case.parsed.reply_to or "(none)")
                with b:
                    st.write("**Return-Path:**", case.parsed.return_path or "(none)")
                    st.write("**Date:**", case.parsed.date or "Unknown")
                    st.write("**Message-ID:**", case.parsed.message_id or "Unknown")
                for f in case.header_findings:
                    cc = SEVERITY_COLOR.get(f.severity, "#2979FF")
                    st.markdown(f'<div class="finding" style="border-left-color:{cc}"><b>{html.escape(f.severity.upper())}</b> · {html.escape(f.message)}</div>', unsafe_allow_html=True)
                if not case.header_findings:
                    st.info("No header anomalies detected.")
            with subtabs[1]:
                for q in case.qr_findings:
                    st.markdown(f'<div class="finding"><b>QR destination</b> · {html.escape(q.decoded)}</div>', unsafe_allow_html=True)
                for ua in case.url_analyses:
                    st.markdown(f"**{html.escape(ua.source)}** · `{html.escape(ua.url)}` · LinkMirror trust `{ua.result.url_score}/100` · fused `{ua.result.fused:.1f}/100`")
                if not case.indicators.urls:
                    st.info("No URLs or QR destinations detected.")
            with subtabs[2]:
                if not case.parsed.attachments:
                    st.info("No attachments detected.")
                for att in case.parsed.attachments:
                    findings = case.attachment_findings.get(att.sha256, [])
                    st.markdown(f'<div class="finding"><b>{html.escape(att.filename)}</b><br><span class="muted">SHA-256: {html.escape(att.sha256)}</span></div>', unsafe_allow_html=True)
                    for f in findings:
                        cc = SEVERITY_COLOR.get(f.severity, "#2979FF")
                        st.markdown(f'<div class="finding" style="border-left-color:{cc}"><b>{f.severity.upper()}</b> · {html.escape(f.message)}</div>', unsafe_allow_html=True)
            with subtabs[3]:
                for ip in case.indicators.ips:
                    intel = lookup_ip(ip)
                    note = " · synthetic demo" if intel.is_demo else ""
                    st.markdown(f"**{ip}** — {intel.org} · {intel.country}{note}")
                st.write("**Domains:**", case.indicators.domains or "none")
            with subtabs[4]:
                steps = build_attack_path(case)
                chunks = []
                for i, step in enumerate(steps):
                    chunks.append(f'<div class="step"><b>{html.escape(step["stage"])}</b><br>{html.escape(step["label"])}<br><span class="muted">{html.escape(step["evidence"])}</span></div>')
                    if i < len(steps)-1:
                        chunks.append('<div class="arrow">→</div>')
                st.markdown('<div class="path">' + ''.join(chunks) + '</div>', unsafe_allow_html=True)

            with subtabs[5]:
                ot = case.origin_trace
                if not ot:
                    st.info("OriginTrace analysis not available for this case.")
                else:
                    top = ot.hypotheses[0]
                    m1, m2, m3 = st.columns(3)
                    with m1: metric("Threat risk", f"{ot.threat_risk}/100")
                    with m2: metric("Probable origin", top.label)
                    with m3: metric("Origin confidence", f"{ot.origin_confidence}/100")

                    if ot.earliest_reliable_node.hop:
                        h = ot.earliest_reliable_node.hop
                        st.markdown(
                            f'<div class="panel"><h3>📍 Earliest Reliable Node</h3>'
                            f'<b>Hop {h.index}</b> — {html.escape(h.from_host or "unknown host")} '
                            f'({html.escape(h.from_ip or "no IP")}) &nbsp; confidence {ot.earliest_reliable_node.confidence}/100'
                            f'<br><span class="muted">{html.escape(ot.earliest_reliable_node.note)}</span></div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.info("No relay hops available — earliest reliable node cannot be determined.")

                    st.markdown('<div class="section">Relay Journey</div>', unsafe_allow_html=True)
                    if not ot.hops:
                        st.info("No Received headers were present — relay journey could not be reconstructed.")
                    else:
                        chunks = []
                        for i, h in enumerate(ot.hops):
                            cc = "#66bb6a" if h.trust_score >= 60 else ("#ffa726" if h.trust_score >= 35 else "#ef5350")
                            chunks.append(
                                f'<div class="step" style="border-left:3px solid {cc}"><b>Hop {h.index}</b><br>'
                                f'{html.escape(h.from_host or h.from_ip or "unknown")}<br>'
                                f'<span class="muted">trust {h.trust_score}/100</span></div>'
                            )
                            if i < len(ot.hops) - 1:
                                chunks.append('<div class="arrow">→</div>')
                        st.markdown('<div class="path">' + ''.join(chunks) + '</div>', unsafe_allow_html=True)

                        labels = [f"Hop {h.index}" for h in ot.hops]
                        vals = [float(h.trust_score) for h in ot.hops]
                        animated_bar_chart(labels, vals, "Trust score per hop", "Trust", key=f"origintrace-hops-{case.case_id}")

                    st.markdown('<div class="section">Provenance Breakpoint</div>', unsafe_allow_html=True)
                    if ot.breakpoint.detected:
                        st.markdown(
                            f'<div class="finding" style="border-left-color:#ef5350;">'
                            f'<b>Trust drop detected:</b> {ot.breakpoint.trust_before}/100 → {ot.breakpoint.trust_after}/100 '
                            f'between hop {ot.breakpoint.hop_before.index} and hop {ot.breakpoint.hop_after.index} '
                            f'(confidence {ot.breakpoint.confidence}/100)'
                            f'<br><span class="muted">{"; ".join(html.escape(e) for e in ot.breakpoint.evidence)}</span></div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.info("No sharp provenance breakpoint detected — trust degrades gradually or stays consistent across the chain.")

                    st.markdown('<div class="section">Origin Hypotheses</div>', unsafe_allow_html=True)
                    for h in ot.hypotheses:
                        cc = "#ef5350" if h.confidence >= 50 else ("#ffa726" if h.confidence >= 25 else "#66bb6a")
                        st.markdown(f'<div class="finding" style="border-left-color:{cc}"><b>{html.escape(h.label)}</b> — {h.confidence}/100</div>', unsafe_allow_html=True)
                        with st.expander(f"Evidence for/against: {h.label}"):
                            if h.supporting_evidence:
                                st.markdown("**Supporting:**")
                                for s in h.supporting_evidence:
                                    st.write("•", s)
                            if h.contradicting_evidence:
                                st.markdown("**Contradicting:**")
                                for c in h.contradicting_evidence:
                                    st.write("•", c)
                            if not h.supporting_evidence and not h.contradicting_evidence:
                                st.caption("No specific evidence found for or against this hypothesis in this case.")

                    with st.expander("📖 Full evidence chain & limitations"):
                        st.markdown("**Evidence chain (every conclusion traced to its source):**")
                        for e in ot.evidence_chain:
                            st.write("•", e)
                        st.markdown("**Limitations:**")
                        for lim in ot.limitations:
                            st.write("•", lim)

                    st.markdown('<div class="section">AI Explanation</div>', unsafe_allow_html=True)
                    st.info(explain_result(ot))

        with etabs[1]:
            cols = st.columns([1, 1])
            with cols[0]:
                st.markdown("#### Case risk")
                animated_pie(risk, title="Case Risk", size=2.8, risk=True)
            with cols[1]:
                animated_severity_breakdown(case.header_findings, key=f"detail-header-severity-{case.case_id}")
            if case.url_analyses:
                labels = [f"URL {i+1}" for i in range(len(case.url_analyses))]
                vals = [u.result.fused for u in case.url_analyses]
                animated_bar_chart(labels, vals, "Fused trust score per URL (lower = more suspicious)", "Score", key=f"detail-url-score-{case.case_id}")
            if case.risk and case.risk.evidence:
                st.markdown("#### Top risk evidence")
                for ev in case.risk.evidence[:6]:
                    st.write(f"• **{ev.category}** — {ev.message}")

# -----------------------------------------------------------------------------
# RESTORED DEDICATED THREAT GRAPH
# -----------------------------------------------------------------------------
with main_tabs[1]:
    st.markdown('<div class="hero"><h2>🕸 Threat Correlation Graph</h2><div class="muted">Dedicated relationship view restored from the original prototype. Connected components, shared infrastructure and cross-case relationships are visualized separately from case details.</div></div>', unsafe_allow_html=True)
    if not st.session_state.cases:
        st.info("Load cases from Email Forensics to build the threat graph.")
    else:
        refresh_case_risks()
        inds = current_case_indicators()
        shared = find_shared_infrastructure(inds)
        graph = build_threat_graph(inds)
        st.markdown('<div class="section">Threat graph</div>', unsafe_allow_html=True)
        animated_threat_graph(graph, key="dedicated-threat-graph")
        if not shared:
            st.markdown('<div class="panel">No shared infrastructure found across the currently loaded cases.</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="panel" style="border-left:4px solid #ef5350;"><b>Found {len(shared)} shared indicator(s)</b> across multiple cases — possible campaign relationships.</div>', unsafe_allow_html=True)
            for indicator, case_ids in shared.items():
                labels = [c.parsed.subject for c in st.session_state.cases if c.case_id in case_ids]
                st.markdown(f"**{html.escape(indicator)}**")
                st.write(" ↳ ".join(labels))

# -----------------------------------------------------------------------------
# RESTORED ORIGINAL-STYLE ANALYTICS
# -----------------------------------------------------------------------------
with main_tabs[2]:
    st.markdown('<div class="hero"><h2>📊 Investigation Analytics</h2><div class="muted">Restored score and severity visualizations from the original prototype, extended with the new case-level risk engine.</div></div>', unsafe_allow_html=True)
    if not st.session_state.cases:
        st.info("Load cases from Email Forensics to populate analytics.")
    else:
        refresh_case_risks()
        st.markdown("### Fused trust score by case")
        case_labels = [c.case_id for c in st.session_state.cases]
        case_scores = [max((ua.result.fused for ua in c.url_analyses), default=0) for c in st.session_state.cases]
        animated_bar_chart(case_labels, case_scores, "Fused trust score by case (lower = more suspicious)", "Score", key="case-risk-bar")

        selected = st.selectbox("Select case for detailed analytics", range(len(st.session_state.cases)), format_func=lambda i: f"{st.session_state.cases[i].parsed.subject} ({st.session_state.cases[i].case_id})", key="analytics_case")
        c = st.session_state.cases[selected]
        left, right = st.columns(2)
        with left:
            st.markdown("### Header finding severity")
            animated_severity_breakdown(c.header_findings, key="header-severity-bar")
        with right:
            st.markdown("### Fused score per URL")
            if c.url_analyses:
                labs = [f"URL {i+1}" for i in range(len(c.url_analyses))]
                vals = [u.result.fused for u in c.url_analyses]
                animated_bar_chart(labs, vals, "Fused score per URL (lower = more suspicious)", "Score", key=f"url-score-bar-{selected}")
            else:
                st.info("No URL analyses available for this case.")

        st.markdown("### Case risk profile")
        rcol1, rcol2 = st.columns([1, 2])
        with rcol1:
            animated_pie(c.risk.score if c.risk else 0, title="Case Risk", size=2.9, risk=True, key=f"case-risk-{c.case_id}")
        with rcol2:
            if c.risk and c.risk.evidence:
                for ev in c.risk.evidence[:8]:
                    st.write(f"• **{ev.category}** — {ev.message}")
            else:
                st.info("No risk evidence available.")

# -----------------------------------------------------------------------------
# LINKMIRROR DIRECT — ORIGINAL FEATURES RESTORED + NEW STRICT URL MODE
# -----------------------------------------------------------------------------
with main_tabs[3]:
    st.markdown('<div class="hero"><h2>🪞 LinkMirror Direct Analysis</h2><div class="muted">Standalone LinkMirror mode. The original URL, screenshot and fusion workflow are preserved, with the stricter URL engine and improved visual comparison.</div></div>', unsafe_allow_html=True)
    direct_tabs = st.tabs(["🔗 URL Intelligence", "📸 Screenshot / Visual Analysis", "🧩 Fusion & Verdict"])

    with direct_tabs[0]:
        st.markdown('<div class="panel"><h3>🔗 URL Mode</h3><p class="muted">Strict URL intelligence checks structural deception, obfuscation, suspicious lexical patterns, risky TLDs, domain age and lookalike behavior.</p></div>', unsafe_allow_html=True)
        url = st.text_input("Suspicious URL", placeholder="https://example.com/login", key="standalone_url")
        if st.button("Analyze URL", type="primary", use_container_width=True, disabled=not url, key="analyze_url_only"):
            st.session_state.direct_result = analyze_standalone_url(url, None, str(REF_DIR))
            st.session_state.last_url_score = st.session_state.direct_result.url_score
        result = st.session_state.direct_result
        if result and result.url == url:
            cols = st.columns(3)
            with cols[0]: metric("URL trust", f"{result.url_score}/100")
            with cols[1]: metric("Visual evidence", "Not supplied")
            with cols[2]: metric("Fused trust", f"{result.fused:.1f}/100")
            pcol, rcol = st.columns([1, 2])
            with pcol:
                animated_pie(result.url_score, title="URL Trust", size=2.9, key="direct-url-trust")
            with rcol:
                st.markdown("### URL findings")
                for reason in result.url_reasons:
                    st.write("•", reason)

    with direct_tabs[1]:
        visual_url = st.text_input("URL associated with screenshot", placeholder="https://example.com/login", key="visual_url")
        shot = st.file_uploader("Upload website screenshot", type=["png", "jpg", "jpeg"], key="standalone_shot")
        if shot:
            image = Image.open(shot).convert("RGB")
            st.markdown("### Submitted image")
            st.image(image, caption="Screenshot supplied for visual impersonation analysis", use_container_width=True)
            if st.button("Analyze Screenshot", type="primary", use_container_width=True, key="visual_analyze"):
                with st.spinner("Computing ORB + ResNet visual similarity..."):
                    best, score, matches = analyze_screenshot_against_refs(image, str(REF_DIR))
                st.session_state.visual_analysis = {"image": image, "best": best, "score": score, "matches": matches, "url": visual_url}
                st.session_state.last_img_score = float(score)
                st.session_state.last_img_best = best
        va = st.session_state.visual_analysis
        if va and (not visual_url or va.get("url") == visual_url):
            if va["best"]:
                st.markdown(f"### Best reference match: `{va['best']}` — **{va['score']:.1f}%**")
                ref_path = REF_DIR / va["best"]
                left, right = st.columns(2)
                with left:
                    st.image(va["image"], caption="Submitted screenshot", use_container_width=True)
                with right:
                    if ref_path.exists():
                        st.image(str(ref_path), caption=f"Closest legitimate reference — {va['best']}", use_container_width=True)
                pcol, mcol = st.columns([1, 1])
                with pcol:
                    animated_pie(va["score"], title="Visual Trust", size=2.9, key="direct-visual-trust")
                with mcol:
                    best_match = va["matches"][0] if va["matches"] else None
                    if best_match:
                        metric("ORB similarity", f"{best_match.orb_similarity*100:.1f}%")
                        metric("ResNet similarity", f"{best_match.resnet_similarity*100:.1f}%" if best_match.resnet_similarity > 0 else "Unavailable")
                        if best_match.fallback_similarity > 0:
                            st.caption(f"Fallback structural similarity: {best_match.fallback_similarity*100:.1f}%")
                st.markdown("#### Top reference matches")
                for m in va["matches"][:6]:
                    st.write(f"• {m.reference_name} — fused {m.score_pct:.1f}% | ORB {m.orb_similarity*100:.1f}% | ResNet {m.resnet_similarity*100:.1f}%")
            else:
                st.warning("No reference matches found. Add legitimate reference screenshots to reference_images/.")
        elif not shot:
            st.info("Upload a screenshot to activate visual comparison and the side-by-side visualization.")

    with direct_tabs[2]:
        url_score = st.session_state.last_url_score
        img_score = st.session_state.last_img_score
        best_ref = st.session_state.last_img_best
        st.markdown('<div class="panel"><h3>🧩 Fusion Mode</h3><p class="muted">Preserves the original adaptive/manual fusion controls while using the stricter URL engine.</p></div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            u_input = st.slider("URL TrustScore", 0, 100, int(url_score) if url_score is not None else 80, key="fusion_url")
        with c2:
            i_input = st.slider("Screenshot TrustScore", 0, 100, int(img_score) if img_score is not None else 85, key="fusion_img")
        st.markdown("#### Tuning thresholds")
        v_high = st.slider("Visual High Threshold", 70, 95, 85, key="fusion_vhigh")
        v_mid = st.slider("Visual Mid Threshold", 30, 70, 60, key="fusion_vmid")
        url_weight = st.slider("Manual URL weight", 0, 100, 50, key="fusion_weight")
        fused_adaptive = fused_score(u_input, i_input)
        manual_fused = round((url_weight/100.0)*u_input + (1-url_weight/100.0)*i_input, 2)
        p1, p2 = st.columns(2)
        with p1:
            st.markdown("**Adaptive fusion**")
            animated_pie(fused_adaptive, title="Adaptive", size=2.7)
        with p2:
            st.markdown("**Manual weighted fusion**")
            animated_pie(manual_fused, title="Manual", size=2.7)
        st.markdown("#### Component scores")
        st.write(f"• URL TrustScore: **{u_input}**")
        st.write(f"• Screenshot TrustScore: **{i_input}**")
        verdict_text, color, reasons = decide_trust(u_input, i_input if img_score is not None else -1, best_ref_name=best_ref, v_high=v_high, v_mid=v_mid)
        color_hex = VERDICT_COLOR_MAP.get(color, "#1976d2")
        st.markdown(f'<div class="finding" style="border-left-color:{color_hex};background:{color_hex};color:white;"><b>{html.escape(verdict_text)}</b></div>', unsafe_allow_html=True)
        st.markdown("#### Decision rationale")
        for reason in reasons:
            st.write("•", reason)

# -----------------------------------------------------------------------------
# CAMPAIGNS
# -----------------------------------------------------------------------------
with main_tabs[4]:
    if not st.session_state.cases:
        st.info("Load cases from Email Forensics to build campaign intelligence.")
    else:
        refresh_case_risks()
        inds = current_case_indicators()
        dna = build_campaign_dna(inds)
        st.markdown(
            f'<div class="hero"><h2>🧬 Campaign DNA</h2><div class="muted">{html.escape(dna.summary)}</div><h3>{dna.campaign_score}/100 campaign confidence</h3></div>',
            unsafe_allow_html=True,
        )
        if dna.shared_indicators:
            for indicator, ids in dna.shared_indicators.items():
                labels = [next((c.parsed.subject for c in st.session_state.cases if c.case_id == cid), cid) for cid in ids]
                st.markdown(f"**{html.escape(indicator)}**")
                st.write(" ↳ ".join(labels))
        else:
            st.info("No cross-case campaign cluster identified yet.")
        st.markdown("### Attack-path examples")
        selected = st.selectbox("Select case", range(len(st.session_state.cases)), format_func=lambda i: st.session_state.cases[i].case_id, key="campaign_path_case")
        steps = build_attack_path(st.session_state.cases[selected])
        chunks = []
        for i, step in enumerate(steps):
            chunks.append(f'<div class="step"><b>{html.escape(step["stage"])}</b><br>{html.escape(step["label"])}</div>')
            if i < len(steps)-1:
                chunks.append('<div class="arrow">→</div>')
        st.markdown('<div class="path">' + ''.join(chunks) + '</div>', unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# REPORTS
# -----------------------------------------------------------------------------
with main_tabs[5]:
    if not st.session_state.cases:
        st.info("Load a case from Email Forensics to generate a report.")
    else:
        refresh_case_risks()
        idx = st.selectbox("Report case", range(len(st.session_state.cases)), format_func=lambda i: st.session_state.cases[i].case_id, key="report_case")
        case = st.session_state.cases[idx]
        shared = find_shared_infrastructure(current_case_indicators())
        related = set()
        for ids in shared.values():
            if case.case_id in ids:
                related.update(i for i in ids if i != case.case_id)
        related_subjects = [c.parsed.subject for c in st.session_state.cases if c.case_id in related]
        report = generate_case_report(case, related_subjects or None)
        st.download_button("⬇ Download forensic report (.md)", report, file_name=f"forensic_report_{case.case_id}.md", mime="text/markdown")
        st.markdown("### Report Preview")
        st.code(report, language="markdown")

# -----------------------------------------------------------------------------
# SIBLING PREDICTION — proactive typosquat / campaign-sibling forecasting
# -----------------------------------------------------------------------------
with main_tabs[6]:
    st.markdown(
        '<div class="hero"><h2>🧭 Sibling Domain Prediction</h2>'
        '<div class="muted">Every other tab is reactive: it judges an email or URL you already fed it. '
        'This tab is proactive — give it ONE confirmed-malicious domain and it predicts the other domains '
        'the same attacker likely also registered for the same campaign, before they show up in a new inbox.</div></div>',
        unsafe_allow_html=True,
    )

    known_domains = sorted({d for c in st.session_state.cases for d in c.indicators.domains})

    col1, col2 = st.columns([2, 1])
    with col1:
        seed_default = known_domains[0] if known_domains else "hdfc-secure-verify.com"
        seed_domain = st.text_input(
            "Confirmed-malicious domain",
            value=seed_default,
            placeholder="hdfc-secure-verify.com",
            key="sibling_seed",
        )
    with col2:
        brand = st.text_input("Brand being impersonated (optional)", placeholder="hdfc", key="sibling_brand")

    if known_domains:
        st.caption(f"Domains already seen across your {len(st.session_state.cases)} loaded case(s): " + ", ".join(known_domains))

    if st.button("Predict siblings", type="primary", use_container_width=True, disabled=not seed_domain, key="predict_siblings_btn"):
        with st.spinner("Generating and scoring candidate sibling domains..."):
            results = predict_siblings(seed_domain, brand_keyword=brand or None, known_domains=known_domains, top_n=12)
        st.session_state.sibling_results = {"seed": seed_domain, "results": results}

    payload = st.session_state.get("sibling_results")
    if payload and payload["seed"] == seed_domain:
        results = payload["results"]
        if not results:
            st.info("No candidate siblings generated for this domain.")
        else:
            st.markdown(f"### {len(results)} predicted sibling(s) for `{html.escape(seed_domain)}`")
            for cand in results:
                is_confirmed = any("Already observed" in r for r in cand.reasons)
                border = "#ef5350" if is_confirmed else ("#ffa726" if cand.similarity >= 60 else "#66bb6a")
                badge = "🔴 CONFIRMED IN CASES" if is_confirmed else ("🟠 HIGH RISK" if cand.similarity >= 60 else "🟢 LOWER RISK")
                st.markdown(
                    f'<div class="finding" style="border-left-color:{border};">'
                    f'<b>{html.escape(cand.domain)}</b> — {cand.similarity:.1f}/100 &nbsp; <i>{badge}</i>'
                    f'<br><span class="muted">{html.escape("; ".join(cand.reasons))}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            st.caption(
                "Structural heuristic only (character similarity, TLD risk, credential-keyword matching) — "
                "no live registrar lookup in this demo. Pair with Intelligence → domain lookups or a real "
                "WHOIS/registrar API to confirm which of these are actually registered."
            )
    elif not payload:
        st.info("Enter a confirmed-malicious domain and click Predict siblings.")

