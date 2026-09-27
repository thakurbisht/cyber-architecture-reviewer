"""DFD Editor page - review and correct the data flow diagram, then approve.

Kept out of app.py (already ~2,400 lines). app.py passes in its shared UI
helpers so this module never imports the running Streamlit script.

The canvas (streamlit-flow / React Flow) handles structure: drag components
between trust-zone columns, draw or delete flows, rename or delete nodes via
right-click. The panel on the right handles properties of the selected
element (protocol, authentication, encryption, kind, data). All state lives
in a src.dfd.DFD; the canvas is rebuilt from it after every change.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import streamlit as st
from streamlit_flow import streamlit_flow
from streamlit_flow.elements import StreamlitFlowEdge, StreamlitFlowNode
from streamlit_flow.state import StreamlitFlowState

from src import dfd as D

KIND_COLOUR = {
    "external_party": "#94A3B8", "user_group": "#94A3B8", "service": "#22D3EE",
    "datastore": "#A78BFA", "identity": "#34D399", "network": "#60A5FA",
    "llm": "#F472B6", "agent": "#F472B6", "vector_db": "#F472B6",
}
RISK = "#F87171"
SAFE = "#64748B"
SENSITIVE = ("pii", "pci", "phi", "credentials", "financial", "regulated")


# --------------------------------------------------------------------------
# DFD <-> canvas
# --------------------------------------------------------------------------
def _canvas_state(dfd: D.DFD, boundary_only: bool) -> StreamlitFlowState:
    h = D.zone_height(dfd)
    nodes: List[StreamlitFlowNode] = []
    for z in dfd.zones:
        nodes.append(StreamlitFlowNode(
            f"zone:{z}", (D.zone_x(dfd, z), 0),
            {"content": f"**{D.ZONE_LABELS.get(z, z)}**"},
            draggable=False, selectable=False, connectable=False, deletable=False,
            z_index=-1,
            style={"width": f"{D.zone_width(dfd, z)}px", "height": f"{h}px",
                   "background": "rgba(34,211,238,0.05)" if z != "unknown" else "rgba(248,113,113,0.06)",
                   "border": f"1px dashed {'#22D3EE' if z != 'unknown' else RISK}",
                   "color": "#CBD5E1", "textAlign": "left", "fontSize": "13px"}))
    for c in dfd.components:
        colour = KIND_COLOUR.get(c.kind, "#CBD5E1")
        nodes.append(StreamlitFlowNode(
            c.id, (c.x, c.y), {"content": c.name}, node_type="default",
            source_position="right", target_position="left",
            draggable=True, selectable=True, connectable=True, deletable=True, z_index=1,
            style={"width": f"{D.NODE_WIDTH}px", "fontSize": "12px",
                   "border": f"2px {'dashed' if c.source == 'ai' and not c.edited else 'solid'} {colour}",
                   "boxShadow": f"0 0 0 2px {RISK}" if c.public else "none"}))
    edges: List[StreamlitFlowEdge] = []
    for f in dfd.flows:
        if boundary_only and not dfd.crosses_boundary(f):
            continue
        risky = D.flow_risky(dfd, f)
        edges.append(StreamlitFlowEdge(
            f.id, f.source, f.target, label=D.flow_label(f), deletable=True,
            animated=dfd.crosses_boundary(f), label_show_bg=True,
            label_style={"fontSize": "10px"},
            style={"stroke": RISK if risky else SAFE,
                   "strokeWidth": 2 if risky else 1.2},
            marker_end={"type": "arrowclosed"}))
    return StreamlitFlowState(nodes, edges)


def _sync(dfd: D.DFD, state: StreamlitFlowState, boundary_only: bool) -> List[str]:
    nodes = [{"id": n.id, "x": n.position["x"], "y": n.position["y"],
              "label": str(n.data.get("content", ""))}
             for n in state.nodes if not n.id.startswith("zone:")]
    edges = [{"id": e.id, "source": e.source, "target": e.target} for e in state.edges]
    if boundary_only:   # flows hidden by the filter were not on the canvas: keep them
        shown = {e["id"] for e in edges}
        edges += [{"id": f.id, "source": f.source, "target": f.target} for f in dfd.flows
                  if not dfd.crosses_boundary(f) and f.id not in shown]
    return D.sync_from_canvas(dfd, nodes, edges)


def _refresh(key: str) -> None:
    st.session_state[f"{key}_rebuild"] = True


# --------------------------------------------------------------------------
# Draft creation
# --------------------------------------------------------------------------
def _load_or_create(result, get_config: Callable) -> D.DFD | None:
    rk = getattr(result, "review_key", "") or result.document_name
    key = f"dfd::{rk}"
    if key in st.session_state:
        return st.session_state[key]
    saved = D.load_latest(rk)
    if saved is not None:
        st.session_state[key] = saved
        return saved
    if getattr(result, "system_model", None):
        dfd = D.from_system_model(result.system_model, rk)
        D.save_draft(dfd)
        st.session_state[key] = dfd
        return dfd

    st.info("No DFD yet for this document. Generate a draft from the document with the "
            "local model, or start from a blank canvas.")
    c1, c2 = st.columns(2)
    if c1.button("Generate draft DFD (local AI, ~2–5 min)", type="primary", width="stretch"):
        from src.system_model import build_extractor_llm, extract_system_model
        with st.spinner("Extracting components, zones and flows…"):
            model = extract_system_model(result.sections, build_extractor_llm(get_config()),
                                         result.document_name)
        result.system_model = model.to_dict()
        dfd = D.from_system_model(result.system_model, rk)
        D.save_draft(dfd)
        st.session_state[key] = dfd
        st.rerun()
    if c2.button("Start blank", width="stretch"):
        dfd = D.DFD(document=rk)
        D.save_draft(dfd)
        st.session_state[key] = dfd
        st.rerun()
    return None


# --------------------------------------------------------------------------
# Page
# --------------------------------------------------------------------------
def render(result, *, section_header: Callable, empty_state: Callable,
           html_block: Callable, esc: Callable, get_config: Callable) -> None:
    if not result:
        empty_state("DFD editor")
        return
    section_header("DFD editor", f"Data flow diagram · {esc(result.document_name)}",
                   "Drag components between trust zones, draw or delete flows, and set "
                   "each flow's protocol, authentication and encryption. Threat modeling "
                   "runs only on an approved version.")
    dfd = _load_or_create(result, get_config)
    if dfd is None:
        return
    ckey = f"canvas::{getattr(result, "review_key", "") or result.document_name}"

    status = ("🟢 Approved v%d" % dfd.version) if dfd.status == "approved" else (
        "🟡 Draft" + (f" (last approved v{dfd.version})" if dfd.version else ""))
    bf = dfd.boundary_flows()
    st.caption(f"{status} · {len(dfd.components)} components · {len(dfd.flows)} flows · "
               f"{len(bf)} cross a trust boundary · dashed border = AI draft, not yet edited · "
               f"red = boundary flow with missing auth/encryption")
    for w in dfd.warnings():
        st.warning(w, icon="⚠️")

    t1, t2, t3 = st.columns([1.2, 1.4, 1.4])
    boundary_only = t1.toggle("Boundary-crossing flows only", value=len(dfd.flows) > 20,
                              key=f"{ckey}_bonly")
    with t2.popover("➕ Component", width="stretch"):
        with st.form(f"{ckey}_addc", clear_on_submit=True, border=False):
            name = st.text_input("Name")
            kind = st.selectbox("Kind", D.KINDS)
            zone = st.selectbox("Zone", D.ZONE_ORDER, format_func=lambda z: D.ZONE_LABELS[z])
            if st.form_submit_button("Add", type="primary") and name.strip():
                D.add_component(dfd, name, kind, zone)
                D.save_draft(dfd)
                _refresh(ckey)
                st.rerun()
    with t3.popover("➕ Trust zone", width="stretch"):
        missing = [z for z in D.ZONE_ORDER if z not in dfd.zones]
        if missing:
            z = st.selectbox("Zone", missing, format_func=lambda z: D.ZONE_LABELS[z])
            if st.button("Add zone", type="primary"):
                D.add_zone(dfd, z)
                D.save_draft(dfd)
                _refresh(ckey)
                st.rerun()
        else:
            st.caption("All zones are on the canvas.")

    if (ckey not in st.session_state or st.session_state.pop(f"{ckey}_rebuild", False)
            or st.session_state.get(f"{ckey}_bonly_prev") != boundary_only):
        st.session_state[ckey] = _canvas_state(dfd, boundary_only)
    st.session_state[f"{ckey}_bonly_prev"] = boundary_only

    left, right = st.columns([3, 1.15])
    with left:
        state = streamlit_flow(
            f"flow_{ckey}", st.session_state[ckey], height=min(640, max(460, int(D.zone_height(dfd)) + 40)),
            fit_view=True, allow_new_edges=True, animate_new_edges=False,
            enable_node_menu=True, enable_edge_menu=True, enable_pane_menu=False,
            get_node_on_click=True, get_edge_on_click=True, show_minimap=False,
            show_controls=True, hide_watermark=True, min_zoom=0.2)
        st.session_state[ckey] = state
        changes = _sync(dfd, state, boundary_only)
        if changes:
            D.save_draft(dfd)
            for c in changes[:4]:
                st.toast(c)
            _refresh(ckey)
            st.rerun()
    with right:
        _properties(dfd, state.selected_id, ckey)
    _approval(dfd, ckey)


def _properties(dfd: D.DFD, selected: str | None, ckey: str) -> None:
    st.markdown("**Properties**")
    f = dfd.flow(selected) if selected else None
    c = dfd.component(selected) if selected else None
    if not f and not c:
        st.caption("Click a component or a flow to edit it. Right-click for rename/delete. "
                   "Drag from a component's right handle to another's left handle to add a flow.")
        return
    if f:
        src, tgt = dfd.component(f.source), dfd.component(f.target)
        st.caption(f"Flow · {src.name if src else f.source} → {tgt.name if tgt else f.target}"
                   + (" · crosses a trust boundary" if dfd.crosses_boundary(f) else ""))
        with st.form(f"{ckey}_flow_{f.id}", border=False):
            protocol = st.text_input("Protocol / port", value=f.protocol, placeholder="HTTPS 443")
            auth = st.selectbox("Authentication", D.AUTH, index=D.AUTH.index(f.auth))
            enc = st.selectbox("Encrypted in transit", D.ENCRYPTED, index=D.ENCRYPTED.index(f.encrypted))
            if st.form_submit_button("Apply", type="primary", width="stretch"):
                f.protocol, f.auth, f.encrypted, f.edited = protocol.strip(), auth, enc, True
                dfd.mark_edited()
                D.save_draft(dfd)
                _refresh(ckey)
                st.rerun()
        st.caption(f"Source: {f.source_tag}" + (" · edited" if f.edited else ""))
        if f.evidence:
            st.caption(f"Evidence: “{f.evidence[:220]}”")
        return
    st.caption(f"Component · zone {D.ZONE_LABELS.get(c.zone, c.zone)}")
    with st.form(f"{ckey}_comp_{c.id}", border=False):
        name = st.text_input("Name", value=c.name)
        kind = st.selectbox("Kind", D.KINDS, index=D.KINDS.index(c.kind) if c.kind in D.KINDS else 0)
        zone = st.selectbox("Trust zone", D.ZONE_ORDER, index=D.ZONE_ORDER.index(c.zone),
                            format_func=lambda z: D.ZONE_LABELS[z])
        public = st.checkbox("Publicly reachable", value=c.public)
        data = st.multiselect("Sensitive data", SENSITIVE, default=[d for d in c.data if d in SENSITIVE])
        if st.form_submit_button("Apply", type="primary", width="stretch"):
            moved = zone != c.zone
            c.name, c.kind, c.public, c.data, c.edited = name.strip() or c.name, kind, public, data, True
            if moved:
                D.add_zone(dfd, zone)
                c.zone = zone
                D.layout(dfd)
            dfd.mark_edited()
            D.save_draft(dfd)
            _refresh(ckey)
            st.rerun()
    st.caption(f"Source: {c.source}" + (" · edited" if c.edited else ""))
    if c.evidence:
        st.caption(f"Evidence: “{c.evidence[:220]}”")


def _approval(dfd: D.DFD, ckey: str) -> None:
    st.divider()
    st.markdown("**Approve for threat modeling**")
    suggested = "Both" if dfd.has_ai_components() else "STRIDE"
    a1, a2, a3 = st.columns([1.3, 1.3, 1])
    framework = a1.radio("Framework", ("STRIDE", "MAESTRO", "Both"),
                         index=("STRIDE", "MAESTRO", "Both").index(suggested), horizontal=True,
                         key=f"{ckey}_fw",
                         help="Suggested from the DFD: 'Both' when it contains LLM, agent or "
                              "vector-DB components, otherwise STRIDE.")
    if framework == "MAESTRO" and not dfd.has_ai_components():
        a1.caption("⚠️ No AI components in this DFD — MAESTRO results will be thin.")
    reviewer = a2.text_input("Approved by", value=st.session_state.get("reviewer_name", ""),
                             key=f"{ckey}_rev")
    note = a2.text_input("Note (optional)", key=f"{ckey}_note")
    unknowns = len(dfd.warnings())
    disabled = dfd.status == "approved" or not dfd.components
    label = "Approved ✓" if dfd.status == "approved" else (
        f"Approve with {unknowns} warning(s)" if unknowns else "Approve DFD")
    if a3.button(label, type="primary", disabled=disabled, width="stretch", key=f"{ckey}_approve"):
        if not reviewer.strip():
            a3.error("Enter who is approving.")
            return
        st.session_state.reviewer_name = reviewer
        dfd.approve(reviewer, note + (f" [approved with {unknowns} open warning(s)]" if unknowns else ""))
        D.save_approved(dfd)
        st.session_state[f"threat_framework::{dfd.document}"] = framework
        st.toast(f"DFD v{dfd.version} approved")
        st.rerun()
    versions = D.list_versions(dfd.document)
    if versions:
        a3.caption("Versions: " + ", ".join(f"v{v}" for v, _ in versions))
    if dfd.status == "approved":
        st.success(f"Approved v{dfd.version} by {dfd.approved_by}. The threat model "
                   f"({st.session_state.get(f'threat_framework::{dfd.document}', framework)}) "
                   "is ready — open the **Threats** page to run it.")
