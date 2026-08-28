"""
Cyber Architecture Reviewer - Streamlit UI

The UI layer only orchestrates:
    Document -> Parser -> Guardrail -> Checkpoint -> ReviewAgent -> Result

Review logic remains inside src/.
"""

from __future__ import annotations

import hashlib
import json
import sys
import textwrap
import time
from pathlib import Path

import streamlit as st


# ============================================================================
# PROJECT PATH
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# INTERNAL IMPORTS
# ============================================================================

from src.agent import ReviewAgent
from src.architecture_flow import (
    Component,
    ComponentType,
    Connection,
    enrich_flow_with_risks,
    extract_components_from_sections,
)
from src.config import load_config
from src.domains import DOMAIN_LABELS
from src.guardrail import assess_scope
from src.llm import check_ollama
from src.models import SEVERITIES
from src.parser import (
    SUPPORTED_SUFFIXES,
    parse_document,
    parse_text,
    summarise_sections,
)
from src.report import save_outputs
from src.retriever import KnowledgeBase
from src.rules import rules_summary


# ============================================================================
# PAGE CONFIG
# ============================================================================

st.set_page_config(
    page_title="Cyber Architecture Reviewer",
    page_icon="ðŸ›¡ï¸",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================================
# CONSTANTS
# ============================================================================

SEV_COLOUR = {
    "CRITICAL": "#ff4d67",
    "HIGH": "#ff9f43",
    "MEDIUM": "#feca57",
    "LOW": "#54a0ff",
}

RAG_COLOUR = {
    "RED": "#ff4757",
    "AMBER": "#ffa502",
    "GREEN": "#2ed573",
}

RISK_ICON = {
    "critical": "ðŸ”´",
    "high": "ðŸŸ ",
    "medium": "ðŸŸ¡",
    "low": "ðŸŸ¢",
}

COMPONENT_ICONS = {
    "service": "âš™ï¸",
    "database": "ðŸ—„ï¸",
    "cache": "âš¡",
    "queue": "ðŸ“¨",
    "api_gateway": "ðŸŒ",
    "external": "â˜ï¸",
    "storage": "ðŸ’¾",
    "user": "ðŸ‘¤",
}


# ============================================================================
# CSS
# ============================================================================

def load_custom_css() -> None:
    """
    Load project theme from assets/theme.css and add a few application-level
    styles on top.
    """

    css_file = PROJECT_ROOT / "assets" / "theme.css"

    if css_file.exists():
        try:
            css = css_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )
            st.markdown(
                f"<style>{css}</style>",
                unsafe_allow_html=True,
            )
        except Exception:
            pass

    st.markdown(
        "\n".join(line.strip() for line in textwrap.dedent("""
        <style>

        /* ============================================================
           GLOBAL
        ============================================================ */

        .stApp {
            background:
                radial-gradient(
                    circle at 10% 0%,
                    rgba(50, 90, 160, 0.10),
                    transparent 30%
                ),
                radial-gradient(
                    circle at 90% 10%,
                    rgba(100, 50, 160, 0.08),
                    transparent 30%
                );
        }

        .block-container {
            padding-top: 1.8rem;
            padding-bottom: 4rem;
            max-width: 1500px;
        }

        /* ============================================================
           HERO
        ============================================================ */

        .hero {
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(120, 150, 190, 0.18);
            border-radius: 22px;
            padding: 30px 34px;
            margin-bottom: 25px;

            background:
                linear-gradient(
                    135deg,
                    rgba(16, 24, 40, 0.98),
                    rgba(20, 31, 55, 0.94)
                );

            box-shadow:
                0 18px 60px rgba(0, 0, 0, 0.25);
        }

        .hero:before {
            content: "";
            position: absolute;
            width: 280px;
            height: 280px;
            right: -90px;
            top: -100px;
            border-radius: 50%;
            background: rgba(75, 120, 255, 0.16);
            filter: blur(5px);
        }

        .hero-title {
            font-size: 38px;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin: 0;
            color: #f8fafc;
        }

        .hero-subtitle {
            margin-top: 8px;
            font-size: 15px;
            color: #aab8cc;
        }

        .hero-badge {
            display: inline-block;
            padding: 5px 10px;
            margin-bottom: 12px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.1em;
            color: #9fc1ff;
            background: rgba(70, 110, 220, 0.12);
            border: 1px solid rgba(100, 140, 255, 0.25);
        }

        /* ============================================================
           CARDS
        ============================================================ */

        .metric-card {
            border: 1px solid rgba(120, 140, 170, 0.16);
            border-radius: 16px;
            padding: 18px 20px;
            background: rgba(255, 255, 255, 0.025);
            transition:
                transform 180ms ease,
                border-color 180ms ease,
                box-shadow 180ms ease;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: rgba(100, 150, 255, 0.35);
            box-shadow: 0 12px 35px rgba(0, 0, 0, 0.16);
        }

        .metric-label {
            font-size: 11px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.09em;
        }

        .metric-value {
            margin-top: 4px;
            font-size: 28px;
            font-weight: 750;
            color: #f8fafc;
        }

        .component-card {
            min-height: 115px;
            border: 1px solid rgba(120, 140, 170, 0.15);
            border-radius: 14px;
            padding: 15px;
            margin-bottom: 10px;
            background:
                linear-gradient(
                    145deg,
                    rgba(255,255,255,0.035),
                    rgba(255,255,255,0.012)
                );
            transition:
                transform 180ms ease,
                border-color 180ms ease;
        }

        .component-card:hover {
            transform: translateY(-3px);
            border-color: rgba(100, 150, 255, 0.35);
        }

        .component-name {
            font-size: 15px;
            font-weight: 700;
            color: #eef2ff;
        }

        .component-type {
            margin-top: 3px;
            font-size: 11px;
            color: #8291a7;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .component-description {
            margin-top: 8px;
            font-size: 12px;
            color: #9aa8bb;
            line-height: 1.45;
        }

        /* ============================================================
           STATUS
        ============================================================ */

        .status-card {
            border-radius: 18px;
            padding: 18px 22px;
            color: white;
            box-shadow: 0 14px 40px rgba(0, 0, 0, 0.18);
        }

        .status-label {
            font-size: 10px;
            letter-spacing: 0.12em;
            opacity: 0.78;
            font-weight: 700;
        }

        .status-value {
            font-size: 30px;
            font-weight: 800;
            margin-top: 4px;
        }

        .status-score {
            font-size: 12px;
            opacity: 0.85;
        }

        /* ============================================================
           ARCHITECTURE EDITOR
        ============================================================ */

        .editor-header {
            border-radius: 18px;
            padding: 20px 24px;
            margin: 10px 0 18px;

            background:
                linear-gradient(
                    135deg,
                    rgba(24, 35, 58, 0.95),
                    rgba(15, 23, 42, 0.98)
                );

            border: 1px solid rgba(100, 140, 220, 0.2);
        }

        .editor-title {
            font-size: 25px;
            font-weight: 800;
            color: #f8fafc;
        }

        .editor-subtitle {
            font-size: 12px;
            color: #94a3b8;
            margin-top: 5px;
        }

        .flow-pill {
            display: inline-block;
            padding: 5px 9px;
            margin-right: 5px;
            border-radius: 999px;
            background: rgba(100, 140, 255, 0.1);
            border: 1px solid rgba(100, 140, 255, 0.2);
            font-size: 11px;
            color: #9fb9ff;
        }

        /* ============================================================
           SIDEBAR
        ============================================================ */

        [data-testid="stSidebar"] {
            border-right: 1px solid rgba(120, 140, 170, 0.12);
        }

        /* ============================================================
           BUTTONS
        ============================================================ */

        .stButton > button {
            border-radius: 10px;
            font-weight: 650;
            transition:
                transform 150ms ease,
                box-shadow 150ms ease;
        }

        .stButton > button:hover {
            transform: translateY(-1px);
        }

        /* ============================================================
           TABLE
        ============================================================ */

        [data-testid="stDataFrame"] {
            border-radius: 14px;
            overflow: hidden;
        }

        </style>
        """).splitlines()),
        unsafe_allow_html=True,
    )


# ============================================================================
# HERO
# ============================================================================

def render_hero() -> None:
    st.markdown(
        "\n".join(line.strip() for line in textwrap.dedent("""
        <div class="hero">
            <div class="hero-badge">
                CYBERSECURITY Â· ARCHITECTURE ASSURANCE
            </div>

            <div class="hero-title">
                Cyber Architecture Reviewer
            </div>

            <div class="hero-subtitle">
                Evidence-based architecture assurance across
                network, application, security, cloud and data.
            </div>
        </div>
        """).splitlines()),
        unsafe_allow_html=True,
    )


# ============================================================================
# CACHED RESOURCES
# ============================================================================

@st.cache_resource(show_spinner=False)
def get_config():
    return load_config()


@st.cache_resource(show_spinner=False)
def get_kb():
    return KnowledgeBase(get_config())


@st.cache_data(ttl=30, show_spinner=False)
def get_kb_status():
    try:
        return get_kb().status()
    except Exception as exc:
        return {
            "counts": {},
            "total": 0,
            "warnings": [str(exc)],
            "embedding_model": "unknown",
        }


@st.cache_data(ttl=30, show_spinner=False)
def get_ollama_status():
    return check_ollama(get_config())


# ============================================================================
# SESSION STATE
# ============================================================================

def initialise_session_state() -> None:
    defaults = {
        "result": None,
        "checkpoint_approved": False,
        "checkpoint_signature": None,
        "input_signature": None,
        "show_arch_editor": False,
        "architecture_flow_obj": None,
        "architecture_flow": None,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ============================================================================
# INPUT SIGNATURES
# ============================================================================

def make_file_signature(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def make_text_signature(
    text: str,
    document_name: str,
) -> str:
    payload = f"{document_name}\n{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def make_checkpoint_signature(
    input_signature: str,
    domains: list[str],
) -> str:
    domain_string = "|".join(sorted(domains))
    payload = f"{input_signature}|{domain_string}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def reset_for_new_input(
    input_signature: str,
) -> None:

    if st.session_state.input_signature == input_signature:
        return

    st.session_state.input_signature = input_signature
    st.session_state.checkpoint_approved = False
    st.session_state.checkpoint_signature = None
    st.session_state.result = None
    st.session_state.architecture_flow_obj = None
    st.session_state.architecture_flow = None
    st.session_state.show_arch_editor = False


# ============================================================================
# SIDEBAR
# ============================================================================

def render_sidebar() -> list[str]:

    cfg = get_config()

    st.sidebar.markdown(
        """
        <div style="
            font-size:22px;
            font-weight:800;
            margin-bottom:2px;
        ">
            ðŸ›¡ï¸ Reviewer
        </div>

        <div style="
            font-size:11px;
            color:#8b9ab0;
            margin-bottom:20px;
        ">
            LOCAL-FIRST ARCHITECTURE ASSURANCE
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.sidebar.subheader("Review domains")

    selected: list[str] = []

    for key in (
        "network",
        "application",
        "security",
        "cloud_data",
    ):
        default = cfg.raw["domains"].get(key, True)

        if st.sidebar.checkbox(
            DOMAIN_LABELS[key],
            value=default,
            key=f"dom_{key}",
        ):
            selected.append(key)

    st.sidebar.divider()

    st.sidebar.subheader("System status")

    # ------------------------------------------------------------------
    # OLLAMA
    # ------------------------------------------------------------------

    ollama = get_ollama_status()

    if ollama["reachable"]:

        if ollama["missing_models"]:

            st.sidebar.error(
                "Ollama is running but required models are missing."
            )

            st.sidebar.code(
                "\n".join(
                    f"ollama pull {model}"
                    for model in ollama["missing_models"]
                ),
                language="powershell",
            )

        else:

            st.sidebar.success(
                f"Ollama ready Â· {ollama['llm']}"
            )

    else:

        st.sidebar.error("Ollama unreachable")

        st.sidebar.caption(
            ollama.get("error", "")[:200]
        )

        st.sidebar.code(
            "ollama serve",
            language="powershell",
        )

    # ------------------------------------------------------------------
    # KNOWLEDGE BASE
    # ------------------------------------------------------------------

    kb = get_kb_status()
    total = kb.get("total", 0)

    if total:

        st.sidebar.success(
            f"Knowledge base Â· {total} clauses"
        )

    else:

        st.sidebar.error(
            "Knowledge base is empty"
        )

        st.sidebar.code(
            "python scripts/seed_kb.py",
            language="powershell",
        )

    with st.sidebar.expander(
        "Clauses by domain",
        expanded=False,
    ):

        for domain, count in kb.get(
            "counts",
            {},
        ).items():

            st.write(
                f"**{DOMAIN_LABELS.get(domain, domain)}** â€” {count}"
            )

        st.caption(
            f"Embedding model: `{kb.get('embedding_model')}`"
        )

    # ------------------------------------------------------------------
    # RULES
    # ------------------------------------------------------------------

    with st.sidebar.expander(
        "Deterministic rules",
        expanded=False,
    ):

        for domain, count in rules_summary().items():

            st.write(
                f"**{DOMAIN_LABELS.get(domain, domain)}** â€” {count} rules"
            )

        st.caption(
            "Rules execute before the model and provide deterministic findings."
        )

    for warning in kb.get("warnings", []):
        st.sidebar.warning(warning)

    st.sidebar.divider()

    st.sidebar.caption(
        "Read and flag only. This tool has no write access "
        "to any system and does not approve or reject designs."
    )

    return selected


# ============================================================================
# CHECKPOINT
# ============================================================================

def render_checkpoint(
    sections: list,
    domains: list[str],
) -> None:

    st.divider()

    st.subheader("ðŸ” Pre-Flight Checkpoint")

    st.caption(
        "Review the deterministic analysis before crossing "
        "the trust boundary into the AI review layer."
    )

    agent = ReviewAgent(
        config=get_config(),
        kb=get_kb(),
    )

    layer1_findings, kb_counts = agent.get_layer1_findings(
        sections,
        domains,
    )

    # ------------------------------------------------------------------
    # METRICS
    # ------------------------------------------------------------------

    in_scope_count = sum(
        1
        for section in sections
        if section.domain in domains
    )

    kb_total = sum(kb_counts.values())

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "Total Sections",
            len(sections),
        )

    with c2:
        st.metric(
            "In-Scope",
            in_scope_count,
        )

    with c3:
        st.metric(
            "Layer 1 Findings",
            len(layer1_findings),
        )

    with c4:
        st.metric(
            "KB Clauses",
            kb_total,
        )

    # ------------------------------------------------------------------
    # DOMAIN BREAKDOWN
    # ------------------------------------------------------------------

    with st.expander(
        "ðŸ“Š Section Distribution by Domain",
        expanded=False,
    ):

        summary = summarise_sections(sections)

        if domains:

            cols = st.columns(len(domains))

            for col, domain in zip(
                cols,
                sorted(domains),
            ):

                count = summary.get(
                    domain,
                    0,
                )

                col.metric(
                    DOMAIN_LABELS.get(
                        domain,
                        domain,
                    ),
                    count,
                )

    # ------------------------------------------------------------------
    # FINDINGS
    # ------------------------------------------------------------------

    if layer1_findings:

        with st.expander(
            "ðŸš© Layer 1 Findings",
            expanded=True,
        ):

            st.caption(
                f"{len(layer1_findings)} findings from deterministic rules."
            )

            for finding in layer1_findings:

                sev_color = SEV_COLOUR.get(
                    finding.severity,
                    "#777",
                )

                st.markdown(
                    "\n".join(line.strip() for line in textwrap.dedent(f"""
                    <div style="
                        padding:12px 15px;
                        border-left:4px solid {sev_color};
                        margin-bottom:9px;
                        border-radius:0 9px 9px 0;
                        background:rgba(255,255,255,0.025);
                    ">
                        <b>{finding.severity}</b>
                        Â· {finding.section[:60]}
                        <br>
                        <span style="color:#a0aec0;">
                            {finding.issue[:150]}
                        </span>
                    </div>
                    """).splitlines()),
                    unsafe_allow_html=True,
                )

    else:

        st.success(
            "âœ“ No findings from deterministic rules."
        )

    # ------------------------------------------------------------------
    # PIPELINE
    # ------------------------------------------------------------------

    st.write("")
    st.subheader("Pipeline")

    p1, p2, p3, p4, p5 = st.columns(5)

    pipeline = [
        ("01", "Parse", "Complete"),
        ("02", "Classify", "Complete"),
        ("03", "Rules", "Complete"),
        ("04", "AI Review", "Next"),
        ("05", "Assurance", "Next"),
    ]

    for col, item in zip(
        [p1, p2, p3, p4, p5],
        pipeline,
    ):

        number, title, status = item

        col.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">{number}</div>
                <div style="
                    font-size:15px;
                    font-weight:700;
                    margin-top:5px;
                ">
                    {title}
                </div>
                <div style="
                    font-size:11px;
                    color:#8291a7;
                    margin-top:4px;
                ">
                    {status}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.info(
        "**Next:** KB retrieval â†’ AI reasoning â†’ citation verification "
        "â†’ cross-domain consistency â†’ assurance report."
    )


# ============================================================================
# ARCHITECTURE FLOW
# ============================================================================

def get_architecture_flow(
    sections: list,
    findings: list,
):

    if st.session_state.architecture_flow_obj is None:

        flow = extract_components_from_sections(
            sections
        )

        flow = enrich_flow_with_risks(
            flow,
            findings,
        )

        st.session_state.architecture_flow_obj = flow

    return st.session_state.architecture_flow_obj


def render_architecture_flow(
    sections: list,
    findings: list,
) -> None:

    st.markdown(
        "\n".join(line.strip() for line in textwrap.dedent("""
        <div class="editor-header">
            <div class="editor-title">
                ðŸ“ Architecture Flow
            </div>

            <div class="editor-subtitle">
                Auto-extracted architecture topology with risk overlays.
                Modify the model using the interactive editor.
            </div>
        </div>
        """).splitlines()),
        unsafe_allow_html=True,
    )

    flow = get_architecture_flow(
        sections,
        findings,
    )

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    critical = sum(
        1
        for component in flow.components.values()
        if component.risk_level == "critical"
    )

    high = sum(
        1
        for component in flow.components.values()
        if component.risk_level == "high"
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            "\n".join(line.strip() for line in textwrap.dedent(f"""
            <div class="metric-card">
                <div class="metric-label">Components</div>
                <div class="metric-value">
                    {len(flow.components)}
                </div>
            </div>
            """).splitlines()),
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            "\n".join(line.strip() for line in textwrap.dedent(f"""
            <div class="metric-card">
                <div class="metric-label">Connections</div>
                <div class="metric-value">
                    {len(flow.connections)}
                </div>
            </div>
            """).splitlines()),
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            "\n".join(line.strip() for line in textwrap.dedent(f"""
            <div class="metric-card">
                <div class="metric-label">Critical</div>
                <div class="metric-value">
                    {critical}
                </div>
            </div>
            """).splitlines()),
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            "\n".join(line.strip() for line in textwrap.dedent(f"""
            <div class="metric-card">
                <div class="metric-label">High Risk</div>
                <div class="metric-value">
                    {high}
                </div>
            </div>
            """).splitlines()),
            unsafe_allow_html=True,
        )

    st.write("")

    # ------------------------------------------------------------------
    # COMPONENT GRID
    # ------------------------------------------------------------------

    if flow.components:

        st.subheader("Detected Components")

        cols = st.columns(3)

        for index, (
            comp_id,
            component,
        ) in enumerate(flow.components.items()):

            icon = COMPONENT_ICONS.get(
                component.component_type.value,
                "ðŸ“¦",
            )

            risk_icon = RISK_ICON.get(
                component.risk_level,
                "âšª",
            )

            description = (
                component.description
                or "No description available."
            )

            with cols[index % 3]:

                st.markdown(
                    "\n".join(line.strip() for line in textwrap.dedent(f"""
                    <div class="component-card">
                        <div class="component-name">
                            {icon}
                            {risk_icon}
                            {component.name}
                        </div>

                        <div class="component-type">
                            {component.component_type.value}
                        </div>

                        <div class="component-description">
                            {description[:180]}
                        </div>
                    </div>
                    """).splitlines()),
                    unsafe_allow_html=True,
                )

    else:

        st.info(
            "No architecture components were automatically detected."
        )

    # ------------------------------------------------------------------
    # CONNECTION SUMMARY
    # ------------------------------------------------------------------

    if flow.connections:

        with st.expander(
            f"ðŸ”— Data Flows Â· {len(flow.connections)}",
            expanded=False,
        ):

            for connection in flow.connections:

                source = flow.components.get(
                    connection.source_id
                )

                target = flow.components.get(
                    connection.target_id
                )

                if source and target:

                    st.markdown(
                        "\n".join(line.strip() for line in textwrap.dedent(f"""
                        <span class="flow-pill">
                            {source.name}
                        </span>
                        â†’
                        <span class="flow-pill">
                            {target.name}
                        </span>
                        """).splitlines()),
                        unsafe_allow_html=True,
                    )

    # ------------------------------------------------------------------
    # EDITOR BUTTON
    # ------------------------------------------------------------------

    st.write("")

    left, right = st.columns(
        [4, 1]
    )

    with right:

        if st.button(
            "ðŸ“ Open Full Editor",
            type="primary",
            key="arch_editor",
            width="stretch",
        ):

            st.session_state.show_arch_editor = True
            st.rerun()

    # ------------------------------------------------------------------
    # EDITOR
    # ------------------------------------------------------------------

    if not st.session_state.show_arch_editor:
        return

    st.divider()

    st.markdown(
        "\n".join(line.strip() for line in textwrap.dedent("""
        <div class="editor-header">
            <div class="editor-title">
                ðŸ§© Architecture Editor
            </div>

            <div class="editor-subtitle">
                Add components, connect services and maintain
                the architecture model used by the assurance process.
            </div>
        </div>
        """).splitlines()),
        unsafe_allow_html=True,
    )

    editor_col1, editor_col2 = st.columns(
        [0.33, 0.67],
        gap="large",
    )

    # ==================================================================
    # LEFT PANEL
    # ==================================================================

    with editor_col1:

        st.subheader("âž• Add Component")

        comp_type = st.selectbox(
            "Component type",
            [
                "service",
                "database",
                "cache",
                "queue",
                "api_gateway",
                "external",
                "storage",
                "user",
            ],
            format_func=lambda x: x.replace(
                "_",
                " ",
            ).title(),
            key="comp_type_select",
        )

        comp_name = st.text_input(
            "Component name",
            placeholder="e.g. Customer API",
            key="comp_name_input",
        )

        comp_desc = st.text_area(
            "Description",
            placeholder="Describe the component...",
            height=110,
            key="comp_desc_input",
        )

        if st.button(
            "âž• Add Component",
            key="add_comp_btn",
            type="primary",
            width="stretch",
        ):

            if not comp_name.strip():

                st.warning(
                    "Enter a component name."
                )

            else:

                base_id = (
                    comp_type
                    + "_"
                    + str(len(flow.components) + 1)
                )

                comp_id = base_id

                counter = 2

                while comp_id in flow.components:

                    comp_id = (
                        base_id
                        + "_"
                        + str(counter)
                    )

                    counter += 1

                new_component = Component(
                    id=comp_id,
                    name=comp_name.strip(),
                    component_type=ComponentType(
                        comp_type
                    ),
                    description=comp_desc.strip(),
                )

                flow.add_component(
                    new_component
                )

                st.success(
                    f"Added {comp_name.strip()}"
                )

                st.rerun()

        st.divider()

        st.subheader("Components")

        if not flow.components:

            st.caption(
                "No components yet."
            )

        for (
            comp_id,
            component,
        ) in list(flow.components.items()):

            icon = COMPONENT_ICONS.get(
                component.component_type.value,
                "ðŸ“¦",
            )

            col1, col2 = st.columns(
                [5, 1]
            )

            with col1:

                st.markdown(
                    "\n".join(line.strip() for line in textwrap.dedent(f"""
                    **{icon} {component.name}**

                    <span style="
                        color:#8291a7;
                        font-size:11px;
                    ">
                        {component.component_type.value}
                    </span>
                    """).splitlines()),
                    unsafe_allow_html=True,
                )

            with col2:

                if st.button(
                    "ðŸ—‘ï¸",
                    key=f"del_{comp_id}",
                    help=f"Delete {component.name}",
                ):

                    flow.remove_component(
                        comp_id
                    )

                    st.rerun()

    # ==================================================================
    # RIGHT PANEL
    # ==================================================================

    with editor_col2:

        st.subheader("ðŸ”— Data Flows")

        if flow.connections:

            for index, connection in enumerate(
                list(flow.connections)
            ):

                source = flow.components.get(
                    connection.source_id
                )

                target = flow.components.get(
                    connection.target_id
                )

                if not source or not target:
                    continue

                col1, col2 = st.columns(
                    [8, 1]
                )

                with col1:

                    st.markdown(
                        "\n".join(line.strip() for line in textwrap.dedent(f"""
                        <div class="component-card"
                             style="min-height:0;">
                            <b>
                                {source.name}
                            </b>
                            <span style="
                                color:#718096;
                                margin:0 8px;
                            ">
                                â†’
                            </span>
                            <b>
                                {target.name}
                            </b>

                            <div style="
                                font-size:11px;
                                color:#718096;
                                margin-top:4px;
                            ">
                                {connection.label or "data flow"}
                            </div>
                        </div>
                        """).splitlines()),
                        unsafe_allow_html=True,
                    )

                with col2:

                    if st.button(
                        "ðŸ—‘ï¸",
                        key=f"del_conn_{index}",
                    ):

                        flow.connections.pop(
                            index
                        )

                        st.rerun()

        else:

            st.info(
                "No connections yet."
            )

        st.divider()

        st.subheader("Create Connection")

        if len(flow.components) >= 2:

            options = {
                component.name: component_id
                for component_id, component
                in flow.components.items()
            }

            names = list(options.keys())

            source_name = st.selectbox(
                "From",
                names,
                key="conn_source",
            )

            target_name = st.selectbox(
                "To",
                names,
                key="conn_target",
            )

            connection_label = st.text_input(
                "Flow label",
                value="data flow",
                key="conn_label",
            )

            if st.button(
                "ðŸ”— Create Connection",
                key="add_conn_btn",
                type="primary",
                width="stretch",
            ):

                if source_name == target_name:

                    st.warning(
                        "Source and target must be different."
                    )

                else:

                    connection = Connection(
                        source_id=options[source_name],
                        target_id=options[target_name],
                        label=connection_label.strip()
                        or "data flow",
                    )

                    flow.add_connection(
                        connection
                    )

                    st.success(
                        f"{source_name} â†’ {target_name}"
                    )

                    st.rerun()

        else:

            st.caption(
                "Add at least two components to create a connection."
            )

    # ------------------------------------------------------------------
    # SAVE / CLOSE
    # ------------------------------------------------------------------

    st.divider()

    save_col, close_col = st.columns(2)

    with save_col:

        if st.button(
            "ðŸ’¾ Save Architecture",
            key="save_arch_btn",
            type="primary",
            width="stretch",
        ):

            try:

                st.session_state.architecture_flow = (
                    flow.to_dict()
                )

                st.success(
                    "Architecture model saved to session."
                )

            except Exception as exc:

                st.error(
                    f"Could not save architecture: {exc}"
                )

    with close_col:

        if st.button(
            "âœ• Close Editor",
            key="close_arch_editor",
            width="stretch",
        ):

            st.session_state.show_arch_editor = False
            st.rerun()


# ============================================================================
# RESULT RENDERING
# ============================================================================

def render_result(
    result,
) -> None:

    counts = result.counts_by_severity()

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------

    c1, c2, c3, c4 = st.columns(
        [1.5, 1, 1, 1]
    )

    with c1:

        colour = RAG_COLOUR.get(
            result.rag_status,
            "#555",
        )

        st.markdown(
            "\n".join(line.strip() for line in textwrap.dedent(f"""
            <div class="status-card"
                 style="background:{colour};">

                <div class="status-label">
                    ASSURANCE STATUS
                </div>

                <div class="status-value">
                    {result.rag_status}
                </div>

                <div class="status-score">
                    Risk score {result.risk_score}/100
                </div>

            </div>
            """).splitlines()),
            unsafe_allow_html=True,
        )

    with c2:

        st.metric(
            "Findings",
            len(result.findings),
        )

    with c3:

        st.metric(
            "Critical",
            counts.get(
                "CRITICAL",
                0,
            ),
        )

    with c4:

        st.metric(
            "Sections analysed",
            len(result.sections),
        )

    st.write("")

    # ------------------------------------------------------------------
    # SEVERITY STRIP
    # ------------------------------------------------------------------

    severity_cols = st.columns(
        len(SEVERITIES)
    )

    for col, severity in zip(
        severity_cols,
        SEVERITIES,
    ):

        col.markdown(
            f"""
            <div style="
                border-left:4px solid {SEV_COLOUR[severity]};
                padding:9px 13px;
                border-radius:0 8px 8px 0;
                background:rgba(255,255,255,0.025);
            ">
                <b style="font-size:18px;">
                    {counts.get(severity, 0)}
                </b>

                <span style="
                    font-size:11px;
                    color:#8291a7;
                    margin-left:7px;
                ">
                    {severity}
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ------------------------------------------------------------------
    # WARNINGS
    # ------------------------------------------------------------------

    for warning in result.warnings:
        st.warning(warning)

    # ------------------------------------------------------------------
    # TABS
    # ------------------------------------------------------------------

    tabs = st.tabs(
        [
            "ðŸ“‹ Report",
            "ðŸš© Findings",
            "ðŸ“ Architecture Flow",
            "ðŸ”Ž Audit Trail",
            "ðŸ—‚ï¸ Section Map",
            "ðŸ“¤ Export",
        ]
    )

    # ==================================================================
    # REPORT
    # ==================================================================

    with tabs[0]:

        st.markdown(
            result.report_markdown
        )

    # ==================================================================
    # FINDINGS
    # ==================================================================

    with tabs[1]:

        if not result.findings:

            st.info(
                "No findings were raised."
            )

        else:

            sev_filter = st.multiselect(
                "Severity",
                SEVERITIES,
                default=list(SEVERITIES),
            )

            available_domains = sorted(
                {
                    finding.domain
                    for finding in result.findings
                }
            )

            dom_filter = st.multiselect(
                "Domain",
                available_domains,
                default=available_domains,
                format_func=lambda domain:
                    DOMAIN_LABELS.get(
                        domain,
                        domain,
                    ),
            )

            only_grounded = st.checkbox(
                "Only findings cited to a knowledge base clause",
                value=False,
            )

            shown = [
                finding
                for finding in result.findings
                if (
                    finding.severity in sev_filter
                    and finding.domain in dom_filter
                    and (
                        finding.is_grounded
                        or not only_grounded
                    )
                )
            ]

            st.caption(
                f"{len(shown)} of "
                f"{len(result.findings)} findings"
            )

            for finding in shown:

                label = (
                    f"{finding.severity} Â· "
                    f"{finding.section[:60]} Â· "
                    f"{finding.issue[:90]}"
                )

                with st.expander(label):

                    st.markdown(
                        f"**Issue.** {finding.issue}"
                    )

                    st.markdown(
                        f"**Recommendation.** "
                        f"{finding.recommendation}"
                    )

                    if finding.standard_reference:

                        standard = (
                            f"**Standard.** "
                            f"{finding.standard_reference}"
                        )

                        if finding.kb_source:

                            standard += (
                                f" â€” `{finding.kb_source}`"
                            )

                        st.markdown(
                            standard
                        )

                    else:

                        st.caption(
                            "No knowledge base clause cited â€” "
                            "this reflects general practice, "
                            "not your organisation's standard."
                        )

                    if finding.evidence_excerpt:

                        st.markdown(
                            "**Evidence from the design**"
                        )

                        st.code(
                            finding.evidence_excerpt,
                            language=None,
                        )

                    if finding.control_mappings:

                        st.markdown(
                            "**Controls.** "
                            + ", ".join(
                                finding.control_mappings
                            )
                        )

                    st.caption(
                        f"Provenance: {finding.origin}"
                        + (
                            f" ({finding.rule_id})"
                            if finding.rule_id
                            else ""
                        )
                        + f" Â· confidence {finding.confidence}"
                        + f" Â· id {finding.fingerprint}"
                    )

    # ==================================================================
    # ARCHITECTURE FLOW
    # ==================================================================

    with tabs[2]:

        render_architecture_flow(
            result.sections,
            result.findings,
        )

    # ==================================================================
    # AUDIT
    # ==================================================================

    with tabs[3]:

        st.caption(
            "Every retrieval, tool call and model decision "
            "in this run."
        )

        from src.audit import AuditTrail

        trail = AuditTrail()

        trail.extend(
            result.audit
        )

        st.markdown(
            trail.render_markdown(
                limit=300
            )
        )

    # ==================================================================
    # SECTION MAP
    # ==================================================================

    with tabs[4]:

        st.caption(
            "How each section of the document was classified."
        )

        rows = [
            {
                "Section": section.heading,
                "Domain": DOMAIN_LABELS.get(
                    section.domain,
                    section.domain,
                ),
                "Topic": section.topic,
                "Confidence": section.topic_confidence,
                "Words": section.word_count,
            }
            for section in result.sections
        ]

        st.dataframe(
            rows,
            width="stretch",
            hide_index=True,
        )

    # ==================================================================
    # EXPORT
    # ==================================================================

    with tabs[5]:

        paths = save_outputs(
            result,
            get_config(),
        )

        st.success(
            f"Saved to `{paths['report'].parent}`"
        )

        st.download_button(
            "â¬‡ï¸ Download report",
            data=result.report_markdown,
            file_name=paths["report"].name,
            mime="text/markdown",
            width="stretch",
        )

        st.download_button(
            "â¬‡ï¸ Download audit bundle",
            data=json.dumps(
                result.to_dict(),
                indent=2,
                default=str,
            ),
            file_name=paths["audit"].name,
            mime="application/json",
            width="stretch",
        )

        st.caption(
            "The audit bundle contains findings, sections "
            "and the reasoning trail."
        )


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:

    initialise_session_state()

    load_custom_css()

    domains = render_sidebar()

    render_hero()

    # ------------------------------------------------------------------
    # INPUT MODE
    # ------------------------------------------------------------------

    mode = st.radio(
        "Input",
        [
            "Upload a document",
            "Paste text",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    document_name = ""
    sections: list = []

    # ==================================================================
    # UPLOAD
    # ==================================================================

    if mode == "Upload a document":

        uploaded = st.file_uploader(
            "Upload HLD / LLD / architecture document",
            type=[
                suffix.lstrip(".")
                for suffix in sorted(
                    SUPPORTED_SUFFIXES
                )
            ],
        )

        if uploaded:

            file_bytes = uploaded.getvalue()

            input_signature = make_file_signature(
                file_bytes
            )

            reset_for_new_input(
                input_signature
            )

            tmp_dir = PROJECT_ROOT / "data" / "uploads"

            tmp_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            tmp = tmp_dir / uploaded.name

            try:

                tmp.write_bytes(
                    file_bytes
                )

                sections = parse_document(
                    tmp
                )

                document_name = uploaded.name

            except Exception as exc:

                st.error(
                    f"Could not read that file: {exc}"
                )

                st.exception(exc)

    # ==================================================================
    # PASTE TEXT
    # ==================================================================

    else:

        text = st.text_area(
            "Paste the design content",
            height=280,
        )

        document_name = st.text_input(
            "Document name",
            value="pasted-design",
        )

        if text:

            input_signature = make_text_signature(
                text,
                document_name or "design",
            )

            reset_for_new_input(
                input_signature
            )

            sections = parse_text(
                text,
                document_name or "design",
            )

    # ------------------------------------------------------------------
    # PROCESS
    # ------------------------------------------------------------------

    scope_ok = True
    force_review = False

    if sections:

        summary = summarise_sections(
            sections
        )

        st.info(
            f"Parsed **{len(sections)} sections** â€” "
            + " Â· ".join(
                f"{DOMAIN_LABELS.get(domain, domain)}: {count}"
                for domain, count in sorted(
                    summary.items()
                )
            )
        )

        # ==============================================================
        # GUARDRAIL
        # ==============================================================

        scope = assess_scope(
            sections
        )

        if not scope.in_scope:

            scope_ok = False

            st.error(
                f"**Not an architecture design document.** "
                f"{scope.reason}"
            )

            st.caption(
                scope.suggestion
            )

            force_review = st.checkbox(
                "I've reviewed the message above and want "
                "to review this input anyway"
            )

        # ==============================================================
        # CHECKPOINT
        # ==============================================================

        if scope_ok or force_review:

            current_checkpoint_signature = (
                make_checkpoint_signature(
                    st.session_state.input_signature,
                    domains,
                )
            )

            checkpoint_approved = (
                st.session_state.checkpoint_approved
                and
                st.session_state.checkpoint_signature
                == current_checkpoint_signature
            )

            if not checkpoint_approved:

                st.session_state.checkpoint_approved = False
                st.session_state.checkpoint_signature = None

                render_checkpoint(
                    sections,
                    domains,
                )

                if st.button(
                    "âœ“ Approve & Proceed to AI Review",
                    type="primary",
                    key="checkpoint_approve",
                    width="stretch",
                ):

                    st.session_state.checkpoint_approved = True

                    st.session_state.checkpoint_signature = (
                        current_checkpoint_signature
                    )

                    st.rerun()

            else:

                with st.expander(
                    "âœ“ Checkpoint Approved",
                    expanded=False,
                ):

                    st.success(
                        "Document approved for AI review."
                    )

                    st.caption(
                        f"{len(sections)} sections ready for Layer 2."
                    )

                    if st.button(
                        "Review Checkpoint Again",
                        key="reopen_checkpoint",
                    ):

                        st.session_state.checkpoint_approved = False
                        st.session_state.checkpoint_signature = None

                        st.rerun()

                st.success(
                    "Trust boundary passed â€” Layer 2 AI review is ready."
                )

    # ==================================================================
    # RUN REVIEW
    # ==================================================================

    current_checkpoint_signature = None

    if (
        sections
        and st.session_state.input_signature
        and domains
    ):

        current_checkpoint_signature = (
            make_checkpoint_signature(
                st.session_state.input_signature,
                domains,
            )
        )

    checkpoint_approved = (
        st.session_state.checkpoint_approved
        and
        st.session_state.checkpoint_signature
        == current_checkpoint_signature
    )

    disabled = (
        not sections
        or not domains
        or (
            not scope_ok
            and not force_review
        )
        or not checkpoint_approved
    )

    if not domains:

        st.warning(
            "Select at least one review domain in the sidebar."
        )

    if st.button(
        "ðŸš€ Run Architecture Review",
        type="primary",
        disabled=disabled,
        key="run_review",
        width="stretch",
    ):

        # --------------------------------------------------------------
        # OLLAMA
        # --------------------------------------------------------------

        ollama = get_ollama_status()

        if not ollama["reachable"]:

            st.error(
                "Ollama is not reachable. Start it with "
                "`ollama serve` and reload this page."
            )

            return

        if ollama["missing_models"]:

            st.error(
                "Pull the required models first: "
                + ", ".join(
                    ollama["missing_models"]
                )
            )

            return

        # --------------------------------------------------------------
        # RESET RESULT
        # --------------------------------------------------------------

        st.session_state.result = None

        st.session_state.architecture_flow_obj = None
        st.session_state.architecture_flow = None
        st.session_state.show_arch_editor = False

        # --------------------------------------------------------------
        # PROGRESS
        # --------------------------------------------------------------

        progress = st.progress(
            0.0,
            text="Starting architecture review...",
        )

        started = time.time()

        # --------------------------------------------------------------
        # AGENT
        # --------------------------------------------------------------

        agent = ReviewAgent(
            config=get_config(),
            kb=get_kb(),
        )

        def update_progress(
            stage,
            pct,
        ):

            progress.progress(
                pct,
                text=(
                    f"{stage} Â· "
                    f"{int(time.time() - started)}s"
                ),
            )

        agent.progress = update_progress

        # --------------------------------------------------------------
        # REVIEW
        # --------------------------------------------------------------

        try:

            st.session_state.result = agent.review(
                sections,
                document_name or "design",
                domains,
            )

        except Exception as exc:

            st.error(
                f"Review failed: {exc}"
            )

            st.exception(exc)

            return

        finally:

            progress.empty()

    # ==================================================================
    # RESULT
    # ==================================================================

    if st.session_state.result:

        st.divider()

        render_result(
            st.session_state.result
        )


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()

