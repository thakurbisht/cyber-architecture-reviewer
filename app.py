"""
Cyber Architecture Reviewer - Streamlit UI

The UI layer only orchestrates:
    Document -> Parser -> Guardrail -> Checkpoint -> ReviewAgent -> Result

Review logic remains inside src/.
"""

from __future__ import annotations

import hashlib
import html
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
from src.report import compute_risk, save_outputs
from src.retriever import KnowledgeBase
from src.rules import rules_summary


# ============================================================================
# PAGE CONFIG
# ============================================================================

st.set_page_config(
    page_title="Archeo · Architecture Review",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================================
# CONSTANTS
# ============================================================================

# Mirrors the severity and status tokens in assets/archeo.css.
SEV_COLOUR = {
    "CRITICAL": "#D92D20",
    "HIGH": "#E8702A",
    "MEDIUM": "#E0A800",
    "LOW": "#3B82F6",
}

RAG_COLOUR = {
    "RED": "#B42318",
    "AMBER": "#B54708",
    "GREEN": "#0F8A7E",
}

RAG_LABEL = {
    "RED": "High risk · requires attention",
    "AMBER": "Elevated risk",
    "GREEN": "Acceptable",
}

VERIFIER_STATES = ("CONFIRMED", "REFUTED", "NEEDS_HUMAN")

RISK_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}

COMPONENT_ICONS = {
    "service": "⚙️",
    "database": "🗄️",
    "cache": "⚡",
    "queue": "📨",
    "api_gateway": "🌐",
    "external": "☁️",
    "storage": "💾",
    "user": "👤",
}


# ============================================================================
# CSS
# ============================================================================

def load_custom_css() -> None:
    """Load the Archeo design system (assets/archeo.css, light theme).

    theme.css, refine.css and enterprise.css (the earlier dark theme) are
    kept on disk but not loaded.
    """

    css_file = PROJECT_ROOT / "assets" / "archeo.css"

    try:
        css = css_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def esc(value) -> str:
    """HTML-escape any document- or model-derived text before it is placed
    inside an unsafe_allow_html block."""

    return html.escape(str(value), quote=True)


def html_block(markup: str) -> None:
    """Render trusted HTML markup. Lines are stripped so Markdown does not
    turn indented HTML into a code block."""

    st.markdown(
        "\n".join(line.strip() for line in markup.splitlines()),
        unsafe_allow_html=True,
    )


# ============================================================================
# HEADER, STEPPER, SECTION HEADINGS
# ============================================================================

SHIELD_SVG = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 9.9C8 19.3 5 15.5 5 11V6l7-3z"/>'
    '<path d="M9 12.5V11a3 3 0 0 1 6 0v1.5"/></svg>'
)


@st.cache_data(ttl=60, show_spinner=False)
def latest_eval_scores() -> dict:
    """Most recent scored golden-set run (results/golden/*/scores.json).

    Surfaces measured pipeline quality in the UI. Empty dict when no run has
    been scored yet - the UI then says so instead of showing a number."""

    runs = sorted(
        (PROJECT_ROOT / "results" / "golden").glob("*/scores.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in runs:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not data.get("rules_only"):
            return data
    return {}


def configured_model(key: str) -> str:
    """Model named under `models:` in config.yaml, or '' when the stage is
    not configured (verifier: A4 not built yet)."""

    return str(get_config().raw.get("models", {}).get(key, "") or "")


def render_header() -> None:
    """Brand, connection status and the model line-up."""

    ollama = get_ollama_status()

    if ollama["reachable"] and not ollama["missing_models"]:
        status = '<span class="status ok"><span class="dot ok"></span>Ollama connected</span>'
    elif ollama["reachable"]:
        status = '<span class="status warn"><span class="dot warn"></span>Models missing</span>'
    else:
        status = '<span class="status bad"><span class="dot bad"></span>Ollama offline</span>'

    verifier = configured_model("verifier") or "off"
    judge = latest_eval_scores().get("judge_model") or "none"

    html_block(f"""
    <div class="ax-header">
      <div class="ax-brand">
        <div class="ax-logo">{SHIELD_SVG}</div>
        <div>
          <div class="ax-name">Archeo</div>
          <div class="ax-tag">Architecture threat detection with evidence and verification</div>
        </div>
      </div>
      <div class="ax-right">
        {status}
        <div class="ax-config">Model <b>{esc(ollama.get("llm") or configured_model("llm"))}</b>
          · Verifier <b>{esc(verifier)}</b> · Judge <b>{esc(judge)}</b></div>
      </div>
    </div>
    """)


STEPS = (
    ("Intake", "Upload or paste a design"),
    ("Pre-flight", "Deterministic checks"),
    ("AI review", "Standards-grounded analysis"),
    ("Report", "Findings and assurance status"),
)


def render_stepper(active: int, slot=None) -> None:
    """Workflow stepper. `active` is the 0-based index of the current step;
    earlier steps render as done. `slot` is an st.empty() placeholder so the
    stepper can sit at the top but be drawn once the state is known."""

    items = []
    for i, (label, sub) in enumerate(STEPS):
        state = "done" if i < active else "active" if i == active else ""
        mark = "&#10003;" if i < active else str(i + 1)
        items.append(
            f'<div class="step {state}"><div class="step-num">{mark}</div>'
            f'<div><div class="step-label">{label}</div>'
            f'<div class="step-sub">{sub}</div></div></div>'
        )
    (slot or st).markdown(f'<div class="stepper">{"".join(items)}</div>',
                          unsafe_allow_html=True)


def section_header(eyebrow: str, title: str, desc: str = "") -> None:
    desc_html = f'<div class="sec-desc">{desc}</div>' if desc else ""
    html_block(f"""
    <div class="sec-head">
      <div class="sec-eyebrow">{eyebrow}</div>
      <div class="sec-title">{title}</div>
      {desc_html}
    </div>
    """)


def severity_chip(severity: str) -> str:
    sev = severity if severity in SEV_COLOUR else "LOW"
    return f'<span class="badge {sev}">{esc(severity)}</span>'


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

    with st.sidebar:
        html_block('<div class="sec-title" style="font-size:16px">Settings</div>')

        # --------------------------------------------------------------
        # SCOPE
        # --------------------------------------------------------------
        html_block('<div class="sb-label">Review scope</div>')

        selected: list[str] = []
        for key in ("network", "application", "security", "cloud_data"):
            default = cfg.raw["domains"].get(key, True)
            if st.checkbox(DOMAIN_LABELS[key], value=default, key=f"dom_{key}"):
                selected.append(key)

        # --------------------------------------------------------------
        # SYSTEM STATUS
        # --------------------------------------------------------------
        ollama = get_ollama_status()
        kb = get_kb_status()
        total = kb.get("total", 0)

        if ollama["reachable"] and not ollama["missing_models"]:
            engine = f'<span class="dot ok"></span>{esc(ollama["llm"])}'
        elif ollama["reachable"]:
            engine = '<span class="dot warn"></span>Models missing'
        else:
            engine = '<span class="dot bad"></span>Offline'

        standards = (f'<span class="dot ok"></span>{total} clauses' if total
                     else '<span class="dot bad"></span>Empty')
        rule_count = sum(rules_summary().values())

        html_block(f"""
        <div class="sb-label">System status</div>
        <div class="sb-status">
          <div class="sb-row">Review engine <span class="v">{engine}</span></div>
          <div class="sb-row">Standards library <span class="v">{standards}</span></div>
          <div class="sb-row">Deterministic rules <span class="v">{rule_count}</span></div>
          <div class="sb-row">Embeddings <span class="v">{esc(kb.get("embedding_model") or "-")}</span></div>
        </div>
        """)

        if not ollama["reachable"]:
            st.caption(ollama.get("error", "")[:200])
            st.code("ollama serve", language="powershell")
        elif ollama["missing_models"]:
            st.code("\n".join(f"ollama pull {m}" for m in ollama["missing_models"]),
                    language="powershell")
        if not total:
            st.code("python scripts/seed_kb.py", language="powershell")

        with st.expander("Coverage by domain", expanded=False):
            counts = kb.get("counts", {})
            rules = rules_summary()
            rows = "".join(
                f'<div class="sb-row">{esc(DOMAIN_LABELS.get(d, d))}'
                f'<span class="v">{counts.get(d, 0)} clauses · {rules.get(d, 0)} rules</span></div>'
                for d in ("network", "application", "security", "cloud_data")
            )
            html_block(f'<div class="sb-status">{rows}</div>')

        for warning in kb.get("warnings", []):
            st.warning(warning)

        html_block("""
        <div class="sb-foot">
          Read and flag only. This tool has no write access to any system
          and does not approve or reject designs.
        </div>
        """)

    return selected


# ============================================================================
# CHECKPOINT
# ============================================================================

def kpi(label: str, value, sub: str = "") -> str:
    sub_html = f'<div class="kpi-sub">{sub}</div>' if sub else ""
    return (f'<div class="kpi"><div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{value}</div>{sub_html}</div>')


def render_checkpoint(
    sections: list,
    domains: list[str],
) -> None:

    section_header(
        "Step 2 · Pre-flight",
        "Deterministic checkpoint",
        "Rule-based findings and scope, reviewed before the document crosses "
        "the trust boundary into the AI review layer.",
    )

    agent = ReviewAgent(
        config=get_config(),
        kb=get_kb(),
    )

    layer1_findings, kb_counts = agent.get_layer1_findings(
        sections,
        domains,
    )

    in_scope_count = sum(1 for section in sections if section.domain in domains)
    kb_total = sum(kb_counts.values())
    critical = sum(1 for f in layer1_findings if f.severity == "CRITICAL")

    cols = st.columns(4)
    cards = [
        kpi("Sections", len(sections), "parsed from the document"),
        kpi("In scope", in_scope_count, f"across {len(domains)} domain(s)"),
        kpi("Rule findings", len(layer1_findings),
            f"{critical} critical" if critical else "none critical"),
        kpi("Standards clauses", kb_total, "available for grounding"),
    ]
    for col, card in zip(cols, cards):
        with col:
            html_block(card)

    st.write("")

    with st.expander("Section distribution by domain", expanded=False):
        summary = summarise_sections(sections)
        tags = "".join(
            f'<span class="tag">{esc(DOMAIN_LABELS.get(d, d))} <b>{summary.get(d, 0)}</b></span>'
            for d in sorted(domains)
        )
        html_block(f'<div class="doc-tags">{tags}</div>')

    if layer1_findings:
        rows = "".join(
            f"""<div class="frow">
                  <div>{severity_chip(f.severity)}</div>
                  <div>
                    <div class="frow-sec">{esc(f.section[:80])}</div>
                    <div class="frow-issue">{esc(f.issue[:220])}</div>
                  </div>
                </div>"""
            for f in layer1_findings
        )
        with st.expander(f"Rule findings ({len(layer1_findings)})", expanded=True):
            html_block(f'<div class="flist">{rows}</div>')
    else:
        st.success("No findings from deterministic rules.")

    st.caption(
        "Next: standards retrieval, AI reasoning, citation verification, "
        "cross-domain consistency, assurance report."
    )


# ============================================================================
# PROGRESS
# ============================================================================

# Stages the agent actually reports (src/agent.py _emit calls). The verifier
# stage (A4) is listed so the pipeline reads end to end, and shows as not
# enabled until a verifier model is configured.
PIPELINE_STAGES = (
    ("parse", "Parse document"),
    ("rules", "Deterministic rules"),
    ("review", "Standards retrieval and AI review"),
    ("correlate", "Cross-domain consistency"),
    ("verify", "Verifier"),
    ("report", "Risk score and report"),
)


def ollama_gpu_share() -> str:
    """What `ollama ps` reports for the reviewer model: share held in VRAM.
    (Ollama exposes no utilisation or temperature, so none is shown.)"""

    try:
        import urllib.request
        base = get_config().raw["models"].get("ollama_host", "http://localhost:11434")
        with urllib.request.urlopen(base.rstrip("/") + "/api/ps", timeout=1.5) as resp:
            models = json.loads(resp.read().decode("utf-8")).get("models", [])
    except Exception:  # noqa: BLE001 - status line only
        return ""
    parts = []
    for m in models:
        size = m.get("size") or 0
        if size:
            vram_gb = (m.get("size_vram") or 0) / 1e9
            parts.append(f'{esc(m.get("name", "?"))} <b>{(m.get("size_vram") or 0) / size:.0%}</b> on GPU'
                         f' ({vram_gb:.1f} GB)')
    return " · ".join(parts)


class ProgressTracker:
    """Renders the stage list while ReviewAgent runs. Streamlit blocks during
    agent.review(), so the panel is redrawn from the agent's progress
    callback; there is no cancel button because a running review cannot be
    interrupted from the same script run."""

    def __init__(self, document_name: str) -> None:
        self.document_name = document_name
        self.slot = st.empty()
        self.t0 = time.time()
        self.started: dict = {}
        self.ended: dict = {}
        self.detail = ""
        self.verifier_on = bool(configured_model("verifier"))
        self._last_gpu = 0.0
        self._gpu = ""

    def start(self, key: str) -> None:
        self.started.setdefault(key, time.time())
        self.render()

    def finish(self, key: str) -> None:
        self.started.setdefault(key, time.time())
        self.ended.setdefault(key, time.time())

    def _advance(self, key: str) -> None:
        order = [k for k, _ in PIPELINE_STAGES]
        for k in order[: order.index(key)]:
            if k == "verify" and not self.verifier_on:
                continue
            self.finish(k)
        self.start(key)

    def on_agent_progress(self, stage: str, pct: float) -> None:
        text = str(stage)
        if text.startswith("Reviewing:"):
            self.detail = text.split(":", 1)[1].strip()
            self._advance("review")
        elif text.startswith("Deterministic rules"):
            self.finish("rules")
            self.start("review")
        elif text.startswith("Cross-domain"):
            self.detail = ""
            self._advance("correlate")
        elif text.startswith("Writing report"):
            self._advance("report")
        elif text == "Complete":
            self._advance("report")
            self.finish("report")
        self.render(pct)

    def durations(self) -> dict:
        return {k: round(self.ended[k] - self.started[k], 1)
                for k in self.ended if k in self.started}

    def render(self, pct: float = 0.0) -> None:
        now = time.time()
        if now - self._last_gpu > 5:
            self._gpu, self._last_gpu = ollama_gpu_share(), now
        rows = []
        for key, label in PIPELINE_STAGES:
            if key == "verify" and not self.verifier_on:
                rows.append(f'<div class="prow skip"><span class="ic"></span>'
                            f'<span class="nm">{label}<span class="detail">not enabled yet (A4)</span></span>'
                            f'<span class="t">skipped</span></div>')
                continue
            if key in self.ended:
                state, icon = "done", "&#10003;"
                t = f"{self.ended[key] - self.started[key]:.1f}s"
            elif key in self.started:
                state, icon = "active", ""
                t = f"{now - self.started[key]:.0f}s elapsed"
            else:
                state, icon, t = "todo", "", ""
            detail = (f'<span class="detail">{esc(self.detail[:70])}</span>'
                      if key == "review" and state == "active" and self.detail else "")
            rows.append(f'<div class="prow {state}"><span class="ic">{icon}</span>'
                        f'<span class="nm">{label}{detail}</span><span class="t">{t}</span></div>')

        remaining = ""
        if 0.05 < pct < 1.0:
            elapsed = now - self.t0
            remaining = f" · about {max(0, elapsed / pct - elapsed) / 60:.0f} min remaining"
        gpu = f"<span>{self._gpu}</span>" if self._gpu else ""
        self.slot.markdown(
            f'''<div class="prog"><div class="prog-title">Analyzing <span>{esc(self.document_name)}</span></div>
            {"".join(rows)}
            <div class="prog-foot"><span>Elapsed <b>{now - self.t0:.0f}s</b>{remaining}</span>{gpu}</div></div>''',
            unsafe_allow_html=True,
        )

    def fail(self, message: str) -> None:
        self.detail = f"failed: {message}"

    def clear(self) -> None:
        self.slot.empty()


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
                📐 Architecture Flow
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

        st.subheader("Detected components")

        cols = st.columns(3)

        for index, (
            comp_id,
            component,
        ) in enumerate(flow.components.items()):

            icon = COMPONENT_ICONS.get(
                component.component_type.value,
                "📦",
            )

            risk_icon = RISK_ICON.get(
                component.risk_level,
                "⚪",
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
            f"🔗 Data Flows · {len(flow.connections)}",
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
                        →
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
            "📐 Open Full Editor",
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
                🧩 Architecture Editor
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

        st.subheader("Add component")

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
            "➕ Add Component",
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
                "📦",
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
                    "🗑️",
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

        st.subheader("Data flows")

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
                                →
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
                        "🗑️",
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

        st.subheader("Create connection")

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
                "🔗 Create Connection",
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
                        f"{source_name} → {target_name}"
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
            "💾 Save Architecture",
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
            "✕ Close Editor",
            key="close_arch_editor",
            width="stretch",
        ):

            st.session_state.show_arch_editor = False
            st.rerun()


# ============================================================================
# RESULT RENDERING
# ============================================================================

def verifier_status(finding) -> str:
    """A4 verifier verdict when the pipeline sets one, else UNVERIFIED."""
    status = str(getattr(finding, "verifier_status", "") or "").upper()
    return status if status in VERIFIER_STATES else "UNVERIFIED"


def finding_sources(finding) -> list[str]:
    sources = getattr(finding, "sources", None) or [finding.origin]
    return [str(src) for src in sources if src]


def confidence_label(value: float) -> str:
    if value >= 0.8:
        return "high"
    if value >= 0.6:
        return "moderate"
    return "low"


def kv(key: str, value: str, pending: bool = False) -> str:
    cls = "v pending" if pending else "v"
    return f'<div class="kv"><span class="k">{key}</span><span class="{cls}">{value}</span></div>'


def findings_csv(findings: list) -> str:
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["severity", "verifier_status", "confidence", "domain", "section",
                     "issue", "recommendation", "evidence", "standard_reference",
                     "sources", "rule_id", "fingerprint"])
    for f in findings:
        writer.writerow([f.severity, verifier_status(f), f.confidence, f.domain, f.section,
                         f.issue, f.recommendation, f.evidence_excerpt, f.standard_reference,
                         "|".join(finding_sources(f)), f.rule_id, f.fingerprint])
    return buf.getvalue()


VERIFIER_LABEL = {
    "CONFIRMED": "&#10003; Verified",
    "REFUTED": "&#10007; Refuted",
    "NEEDS_HUMAN": "? Needs review",
    "UNVERIFIED": "Not verified",
}


def finding_card(f) -> str:
    vstat = verifier_status(f)
    evidence = f.evidence_excerpt.strip()
    if evidence:
        quote = f'<div class="quote">&ldquo;{esc(evidence)}&rdquo;</div>'
    else:
        quote = '<div class="quote missing">No evidence quote captured for this finding (A2).</div>'
    reason = str(getattr(f, "verifier_reason", "") or "")
    vnote = ""
    if reason and vstat != "UNVERIFIED":
        vnote = (f'<div class="vnote {vstat}">Verifier '
                 f'{vstat.lower().replace("_", " ")}: {esc(reason)}</div>')
    sources = "".join(f'<span class="pill">{esc(src)}</span>' for src in finding_sources(f))
    if f.rule_id:
        sources += f'<span class="pill">{esc(f.rule_id)}</span>'
    if f.standard_reference:
        standard = f'<span>Standard: <b>{esc(f.standard_reference)}</b></span>'
    else:
        standard = "<span>No standard clause cited</span>"
    return f"""
    <div class="fcard {f.severity}">
      <div class="fmeta">
        {severity_chip(f.severity)}
        <span class="badge {vstat}">{VERIFIER_LABEL[vstat]}</span>
        <span class="fconf">Confidence {f.confidence:.2f} ({confidence_label(f.confidence)})</span>
      </div>
      <div class="ftitle">{esc(f.issue)}</div>
      <div class="fdesc"><b>Recommendation.</b> {esc(f.recommendation)}</div>
      {quote}
      <div class="fsec">Section: <b>{esc(f.section)}</b> · {esc(DOMAIN_LABELS.get(f.domain, f.domain))}</div>
      <div class="ffoot"><span>Detected by</span>{sources}{standard}</div>
      {vnote}
    </div>
    """


def domain_risk_colour(score: float) -> str:
    if score >= 70:
        return SEV_COLOUR["CRITICAL"]
    if score >= 40:
        return SEV_COLOUR["HIGH"]
    if score >= 12:
        return SEV_COLOUR["MEDIUM"]
    return SEV_COLOUR["LOW"]


def render_result(
    result,
) -> None:

    cfg = get_config()
    findings = result.findings
    counts = result.counts_by_severity()
    n = len(findings)

    section_header(
        "Step 4 · Results",
        f"Findings summary · {esc(result.document_name)}",
        "Risk status is computed from the findings table, never by the model, "
        "so anyone can recompute it by hand.",
    )

    # ------------------------------------------------------------------
    # KEY METRICS
    # ------------------------------------------------------------------

    cards = [("TOTAL", "Total findings", n)] + [
        (sev, sev.title(), counts.get(sev, 0)) for sev in SEVERITIES
    ]
    for col, (cls, label, value) in zip(st.columns(len(cards)), cards):
        with col:
            html_block(f'<div class="kpi sev {cls}"><div class="kpi-label">{label}</div>'
                       f'<div class="kpi-value">{value}</div></div>')

    st.write("")

    v1, v2, v3 = st.columns([1, 1, 1.25])

    # ------------------------------------------------------------------
    # VERIFICATION (A4)
    # ------------------------------------------------------------------

    with v1:
        vcounts = {state: 0 for state in VERIFIER_STATES + ("UNVERIFIED",)}
        for f in findings:
            vcounts[verifier_status(f)] += 1
        if n and vcounts["UNVERIFIED"] < n:
            bar = "".join(
                f'<span style="width:{vcounts[state] / n * 100:.1f}%;background:{colour}"></span>'
                for state, colour in (("CONFIRMED", "#0F8A7E"), ("REFUTED", "#C0392B"),
                                      ("NEEDS_HUMAN", "#B7791F"))
                if vcounts[state]
            )
            body = (f'<div class="vbar">{bar}</div>'
                    + kv("Confirmed", f'{vcounts["CONFIRMED"]} / {n} ({vcounts["CONFIRMED"] / n:.0%})')
                    + kv("Refuted", str(vcounts["REFUTED"]))
                    + kv("Needs human review", str(vcounts["NEEDS_HUMAN"])))
        else:
            body = (kv("Confirmed", "not run", True)
                    + kv("Refuted", "not run", True)
                    + kv("Needs human review", "not run", True)
                    + '<div class="pending-note">The verifier stage (A4, phi4:14b) is not built '
                      'yet, so no finding has been independently confirmed. Treat every '
                      'finding as a candidate.</div>')
        html_block(f'<div class="panel"><div class="panel-title">Verification</div>{body}</div>')

    # ------------------------------------------------------------------
    # EVIDENCE AND QUALITY (A2, A3, A6)
    # ------------------------------------------------------------------

    with v2:
        with_quote = sum(1 for f in findings if f.evidence_excerpt.strip())
        grounded = sum(1 for f in findings if f.is_grounded)
        avg_conf = sum(f.confidence for f in findings) / n if n else 0.0
        scores = latest_eval_scores()
        kappa = scores.get("judge_kappa")
        has_kappa = isinstance(kappa, (int, float))
        if has_kappa:
            kappa_txt = f"{kappa:.2f} " + ("&#10003; trustworthy" if kappa >= 0.7 else "&#9888; below 0.7")
        else:
            kappa_txt = "not calibrated (A6)"
        quote_txt = f"{with_quote} / {n}" + (f" ({with_quote / n:.0%})" if n else "")
        body = (kv("Avg confidence", f"{avg_conf:.2f} ({confidence_label(avg_conf)})")
                + kv("Evidence quotes", quote_txt)
                + kv("Cited to a standard", f"{grounded} / {n}")
                + kv("Semantic dedup", "not built yet (A3)", True)
                + kv("Judge agreement (kappa)", kappa_txt, not has_kappa))
        if scores:
            body += (f'<div class="pending-note">Golden-set benchmark '
                     f'<b>{esc(scores.get("label") or scores.get("run_name", ""))}</b>: '
                     f'precision {scores.get("precision", 0):.0%}, '
                     f'recall {scores.get("recall", 0):.0%}, '
                     f'mitigated items flagged {scores.get("trap_violation_rate", 0):.0%}.</div>')
        html_block(f'<div class="panel"><div class="panel-title">Evidence and quality</div>{body}</div>')

    # ------------------------------------------------------------------
    # RISK SCORE (A5)
    # ------------------------------------------------------------------

    with v3:
        domains_present = [
            d for d in ("network", "application", "security", "cloud_data")
            if d in result.domains_reviewed or any(f.domain == d for f in findings)
        ]
        bars = ""
        for d in domains_present:
            score = compute_risk([f for f in findings if f.domain == d], cfg)[0]
            bars += (f'<div class="bar-row"><span class="bar-label">{esc(DOMAIN_LABELS.get(d, d))}</span>'
                     f'<div class="bar-track"><div class="bar-fill" style="width:{score:.0f}%;'
                     f'background:{domain_risk_colour(score)}"></div></div>'
                     f'<span class="bar-val">{score:.0f}</span></div>')
        rag = result.rag_status if result.rag_status in RAG_COLOUR else "GREEN"
        html_block(f"""
        <div class="panel">
          <div class="panel-title">Risk score</div>
          <div class="risk-top">
            <span class="risk-score">{result.risk_score:.0f}</span><span class="risk-of">/ 100</span>
            <span class="rag-pill {rag}">{esc(result.rag_status)}</span>
          </div>
          <div class="muted" style="font-size:13px;margin:-8px 0 8px">{RAG_LABEL.get(rag, "")}</div>
          {bars}
        </div>
        """)

    for warning in result.warnings:
        st.warning(warning)

    st.write("")

    # ------------------------------------------------------------------
    # TABS
    # ------------------------------------------------------------------

    tabs = st.tabs(["Findings", "Report", "Architecture flow", "Audit trail", "Section map", "Export"])

    with tabs[0]:
        if not findings:
            st.info("No findings were raised.")
        else:
            c1, c2, c3, c4 = st.columns([1.2, 1.2, 1, 1.6])
            sev_filter = c1.multiselect("Severity", SEVERITIES, default=list(SEVERITIES))
            available_domains = sorted({f.domain for f in findings})
            dom_filter = c2.multiselect("Domain", available_domains, default=available_domains,
                                        format_func=lambda d: DOMAIN_LABELS.get(d, d))
            status_filter = c3.selectbox(
                "Verifier status",
                ["All", "Confirmed", "Refuted", "Needs review", "Not verified"],
                key="findings_status",
            )
            query = c4.text_input("Search", placeholder="Issue, section, recommendation or evidence",
                                  key="findings_search")

            status_key = {"Confirmed": "CONFIRMED", "Refuted": "REFUTED",
                          "Needs review": "NEEDS_HUMAN", "Not verified": "UNVERIFIED"}.get(status_filter)
            q = query.strip().lower()
            shown = [
                f for f in findings
                if f.severity in sev_filter
                and f.domain in dom_filter
                and (status_key is None or verifier_status(f) == status_key)
                and (not q or q in f"{f.issue} {f.section} {f.recommendation} {f.evidence_excerpt}".lower())
            ]

            page = st.session_state.setdefault("findings_page_size", 10)
            st.caption(f"Showing {min(page, len(shown))} of {len(shown)} matching findings ({n} total)")

            for f in shown[:page]:
                html_block(finding_card(f))
                with st.expander("Details"):
                    if f.control_mappings:
                        st.markdown("**Control mappings.** " + ", ".join(f.control_mappings))
                    if f.kb_source:
                        st.markdown(f"**Standards source.** `{f.kb_source}`")
                    if f.origin == "rules_engine":
                        model = "deterministic rule"
                    else:
                        model = getattr(f, "model", "") or configured_model("llm")
                    st.caption(
                        f"Origin {f.origin}"
                        + (f" · rule {f.rule_id}" if f.rule_id else "")
                        + f" · model {model} · id {f.fingerprint}"
                    )

            if len(shown) > page:
                if st.button(f"Show more findings ({len(shown) - page} remaining)", key="more_findings"):
                    st.session_state.findings_page_size = page + 10
                    st.rerun()

    with tabs[1]:
        st.markdown(result.report_markdown)

    with tabs[2]:
        render_architecture_flow(result.sections, findings)

    with tabs[3]:
        st.caption("Every retrieval, tool call and model decision in this run.")
        from src.audit import AuditTrail

        trail = AuditTrail()
        trail.extend(result.audit)
        st.markdown(trail.render_markdown(limit=300))

    with tabs[4]:
        st.caption("How each section of the document was classified.")
        st.dataframe(
            [
                {
                    "Section": section.heading,
                    "Domain": DOMAIN_LABELS.get(section.domain, section.domain),
                    "Topic": section.topic,
                    "Confidence": section.topic_confidence,
                    "Words": section.word_count,
                }
                for section in result.sections
            ],
            width="stretch",
            hide_index=True,
        )

    with tabs[5]:
        paths = save_outputs(result, cfg)
        st.caption(f"Saved to {paths['report'].parent}")
        e1, e2, e3 = st.columns(3)
        e1.download_button("Export report (.md)", data=result.report_markdown,
                           file_name=paths["report"].name, mime="text/markdown", width="stretch")
        e2.download_button("Download JSON bundle",
                           data=json.dumps(result.to_dict(), indent=2, default=str),
                           file_name=paths["audit"].name, mime="application/json", width="stretch")
        e3.download_button("Export findings (.csv)", data=findings_csv(findings),
                           file_name=paths["report"].with_suffix(".csv").name, mime="text/csv",
                           width="stretch")
        st.caption("The JSON bundle holds findings, sections and the full reasoning trail.")


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:

    initialise_session_state()

    load_custom_css()

    domains = render_sidebar()

    render_header()

    stepper_slot = st.empty()

    section_header(
        "Step 1 · Intake",
        "Upload architecture document",
        "Analyze architecture documents. Get findings with evidence and "
        "verification. Runs on this machine; nothing is sent anywhere.",
    )

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
            "Drag a document here or browse · .md .pdf .docx .txt .yaml .json · max 10 MB",
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

        tags = "".join(
            f'<span class="tag">{esc(DOMAIN_LABELS.get(domain, domain))} <b>{count}</b></span>'
            for domain, count in sorted(summary.items())
        )
        html_block(f"""
        <div class="doc-card">
          <div>
            <div class="doc-name">{esc(document_name or "Pasted design")}</div>
            <div class="doc-sub">{len(sections)} sections parsed and classified</div>
          </div>
          <div class="doc-tags">{tags}</div>
        </div>
        """)

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
                    "Approve and continue to AI review",
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
                    "Pre-flight checkpoint approved",
                    expanded=False,
                ):

                    st.success(
                        "Document approved for AI review."
                    )

                    st.caption(
                        f"{len(sections)} sections ready for Layer 2."
                    )

                    if st.button(
                        "Reopen checkpoint",
                        key="reopen_checkpoint",
                    ):

                        st.session_state.checkpoint_approved = False
                        st.session_state.checkpoint_signature = None

                        st.rerun()

                section_header(
                    "Step 3 · AI review",
                    "Standards-grounded review",
                    "The model reviews each in-scope section against your "
                    "standards library. Expect a few minutes per document.",
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
        "Run architecture review",
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

        tracker = ProgressTracker(document_name or "design")
        tracker.start("parse")
        tracker.finish("parse")
        tracker.start("rules")

        agent = ReviewAgent(
            config=get_config(),
            kb=get_kb(),
        )
        agent.progress = tracker.on_agent_progress

        # --------------------------------------------------------------
        # REVIEW
        # --------------------------------------------------------------

        try:

            st.session_state.result = agent.review(
                sections,
                document_name or "design",
                domains,
            )
            st.session_state.stage_times = tracker.durations()

        except Exception as exc:

            tracker.fail(str(exc))

            st.error(
                f"Review failed: {exc}"
            )

            st.exception(exc)

            return

        finally:

            tracker.clear()

    # ==================================================================
    # RESULT
    # ==================================================================

    if st.session_state.result:

        st.divider()

        render_result(
            st.session_state.result
        )

    # ------------------------------------------------------------------
    # STEPPER (drawn last, shown first)
    # ------------------------------------------------------------------

    if st.session_state.result:
        step = 3
    elif checkpoint_approved:
        step = 2
    elif sections:
        step = 1
    else:
        step = 0

    render_stepper(step, stepper_slot)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
