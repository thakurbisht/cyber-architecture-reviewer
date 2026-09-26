"""Streamlit UI for the Cyber Architecture Reviewer.

This file contains no review logic. It uploads a document, calls the review
pipeline, and renders the result. Everything it knows about reviewing comes
from src/. That separation is deliberate: the same pipeline runs from the CLI
and from CI with no UI code involved.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))

from src.agent import ReviewAgent
from src.config import load_config
from src.domains import DOMAIN_LABELS
from src.llm import check_ollama
from src.models import SEVERITIES
from src.parser import SUPPORTED_SUFFIXES, parse_text, read_document, summarise_sections
from src.report import save_outputs
from src.retriever import KnowledgeBase
from src.rules import rules_summary

st.set_page_config(
    page_title="Cyber Architecture Reviewer",
    page_icon="🛡️",
    layout="wide",
)

SEV_COLOUR = {
    "CRITICAL": "#b3261e",
    "HIGH": "#c9741a",
    "MEDIUM": "#8a7a12",
    "LOW": "#4a6572",
}
RAG_COLOUR = {"RED": "#b3261e", "AMBER": "#c9741a", "GREEN": "#2e7d32"}


# ==========================================================================
# Cached resources
# ==========================================================================
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
    except Exception as exc:  # noqa: BLE001
        return {"counts": {}, "total": 0, "warnings": [str(exc)],
                "embedding_model": "unknown"}


@st.cache_data(ttl=30, show_spinner=False)
def get_ollama_status():
    return check_ollama(get_config())


# ==========================================================================
# Sidebar - system health
# ==========================================================================
def render_sidebar() -> list[str]:
    cfg = get_config()
    st.sidebar.title("🛡️ Reviewer")
    st.sidebar.caption("Local-first architecture assurance")

    st.sidebar.subheader("Review domains")
    selected: list[str] = []
    for key in ("network", "application", "security", "cloud_data"):
        default = cfg.raw["domains"].get(key, True)
        if st.sidebar.checkbox(DOMAIN_LABELS[key], value=default, key=f"dom_{key}"):
            selected.append(key)

    st.sidebar.divider()
    st.sidebar.subheader("System status")

    ollama = get_ollama_status()
    if ollama["reachable"]:
        if ollama["missing_models"]:
            st.sidebar.error(
                "Ollama is running but these models are not pulled: "
                + ", ".join(ollama["missing_models"])
            )
            st.sidebar.code(
                "\n".join(f"ollama pull {m}" for m in ollama["missing_models"]),
                language="bash",
            )
        else:
            st.sidebar.success(f"Ollama ready · {ollama['llm']}")
    else:
        st.sidebar.error("Ollama unreachable")
        st.sidebar.caption(ollama.get("error", "")[:200])
        st.sidebar.code("ollama serve", language="bash")

    kb = get_kb_status()
    total = kb.get("total", 0)
    if total:
        st.sidebar.success(f"Knowledge base · {total} clauses")
    else:
        st.sidebar.error("Knowledge base is empty")
        st.sidebar.code("python scripts/seed_kb.py", language="bash")

    with st.sidebar.expander("Clauses by domain"):
        for domain, count in kb.get("counts", {}).items():
            st.write(f"**{DOMAIN_LABELS.get(domain, domain)}** — {count}")
        st.caption(f"Embedding model: `{kb.get('embedding_model')}`")

    with st.sidebar.expander("Deterministic rules"):
        for domain, count in rules_summary().items():
            st.write(f"**{DOMAIN_LABELS.get(domain, domain)}** — {count} rules")
        st.caption("These run before the model and produce identical findings "
                   "on every run.")

    for warning in kb.get("warnings", []):
        st.sidebar.warning(warning)

    st.sidebar.divider()
    st.sidebar.caption(
        "Read and flag only. This tool has no write access to any system and "
        "does not approve or reject designs."
    )
    return selected


# ==========================================================================
# Result rendering
# ==========================================================================
def render_result(result) -> None:
    counts = result.counts_by_severity()

    c1, c2, c3, c4 = st.columns([1.4, 1, 1, 1])
    with c1:
        colour = RAG_COLOUR.get(result.rag_status, "#555")
        st.markdown(
            f"<div style='padding:14px 18px;border-radius:10px;"
            f"background:{colour};color:white;'>"
            f"<div style='font-size:12px;opacity:.85;letter-spacing:.08em;'>"
            f"ASSURANCE STATUS</div>"
            f"<div style='font-size:30px;font-weight:700;line-height:1.2;'>"
            f"{result.rag_status}</div>"
            f"<div style='font-size:12px;opacity:.9;'>risk score "
            f"{result.risk_score}/100</div></div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.metric("Findings", len(result.findings))
    with c3:
        st.metric("Critical", counts.get("CRITICAL", 0))
    with c4:
        st.metric("Sections analysed", len(result.sections))

    st.write("")
    sev_cols = st.columns(4)
    for col, sev in zip(sev_cols, SEVERITIES):
        col.markdown(
            f"<div style='border-left:4px solid {SEV_COLOUR[sev]};"
            f"padding:6px 12px;'><b>{counts.get(sev, 0)}</b> "
            f"<span style='font-size:12px;color:#666;'>{sev}</span></div>",
            unsafe_allow_html=True,
        )

    for warning in result.warnings:
        st.warning(warning)

    tabs = st.tabs(["Report", "Findings", "Audit trail", "Section map", "Export"])

    with tabs[0]:
        st.markdown(result.report_markdown)

    with tabs[1]:
        if not result.findings:
            st.info("No findings were raised.")
        else:
            sev_filter = st.multiselect("Severity", SEVERITIES, default=list(SEVERITIES))
            dom_filter = st.multiselect(
                "Domain",
                sorted({f.domain for f in result.findings}),
                default=sorted({f.domain for f in result.findings}),
                format_func=lambda d: DOMAIN_LABELS.get(d, d),
            )
            only_grounded = st.checkbox(
                "Only findings cited to a knowledge base clause", value=False)

            shown = [
                f for f in result.findings
                if f.severity in sev_filter and f.domain in dom_filter
                and (f.is_grounded or not only_grounded)
            ]
            st.caption(f"{len(shown)} of {len(result.findings)} findings")

            for f in shown:
                label = (f"{f.severity} · {f.section[:60]} · {f.issue[:90]}")
                with st.expander(label):
                    st.markdown(f"**Issue.** {f.issue}")
                    st.markdown(f"**Recommendation.** {f.recommendation}")
                    if f.standard_reference:
                        st.markdown(f"**Standard.** {f.standard_reference}"
                                    + (f" — `{f.kb_source}`" if f.kb_source else ""))
                    else:
                        st.caption("No knowledge base clause cited — this "
                                   "reflects general practice, not your "
                                   "organisation's standard.")
                    if f.evidence_excerpt:
                        st.markdown("**Evidence from the design**")
                        st.code(f.evidence_excerpt, language=None)
                    if f.control_mappings:
                        st.markdown("**Controls.** " + ", ".join(f.control_mappings))
                    st.caption(
                        f"Provenance: {f.origin}"
                        + (f" ({f.rule_id})" if f.rule_id else "")
                        + f" · confidence {f.confidence} · id {f.fingerprint}"
                    )

    with tabs[2]:
        st.caption("Every retrieval, tool call and model decision in this run. "
                   "If a finding cannot be explained from this trail, it should "
                   "not be acted on.")
        from src.audit import AuditTrail
        trail = AuditTrail()
        trail.extend(result.audit)
        st.markdown(trail.render_markdown(limit=300))

    with tabs[3]:
        st.caption("How each section of your document was classified. Low "
                   "confidence means the classifier was unsure which lens to "
                   "apply — check those sections manually.")
        rows = [
            {
                "Section": s.heading,
                "Domain": DOMAIN_LABELS.get(s.domain, s.domain),
                "Topic": s.topic,
                "Confidence": s.topic_confidence,
                "Words": s.word_count,
            }
            for s in result.sections
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

    with tabs[4]:
        paths = save_outputs(result, get_config())
        st.success(f"Saved to `{paths['report'].parent}`")
        st.download_button(
            "Download report (Markdown)",
            data=result.report_markdown,
            file_name=paths["report"].name,
            mime="text/markdown",
        )
        st.download_button(
            "Download audit bundle (JSON)",
            data=json.dumps(result.to_dict(), indent=2, default=str),
            file_name=paths["audit"].name,
            mime="application/json",
        )
        st.caption("The audit bundle contains every finding, every section, and "
                   "the full reasoning trail. Retain it with the design "
                   "authority record.")


# ==========================================================================
# Main
# ==========================================================================
def main() -> None:
    domains = render_sidebar()

    st.title("Cyber Architecture Reviewer")
    st.caption(
        "End-to-end design assurance across network, application, security and "
        "cloud architecture. Findings cite your standards, not generic guidance."
    )

    if "result" not in st.session_state:
        st.session_state.result = None

    mode = st.radio("Input", ["Upload a document", "Paste text"],
                    horizontal=True, label_visibility="collapsed")

    text = ""
    document_name = ""

    if mode == "Upload a document":
        uploaded = st.file_uploader(
            "HLD, LLD, application design, OpenAPI spec or IaC definition",
            type=[s.lstrip(".") for s in sorted(SUPPORTED_SUFFIXES)],
        )
        if uploaded:
            tmp_dir = Path("data/uploads")
            tmp_dir.mkdir(parents=True, exist_ok=True)
            tmp = tmp_dir / uploaded.name
            tmp.write_bytes(uploaded.getbuffer())
            try:
                text = read_document(tmp)
                document_name = uploaded.name
            except Exception as exc:  # noqa: BLE001
                st.error(f"Could not read that file: {exc}")
    else:
        text = st.text_area("Paste the design content", height=280)
        document_name = st.text_input("Document name", value="pasted-design")

    if text:
        sections = parse_text(text, document_name or "design")
        summary = summarise_sections(sections)
        st.info(
            f"Parsed **{len(sections)} sections** — "
            + " · ".join(f"{DOMAIN_LABELS.get(d, d)}: {n}"
                         for d, n in sorted(summary.items()))
        )

    disabled = not text or not domains
    if not domains:
        st.warning("Select at least one review domain in the sidebar.")

    if st.button("Run review", type="primary", disabled=disabled):
        ollama = get_ollama_status()
        if not ollama["reachable"]:
            st.error("Ollama is not reachable. Start it with `ollama serve` "
                     "and reload this page.")
            return
        if ollama["missing_models"]:
            st.error("Pull the required models first: "
                     + ", ".join(ollama["missing_models"]))
            return

        sections = parse_text(text, document_name or "design")
        progress = st.progress(0.0, text="Starting")
        started = time.time()

        agent = ReviewAgent(config=get_config(), kb=get_kb())
        agent.progress = lambda stage, pct: progress.progress(
            pct, text=f"{stage} — {int(time.time() - started)}s")

        try:
            st.session_state.result = agent.review(
                sections, document_name or "design", domains)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Review failed: {exc}")
            st.exception(exc)
            return
        finally:
            progress.empty()

    if st.session_state.result:
        st.divider()
        render_result(st.session_state.result)


if __name__ == "__main__":
    main()
