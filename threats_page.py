"""Threats page - run the threat model agent on the approved DFD and review it.

Kept out of app.py; app.py passes in its shared UI helpers.
"""

from __future__ import annotations

import csv
import io
from typing import Callable, List

import streamlit as st

from src import dfd as D
from src import threat_agent as TA

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
STATUS_LABEL = {"open": "Open", "accepted": "✓ Accepted", "disputed": "✗ Disputed",
                "mitigated": "Mitigated"}


def _frameworks(choice: str) -> List[str]:
    return ["STRIDE", "MAESTRO"] if choice == "Both" else [choice]


def _jira_csv(run: TA.ThreatModelRun) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Summary", "Description", "Priority", "Labels"])
    prio = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    for t in run.threats:
        if t.status in ("disputed", "mitigated"):
            continue
        desc = (f"{t.description}\n\nElement: {t.target_label}"
                + (f"\nTrust boundary: {t.boundary}" if t.boundary else "")
                + "\n\nMitigations:\n" + "\n".join(f"- {m}" for m in t.mitigations)
                + f"\n\nSource: Archeo threat model {t.id} ({t.framework} · {t.category}), "
                  f"DFD v{run.dfd_version}")
        w.writerow([f"[{t.id}] {t.title}", desc, prio.get(t.risk, "Medium"),
                    f"threat-model {t.framework.lower()}"])
    return buf.getvalue()


def render(result, *, section_header: Callable, empty_state: Callable, esc: Callable,
           get_config: Callable, switch_to_dfd: Callable, merge_findings: Callable) -> None:
    if not result:
        empty_state("Threats")
        return
    section_header("Threat model", f"Threats · {esc(result.document_name)}",
                   "STRIDE and/or MAESTRO threats for the approved DFD. Rule threats come "
                   "from facts the engineer confirmed; model threats count only once accepted.")
    dfd = st.session_state.get(f"dfd::{result.document_name}") or D.load_latest(result.document_name)
    if dfd is None or not dfd.version:
        st.info("Approve a DFD first — threat modeling runs only on an approved version.")
        if st.button("Open DFD editor", type="primary"):
            switch_to_dfd()
        return
    if dfd.status != "approved":
        st.warning(f"The DFD has unapproved edits since v{dfd.version}. Threats below use "
                   f"v{dfd.version}; approve the new draft to model it.", icon="⚠️")

    runs = TA.load_runs(result.document_name)
    fw_default = st.session_state.get(f"threat_framework::{dfd.document}",
                                      "Both" if dfd.has_ai_components() else "STRIDE")
    c1, c2, c3 = st.columns([1.6, 1, 1])
    choice = c1.radio("Framework", ("STRIDE", "MAESTRO", "Both"),
                      index=("STRIDE", "MAESTRO", "Both").index(fw_default), horizontal=True,
                      key="tm_framework")
    in_scope = TA.applicability(dfd)
    est = min(len(in_scope), TA.MAX_LLM_TARGETS)
    c2.metric("Elements in scope", len(in_scope),
              help="Boundary-crossing flows, components that touch them, and AI components.")
    run_clicked = c3.button("Run threat model" if not runs else "Replay threat model",
                            type="primary", width="stretch",
                            help=f"~{est} local model calls; roughly {max(1, est // 2)}–{est} min.")
    if choice == "MAESTRO" and not dfd.has_ai_components():
        st.caption("⚠️ No AI components in this DFD — MAESTRO will find nothing to model.")

    if run_clicked:
        approved = D.DFD.from_dict(dfd.to_dict())
        if approved.status != "approved":        # model the last approved version
            v = dict(D.list_versions(dfd.document))[dfd.version]
            approved = D.DFD.from_dict(__import__("json").loads(v.read_text(encoding="utf-8")))
        cfg = get_config()
        with st.status("Threat modeling on the local model…", expanded=True) as box:
            bar = st.progress(0.0)
            line = st.empty()

            def progress(msg: str, frac: float) -> None:
                bar.progress(min(1.0, frac))
                line.caption(msg)
            try:
                run = TA.run_threat_model(approved, TA.build_threat_llm(cfg), _frameworks(choice),
                                          model_name=str(cfg.models.get("threat_model")
                                                         or cfg.models["llm"]),
                                          progress=progress)
            except Exception as exc:  # noqa: BLE001
                box.update(label=f"Threat modeling failed: {exc}", state="error")
                return
            TA.save_run(run)
            box.update(label=f"{len(run.threats)} threats in {run.seconds:.0f}s "
                             f"({run.llm_calls} model calls, {run.llm_errors} failed)",
                       state="complete", expanded=False)
        st.rerun()

    if not runs:
        st.caption("No threat model yet for this document.")
        return
    labels = [f"DFD v{r.dfd_version} · {' + '.join(r.frameworks)} · {r.finished_at[:16]}"
              for r in runs]
    idx = st.selectbox("Run", range(len(runs)), index=len(runs) - 1,
                       format_func=lambda i: labels[i])
    run = runs[idx]
    if run.targets_skipped:
        st.caption(f"⚠️ {run.targets_skipped} lower-priority elements were not sent to the "
                   f"model (cap {TA.MAX_LLM_TARGETS}).")

    counts = {r: sum(1 for t in run.threats if t.risk == r) for r in RISK_ORDER}
    k = st.columns(5)
    k[0].metric("Threats", len(run.threats))
    for col, r in zip(k[1:], RISK_ORDER):
        col.metric(r.title(), counts[r])

    f1, f2, f3 = st.columns(3)
    risk_f = f1.multiselect("Risk", RISK_ORDER, default=RISK_ORDER, key="tm_risk")
    fw_f = f2.multiselect("Framework", run.frameworks, default=run.frameworks, key="tm_fw")
    src_f = f3.multiselect("Source", ["rule", "llm"], default=["rule", "llm"], key="tm_src")
    shown = [t for t in run.threats if t.risk in risk_f and t.framework in fw_f
             and t.source in src_f]

    left, right = st.columns([1.5, 1])
    with left:
        ev = st.dataframe(
            [{"ID": t.id, "Risk": t.risk, "Category": f"{t.framework} · {t.category}",
              "Element": t.target_label, "Threat": t.title,
              "Source": "📐 rule" if t.source == "rule" else "🤖 model",
              "Status": STATUS_LABEL.get(t.status, t.status)} for t in shown],
            hide_index=True, width="stretch", height=480, on_select="rerun",
            selection_mode="single-row", key="tm_table")
    with right:
        rows = ev.selection.rows if ev else []
        if not rows:
            st.caption("Select a threat to see details, mitigations and to accept or dispute it.")
        else:
            t = shown[rows[0]]
            st.markdown(f"**{t.id} · {t.title}**")
            st.caption(f"{t.risk} · {t.framework} · {t.category} · likelihood {t.likelihood}, "
                       f"impact {t.impact}")
            st.caption(f"Element: {t.target_label}" + (f" · boundary {t.boundary}" if t.boundary else ""))
            st.write(t.description)
            if t.mitigations:
                st.markdown("**Mitigations**\n" + "\n".join(f"- {m}" for m in t.mitigations))
            note = st.text_input("Note", value=t.reviewer_note, key=f"tm_note_{run.dfd_version}_{t.id}")
            b1, b2, b3 = st.columns(3)
            for col, status, label in ((b1, "accepted", "Accept"), (b2, "disputed", "Dispute"),
                                       (b3, "mitigated", "Mitigated")):
                if col.button(label, key=f"tm_{status}_{t.id}", width="stretch",
                              type="primary" if status == "accepted" else "secondary"):
                    t.status, t.reviewer_note = status, note
                    TA.save_run(run)
                    st.rerun()

    st.divider()
    e1, e2 = st.columns(2)
    e1.download_button("Export mitigations (Jira CSV)", _jira_csv(run),
                       file_name=f"{D.slug(run.document)}-threats-v{run.dfd_version}.csv",
                       mime="text/csv", width="stretch")
    confirmed = TA.to_findings(run)
    if e2.button(f"Add {len(confirmed)} confirmed threats to Findings", width="stretch",
                 disabled=not confirmed,
                 help="Rule threats plus threats you accepted join the findings and risk score."):
        added = merge_findings(confirmed)
        st.toast(f"{added} threat(s) added to Findings")
