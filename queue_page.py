"""Review queue page - findings and threats in one list (src/review_queue.py).

Kept out of app.py; app.py passes in its shared UI helpers.
"""

from __future__ import annotations

from typing import Callable

import streamlit as st

from src import dfd as D
from src import review_queue as Q
from src import threat_agent as TA
from src.feedback import DISPUTE_REASONS, latest_decisions, record_decision

SOURCE_LABEL = {"rule": "📐 rule", "threat-rule": "📐 DFD rule", "model": "🤖 model",
                "threat-model": "🤖 threat model"}
STATUS_LABEL = {"open": "Open", "accepted": "✓ Accepted", "disputed": "✗ Disputed",
                "mitigated": "Mitigated"}


def render(result, *, section_header: Callable, empty_state: Callable, esc: Callable,
           review_key_of: Callable, render_questions: Callable) -> None:
    if not result or not getattr(result, "findings", None) and not TA.load_runs(
            review_key_of(result)):
        empty_state("Review queue")
        return
    rk = review_key_of(result)
    runs = TA.load_runs(rk)
    dfd = D.approved_version(rk) or D.load_latest(rk)
    findings = list(getattr(result, "findings", []) or [])
    items = Q.build_queue(findings, latest_decisions(rk), runs, dfd)
    counts = Q.summary(items)
    done = len(items) - counts["open"]
    section_header("Review queue", f"{len(items)} items · {esc(result.document_name)}",
                   "Findings and threats in one list, duplicates merged. Rule-based items "
                   "(most reliable) come first. Select one or many rows and decide once.")
    st.progress(done / len(items) if items else 1.0,
                text=f"{done} of {len(items)} decided · {counts['accepted']} accepted · "
                     f"{counts['disputed']} disputed · {counts['mitigated']} mitigated")

    c1, c2, c3, c4 = st.columns([1.1, 1.3, 1.2, 1.4])
    status_f = c1.multiselect("Status", list(STATUS_LABEL), default=["open"],
                              format_func=STATUS_LABEL.get, key="q_status")
    source_f = c2.multiselect("Source", list(SOURCE_LABEL), default=list(SOURCE_LABEL),
                              format_func=SOURCE_LABEL.get, key="q_source")
    sev_f = c3.multiselect("Severity", Q.ORDER, default=Q.ORDER, key="q_sev")
    query = c4.text_input("Search", key="q_search", placeholder="Title, section, element")
    q = query.strip().lower()
    shown = [i for i in items if i.status in status_f and i.source in source_f
             and i.severity in sev_f and (not q or q in f"{i.title} {i.where}".lower())]

    left, right = st.columns([1.55, 1])
    with left:
        ev = st.dataframe(
            [{"Severity": i.severity, "Title": i.title, "Where": i.where,
              "Source": SOURCE_LABEL[i.source], "Status": STATUS_LABEL.get(i.status, i.status),
              "Merged": f"+{len(i.merged)}" if i.merged else ""} for i in shown],
            hide_index=True, width="stretch", height=520, on_select="rerun",
            selection_mode="multi-row", key="q_table",
            column_config={"Title": st.column_config.TextColumn(width="large"),
                           "Severity": st.column_config.TextColumn(width="small"),
                           "Merged": st.column_config.TextColumn(width="small")})
    rows = ev.selection.rows if ev else []
    selected = [shown[r] for r in rows if r < len(shown)]
    with right:
        if not selected:
            st.caption("Select rows (tick the header box to select all shown) to accept, "
                       "dispute or mark mitigated in one go.")
        else:
            if len(selected) == 1:
                it = selected[0]
                st.markdown(f"**{it.title}**")
                st.caption(f"{it.severity} · {SOURCE_LABEL[it.source]} · {it.where}"
                           + (f" · {it.reference}" if it.reference else ""))
                if it.evidence:
                    st.markdown(f"> {it.evidence[:500]}")
                if it.recommendation:
                    st.markdown(f"**Recommendation.** {it.recommendation}")
                if it.merged:
                    st.caption(f"Also stands for {len(it.merged)} duplicate(s) from the "
                               "other source — one decision applies to all.")
            else:
                st.markdown(f"**{len(selected)} items selected**")
            with st.form("q_decide", border=True):
                reason = st.selectbox("If disputing, why?", ("",) + DISPUTE_REASONS,
                                      format_func=lambda r: r or "Choose a reason")
                note = st.text_input("Note (optional)")
                reviewer = st.text_input("Reviewer", value=st.session_state.get("reviewer_name", ""))
                b1, b2, b3 = st.columns(3)
                acc = b1.form_submit_button("Accept", type="primary", width="stretch")
                dis = b2.form_submit_button("Dispute", width="stretch")
                mit = b3.form_submit_button("Mitigated", width="stretch")
            if acc or dis or mit:
                if dis and not reason:
                    st.error("Choose a reason to dispute.")
                else:
                    st.session_state.reviewer_name = reviewer
                    decision = "accepted" if acc else "disputed" if dis else "mitigated"
                    fps = {f.fingerprint: f for f in findings}
                    by_v = {r.dfd_version: r for r in runs}
                    n = sum(Q.apply_decision(it, decision, findings_by_fp=fps,
                                             runs_by_version=by_v, review_key=rk,
                                             reason=reason, note=note, reviewer=reviewer,
                                             record=record_decision, save_run=TA.save_run)
                            for it in selected)
                    st.toast(f"{decision.title()}: {n} record(s)")
                    st.rerun()
    render_questions(result)
