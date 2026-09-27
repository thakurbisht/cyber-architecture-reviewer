"""Prelim report page - the Stage 1 register for stakeholders and Archer.

Kept out of app.py; app.py passes in its shared UI helpers.
"""

from __future__ import annotations

from datetime import date
from typing import Callable

import pandas as pd
import streamlit as st

from src import dfd as D
from src import prelim_report as P
from src import threat_agent as TA
from src.feedback import latest_decisions

RATINGS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def render(result, *, section_header: Callable, empty_state: Callable, esc: Callable,
           get_config: Callable) -> None:
    if not result:
        empty_state("Prelim report")
        return
    cfg = get_config()
    settings = P.export_settings(cfg)
    doc = getattr(result, "review_key", "") or result.document_name
    section_header("Preliminary review", f"Prelim report · {esc(result.document_name)}",
                   "The register that goes to stakeholders and into Archer: Domain, Threat, "
                   "Risk, Risk Rating, Cyber Recommendation — built only from items you "
                   "confirmed. IDs stay fixed so the final (as-built) review can verify each row.")

    key = f"prelim::{doc}"
    if key not in st.session_state:
        st.session_state[key] = P.load(doc)
    reg: P.PrelimRegister = st.session_state[key]

    c1, c2, c3 = st.columns([1.6, 1, 1])
    include = c1.radio("Include", ("accepted", "confirmed"), horizontal=True,
                       format_func=lambda x: {"accepted": "Only what I accepted",
                                              "confirmed": "Accepted + rule-based (not disputed)"}[x],
                       key=f"{key}_incl")
    if c2.button("Add confirmed items", type="primary", width="stretch"):
        fresh = P.candidates(result.findings, latest_decisions(doc), TA.load_runs(doc),
                             D.load_latest(doc), include=include)
        added = P.sync_register(reg, fresh)
        P.save(reg)
        st.toast(f"Added {len(added)} row(s)" if added else "Nothing new to add")
        st.rerun()
    if c3.button("Draft Risk + Acceptance (local AI)", width="stretch", disabled=not reg.rows,
                 help="Fills empty Risk and Acceptance Criteria cells. Rows you edited are never touched."):
        from src.threat_agent import build_threat_llm
        with st.spinner("Drafting risk statements and acceptance criteria…"):
            n = P.draft_risk_and_acceptance(reg.rows, build_threat_llm(cfg))
        P.save(reg)
        st.toast(f"Drafted {n} row(s)")
        st.rerun()

    if not reg.rows:
        st.info("No rows yet. Accept findings on the **Findings** page and threats on the "
                "**Threats** page, then click **Add confirmed items**.")
        return

    labels = settings["domains"]
    df = pd.DataFrame([{
        "Remove": False, "ID": r.id, "Domain": labels.get(r.domain, r.domain),
        "Threat": r.threat_specific or r.threat, "Risk": r.risk, "Risk Rating": r.rating,
        "Cyber Recommendation": r.recommendation_specific or r.recommendation, "Acceptance Criteria": r.acceptance,
        "Source": f"{r.source} · {r.section}"[:80]} for r in reg.rows])
    edited = st.data_editor(
        df, hide_index=True, width="stretch", num_rows="fixed", key=f"{key}_editor",
        column_config={
            "Remove": st.column_config.CheckboxColumn(width="small"),
            "ID": st.column_config.TextColumn(disabled=True, width="small"),
            "Domain": st.column_config.SelectboxColumn(options=list(labels.values()), width="small"),
            "Risk Rating": st.column_config.SelectboxColumn(options=RATINGS, width="small"),
            "Threat": st.column_config.TextColumn(width="large"),
            "Risk": st.column_config.TextColumn(width="large"),
            "Cyber Recommendation": st.column_config.TextColumn(width="large"),
            "Acceptance Criteria": st.column_config.TextColumn(width="large"),
            "Source": st.column_config.TextColumn(disabled=True),
        })
    to_key = {v: k for k, v in labels.items()}
    changed = False
    keep = []
    for r, (_, row) in zip(reg.rows, edited.iterrows()):
        if row["Remove"]:
            changed = True
            continue
        # Compare against what the table SHOWED (specific text falls back to the
        # generic text), otherwise every untouched row looks edited and the AI
        # draft would skip it.
        shown = {"domain": r.domain, "threat_specific": r.threat_specific or r.threat,
                 "risk": r.risk, "rating": r.rating,
                 "recommendation_specific": r.recommendation_specific or r.recommendation,
                 "acceptance": r.acceptance}
        new = {"domain": to_key.get(row["Domain"], r.domain),
               "threat_specific": row["Threat"] or "", "risk": row["Risk"] or "",
               "rating": row["Risk Rating"],
               "recommendation_specific": row["Cyber Recommendation"] or "",
               "acceptance": row["Acceptance Criteria"] or ""}
        diff = {k: v for k, v in new.items() if v != shown[k]}
        if diff:
            for k, v in diff.items():
                setattr(r, k, v)
            r.edited = changed = True
        keep.append(r)
    if changed:
        reg.rows = keep            # removed IDs are not reused (next_id only grows)
        P.save(reg)
        st.caption("Saved.")

    counts = {r: sum(1 for x in reg.rows if x.rating == r) for r in RATINGS}
    missing = sum(1 for x in reg.rows if not x.risk or not x.acceptance)
    st.caption(f"{len(reg.rows)} rows · " + " · ".join(f"{k.title()} {v}" for k, v in counts.items())
               + (f" · ⚠️ {missing} row(s) missing Risk or Acceptance Criteria" if missing else ""))

    name = f"{D.slug(doc)}-prelim-review-{date.today().isoformat()}"
    e1, e2 = st.columns(2)
    e1.download_button("Download Excel for Archer (.xlsx)", P.to_xlsx(reg, settings),
                       file_name=f"{name}.xlsx", type="primary", width="stretch",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    e2.download_button("Download CSV", P.to_csv(reg, settings), file_name=f"{name}.csv",
                       mime="text/csv", width="stretch")
    st.caption("One sheet, one header row, one row per recommendation, no merged cells. Column "
               "names, rating values and domain values come from `archer_export` in config.yaml — "
               "set them to match your Archer field names and values lists exactly.")
