"""HLD vs LLD page - did the detailed design build what the HLD promised?

Deliberately self-contained: you give it two documents and it answers one
question. It does not need a review to have been run first, because the
question is asked between the two gates, not inside either of them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, List

import streamlit as st

from src import consistency as C
from src.parser import SUPPORTED_SUFFIXES, parse_document, parse_text

VERDICT = {
    "contradicted": ("🔴 Contradicted", "The LLD conflicts with the commitment"),
    "missing": ("🟠 Not addressed", "The LLD never speaks to it"),
    "unclear": ("🟡 Unclear", "The LLD touches it but does not say enough"),
    "implemented": ("🟢 Implemented", "The LLD shows the control"),
}
STORE = Path("data/consistency")


def _save(key: str, checks: List[C.ControlCheck]) -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    (STORE / f"{key}.json").write_text(
        json.dumps([c.to_dict() for c in checks], indent=1), encoding="utf-8")


def _upload(label: str, slot: str, help_text: str):
    """Return parsed sections for one side, or None."""
    tab_file, tab_text = st.tabs(["Upload", "Paste"])
    with tab_file:
        up = st.file_uploader(label, key=f"cons_{slot}_file",
                              type=[s.lstrip(".") for s in sorted(SUPPORTED_SUFFIXES)],
                              help=help_text)
        if up is not None:
            tmp = Path("data/uploads")
            tmp.mkdir(parents=True, exist_ok=True)
            path = tmp / up.name
            path.write_bytes(up.getvalue())
            try:
                return parse_document(path), up.name
            except Exception as exc:  # noqa: BLE001
                st.error(f"Could not read {up.name}: {exc}")
                return None, ""
    with tab_text:
        text = st.text_area(f"Paste the {slot.upper()}", key=f"cons_{slot}_text",
                            height=160)
        if text.strip():
            return parse_text(text, f"{slot}-pasted"), f"{slot}-pasted"
    return None, ""


def render(*, section_header: Callable, esc: Callable, get_config: Callable,
           merge_findings: Callable | None = None) -> None:
    section_header(
        "HLD vs LLD", "Commitment check",
        "Reviewing each document alone answers 'is this one sound?'. This answers "
        "the other question: the HLD committed to a control — did the detailed "
        "design implement it? Commitments are extracted by rule; only the "
        "verdict is the model's, and its quote is checked against the LLD.")

    left, right = st.columns(2)
    with left:
        st.markdown("**1 · High level design**")
        hld, hld_name = _upload("HLD", "hld", "The design that made the commitments.")
    with right:
        st.markdown("**2 · Low level design**")
        lld, lld_name = _upload("LLD", "lld", "The detailed design to check against it.")

    if not hld or not lld:
        st.caption("Give it both documents to run the check.")
        return

    key = f"{hld_name}__{lld_name}".replace("/", "_")[:120]
    claims = C.extract_claims(hld)
    st.caption(f"**{len(claims)} commitments** found in {esc(hld_name)} · "
               f"checking against {len(lld)} LLD sections")
    if not claims:
        st.warning("No control commitments found in the HLD. Either it is not a "
                   "design document, or it describes the system without committing "
                   "to any controls.")
        return

    with st.expander(f"The HLD's control register · {len(claims)}"):
        st.dataframe(
            [{"ID": c.id, "Control": c.label, "Strength": c.strength,
              "Section": c.section, "Commitment": c.text} for c in claims],
            hide_index=True, width="stretch",
            column_config={"Commitment": st.column_config.TextColumn(width="large")})

    runs = st.session_state.setdefault("consistency_runs", {})
    if key not in runs and st.button(
            f"Check {len(claims)} commitments", type="primary",
            help=f"About {len(claims) * 3}s on this machine"):
        box = st.status("Checking the LLD…", expanded=True)
        try:
            llm = C.build_consistency_llm(get_config())
            checks = C.check_claims(claims, lld, llm, progress=box.write)
            runs[key] = checks
            _save(key, checks)
            s = C.summary(checks)
            box.update(label=f"{s['contradicted']} contradicted · {s['missing']} not "
                             f"addressed · {s['implemented']} implemented",
                       state="complete")
        except Exception as exc:  # noqa: BLE001
            box.update(label=f"Check failed: {exc}", state="error")
        st.rerun()

    checks = runs.get(key)
    if not checks:
        return

    s = C.summary(checks)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Contradicted", s["contradicted"])
    c2.metric("Not addressed", s["missing"])
    c3.metric("Unclear", s["unclear"])
    c4.metric("Implemented", f"{s['implemented']} / {s['commitments']}")
    st.progress(s["coverage"],
                text=f"{s['coverage']:.0%} of the HLD's commitments verified in the LLD")

    show = st.multiselect("Show", list(VERDICT), key="cons_filter",
                          default=["contradicted", "missing", "unclear"],
                          format_func=lambda v: VERDICT[v][0])
    rows = [c for c in checks if c.status in show]
    order = {v: i for i, v in enumerate(VERDICT)}
    rows.sort(key=lambda c: (order.get(c.status, 9),
                             c.claim.strength != "mandatory", c.claim.id))

    for ch in rows:
        icon, _ = VERDICT.get(ch.status, (ch.status, ""))
        with st.container(border=True):
            st.markdown(f"**{icon} · {ch.claim.label}** · `{ch.claim.id}`"
                        + ("  ·  *mandatory*" if ch.claim.strength == "mandatory" else ""))
            st.markdown(f"**HLD** ({esc(ch.claim.section)}) — “{esc(ch.claim.text)}”")
            if ch.evidence:
                st.markdown(f"**LLD** ({esc(ch.lld_section)}) — “{esc(ch.evidence)}”")
            elif ch.status == "missing":
                st.caption("Nothing in the LLD speaks to this.")
            if ch.reason:
                st.caption(esc(ch.reason))

    findings = C.to_findings(checks)
    defects = [f for f in findings if f.kind == "finding"]
    if findings:
        st.divider()
        st.caption(f"{len(defects)} of these would be raised as findings and "
                   f"{len(findings) - len(defects)} as questions for the author.")
        if merge_findings is not None and st.button(
                f"Add {len(findings)} items to the review queue"):
            added = merge_findings(findings)
            st.toast(f"Added {added} item(s)")
