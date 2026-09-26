"""Report synthesis, risk scoring and export.

Scoring philosophy
------------------
The risk score is computed in Python, not by the model. A board-facing RAG
status must be reproducible and defensible: the same findings must always
produce the same status, and an architect must be able to recompute it by
hand from the findings table. Asking a language model to "decide RED or
AMBER" gives you a number nobody can audit and that moves between runs.

The model writes the narrative. Python decides the verdict.

Score = sum(severity weight) normalised against a saturation ceiling, so a
design with 40 LOW findings never outranks one with a single CRITICAL.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import Config, load_config
from .domains import DOMAIN_LABELS
from .models import (
    Finding,
    ORIGIN_CORRELATION,
    ORIGIN_RULES,
    ReviewResult,
    SEVERITIES,
    sort_findings,
)

SATURATION = 100.0   # score ceiling used for normalisation

RAG_MEANING = {
    "RED": "Do not approve. Critical defects must be remediated and the design re-submitted.",
    "AMBER": "Conditional approval. Implementation may begin only on workstreams unaffected by the open findings.",
    "GREEN": "Approved against the standards currently held in the knowledge base.",
}

ORIGIN_LABEL = {
    ORIGIN_RULES: "Rules engine (deterministic)",
    ORIGIN_CORRELATION: "Cross-domain pass",
    "agent": "Agent reasoning",
}


# ==========================================================================
# Scoring
# ==========================================================================
def compute_risk(findings: List[Finding], config: Optional[Config] = None
                 ) -> Tuple[float, str, Dict[str, int]]:
    """Return (normalised_score_0_100, rag_status, counts_by_severity)."""
    cfg = config or load_config()
    weights: Dict[str, int] = cfg.scoring["weights"]
    rag_cfg: Dict[str, object] = cfg.scoring["rag"]

    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    raw = sum(weights.get(sev, 0) * n for sev, n in counts.items())
    # Diminishing returns: the 6th HIGH matters less than the 1st for the
    # go/no-go decision, but must still move the number.
    score = round(min(SATURATION, SATURATION * (1 - pow(2.718281828, -raw / 60.0))), 1)

    red_at = float(rag_cfg.get("red_at_score", 40))
    amber_at = float(rag_cfg.get("amber_at_score", 12))
    critical_forces_red = bool(rag_cfg.get("critical_forces_red", True))

    if critical_forces_red and counts.get("CRITICAL", 0) > 0:
        rag = "RED"
    elif score >= red_at:
        rag = "RED"
    elif score >= amber_at:
        rag = "AMBER"
    else:
        rag = "GREEN"

    return score, rag, counts


def priority_actions(findings: List[Finding], limit: int = 3) -> List[Finding]:
    """The findings that must be closed before implementation proceeds.

    Ranked by severity, then by whether the finding is grounded in a cited
    standard (a citable finding is actionable in a governance forum, an
    uncited one invites debate), then by breadth of control impact.

    Distinct *problems* are preferred over distinct instances: three lines
    telling a board to fix hardcoded secrets in three different sections is
    one action, not three. Repeats are only used to fill the list if there
    are not enough distinct problems to fill it.
    """
    ranked = sorted(
        findings,
        key=lambda f: (
            SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9,
            0 if f.is_grounded else 1,
            -len(f.control_mappings),
        ),
    )

    def problem_key(f: Finding) -> str:
        return f.rule_id or f"{f.domain}:{f.issue.lower()[:80]}"

    top: List[Finding] = []
    seen: set[str] = set()
    for f in ranked:
        key = problem_key(f)
        if key in seen:
            continue
        seen.add(key)
        top.append(f)
        if len(top) == limit:
            return top

    for f in ranked:                      # backfill only if needed
        if f not in top:
            top.append(f)
        if len(top) == limit:
            break
    return top[:limit]


def coverage_by_domain(result: ReviewResult) -> Dict[str, Dict[str, int]]:
    """Sections analysed and findings raised per domain."""
    out: Dict[str, Dict[str, int]] = {}
    for s in result.sections:
        out.setdefault(s.domain, {"sections": 0, "findings": 0, "critical": 0})
        out[s.domain]["sections"] += 1
    for f in result.findings:
        out.setdefault(f.domain, {"sections": 0, "findings": 0, "critical": 0})
        out[f.domain]["findings"] += 1
        if f.severity == "CRITICAL":
            out[f.domain]["critical"] += 1
    return out


# ==========================================================================
# Markdown rendering
# ==========================================================================
def _esc(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _fallback_summary(result: ReviewResult, counts: Dict[str, int]) -> str:
    total = sum(counts.values())
    if total == 0:
        return (
            f"This review examined {len(result.sections)} sections of "
            f"{result.document_name} against the organisation's architectural "
            f"standards. No departures from those standards were identified. "
            f"The design is recommended for sign-off, subject to the caveat "
            f"that the review can only assess what the standards library "
            f"currently covers."
        )
    worst = "critical" if counts.get("CRITICAL") else "significant"
    return (
        f"This review examined {len(result.sections)} sections of "
        f"{result.document_name} against the organisation's architectural "
        f"standards and identified {total} departures, of which "
        f"{counts.get('CRITICAL', 0)} are critical and "
        f"{counts.get('HIGH', 0)} are high severity. The {worst} issues concern "
        f"the resilience and protection of the described solution and would "
        f"expose the organisation to service disruption or data loss if built "
        f"as documented. The overall assurance status is "
        f"{result.rag_status}. {RAG_MEANING.get(result.rag_status, '')}"
    )


def render_markdown(result: ReviewResult, config: Optional[Config] = None,
                    assurance_opinion: str = "") -> str:
    cfg = config or load_config()
    counts = result.counts_by_severity()
    findings = sort_findings(result.findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    badge = {"RED": "🔴 RED", "AMBER": "🟠 AMBER", "GREEN": "🟢 GREEN"}[result.rag_status]

    lines: List[str] = []
    lines.append(f"# Architecture Assurance Review: {result.document_name}")
    lines.append("")
    lines.append(f"**Status:** {badge} &nbsp;|&nbsp; "
                 f"**Risk score:** {result.risk_score}/100 &nbsp;|&nbsp; "
                 f"**Findings:** {len(findings)} &nbsp;|&nbsp; "
                 f"**Generated:** {now}")
    lines.append("")
    lines.append(f"**Domains reviewed:** " + ", ".join(
        DOMAIN_LABELS.get(d, d) for d in result.domains_reviewed))
    lines.append(f"**Sections analysed:** {len(result.sections)} &nbsp;|&nbsp; "
                 f"**Standards clauses available:** {result.kb_chunk_count}")
    lines.append("")
    lines.append("> This report is advisory. Every finding cites the clause it "
                 "rests on so a human architect can verify, accept, amend or "
                 "override it. The reviewer has read access only and cannot "
                 "change any system.")
    lines.append("")

    if result.warnings:
        lines.append("## ⚠ Review Caveats")
        lines.append("")
        for w in result.warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(result.executive_summary.strip()
                 or _fallback_summary(result, counts))
    lines.append("")

    lines.append("## Overall Status")
    lines.append("")
    lines.append(f"### {badge} — risk score {result.risk_score}/100")
    lines.append("")
    lines.append(RAG_MEANING.get(result.rag_status, ""))
    lines.append("")
    lines.append("| Severity | Count | Weight each | Contribution |")
    lines.append("|---|---:|---:|---:|")
    weights = cfg.scoring["weights"]
    for sev in SEVERITIES:
        n = counts.get(sev, 0)
        lines.append(f"| {sev} | {n} | {weights.get(sev, 0)} | "
                     f"{n * weights.get(sev, 0)} |")
    lines.append("")

    if assurance_opinion.strip():
        lines.append("## Assurance Opinion")
        lines.append("")
        lines.append(assurance_opinion.strip())
        lines.append("")

    # -- threat model summary ---------------------------------------------
    tm = getattr(result, "threat_model", None)
    if tm:
        lines.append("## Threat Model Summary")
        lines.append("")
        lines.append(
            f"{len(tm.get('threats', []))} threats identified across "
            f"{len(tm.get('trust_zones', []))} inferred trust zones, with "
            f"{len(tm.get('trust_boundary_crossings', []))} trust-boundary "
            f"crossings in the document flow."
        )
        lines.append("")
        lines.append("**STRIDE coverage** (threats per category):")
        lines.append("")
        lines.append("| Category | Threats |")
        lines.append("|---|---:|")
        for cat, count in (tm.get("stride_totals") or {}).items():
            lines.append(f"| {cat} | {count} |")
        lines.append("")
        blind_spots = tm.get("blind_spots") or []
        if blind_spots:
            lines.append(
                f"**{len(blind_spots)} coverage gaps** - domain/category "
                f"pairs with zero threats surfaced (see full threat model "
                f"for detail; a gap means the review found nothing there, "
                f"not that the design is confirmed safe there)."
            )
            lines.append("")
        for note in tm.get("caveats") or []:
            lines.append(f"> {note}")
        lines.append("")

    # -- priority actions -------------------------------------------------
    top = priority_actions(findings, 3)
    if top:
        lines.append("## Top 3 Priority Actions")
        lines.append("")
        for i, f in enumerate(top, start=1):
            ref = f" _(per {f.standard_reference})_" if f.standard_reference else ""
            lines.append(f"{i}. **[{f.severity}] {_esc(f.issue)}**{ref}  ")
            lines.append(f"   _Section:_ {_esc(f.section)} — "
                         f"_Action:_ {_esc(f.recommendation)}")
        lines.append("")

    # -- findings by domain ----------------------------------------------
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings were raised against the standards currently "
                     "held in the knowledge base.")
        lines.append("")
    else:
        for domain in ("network", "application", "security", "cloud_data",
                       "general"):
            domain_findings = [f for f in findings if f.domain == domain]
            if not domain_findings:
                continue
            lines.append(f"### {DOMAIN_LABELS.get(domain, domain)} "
                         f"({len(domain_findings)})")
            lines.append("")
            lines.append("| Sev | Section | Issue | Standard Reference | "
                         "Recommendation |")
            lines.append("|---|---|---|---|---|")
            for f in domain_findings:
                ref = _esc(f.standard_reference) or "_uncited_"
                lines.append(
                    f"| **{f.severity}** | {_esc(f.section)} | {_esc(f.issue)} "
                    f"| {ref} | {_esc(f.recommendation)} |"
                )
            lines.append("")

    # -- evidence appendix ------------------------------------------------
    if cfg.output.get("include_evidence_excerpts", True) and findings:
        lines.append("## Evidence Appendix")
        lines.append("")
        lines.append("Each finding with the design text it was raised against, "
                     "its provenance, and the controls it maps to.")
        lines.append("")
        for i, f in enumerate(findings, start=1):
            lines.append(f"**F{i:03d} — [{f.severity}] {_esc(f.issue)}**")
            lines.append("")
            lines.append(f"- Section: `{f.section}`")
            lines.append(f"- Domain: {DOMAIN_LABELS.get(f.domain, f.domain)}")
            lines.append(f"- Provenance: {ORIGIN_LABEL.get(f.origin, f.origin)}"
                         + (f" (`{f.rule_id}`)" if f.rule_id else ""))
            lines.append(f"- Grounded in knowledge base: "
                         f"{'yes' if f.is_grounded else 'no'}"
                         + (f" — `{f.kb_source}`" if f.kb_source else ""))
            if f.control_mappings:
                lines.append(f"- Control mapping: {', '.join(f.control_mappings)}")
            if f.evidence_excerpt:
                lines.append(f"- Evidence: _\"{_esc(f.evidence_excerpt)}\"_")
            lines.append("")

    # -- coverage ---------------------------------------------------------
    lines.append("## Review Coverage")
    lines.append("")
    lines.append("| Domain | Sections analysed | Findings | Critical |")
    lines.append("|---|---:|---:|---:|")
    for domain, stats in sorted(coverage_by_domain(result).items()):
        lines.append(f"| {DOMAIN_LABELS.get(domain, domain)} | "
                     f"{stats['sections']} | {stats['findings']} | "
                     f"{stats['critical']} |")
    lines.append("")

    ungrounded = [f for f in findings if not f.is_grounded]
    if ungrounded:
        lines.append(f"**{len(ungrounded)} of {len(findings)} findings are not "
                     f"tied to a knowledge base clause.** These reflect general "
                     f"practice rather than this organisation's standards. "
                     f"Treat them as advisory, and consider adding the missing "
                     f"standards to the knowledge base so future reviews cite "
                     f"them properly.")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Produced by the Cyber Architecture Reviewer. "
                 "Human-in-the-loop: this report records observations and "
                 "citations. It does not approve, reject, or change anything. "
                 "The design authority decides._")

    return "\n".join(lines)


# ==========================================================================
# Assembly + export
# ==========================================================================
def build_report(result: ReviewResult, config: Optional[Config] = None,
                 executive_summary: str = "",
                 assurance_opinion: str = "") -> ReviewResult:
    """Compute score/status and render markdown onto the result in place."""
    cfg = config or load_config()
    score, rag, _counts = compute_risk(result.findings, cfg)
    result.risk_score = score
    result.rag_status = rag
    result.executive_summary = executive_summary or ""
    result.report_markdown = render_markdown(result, cfg, assurance_opinion)
    return result


def save_outputs(result: ReviewResult, config: Optional[Config] = None,
                 stem: Optional[str] = None) -> Dict[str, Path]:
    """Write the markdown report and the JSON audit bundle to disk."""
    cfg = config or load_config()
    cfg.ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = stem or (
        "".join(ch if ch.isalnum() or ch in "-_" else "-"
                for ch in Path(result.document_name).stem)[:60] or "review"
    )

    report_path = cfg.reports_dir / f"{base}-{ts}.md"
    report_path.write_text(result.report_markdown, encoding="utf-8")

    audit_path = cfg.audit_dir / f"{base}-{ts}.json"
    audit_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return {"report": report_path, "audit": audit_path}


def diff_reviews(previous: List[Finding], current: List[Finding]
                 ) -> Dict[str, List[Finding]]:
    """Compare two runs by fingerprint.

    Agentic review is non-deterministic: wording and ordering drift between
    runs. Fingerprint comparison answers the question that actually matters -
    "did anything genuinely change since the last review?" - and doubles as a
    stability measure when you run the same document twice.
    """
    prev_map = {f.fingerprint: f for f in previous}
    curr_map = {f.fingerprint: f for f in current}
    return {
        "resolved": [f for k, f in prev_map.items() if k not in curr_map],
        "new": [f for k, f in curr_map.items() if k not in prev_map],
        "persisting": [f for k, f in curr_map.items() if k in prev_map],
    }
