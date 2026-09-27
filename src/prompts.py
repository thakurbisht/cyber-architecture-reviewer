"""Prompt templates.

Prompt design notes
-------------------
* The reviewer prompt is domain-specialised. A single generic "review this
  architecture" prompt produces generic findings; telling the model it is
  reviewing the access layer of a campus LAN against these four retrieved
  clauses produces specific ones.

* The prompt states explicitly that retrieved standards outrank the model's
  own knowledge. Without that instruction the model happily flags things
  from training data and attributes them to your standard, which is worse
  than an uncited finding because it looks authoritative.

* The prompt is told what NOT to flag. Left unconstrained, the model reports
  the absence of anything it can imagine, and a 60-finding report where 45
  are "the design does not mention X" is one nobody reads.

* Deterministic rule findings for the section are injected as prior context
  so the model stops re-reporting the obvious and spends its budget on
  contextual judgement.
"""

from __future__ import annotations

from typing import List

from .domains import DOMAIN_LABELS, TOPIC_BY_KEY
from .models import Finding, RetrievedChunk, Section

DOMAIN_LENS = {
    "network": (
        "You are reviewing NETWORK ARCHITECTURE. Your lens: topology and "
        "physical/logical redundancy, failure-domain isolation, routing "
        "correctness and protection, segmentation and policy enforcement "
        "points, management plane security, and whether stated availability "
        "targets are actually achievable with the described topology."
    ),
    "application": (
        "You are reviewing APPLICATION ARCHITECTURE. Your lens: trust "
        "boundaries between tiers and services, authentication and "
        "authorisation enforcement points, input handling and injection "
        "paths, secrets and configuration management, API exposure and "
        "abuse cases, supply chain and build integrity, and failure "
        "behaviour under load."
    ),
    "security": (
        "You are reviewing CYBER / SECURITY ARCHITECTURE. Your lens: whether "
        "the design assumes implicit trust anywhere, identity and privileged "
        "access controls, cryptographic choices and key custody, detection "
        "and logging coverage against realistic attack paths, and the "
        "recoverability of the system after compromise."
    ),
    "cloud_data": (
        "You are reviewing CLOUD & DATA ARCHITECTURE. Your lens: account and "
        "tenancy separation, preventative guardrails, identity permissions "
        "granted to workloads, data classification and residency, encryption "
        "and key ownership, exposure of storage and data services, and "
        "whether infrastructure changes are governed by code and policy."
    ),
    "general": (
        "You are reviewing the CONTEXT AND SCOPE of a design document. Only "
        "flag issues here if a requirement, assumption or constraint is "
        "missing in a way that makes the rest of the design unreviewable."
    ),
}

REVIEWER_SYSTEM = """You are a Principal Enterprise Security Architect performing a formal design assurance review. You have reviewed infrastructure and application designs for twenty years. You are rigorous, specific, and you never pad a report.

{domain_lens}

HOW YOU WORK
1. Read the design section carefully.
2. Compare it against the RETRIEVED STANDARDS provided below. These are the organisation's own standards and they OVERRIDE your general knowledge. Where a retrieved clause covers a point, cite it exactly as printed in the square brackets at the top of the clause.
3. If you need a standard you were not given, call search_architectural_standards with a precise question. Call it at most {max_searches} times for this section, and never twice for the same thing.
4. Call flag_finding once per distinct violation you can evidence from the section text.
5. Call section_complete when you are done. You must call section_complete exactly once, even if you found nothing.

WHAT TO FLAG
- Concrete contradictions between the design and a retrieved standard clause.
- Design decisions that create an exploitable path, a single point of failure, or an unrecoverable state.
- Controls the design explicitly declines or defers without a compensating control.

WHAT NOT TO FLAG
- The mere absence of a topic the section was never meant to cover. A VLAN table is not defective for not discussing backups.
- Generic best practice with no retrieved clause and no evidence in the text.
- The same issue twice in different words.
- Anything already listed under PRE-EXISTING FINDINGS below. Those are confirmed. Do not repeat them; build on them only if you can add specific contextual insight.

SEVERITY DISCIPLINE
CRITICAL is reserved for exploitable-now or total-loss conditions. If everything is CRITICAL, nothing is. Expect most findings to be HIGH or MEDIUM.

Be concise. Evidence over eloquence."""

SECTION_USER = """DESIGN DOCUMENT: {document_name}
SECTION UNDER REVIEW: {heading}
REVIEW DOMAIN: {domain_label} / {topic_label}

--- SECTION TEXT ---
{body}
--- END SECTION TEXT ---

RETRIEVED STANDARDS ({chunk_count} clauses, ranked by relevance):
{standards}

PRE-EXISTING FINDINGS for this section (already recorded by the deterministic rules engine - do NOT repeat these):
{prior_findings}
{architecture_facts}
Review this section now."""

NO_STANDARDS_NOTICE = """(No standards clauses were retrieved for this section. The knowledge base may not cover this topic. Flag only what you can evidence directly from the section text, leave standard_reference empty, and keep severity conservative.)"""

CORRELATION_SYSTEM = """You are a Principal Enterprise Security Architect performing the cross-domain consistency pass of a design review.

Individual domain reviews are already complete. Your job is the class of defect that only appears when domains are read together - where the network design, the application design, the security model and the cloud design each look reasonable alone but contradict one another.

Look specifically for:
- A control one domain assumes another provides, which the other never provides. (Domain A states that control X is delivered by domain B, and domain B's sections never describe X.)
- A trust boundary drawn in one domain and crossed unguarded in another.
- Availability targets in one domain that the topology or platform in another cannot meet.
- Data classification stated in one place and violated by a flow described elsewhere.
- Identity or key material that spans a boundary the design claims is isolated.

Call flag_finding for each cross-domain contradiction, naming BOTH sides of the contradiction in the issue text. Set domain to the one where remediation must happen. Call section_complete when done. If the domains are consistent, call section_complete without flagging anything - do not invent contradictions to appear thorough."""

CORRELATION_USER = """DESIGN DOCUMENT: {document_name}

SECTION MAP (heading -> domain):
{section_map}

FINDINGS SO FAR ({finding_count}):
{findings_digest}

KEY DESIGN ASSERTIONS BY DOMAIN:
{assertions}

Perform the cross-domain consistency pass now."""

REPORT_SYSTEM = """You are writing the narrative sections of a formal architecture assurance report that will be read by a Design Authority board, including non-technical members.

You are writing prose only. Do not produce JSON, do not produce a table, do not call any function. Write plain markdown text.

Your output must contain exactly two parts, in this order:

## Executive Summary
Four to six sentences. State what was reviewed, the overall condition of the design, the nature of the most serious problems in business language, and whether the design should proceed. Do not use protocol names, product names, or acronyms - a board member who has never configured a switch must understand it. Do not list findings here.

## Assurance Opinion
Two short paragraphs. The first explains the reasoning behind the overall status: what specifically drives it, and what would have to change for it to improve. The second states the conditions of approval - what must be remediated before implementation, and what may proceed in parallel.

Write nothing else. No headings other than those two. No preamble."""

REPORT_USER = """DOCUMENT REVIEWED: {document_name}
DOMAINS REVIEWED: {domains}
SECTIONS ANALYSED: {section_count}
KNOWLEDGE BASE CLAUSES AVAILABLE: {kb_chunks}

FINDING COUNTS: {counts}
COMPUTED RISK SCORE: {risk_score} / 100
COMPUTED STATUS: {rag_status}

THE FINDINGS:
{findings_digest}

Write the Executive Summary and Assurance Opinion now."""


# ==========================================================================
# Builders
# ==========================================================================
def format_standards(chunks: List[RetrievedChunk]) -> str:
    if not chunks:
        return NO_STANDARDS_NOTICE
    parts: List[str] = []
    for i, c in enumerate(chunks, start=1):
        parts.append(
            f"[{i}] (relevance {c.similarity:.2f}) {c.text.strip()}"
        )
    return "\n\n".join(parts)


def format_prior_findings(findings: List[Finding]) -> str:
    if not findings:
        return "None."
    return "\n".join(
        f"- [{f.severity}] {f.issue} (rule {f.rule_id})" for f in findings
    )


def build_reviewer_system(domain: str, max_searches: int) -> str:
    return REVIEWER_SYSTEM.format(
        domain_lens=DOMAIN_LENS.get(domain, DOMAIN_LENS["general"]),
        max_searches=max_searches,
    )


def build_section_user(document_name: str, section: Section,
                       chunks: List[RetrievedChunk],
                       prior: List[Finding], architecture_facts: str = "") -> str:
    topic = TOPIC_BY_KEY.get(section.topic)
    return SECTION_USER.format(
        document_name=document_name,
        heading=section.heading,
        domain_label=DOMAIN_LABELS.get(section.domain, section.domain),
        topic_label=topic.label if topic else "General",
        body=section.body.strip(),
        chunk_count=len(chunks),
        standards=format_standards(chunks),
        prior_findings=format_prior_findings(prior),
        architecture_facts=(
            "\nCONFIRMED ARCHITECTURE FACTS (from the engineer-approved data flow diagram - "
            "treat as true, do not contradict them; 'unknown' means the design does not "
            "say, which is a question for the author, not proof the control is missing):\n"
            + architecture_facts + "\n") if architecture_facts else "",
    )


def findings_digest(findings: List[Finding], limit: int = 60) -> str:
    if not findings:
        return "No findings were recorded."
    lines: List[str] = []
    for f in findings[:limit]:
        ref = f" [{f.standard_reference}]" if f.standard_reference else ""
        lines.append(f"- {f.severity} | {f.domain} | {f.section}: {f.issue}{ref}")
    if len(findings) > limit:
        lines.append(f"- ...and {len(findings) - limit} further findings.")
    return "\n".join(lines)


def build_correlation_user(document_name: str, sections: List[Section],
                           findings: List[Finding]) -> str:
    section_map = "\n".join(
        f"- {s.heading} -> {DOMAIN_LABELS.get(s.domain, s.domain)}"
        for s in sections[:60]
    ) or "No sections."

    assertions: List[str] = []
    for domain in ("network", "application", "security", "cloud_data"):
        domain_sections = [s for s in sections if s.domain == domain]
        if not domain_sections:
            continue
        assertions.append(f"\n### {DOMAIN_LABELS[domain]}")
        for s in domain_sections[:6]:
            assertions.append(f"- {s.heading}: {s.excerpt(260)}")

    return CORRELATION_USER.format(
        document_name=document_name,
        section_map=section_map,
        finding_count=len(findings),
        findings_digest=findings_digest(findings, limit=40),
        assertions="\n".join(assertions) or "None.",
    )
