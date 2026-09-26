"""Completeness checks - is this design even reviewable?

Why this runs before the rules engine and the agent
---------------------------------------------------
A rules engine answers "does this design violate a standard?". On an
incomplete design that question is unanswerable, and the honest answer is
not "no violations found" - it is "not reviewable, X is missing".

  "All traffic is encrypted."          -> reviewable, checkable
  (no mention of encryption anywhere)  -> NOT the same thing

Both produce zero encryption findings from a pattern matcher. The second one
is the dangerous case: silence read as a pass. A human reviewer's first move
is to ask what is missing, so that is what this module does first.

Design notes
------------
Absence is much weaker evidence than presence, so each criterion is checked
against the WHOLE document, not per section - one mention of a trust boundary
anywhere is enough to say the design engages with the topic. That keeps this
layer to what it can defend: it reports that a topic is unaddressed, never
that it is addressed badly. Judging quality is the agent's job.

Severity is deliberately capped at MEDIUM. A missing section is a gap in the
document, not a demonstrated defect in the system, and a completeness gap
should never be the thing that forces a design to RED on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Set

from .models import Finding, ORIGIN_RULES, Section

FLAGS = re.IGNORECASE

# The section label attached to completeness findings. These are document-wide
# observations, not defects located in one section.
_SECTION_LABEL = "Document (completeness)"


@dataclass(frozen=True)
class Criterion:
    """One thing a reviewable design has to say something about."""

    key: str
    label: str                  # short name, used in the summary
    domain: str                 # which review domain owns the gap
    severity: str               # severity of the finding when absent
    patterns: List[Pattern[str]]
    issue: str                  # what is missing, and why that blocks review
    recommendation: str         # what to add to make it reviewable


def _p(*patterns: str) -> List[Pattern[str]]:
    return [re.compile(p, FLAGS) for p in patterns]


CRITERIA: List[Criterion] = [
    Criterion(
        key="data_flow",
        label="Data flow",
        domain="application",
        severity="MEDIUM",
        patterns=_p(
            r"\bdata\s*flows?\b",
            r"\b(?:information|traffic|message)\s+flow\b",
            r"\bflow\s+(?:diagram|matrix|table)\b",
            r"\bsequence\s+diagram\b",
            r"\b(?:sends?|writes?|publishes?|forwards?|posts?)\s+(?:\w+\s+){0,3}to\b",
            r"->|-->|=>|→",
        ),
        issue=(
            "The design does not describe how data moves between components. "
            "Without a data flow, encryption-in-transit, boundary controls and "
            "data residency cannot be assessed at all - their absence from the "
            "findings below means they were unreviewable, not that they are sound."
        ),
        recommendation=(
            "Add a data flow diagram or a flow table listing, for each flow: "
            "source, destination, protocol, and what data it carries."
        ),
    ),
    Criterion(
        key="trust_boundaries",
        label="Trust boundaries",
        domain="security",
        severity="MEDIUM",
        patterns=_p(
            r"\btrust\s+boundar",
            r"\b(?:security|network|trust)\s+zones?\b",
            r"\b(?:DMZ|demilitari[sz]ed\s+zone)\b",
            r"\b(?:segment|segmentation|micro-?segmentation)\b",
            r"\b(?:untrusted|semi-?trusted|trusted)\s+(?:zone|network|tier|segment)\b",
            r"\bperimeter\b",
        ),
        issue=(
            "The design does not state where its trust boundaries lie. Controls "
            "are only meaningful relative to a boundary, so authentication "
            "placement, filtering and encryption requirements cannot be judged."
        ),
        recommendation=(
            "Mark the trust boundaries on the architecture diagram and state, for "
            "each boundary crossing, what authenticates and what is filtered."
        ),
    ),
    Criterion(
        key="authentication_model",
        label="Authentication model",
        domain="security",
        severity="MEDIUM",
        patterns=_p(
            r"\bauthenticat",
            r"\bauthori[sz]ation\b",
            r"\b(?:RBAC|ABAC|ACL|IAM)\b",
            r"\b(?:OAuth|OIDC|SAML|Kerberos|LDAP|mTLS|mutual\s+TLS)\b",
            r"\b(?:service\s+account|identity\s+provider|SSO|single\s+sign-?on)\b",
            r"\b(?:API\s+key|bearer\s+token|JWT)\b",
        ),
        issue=(
            "The design does not describe how callers are authenticated or "
            "authorised. Every access-control finding below is therefore absent "
            "for lack of evidence rather than because access control is adequate."
        ),
        recommendation=(
            "State the authentication mechanism at each boundary crossing, where "
            "credentials are stored, and how they are rotated."
        ),
    ),
    Criterion(
        key="data_classification",
        label="Data classification",
        domain="cloud_data",
        severity="MEDIUM",
        patterns=_p(
            r"\bdata\s+classification\b",
            r"\b(?:PII|PHI|PCI|CHD|SPI)\b",
            r"\b(?:confidential|restricted|sensitive|public|internal)\s+data\b",
            r"\bclassif(?:ied|ication)\s+as\b",
            r"\bsensitivity\s+(?:level|tier|label)\b",
            r"\bpersonal\s+data\b",
        ),
        issue=(
            "The design does not classify the data it handles. Retention, "
            "residency, encryption strength and access-logging requirements all "
            "derive from classification, so none of them can be checked."
        ),
        recommendation=(
            "State, per data store and per flow, the classification of the data "
            "held or carried (for example Public / Internal / Confidential / PHI)."
        ),
    ),
    Criterion(
        key="encryption",
        label="Encryption",
        domain="security",
        severity="MEDIUM",
        patterns=_p(
            r"\bencrypt",
            r"\b(?:TLS|SSL|HTTPS|IPsec|AES|RSA|KMS|HSM)\b",
            r"\bat\s+rest\b",
            r"\bin\s+(?:transit|flight)\b",
            r"\bkey\s+(?:management|rotation|store|vault)\b",
            r"\bcipher\b",
        ),
        issue=(
            "The design does not mention encryption in transit or at rest, or key "
            "management. This is unreviewable rather than compliant."
        ),
        recommendation=(
            "State the encryption applied to each data store and each network "
            "flow, and where the keys live and how they rotate."
        ),
    ),
    Criterion(
        key="third_party",
        label="Third-party dependencies",
        domain="application",
        severity="LOW",
        patterns=_p(
            r"\bthird[-\s]?part(?:y|ies)\b",
            r"\bexternal\s+(?:service|system|provider|API|dependency)\b",
            r"\b(?:vendor|supplier|partner|sub-?processor)\b",
            r"\b(?:SaaS|managed\s+service)\b",
            r"\bno\s+(?:external|third[-\s]?party)\s+dependenc",
        ),
        issue=(
            "The design does not name its external or third-party dependencies. "
            "Data leaving to a third party, and under what agreement, cannot be "
            "assessed."
        ),
        recommendation=(
            "List every external system the design talks to, what data it "
            "receives, and the agreement that covers it - or state explicitly "
            "that there are none."
        ),
    ),
    Criterion(
        key="logging_monitoring",
        label="Logging and monitoring",
        domain="security",
        severity="LOW",
        patterns=_p(
            r"\b(?:log|logs|logging|audit\s+trail|audit\s+log)\b",
            r"\b(?:SIEM|monitoring|observability|telemetry)\b",
            r"\b(?:alert|alerting)\b",
            r"\bretention\s+period\b",
        ),
        issue=(
            "The design does not describe logging, monitoring or alerting. "
            "Detection and incident response capability cannot be assessed."
        ),
        recommendation=(
            "State what is logged, where logs are sent, how long they are kept, "
            "and what raises an alert."
        ),
    ),
    Criterion(
        key="availability",
        label="Availability and recovery",
        domain="network",
        severity="LOW",
        patterns=_p(
            r"\b(?:redundan|resilien|failover|fail-?over)\b",
            r"\bhigh\s+availability\b|\bHA\b",
            r"\b(?:RTO|RPO)\b",
            r"\b(?:backup|disaster\s+recovery|DR)\b",
            r"\b(?:active-active|active-passive|multi-?AZ|multi-?region)\b",
        ),
        issue=(
            "The design does not state availability targets or a recovery "
            "approach. Single points of failure cannot be identified."
        ),
        recommendation=(
            "State the availability target (RTO/RPO if applicable) and the "
            "redundancy or failover approach for each tier."
        ),
    ),
]

CRITERIA_BY_KEY: Dict[str, Criterion] = {c.key: c for c in CRITERIA}

# Below this many words the document is a stub, not a design. Reporting eight
# separate gaps on a two-line document is noise; one finding is the honest
# answer.
MIN_REVIEWABLE_WORDS = 120


@dataclass
class CompletenessResult:
    """What the document does and does not address."""

    present: Set[str] = field(default_factory=set)
    missing: Set[str] = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    reviewable: bool = True
    word_count: int = 0

    @property
    def coverage(self) -> float:
        """Fraction of criteria the document addresses, 0.0-1.0."""
        total = len(self.present) + len(self.missing)
        return (len(self.present) / total) if total else 0.0


def _finding(section: str, domain: str, severity: str, issue: str,
             recommendation: str, rule_id: str) -> Finding:
    return Finding(
        section=section,
        domain=domain,
        severity=severity,
        issue=issue,
        recommendation=recommendation,
        origin=ORIGIN_RULES,
        rule_id=rule_id,
        confidence=1.0,
    )


def check_document_completeness(
    sections: List[Section],
    enabled_domains: List[str] | None = None,
) -> CompletenessResult:
    """Report which review-critical topics the document never addresses.

    Args:
        sections: parsed document sections.
        enabled_domains: if given, only criteria owned by these domains are
            reported - a network-only review should not demand a data
            classification section.

    Returns:
        CompletenessResult with present/missing criteria and findings.
    """
    # Headings carry real signal ("## 7. Encryption at Rest") and are stored
    # separately from the body, so both are searched.
    text = "\n".join(f"{s.heading}\n{s.body}" for s in sections)
    words = sum(s.word_count for s in sections)

    if not sections or words == 0:
        return CompletenessResult(
            present=set(),
            missing={c.key for c in CRITERIA},
            reviewable=False,
            word_count=0,
            findings=[
                _finding(
                    section=_SECTION_LABEL,
                    domain="security",
                    severity="MEDIUM",
                    issue=(
                        "No readable content was extracted from the document, so "
                        "no review took place. An empty findings list here means "
                        "nothing was checked."
                    ),
                    recommendation=(
                        "Check the upload parsed correctly (scanned PDFs need OCR) "
                        "and resubmit."
                    ),
                    rule_id="COMPLETE-000",
                )
            ],
        )

    wanted = set(enabled_domains) if enabled_domains else None

    present: Set[str] = set()
    missing: Set[str] = set()
    for c in CRITERIA:
        if any(p.search(text) for p in c.patterns):
            present.add(c.key)
        elif wanted is None or c.domain in wanted:
            missing.add(c.key)

    # A stub document: one honest finding beats eight derived from the same fact.
    if words < MIN_REVIEWABLE_WORDS:
        named = ", ".join(sorted(CRITERIA_BY_KEY[k].label for k in missing))
        return CompletenessResult(
            present=present,
            missing=missing,
            reviewable=False,
            word_count=words,
            findings=[
                _finding(
                    section=_SECTION_LABEL,
                    domain="security",
                    severity="MEDIUM",
                    issue=(
                        f"The document is {words} words and does not contain enough "
                        f"detail to review. Unaddressed: {named or 'nothing specific'}. "
                        f"Any findings below cover only what little was stated."
                    ),
                    recommendation=(
                        "Submit the full design document rather than a summary or "
                        "an extract."
                    ),
                    rule_id="COMPLETE-001",
                )
            ],
        )

    findings = [
        _finding(
            section=_SECTION_LABEL,
            domain=CRITERIA_BY_KEY[key].domain,
            severity=CRITERIA_BY_KEY[key].severity,
            issue=CRITERIA_BY_KEY[key].issue,
            recommendation=CRITERIA_BY_KEY[key].recommendation,
            rule_id=f"COMPLETE-{key.upper()}",
        )
        for key in sorted(missing)
    ]

    return CompletenessResult(
        present=present,
        missing=missing,
        findings=findings,
        reviewable=True,
        word_count=words,
    )


def completeness_summary(result: CompletenessResult) -> str:
    """One-paragraph plain-text summary, for the report header and the UI."""
    total = len(result.present) + len(result.missing)
    if not result.reviewable:
        return (
            f"Not reviewable: {result.word_count} words of content. "
            f"Treat the findings below as incomplete."
        )
    if not result.missing:
        return f"Design addresses all {total} review-critical topics."
    named = ", ".join(sorted(CRITERIA_BY_KEY[k].label for k in result.missing))
    return (
        f"Design addresses {len(result.present)} of {total} review-critical "
        f"topics. Unaddressed: {named}. Findings in those areas are absent for "
        f"lack of evidence, not because the areas are sound."
    )
