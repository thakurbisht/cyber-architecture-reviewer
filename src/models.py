"""Core data structures shared across the pipeline.

Findings are the unit of value in this system. Every field on Finding
exists to answer a question a human governance reviewer will ask:

  "What did you find?"          -> issue
  "How bad is it?"              -> severity + risk_weight
  "Says who?"                   -> standard_reference + kb_source
  "Where in my document?"       -> section + evidence_excerpt
  "What do I do about it?"      -> recommendation
  "Which control does it map?"  -> control_mappings
  "Did a model guess this?"     -> origin + confidence
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

ORIGIN_RULES = "rules_engine"      # deterministic pattern match
ORIGIN_AGENT = "agent"             # LLM reasoning over retrieved standards
ORIGIN_CORRELATION = "correlation"  # cross-domain consistency pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalise_severity(value: str | None) -> str:
    """Coerce whatever the model produced into a valid severity."""
    if not value:
        return "MEDIUM"
    v = str(value).strip().upper()
    aliases = {
        "CRIT": "CRITICAL", "SEV1": "CRITICAL", "P1": "CRITICAL",
        "SEVERE": "CRITICAL", "BLOCKER": "CRITICAL",
        "MAJOR": "HIGH", "SEV2": "HIGH", "P2": "HIGH",
        "MODERATE": "MEDIUM", "SEV3": "MEDIUM", "P3": "MEDIUM", "MED": "MEDIUM",
        "MINOR": "LOW", "SEV4": "LOW", "P4": "LOW", "INFO": "LOW",
        "INFORMATIONAL": "LOW", "OBSERVATION": "LOW",
    }
    if v in SEVERITY_ORDER:
        return v
    return aliases.get(v, "MEDIUM")


@dataclass
class Section:
    """One typed section of an ingested design document."""

    index: int
    heading: str
    body: str
    level: int = 1
    domain: str = "general"
    topic: str = "context_scope"
    topic_confidence: float = 0.0
    secondary_topics: List[str] = field(default_factory=list)
    source_file: str = ""

    @property
    def word_count(self) -> int:
        return len(self.body.split())

    def excerpt(self, limit: int = 400) -> str:
        text = re.sub(r"\s+", " ", self.body).strip()
        return text[:limit] + ("..." if len(text) > limit else "")

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["word_count"] = self.word_count
        return d


@dataclass
class RetrievedChunk:
    """A knowledge-base passage returned by the vector search."""

    chunk_id: str
    text: str
    source: str
    domain: str
    clause: str = ""
    similarity: float = 0.0

    def citation(self) -> str:
        return f"{self.source}{(' ' + self.clause) if self.clause else ''}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single reviewable, citable defect in the design."""

    section: str
    domain: str
    severity: str
    issue: str
    recommendation: str
    standard_reference: str = ""
    kb_source: str = ""
    evidence_excerpt: str = ""
    control_mappings: List[str] = field(default_factory=list)
    origin: str = ORIGIN_AGENT
    rule_id: str = ""
    confidence: float = 0.0
    evidence_chunk_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    # Human feedback tracking
    acknowledged_by: str = ""           # human who reviewed this
    acknowledged_at: str = ""           # when they reviewed it
    acknowledgment_reason: str = ""     # why they marked it (mitigated, false_positive, accept_risk, n/a)

    # A4 verifier (src/verifier.py): CONFIRMED / REFUTED / NEEDS_HUMAN, or ""
    # when no verifier ran.
    verifier_status: str = ""
    verifier_reason: str = ""

    # "finding" is a claimed defect and is scored. "question" is something
    # the author must answer (a gap, a document-level note, a vague claim):
    # shown separately and never scored. See src/triage.py.
    kind: str = "finding"
    # True when evidence_excerpt is found verbatim in the design document.
    evidence_grounded: bool = False
    # Other sections reporting the same problem (triage.merge_duplicates).
    also_in: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = normalise_severity(self.severity)

    # -- identity ---------------------------------------------------------
    @property
    def fingerprint(self) -> str:
        """Stable identity for dedup across repeated non-deterministic runs.

        Deliberately excludes wording of the recommendation and the model's
        prose, which drift run to run. Two findings about the same defect in
        the same section collapse to one.
        """
        basis = "|".join([
            self.domain.lower().strip(),
            re.sub(r"[^a-z0-9]+", "", self.section.lower())[:60],
            self.rule_id or _semantic_key(self.issue),
        ])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    @property
    def is_grounded(self) -> bool:
        """True when the finding cites a knowledge-base clause.

        Ungrounded findings are the model's parametric memory talking. They
        are kept, but flagged separately in the report - governance decisions
        should not rest on uncited claims.
        """
        return bool(self.standard_reference and self.kb_source)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        d["grounded"] = self.is_grounded
        return d


_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "to", "of",
    "in", "on", "at", "for", "with", "and", "or", "not", "no", "this", "that",
    "it", "its", "as", "by", "from", "has", "have", "there", "which", "but",
    "design", "document", "section", "should", "must", "may", "will",
}


_SUFFIXES = ("ations", "ation", "ingly", "ing", "edly", "ies", "ied", "es",
             "ed", "ly", "s")


def _stem(word: str) -> str:
    """Crude suffix stripping.

    Deliberately not a real stemmer. Its only job is to make "terminate",
    "terminates" and "terminating" collapse to the same token so that two
    runs describing the same defect in different tenses produce the same
    fingerprint. Over-stemming costs nothing here; the fingerprint is a
    dedup key, not a search index.
    """
    for suffix in _SUFFIXES:
        if len(word) > len(suffix) + 2 and word.endswith(suffix):
            word = word[: -len(suffix)]
            break
    # Collapse the silent-e pair too, so "terminate" and "terminates"
    # (-> "terminat") land on the same token.
    if len(word) > 4 and word.endswith("e"):
        word = word[:-1]
    return word


def _semantic_key(issue: str) -> str:
    """Order- and tense-independent keyword signature of an issue statement."""
    words = re.findall(r"[a-z0-9]+", issue.lower())
    keep = sorted({
        _stem(w) for w in words if w not in _STOPWORDS and len(w) > 2
    })
    return hashlib.sha1(" ".join(keep[:12]).encode()).hexdigest()[:12]


@dataclass
class AuditEvent:
    """One entry in the immutable reasoning trail."""

    step: str
    detail: Dict[str, Any] = field(default_factory=dict)
    at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewResult:
    """Everything a completed review produces."""

    document_name: str
    findings: List[Finding]
    sections: List[Section]
    audit: List[AuditEvent]
    report_markdown: str = ""
    risk_score: float = 0.0
    rag_status: str = "GREEN"
    executive_summary: str = ""
    domains_reviewed: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=_now)
    finished_at: str = ""
    kb_chunk_count: int = 0
    warnings: List[str] = field(default_factory=list)
    # Findings the A4 verifier refuted with a quote from the design. Kept out
    # of `findings` (and so out of the risk score) but preserved for review.
    refuted_findings: List[Finding] = field(default_factory=list)
    # Questions for the author (src/triage.py): not defects, never scored.
    questions: List[Finding] = field(default_factory=list)
    # src/system_model.py SystemModel.to_dict(), when enable_system_model.
    system_model: Optional[Dict[str, Any]] = None
    # src/project.py: which project / stage / content version this review is.
    # review_key keys every artefact (DFD, threats, register, decisions);
    # empty for ad-hoc reviews, which fall back to the document name.
    review_key: str = ""
    project_id: str = ""
    stage: str = ""
    # Populated by threat_model_node (see agent.py) when
    # config.agent.enable_threat_modeling is true. A plain dict (already
    # ThreatModel.to_dict()'s shape), not the dataclass, so it serialises
    # for free wherever ReviewResult already does.
    threat_model: Optional[Dict[str, Any]] = None

    def counts_by_severity(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_name": self.document_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "domains_reviewed": self.domains_reviewed,
            "risk_score": self.risk_score,
            "rag_status": self.rag_status,
            "kb_chunk_count": self.kb_chunk_count,
            "counts_by_severity": self.counts_by_severity(),
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.findings],
            "questions": [f.to_dict() for f in self.questions],
            "sections": [s.to_dict() for s in self.sections],
            "audit": [a.to_dict() for a in self.audit],
            "threat_model": self.threat_model,
            "system_model": self.system_model,
        }


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Deterministic ordering: severity, then domain, then section.

    The article notes that repeat runs produce findings in different order.
    Sorting at the boundary makes two reports diffable.
    """
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            f.domain,
            f.section.lower(),
            f.issue.lower(),
        ),
    )


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Collapse duplicates by fingerprint, keeping the best-evidenced copy."""
    best: Dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        current = best.get(key)
        if current is None:
            best[key] = f
            continue
        # Prefer grounded over ungrounded, then higher severity, then the
        # deterministic rules-engine copy over the model's.
        candidates = [
            (int(f.is_grounded), -SEVERITY_ORDER.get(f.severity, 99),
             int(f.origin == ORIGIN_RULES), f),
            (int(current.is_grounded), -SEVERITY_ORDER.get(current.severity, 99),
             int(current.origin == ORIGIN_RULES), current),
        ]
        candidates.sort(key=lambda t: t[:3], reverse=True)
        best[key] = candidates[0][3]
    return list(best.values())
