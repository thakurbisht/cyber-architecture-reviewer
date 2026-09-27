"""Findings vs Questions - the triage step between detection and scoring.

Measured on the golden set (judge-v2), roughly a third of everything the
pipeline reported was not a claimed defect at all:

  * document-level notes ("no threat model is described", completeness gaps)
  * absence rules that fire on any mention of a topic ("backups" without the
    word "immutable")
  * vague model output ("Unspecified issue", "requires architect input")

None of these matched a planted issue, and they drowned the real findings.
They are still useful - as questions the author must answer - so they are
moved, not deleted: ``ReviewResult.questions`` is shown separately and is
never scored.

Triage also records whether each finding's evidence quote actually appears
in the document (``Finding.evidence_grounded``). Scoring uses that to decide
which findings are allowed to drive the RAG status (see report.compute_risk).
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from .models import Finding, ORIGIN_RULES, Section

DOC_LEVEL_SECTIONS = ("whole document", "document (completeness)")

VAGUE_ISSUE = re.compile(
    r"unspecified issue|remediation not specified|requires architect input|"
    r"^\s*(n/?a|none|tbd|unknown)\s*$",
    re.I,
)

# A quote shorter than this proves nothing: six common words occur by chance.
MIN_GROUNDING_WORDS = 6


def _norm(text: str) -> str:
    text = re.sub(r"[^\w\s]", " ", (text or "").lower())
    return re.sub(r"\s+", " ", text).strip()


def document_text(sections: Iterable[Section]) -> str:
    """Normalised full text used for evidence grounding."""
    return _norm("\n".join(f"{s.heading}\n{s.body}" for s in sections))


def evidence_is_grounded(evidence: str, doc_norm: str,
                         min_words: int = MIN_GROUNDING_WORDS) -> bool:
    """True if the evidence, or a run of min_words of it, is in the document.

    Reviewers truncate and ellipsise quotes, so a substantial verbatim run
    is enough; paraphrase is not.
    """
    ev = _norm((evidence or "").replace("...", " ").replace("…", " "))
    words = ev.split()
    if len(words) < min_words:
        return False
    return any(" ".join(words[i:i + min_words]) in doc_norm
               for i in range(len(words) - min_words + 1))


def is_question(f: Finding) -> bool:
    """A prompt for the author rather than a claimed defect."""
    if f.kind == "question":
        return True
    if f.section.strip().lower().startswith(DOC_LEVEL_SECTIONS):
        return True
    return not f.issue.strip() or bool(VAGUE_ISSUE.search(f.issue))


def is_confirmed(f: Finding) -> bool:
    """Evidence a finding is real enough to drive the RAG status.

    A deterministic rule matched the text, or the verifier confirmed it.
    A verbatim quote is NOT enough: on the golden set ~75% of model findings
    quote the document correctly and still misread it (the clean designs
    gs-09/gs-10 drew 12-22 quoted-but-wrong findings each). An unconfirmed
    model claim may be right, but it cannot turn a design RED on its own.
    """
    return f.origin == ORIGIN_RULES or f.verifier_status == "CONFIRMED"


def triage(findings: List[Finding], sections: Iterable[Section]
           ) -> Tuple[List[Finding], List[Finding]]:
    """Split into (findings, questions) and mark evidence grounding."""
    doc_norm = document_text(sections)
    kept: List[Finding] = []
    questions: List[Finding] = []
    for f in findings:
        f.evidence_grounded = evidence_is_grounded(f.evidence_excerpt, doc_norm)
        if is_question(f):
            f.kind = "question"
            questions.append(f)
        else:
            kept.append(f)
    return kept, questions
