"""Input-scope guardrail - reject documents that are not architecture designs.

Why this exists
----------------
The rest of the pipeline (rules engine, retrieval, agent) will cheerfully
"review" whatever text it is handed - a vendor memo, a resume, a recipe - and
produce a report that looks exactly as confident as a real one, just with
findings that are noise. That is a worse failure mode than refusing to run:
a governance artefact nobody can trust because it might be reviewing the
wrong thing is more dangerous than one that visibly declines.

So this runs BEFORE the rules engine, the knowledge base, or the model see
anything, and it never calls the LLM - same reasoning as the rest of Layer 1:
same input, same verdict, every time, and it still works with Ollama down.

How it decides
---------------
It reuses the existing deterministic domain/topic keyword taxonomy
(src/domains.py) rather than inventing a second vocabulary to keep in sync.
Two independent signals, both keyed off that taxonomy:

  architecture_score    total keyword-match weight across every NON-general
                        topic (network/application/security/cloud_data),
                        scored over the whole document at once.
  distinct_topics       how many different topics contributed any of that
                        score - guards against one incidental keyword ("...
                        IT will look at the firewall rules at some point")
                        in an otherwise unrelated document inflating the
                        score on repetition alone.

Thresholds were picked empirically against the shipped samples (which score
85-171 across 18-28 topics) and a set of deliberately unrelated documents
(recipes, meeting notes, a vendor memo - which score 0-3 across 0-2 topics),
leaving a wide margin on both sides; see tests/test_guardrail.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .domains import GENERAL, TOPIC_BY_KEY, score_topics
from .models import Section

MIN_TOTAL_WORDS = 25
MIN_ARCHITECTURE_SCORE = 8.0
MIN_DISTINCT_TOPICS = 3


@dataclass
class ScopeAssessment:
    """The guardrail's verdict on one document."""

    in_scope: bool
    reason: str = ""
    suggestion: str = ""
    total_words: int = 0
    architecture_score: float = 0.0
    distinct_topics: int = 0
    matched_topics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "in_scope": self.in_scope,
            "reason": self.reason,
            "suggestion": self.suggestion,
            "total_words": self.total_words,
            "architecture_score": self.architecture_score,
            "distinct_topics": self.distinct_topics,
            "matched_topics": self.matched_topics,
        }


def assess_scope(sections: List[Section]) -> ScopeAssessment:
    """Decide whether parsed sections look like an architecture design document.

    Runs on the whole document at once (not per-section, then aggregated) so
    that a single off-topic sentence in an otherwise on-topic document can't
    flip the verdict either way - it's the shape of the whole document that
    matters here, not any one paragraph.
    """
    total_words = sum(s.word_count for s in sections)

    if total_words < MIN_TOTAL_WORDS:
        return ScopeAssessment(
            in_scope=False,
            reason=(
                f"This input is only {total_words} word(s) - too short to "
                f"be a design document worth reviewing."
            ),
            suggestion="Upload the full HLD/LLD, or paste more of its content.",
            total_words=total_words,
        )

    full_text = "\n\n".join(f"{s.heading}\n{s.body}" for s in sections)
    scores = score_topics("", full_text)
    arch_scores = {
        key: value for key, value in scores.items()
        if TOPIC_BY_KEY[key].domain != GENERAL
    }
    architecture_score = sum(arch_scores.values())
    distinct_topics = len(arch_scores)
    matched_topics = sorted(arch_scores, key=arch_scores.get, reverse=True)[:6]

    if architecture_score < MIN_ARCHITECTURE_SCORE or distinct_topics < MIN_DISTINCT_TOPICS:
        return ScopeAssessment(
            in_scope=False,
            reason=(
                "This does not read as a network, application, security, or "
                "cloud/data architecture design document (HLD/LLD). Only "
                f"{distinct_topics} architecture topic(s) were detected, "
                f"with a combined signal of {architecture_score:.1f} "
                f"(minimum {MIN_DISTINCT_TOPICS} topics / "
                f"{MIN_ARCHITECTURE_SCORE:.0f} signal required)."
            ),
            suggestion=(
                "This reviewer is scoped to architecture design documents. "
                "If this genuinely is one, add more detail on the topology, "
                "components, controls, or data flows it describes - a title "
                "and a paragraph of business context alone won't clear the "
                "bar. Otherwise, use --force / the override checkbox only "
                "if you're intentionally testing the tool against an "
                "off-scope input."
            ),
            total_words=total_words,
            architecture_score=architecture_score,
            distinct_topics=distinct_topics,
            matched_topics=matched_topics,
        )

    return ScopeAssessment(
        in_scope=True,
        total_words=total_words,
        architecture_score=architecture_score,
        distinct_topics=distinct_topics,
        matched_topics=matched_topics,
    )
