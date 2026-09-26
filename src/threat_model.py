"""Deterministic threat modeling over a completed architecture review.

Design rationale
-----------------
Everything else in this pipeline answers "does this design violate a
standard?". Threat modeling answers a different question: "if I were an
attacker, what could I actually do to this system, and does the review
above actually cover every angle of that?"

This module deliberately does NOT add a new LLM call. Three reasons:

1. Reliability. The reviewer/writer LLM calls already run a bounded tool
   loop per section; a fourth agentic pass would double run time and add
   another place non-determinism and hallucination can creep in, for a
   capability whose main value is a *structured, auditable* view of what
   the review already found.
2. Determinism. STRIDE classification is a taxonomy problem, not a
   judgment problem - "missing MFA on an admin path" is Spoofing +
   Elevation of Privilege regardless of which model reviewed the section.
   A rule-based mapping gives the same answer on every run, which matters
   for the same reason report.py computes risk score in Python instead of
   asking the model to grade itself (see report.py's module docstring).
3. It works today. This runs entirely off `Finding`/`Section` objects the
   pipeline already produces, so it needs no new prompts, no new tool
   schemas, and no Ollama round trip to test - see
   tests/test_threat_model.py, which exercises it with plain fixtures.

What it produces
-----------------
- **Entities**: one per reviewed section, placed into a trust zone inferred
  from the section's heading/domain (external / perimeter / internal /
  cloud / security / unclassified).
- **Trust boundary crossings**: adjacent sections whose inferred zones
  differ - the places in the document where data moves across a boundary,
  which is exactly where STRIDE threats concentrate.
- **Threats**: every existing Finding tagged with the STRIDE category (or
  categories) it represents. A CRITICAL finding about a wildcard IAM
  policy becomes an Elevation-of-Privilege *threat*, not just a compliance
  line item - same evidence, reframed as "what can an attacker now do".
- **STRIDE coverage matrix**: threat counts per domain per category. This
  is the actual new capability the user asked for beyond "more findings":
  a domain that was reviewed but shows zero Repudiation threats either has
  excellent logging, or logging was never checked - the matrix surfaces
  that as a *coverage gap* to send back to a human, rather than silently
  saying nothing.

This is intentionally a lower bound, not a full manual threat model: it
can only classify what the review already found, and its data-flow view is
inferred from document structure (section order), not a real DFD. Both
limits are stated in the rendered output rather than hidden - see
`ThreatModel.caveats`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import Finding, Section

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

STRIDE_BLURB = {
    "Spoofing": "An attacker impersonates a user, service, or device.",
    "Tampering": "An attacker modifies data or code in transit or at rest.",
    "Repudiation": "An action cannot be traced back to whoever performed it.",
    "Information Disclosure": "Data is exposed to someone not authorised to see it.",
    "Denial of Service": "A service is degraded or made unavailable.",
    "Elevation of Privilege": "An attacker gains capabilities beyond what they were granted.",
}

# ---------------------------------------------------------------------------
# STRIDE classification
# ---------------------------------------------------------------------------
# Precise mapping first: the pattern-skills and rules engine emit stable
# rule_ids (see src/skill_executor_v2.py's PATTERN_CHECKS and the rules
# engine), so a finding produced from a known rule is classified exactly,
# with no ambiguity. This table is deliberately explicit rather than
# derived, so a reviewer can look at one line and see why a rule maps
# where it does.
_RULE_ID_STRIDE: Dict[str, Tuple[str, ...]] = {
    "aws_wildcard_action": ("Elevation of Privilege", "Tampering"),
    "aws_wildcard_resource": ("Elevation of Privilege", "Information Disclosure"),
    "aws_inline_policy": ("Elevation of Privilege",),
    "permit_any_any": ("Elevation of Privilege", "Information Disclosure"),
    "telnet_enabled": ("Information Disclosure", "Spoofing"),
    "ftp_backup": ("Information Disclosure",),
    "snmpv1_v2c": ("Information Disclosure", "Tampering"),
    "no_mfa_admin": ("Spoofing", "Elevation of Privilege"),
    "credentials_in_code": ("Spoofing", "Information Disclosure"),
    "no_csrf_token": ("Tampering", "Spoofing"),
}

# Fallback for findings without a recognised rule_id (agent-origin and
# correlation-origin findings reason in free text, not fixed rule ids).
# Ordered tuples of (keywords, categories) - checked in order, all matches
# kept, so one finding can legitimately land in more than one category.
_KEYWORD_STRIDE: List[Tuple[Tuple[str, ...], Tuple[str, ...]]] = [
    (("mfa", "multi-factor", "multi factor", "password", "credential",
      "authentication", "impersonat"), ("Spoofing",)),
    (("encrypt", "tls", "cleartext", "clear text", "plaintext", "plain text",
      "expose", "exposed", "exposure", "public access", "public bucket",
      "data classification", "confidential"), ("Information Disclosure",)),
    (("integrity", "checksum", "signing", "signed", "unsigned", "tamper",
      "csrf", "injection"), ("Tampering",)),
    (("logging", "audit trail", "audit log", "non-repudiation",
      "traceability", "no logs", "not logged"), ("Repudiation",)),
    (("availability", "redundan", "failover", "single point of failure",
      "rate limit", "denial of service", "ddos", "resiliency",
      "resilience"), ("Denial of Service",)),
    (("privilege", "wildcard", "admin access", "least privilege",
      "excessive permission", "over-privileged", "overprivileged",
      "role assignment", "elevat"), ("Elevation of Privilege",)),
]


def classify_stride(finding: Finding) -> List[str]:
    """Return the STRIDE categories a finding represents.

    Rule-based findings (rules_engine, skill_executor) are classified by
    their exact rule_id when known. Everything else - and any rule_id not
    yet in the table above, which will happen as new skills are added -
    falls back to keyword matching over the issue and recommendation text.
    A finding that matches nothing returns an empty list; callers treat
    that as "Unclassified" rather than guessing.
    """
    rule_id = (finding.rule_id or "").strip()
    if rule_id in _RULE_ID_STRIDE:
        return list(_RULE_ID_STRIDE[rule_id])

    haystack = f"{finding.issue} {finding.recommendation}".lower()
    hits: List[str] = []
    for keywords, categories in _KEYWORD_STRIDE:
        if any(kw in haystack for kw in keywords):
            for cat in categories:
                if cat not in hits:
                    hits.append(cat)
    return hits


# ---------------------------------------------------------------------------
# Trust zone inference
# ---------------------------------------------------------------------------
_ZONE_KEYWORDS: List[Tuple[Tuple[str, ...], str]] = [
    # Systems genuinely outside the organisation's administrative control.
    (("third-party", "third party", "partner", "vendor", "external system",
      "external provider"), "external"),
    # The org's own internet-facing/public edge - reachable from outside,
    # but still the organisation's component, not someone else's system.
    (("internet-facing", "internet facing", "internet", "public", "dmz",
      "perimeter", "edge", "waf", "load balancer", "reverse proxy",
      "api gateway", "ingress", "customer-facing", "customer facing"),
     "perimeter"),
    (("internal", "private", "corporate", "on-prem", "on-premise",
      "on-premises", "backend", "back-end", "core network"), "internal"),
]

_DOMAIN_DEFAULT_ZONE = {
    "network": "network_zone",
    "application": "application_zone",
    "cloud_data": "cloud_zone",
    "security": "security_zone",
    "general": "unclassified",
}


def infer_trust_zone(section: Section) -> str:
    """Best-effort trust zone for a section, from its heading/topic text.

    This reads document structure, not a real network diagram - it is a
    heuristic signal for "where in the design does this sit", good enough
    to flag likely trust-boundary crossings for a human to confirm, not a
    substitute for an actual data-flow diagram.
    """
    haystack = f"{section.heading} {section.topic}".lower()
    for keywords, zone in _ZONE_KEYWORDS:
        if any(kw in haystack for kw in keywords):
            return zone
    return _DOMAIN_DEFAULT_ZONE.get(section.domain, "unclassified")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class ThreatModelEntity:
    name: str
    domain: str
    trust_zone: str
    section_index: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrustBoundaryCrossing:
    """An adjacent pair of sections whose inferred trust zones differ."""
    from_entity: str
    from_zone: str
    to_entity: str
    to_zone: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Threat:
    """One Finding, reframed as an attacker-capability statement."""
    id: str
    stride_category: str
    title: str
    target_section: str
    target_domain: str
    severity: str
    likelihood: str
    impact: str
    existing_mitigation: str
    recommended_mitigation: str
    origin: str
    rule_id: str = ""
    standard_reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatModel:
    document_name: str
    entities: List[ThreatModelEntity] = field(default_factory=list)
    trust_zones: List[str] = field(default_factory=list)
    trust_boundary_crossings: List[TrustBoundaryCrossing] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    stride_coverage: Dict[str, Dict[str, int]] = field(default_factory=dict)
    stride_totals: Dict[str, int] = field(default_factory=dict)
    blind_spots: List[Dict[str, str]] = field(default_factory=list)
    unclassified_findings: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    caveats: List[str] = field(default_factory=lambda: [
        "Entities and trust zones are inferred from section headings and "
        "topics, not a verified network/data-flow diagram - confirm zone "
        "placement with the design authority before treating a boundary "
        "crossing as fact.",
        "Threats are derived only from findings this review already "
        "raised. A blind spot means the review surfaced nothing in that "
        "category for that domain - it does not certify the category is "
        "actually safe.",
    ])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_name": self.document_name,
            "generated_at": self.generated_at,
            "entities": [e.to_dict() for e in self.entities],
            "trust_zones": self.trust_zones,
            "trust_boundary_crossings": [c.to_dict() for c in self.trust_boundary_crossings],
            "threats": [t.to_dict() for t in self.threats],
            "stride_coverage": self.stride_coverage,
            "stride_totals": self.stride_totals,
            "blind_spots": self.blind_spots,
            "unclassified_findings": self.unclassified_findings,
            "caveats": self.caveats,
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def build_threat_model(document_name: str, sections: Sequence[Section],
                       findings: Sequence[Finding],
                       domains: Optional[Sequence[str]] = None) -> ThreatModel:
    """Assemble a ThreatModel from a completed review's sections + findings.

    Pure function, no I/O, no LLM call - safe to run on every review and
    safe to unit test with plain fixtures.
    """
    domains_in_scope = set(domains or {s.domain for s in sections})

    # -- entities + trust zones -------------------------------------------
    entities: List[ThreatModelEntity] = []
    zone_by_index: Dict[int, str] = {}
    for s in sections:
        zone = infer_trust_zone(s)
        zone_by_index[s.index] = zone
        entities.append(ThreatModelEntity(
            name=s.heading, domain=s.domain, trust_zone=zone,
            section_index=s.index,
        ))
    trust_zones = sorted({e.trust_zone for e in entities})

    # -- trust boundary crossings (adjacent sections, differing zone) -----
    ordered = sorted(entities, key=lambda e: e.section_index)
    crossings: List[TrustBoundaryCrossing] = []
    for a, b in zip(ordered, ordered[1:]):
        if a.trust_zone != b.trust_zone:
            crossings.append(TrustBoundaryCrossing(
                from_entity=a.name, from_zone=a.trust_zone,
                to_entity=b.name, to_zone=b.trust_zone,
            ))

    # -- threats from findings ---------------------------------------------
    threats: List[Threat] = []
    coverage: Dict[str, Dict[str, int]] = {
        d: {c: 0 for c in STRIDE_CATEGORIES} for d in domains_in_scope
    }
    totals: Dict[str, int] = {c: 0 for c in STRIDE_CATEGORIES}
    unclassified = 0

    likelihood_by_origin = {
        "rules_engine": "High",       # deterministic pattern match - it's really there
        "skill_executor": "High",
        "agent": "Medium",            # LLM judgment against retrieved standards
        "correlation": "Medium",
    }

    for i, f in enumerate(findings):
        categories = classify_stride(f)
        if not categories:
            unclassified += 1
            continue
        for cat in categories:
            threats.append(Threat(
                id=f"TM-{i+1:04d}-{cat[:1]}",
                stride_category=cat,
                title=f.issue,
                target_section=f.section,
                target_domain=f.domain,
                severity=f.severity,
                likelihood=likelihood_by_origin.get(f.origin, "Medium"),
                impact=f.severity,
                existing_mitigation=(
                    "Acknowledged/mitigated by reviewer"
                    if getattr(f, "acknowledged_by", "") else
                    "None identified in the reviewed document"
                ),
                recommended_mitigation=f.recommendation,
                origin=f.origin,
                rule_id=f.rule_id,
                standard_reference=f.standard_reference,
            ))
            totals[cat] = totals.get(cat, 0) + 1
            coverage.setdefault(f.domain, {c: 0 for c in STRIDE_CATEGORIES})
            coverage[f.domain][cat] = coverage[f.domain].get(cat, 0) + 1

    # -- blind spots: domain was reviewed but has zero threats in category
    blind_spots: List[Dict[str, str]] = []
    domain_has_sections = {s.domain for s in sections}
    for d in sorted(domains_in_scope & domain_has_sections):
        for c in STRIDE_CATEGORIES:
            if coverage.get(d, {}).get(c, 0) == 0:
                blind_spots.append({
                    "domain": d, "stride_category": c,
                    "note": f"No {c} threats surfaced for {d} - confirm this "
                            f"reflects an actual control, not a gap in review "
                            f"coverage.",
                })

    return ThreatModel(
        document_name=document_name,
        entities=ordered,
        trust_zones=trust_zones,
        trust_boundary_crossings=crossings,
        threats=threats,
        stride_coverage=coverage,
        stride_totals=totals,
        blind_spots=blind_spots,
        unclassified_findings=unclassified,
    )
