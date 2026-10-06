"""Did the LLD build what the HLD promised?

Why this exists
---------------
Reviewing an HLD and an LLD separately answers "is each document sound?".
It never answers the question the second review is actually for: the HLD
committed to a control, so did the detailed design implement it?

That gap is where real defects live. An HLD says every internal hop is
TLS 1.3; the LLD quietly runs the replication link in the clear because
the appliance does not support it. Both documents read fine alone. Read
together they contain a contradiction, and nobody notices because nobody
reads them together line by line.

How it works
------------
  1. Commitments are extracted from the HLD *deterministically* - a
     commitment verb ("must", "will be", "all ... are") next to a control
     from a fixed catalogue. Same document in, same register out, with
     the sentence quoted. This is the auditable half.
  2. For each commitment, the LLD sections most likely to speak to it are
     found by term overlap, and a model is asked one narrow question:
     implemented, contradicted, missing or unclear - quoting the LLD.
  3. The quote is checked against the LLD text before it is believed
     (triage.evidence_is_grounded). A verdict whose evidence is not in
     the document is demoted to "unclear", because an ungrounded
     contradiction is worse than no answer.

What becomes a finding
----------------------
A contradiction is a finding: the LLD says something that conflicts with
a commitment, and there is a quote for both halves. A mandatory
commitment the LLD never addresses is a finding too, but a softer one -
the HLD said "must" and the detail is absent. Anything weaker is a
question for the author, because silence is not proof (see triage.py).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Finding, ORIGIN_AGENT, Section
from .triage import evidence_is_grounded

# ==========================================================================
# The control catalogue
# ==========================================================================
# What a commitment can be *about*. A sentence only enters the register if
# it both commits to something and names one of these; "the platform will
# be deployed in Q3" commits to nothing reviewable.
CONTROLS: Tuple[Tuple[str, str, str, str], ...] = (
    # key, label, domain, pattern
    ("transit_encryption", "Encryption in transit", "security",
     r"\btls\b|\bssl\b|\bmtls\b|https|encrypt\w*\s+in\s+transit|in[- ]flight\s+encrypt|"
     r"\bipsec\b|\bvpn\b.{0,20}encrypt"),
    ("rest_encryption", "Encryption at rest", "cloud_data",
     r"encrypt\w*\s+at\s+rest|at[- ]rest\s+encrypt|\btde\b|transparent\s+data\s+encryption|"
     r"(?:disk|volume|storage|bucket|database)\s+encrypt\w*|field[- ]level\s+encrypt|"
     r"encrypt\w*\s+(?:the\s+)?(?:disk|volume|storage|bucket|snapshot)"),
    ("key_management", "Key custody and rotation", "security",
     r"\bkms\b|\bhsm\b|key\s+(vault|custody|rotation|management|escrow)|"
     r"rotat\w*\s+(?:the\s+)?keys?|keys?\s+(?:are|is|must\s+be|should\s+be)\s+rotated|"
     r"customer[- ]managed\s+keys?|\bcmk\b|byok"),
    ("mfa", "Multi-factor authentication", "security",
     r"\bmfa\b|multi[- ]factor|two[- ]factor|\b2fa\b|phishing[- ]resistant|\bfido\b|"
     r"passkey|hardware\s+token"),
    ("authentication", "Authentication", "application",
     r"authenticat\w+|\boauth\b|\boidc\b|\bsaml\b|\bsso\b|kerberos|client\s+certificate|"
     r"api\s+keys?|bearer\s+token"),
    # "Authorization" is also an HTTP header name, and a sentence about which
    # headers are logged is about logging, not about access control.
    ("authorisation", "Authorisation and least privilege", "application",
     r"authoris\w+(?!\s+header)|authoriz\w+(?!\s+(?:header|and\s+cookie))|\brbac\b|"
     r"\babac\b|least[- ]privilege|role[- ]based|separation\s+of\s+duties|"
     r"scoped\s+permission|\bno\s+role\s+may\b|granted\s+by\s+role|"
     r"mutually\s+exclusive"),
    ("segmentation", "Network segmentation", "network",
     r"segment\w*|micro[- ]segment|\bvlan\b|security\s+group|network\s+policy|"
     r"trust\s+(zone|boundary)|\bdmz\b|firewall\s+(rule|policy)|east[- ]west|"
     r"accepts?\s+connections?\s+only\s+from|permitted\s+only\s+on|peered\s+to"),
    ("private_access", "No public exposure", "cloud_data",
     r"private\s+(endpoint|link|subnet)|not\s+publicly|no\s+public\s+(access|ip)|"
     r"block\s+public\s+access|internal\s+only|allow[- ]?list|"
     r"reachable\s+from\s+the\s+internet|public\s+network\s+access|"
     r"exposed\s+to\s+the\s+internet"),
    ("logging", "Logging and audit trail", "security",
     r"\bsiem\b|audit\s+(log|trail)|centrali[sz]ed\s+log|log\s+(aggregation|forward|"
     r"retention)|cloudtrail|security\s+event|access\s+logs?|\blogs?\s+(are|record)|"
     r"(?:are|not)\s+logged\b"),
    ("monitoring_alerting", "Detection and alerting", "security",
     r"\balert\w*|detection\s+rule|\bsoc\b|anomaly\s+detect|threshold\s+alarm"),
    ("backup_recovery", "Backup and recovery", "security",
     r"backup|restore|\brpo\b|\brto\b|immutable\s+copy|point[- ]in[- ]time|disaster\s+recovery"),
    ("secrets", "Secrets management", "application",
     r"secret\w*\s+(manager|store|vault)|hashicorp\s+vault|key\s+vault|"
     r"no\s+hard[- ]?coded|credential\s+(store|vault|rotation)|"
     r"\bsecrets?\s+(?:are|is|must|should|never)|pipeline\s+variable"),
    ("patching", "Patching and vulnerability management", "security",
     r"patch\w*|vulnerabilit\w*\s+(scan|management)|\bcve\b|image\s+scan|"
     r"dependency\s+scan|\bsbom\b|scann?\w*\s+for\s+vulnerab\w*|"
     r"images?\s+(?:are|is)\s+scanned"),
    ("rate_limiting", "Rate limiting and abuse protection", "application",
     r"rate[- ]limit\w*|throttl\w+|\bwaf\b|\bddos\b|quota"),
    ("input_validation", "Input validation", "application",
     r"input\s+validat\w+|schema\s+validat\w+|parameteris\w+|parameteriz\w+|"
     r"output\s+encoding|sanitis\w+|sanitiz\w+"),
    ("change_control", "Change control and review", "application",
     r"code\s+review|peer\s+review|four[- ]eyes|pull\s+request|change\s+approval|"
     r"defined\s+(?:in|as)\s+code|terraform|reviewer\s+approval|branch\s+polic\w+|"
     r"\biac\b|infrastructure\s+as\s+code|pipeline\s+gate"),
    ("data_classification", "Data classification and residency", "cloud_data",
     r"classif\w+|\bpii\b|\bphi\b|\bpci\b|residency|data\s+sovereignty|retention\s+period|"
     r"restricted\s+data"),
    ("availability", "Resilience and availability", "network",
     r"high\s+availability|\bha\b\s+pair|failover|redundan\w+|multi[- ]az|active[- ]active|"
     r"active[- ]passive|\bslo\b|\bsla\b"),
)
CONTROL_RX = tuple((key, label, domain, re.compile(p, re.I))
                   for key, label, domain, p in CONTROLS)
CONTROL_LABEL = {key: label for key, label, _, _ in CONTROLS}

# Design documents are written in the present indicative - "Kong applies a
# rate limit", "the VPC has private subnets" - so a declarative sentence
# about a control IS the commitment. Requiring a modal verb ("must", "will
# be") looked principled and threw away 21 of 24 real commitments in
# gs-01, which is why there is no such filter: naming a control in a
# statement about this system is enough to owe the LLD an answer.
#
# What the modal still decides is the *consequence*. "must" and "all X
# are" are promises, so an LLD that never mentions them is a finding. A
# plain statement is weaker, and its absence is only a question.
MANDATORY = re.compile(
    r"\b(must|shall|is\s+required|are\s+required|mandator\w+|enforced?\b|"
    r"only\s+\w+\s+(?:can|may|are\s+permitted|is\s+permitted)|never\b|"
    r"no\s+\w+\s+(?:may|can|is\s+permitted)|always\b|"
    r"every\s+\w+\s+(?:is|are|must|has|have)|all\s+\w+\s+(?:are|is|must|will))\b", re.I)
# Not a statement about this system: a question, a heading or caption, or the
# front-matter block ("**Classification:** Internal") that every design
# document carries and that mentions controls without committing to any.
NOT_A_STATEMENT = re.compile(
    r"\?\s*$|^\s*[*_#]*\s*(table|figure|appendix|see\s|company|document|"
    r"classification|author|version|status|date|owner|approved)\b[:*\s]", re.I)
# The HLD naming a control in order to decline it is a decision, not a
# promise, so it never enters the register as something to verify. The
# rules engine already flags declined controls in the HLD's own review.
WAIVED = re.compile(
    r"\b(not\s+(?:be\s+)?(?:required|in\s+scope|implemented|enforced|supported|"
    r"configured|applied)|"
    r"no\s+(?:mfa|encryption|tls|segmentation|logging|authentication)\b|"
    r"(?:disabled|turned\s+off|switched\s+off|bypassed|removed)\b|without\s+\w+ing|"
    r"out\s+of\s+scope|deferred|descoped|de-scoped|phase\s*2|"
    r"future\s+(?:phase|release)|accepted\s+risk|risk\s+accepted|exempt|waiver|"
    r"waived)\b", re.I)

STATUSES = ("implemented", "contradicted", "missing", "unclear")
MIN_CLAIM_WORDS = 6
MAX_CLAIM_WORDS = 70


@dataclass
class ControlClaim:
    """One commitment the HLD makes, quoted."""

    id: str
    control: str                  # catalogue key
    text: str                     # the sentence, verbatim
    section: str
    domain: str
    strength: str                 # mandatory / intended

    @property
    def label(self) -> str:
        return CONTROL_LABEL.get(self.control, self.control)


@dataclass
class ControlCheck:
    """What the LLD does about one commitment."""

    claim: ControlClaim
    status: str                   # see STATUSES
    evidence: str = ""            # quote from the LLD
    lld_section: str = ""
    reason: str = ""
    grounded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["claim"] = asdict(self.claim)
        return d


# ==========================================================================
# 1. Extract commitments from the HLD - deterministic
# ==========================================================================
# Design documents number their steps ("... on the checkout page. 4. payment-svc
# creates ..."). Splitting only before a capital glued those steps into one
# sentence, which then matched a control mentioned three steps away and put a
# nonsense entry in the register. So a digit starts a sentence too.
_SENTENCE = re.compile(
    r"(?<=[.!?])\s+(?=[A-Z(]|\d+[.)]\s)|\n(?=[-*•]\s|\d+[.)]\s)|\n{2,}")


def sentences(text: str) -> List[str]:
    out: List[str] = []
    for raw in _SENTENCE.split(text or ""):
        s = re.sub(r"^\s*[-*•]\s*", "", raw).strip()
        s = re.sub(r"\s+", " ", s)
        if s:
            out.append(s)
    return out


def control_for(sentence: str) -> Optional[Tuple[str, str]]:
    """(control key, domain) for the control the sentence is most about.

    A sentence can brush several controls ("storage encryption with a
    customer-managed KMS key ... force_ssl"). The one with the most
    distinct hits is the subject; a tie goes to the longer, and therefore
    more specific, matched phrase - "storage encryption" says more about
    what the sentence is about than a stray "TLS" three clauses later.
    """
    best: Optional[Tuple] = None
    for order, (key, _label, domain, rx) in enumerate(CONTROL_RX):
        matches = list(rx.finditer(sentence))
        if not matches:
            continue
        # Earliest wins a tie: the subject of a sentence comes before its
        # qualifiers. "events are forwarded to the group SIEM, including
        # authentication events" is about logging, not authentication.
        rank = (len({m.group(0).lower() for m in matches}),
                -matches[0].start(),
                max(len(m.group(0)) for m in matches),
                -order)
        if best is None or rank > best[:4]:
            best = (*rank, key, domain)
    return (best[4], best[5]) if best else None


def claim_strength(sentence: str) -> str:
    """mandatory when the sentence is a promise, stated otherwise."""
    return "mandatory" if MANDATORY.search(sentence) else "stated"


def extract_claims(sections: Sequence[Section]) -> List[ControlClaim]:
    """The HLD's control register, in document order, with stable ids."""
    claims: List[ControlClaim] = []
    seen: set = set()
    for section in sections:
        for sentence in sentences(section.body):
            words = sentence.split()
            if not (MIN_CLAIM_WORDS <= len(words) <= MAX_CLAIM_WORDS):
                continue
            if WAIVED.search(sentence) or NOT_A_STATEMENT.search(sentence):
                continue                      # a decision, or not a statement
            hit = control_for(sentence)
            if hit is None:
                continue
            strength = claim_strength(sentence)
            key = (hit[0], re.sub(r"\W+", "", sentence.lower())[:80])
            if key in seen:
                continue
            seen.add(key)
            claims.append(ControlClaim(
                id=f"HLD-C-{len(claims) + 1:03d}", control=hit[0], text=sentence,
                section=section.heading, domain=section.domain or hit[1],
                strength=strength))
    return claims


# ==========================================================================
# 2. Find the LLD sections that speak to a commitment
# ==========================================================================
_STOP = {"the", "and", "for", "with", "that", "this", "are", "all", "will", "must",
         "from", "into", "every", "shall", "each", "any", "its", "our", "their",
         "where", "which", "been", "have", "has", "use", "used", "using", "via"}


def _terms(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower())
            if len(w) > 2 and w not in _STOP}


def candidate_sections(claim: ControlClaim, sections: Sequence[Section],
                       top_k: int = 3) -> List[Section]:
    """LLD sections most likely to answer this commitment.

    Term overlap rather than embeddings: the result has to be the same on
    every run, and the reviewer has to be able to see why a section was
    consulted.
    """
    rx = next((r for key, _l, _d, r in CONTROL_RX if key == claim.control), None)
    claim_terms = _terms(claim.text)
    scored: List[Tuple[float, int, Section]] = []
    for i, s in enumerate(sections):
        body = f"{s.heading}\n{s.body}"
        overlap = len(claim_terms & _terms(body))
        score = overlap / max(len(claim_terms), 1)
        if rx is not None and rx.search(body):
            score += 1.0                      # names the control itself
        if score <= 0:
            continue
        # Only a nudge between sections that are already relevant. On its own
        # it admitted every same-domain section, so a commitment nothing in
        # the LLD speaks to still cost a model call and came back "unclear"
        # instead of the truthful "missing".
        if s.domain and s.domain == claim.domain:
            score += 0.15
        scored.append((score, -i, s))
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [s for _score, _i, s in scored[:top_k]]


# ==========================================================================
# 3. Ask the model one narrow question
# ==========================================================================
CHECK_SYSTEM = """You are a Principal Enterprise Security Architect checking whether a detailed design (LLD) implements a commitment made in the high-level design (HLD).

You are given one HLD commitment and the LLD sections most likely to address it.

Answer with ONE of:
  "implemented"   - the LLD describes this control being applied. Quote the line.
  "contradicted"  - the LLD describes something that conflicts with the commitment
                    (a weaker algorithm, an exempted system, a disabled control,
                    a plaintext path). Quote the conflicting line.
  "missing"       - these LLD sections simply do not address the commitment.
  "unclear"       - the LLD touches the topic but does not say enough to tell.

Rules:
- Quote the LLD verbatim. Never paraphrase and never quote the HLD.
- "contradicted" is the serious answer. Use it only with a line that genuinely
  conflicts, not one that merely says less than the HLD did.
- Partial implementation with a stated exception is "contradicted" - the
  exception is the point. One exempted account, one legacy partner, one
  environment left out is enough to break a commitment that said "all",
  "every" or "no".
- Finding a line that supports the commitment does not end the question. Keep
  reading for an exception, an exemption, or a weaker setting than the one
  committed to, and answer "contradicted" if you find one.
- A commitment with several parts ("nightly, immutable, 35 days") is
  "implemented" only if the LLD covers every part. If the LLD covers some and
  is silent on the rest, that is "unclear".
- If the LLD is silent, say "missing". Silence is not a contradiction.

Return ONLY JSON: {"status": "...", "evidence": "...", "reason": "one sentence"}"""

CHECK_USER = """HLD COMMITMENT ({strength})
Control: {label}
Section: {section}
"{text}"

LLD SECTIONS TO CHECK
{excerpts}
{exceptions}
Does the LLD implement this commitment? If the commitment has several parts,
it is only "implemented" when the LLD covers all of them."""

EXCEPTIONS_BLOCK = """
LINES IN THOSE SECTIONS THAT ANNOUNCE AN EXCEPTION - read each one and decide
whether it weakens this commitment before you answer "implemented":
{lines}
"""

# A detailed design announces the place it fell short of the HLD with a
# connective, not with a heading: "... permits TLS 1.2 to avoid breaking
# their nightly batch", "excluded from the policy so that recovery is
# possible", "could not obtain a private link in time for go-live".
#
# Measured: without this, the model found confirming evidence, stopped
# reading, and called three broken commitments implemented - the
# non-production peering, the pipeline variable group and the backups that
# were geo-redundant but not immutable. The exceptions were in the very
# sections it had been given.
EXCEPTION_MARKER = re.compile(
    r"\b(because|so\s+that|to\s+avoid|in\s+order\s+to|could\s+not|cannot|can't|"
    r"unable\s+to|does\s+not\s+support|do\s+not\s+support|except\b|excluded|exempt|"
    r"legacy|interim|temporar\w+|for\s+now|until\b|workaround|waiver|waived|"
    r"in\s+time\s+for|instead\s+of|rather\s+than|only\s+\w+\s+days?|"
    r"deviat\w+|does\s+not\s+apply)\b", re.I)
MAX_EXCEPTION_LINES = 8


def build_consistency_llm(config: Any) -> Any:
    from langchain_ollama import ChatOllama

    name = str(config.models.get("consistency") or config.models["llm"])
    return ChatOllama(
        model=name, base_url=config.models["ollama_host"], temperature=0.0,
        num_ctx=int(config.models.get("num_ctx", 8192)),
        num_predict=512, format="json",
        client_kwargs={"timeout": float(config.models.get("request_timeout_s", 300))})


def _message_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(p.get("text", "") if isinstance(p, dict) else str(p)
                       for p in content)
    return str(content or "")


def _parse(text: str) -> Dict[str, Any]:
    body = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", body, re.S)
    if fence:
        body = fence.group(1).strip()
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        m = re.search(r'"status"\s*:\s*"(\w+)"', body)
        data = {"status": m.group(1)} if m else {}
    return data if isinstance(data, dict) else {}


def _excerpts(sections: Sequence[Section], limit: int = 1400) -> str:
    out = []
    for s in sections:
        body = re.sub(r"\s+", " ", s.body).strip()
        out.append(f"--- {s.heading} ---\n{body[:limit]}")
    return "\n\n".join(out) if out else "(no LLD section mentions this topic)"


def exception_lines(sections: Sequence[Section],
                    claim: Optional["ControlClaim"] = None) -> List[str]:
    """LLD sentences announcing a deviation *from this commitment*.

    The relevance filter is not optional. Handing the model every
    exception in the candidate sections made it 5 times more likely to
    report a contradiction, because it reached for whichever exception
    was in front of it: a public storage account was offered as evidence
    against the SIEM commitment, the key-rotation commitment and the RPO.
    An exception only counts when it is about the same control.
    """
    rx = None
    claim_terms: set = set()
    if claim is not None:
        rx = next((r for key, _l, _d, r in CONTROL_RX if key == claim.control), None)
        claim_terms = _terms(claim.text)
    out: List[str] = []
    for s in sections:
        for sentence in sentences(s.body):
            if len(sentence.split()) < MIN_CLAIM_WORDS or sentence in out:
                continue
            if not EXCEPTION_MARKER.search(sentence):
                continue
            if claim is not None:
                on_topic = bool(rx and rx.search(sentence))
                if not on_topic and claim_terms:
                    shared = claim_terms & _terms(sentence)
                    on_topic = len(shared) / len(claim_terms) >= 0.2
                if not on_topic:
                    continue
            out.append(sentence)
    return out[:MAX_EXCEPTION_LINES]


def check_claim(claim: ControlClaim, sections: Sequence[Section], llm: Any,
                lld_norm: str) -> ControlCheck:
    """One commitment against the LLD. Never raises."""
    candidates = candidate_sections(claim, sections)
    if not candidates:
        return ControlCheck(claim=claim, status="missing",
                            reason="No LLD section mentions this control.")
    exceptions = exception_lines(candidates, claim)
    user = CHECK_USER.format(
        strength=claim.strength, label=claim.label, section=claim.section,
        text=claim.text, excerpts=_excerpts(candidates),
        exceptions=EXCEPTIONS_BLOCK.format(
            lines="\n".join(f"- “{line}”" for line in exceptions))
        if exceptions else "")
    try:
        data = _parse(_message_text(
            llm.invoke([("system", CHECK_SYSTEM), ("human", user)])))
    except Exception as exc:  # noqa: BLE001 - one bad answer must not stop the run
        return ControlCheck(claim=claim, status="unclear",
                            reason=f"check failed: {str(exc)[:120]}")

    status = str(data.get("status", "")).strip().lower()
    if status not in STATUSES:
        status = "unclear"
    evidence = str(data.get("evidence", "")).strip()
    reason = str(data.get("reason", "")).strip()[:300]
    grounded = bool(evidence) and evidence_is_grounded(evidence, lld_norm)
    # A verdict is only as good as its quote. An ungrounded "contradicted"
    # is the model writing the LLD it expected to see, so it is demoted
    # rather than reported.
    if status in ("implemented", "contradicted") and not grounded:
        reason = (reason + " [evidence not found in the LLD]").strip()
        status = "unclear"
    return ControlCheck(claim=claim, status=status, evidence=evidence,
                        lld_section=candidates[0].heading, reason=reason,
                        grounded=grounded)


def check_claims(claims: Sequence[ControlClaim], lld_sections: Sequence[Section],
                 llm: Any, progress=None) -> List[ControlCheck]:
    from .triage import document_text

    lld_norm = document_text(lld_sections)
    out: List[ControlCheck] = []
    for n, claim in enumerate(claims, start=1):
        if progress:
            progress(f"Checking {claim.id} of {len(claims)}: {claim.label}")
        out.append(check_claim(claim, lld_sections, llm, lld_norm))
    return out


# ==========================================================================
# 4. Findings
# ==========================================================================
def to_findings(checks: Sequence[ControlCheck]) -> List[Finding]:
    """Contradictions and unkept mandatory commitments.

    An implemented commitment produces nothing: it is coverage, reported
    in the summary, not a defect.
    """
    out: List[Finding] = []
    for check in checks:
        claim = check.claim
        if check.status == "contradicted":
            out.append(Finding(
                section=check.lld_section or claim.section,
                domain=claim.domain,
                severity="HIGH" if claim.strength == "mandatory" else "MEDIUM",
                issue=(f"The LLD contradicts an HLD commitment on "
                       f"{claim.label.lower()}. HLD ({claim.section}): "
                       f"“{claim.text[:200]}”"),
                recommendation=(
                    "Reconcile the two designs: either change the detailed design "
                    "to meet the commitment, or record a risk acceptance against "
                    f"{claim.id} and update the HLD so the two agree."),
                evidence_excerpt=check.evidence,
                origin=ORIGIN_AGENT, rule_id=f"CONSIST-{claim.control.upper()}",
                kind="finding", evidence_grounded=check.grounded,
                control_mappings=[claim.id]))
        elif check.status == "missing" and claim.strength == "mandatory":
            out.append(Finding(
                section=claim.section, domain=claim.domain, severity="MEDIUM",
                issue=(f"The HLD requires {claim.label.lower()} but the LLD does "
                       f"not describe it. HLD: “{claim.text[:200]}”"),
                recommendation=("Describe in the detailed design how this control is "
                                "implemented, or record why it no longer applies."),
                evidence_excerpt=claim.text,
                origin=ORIGIN_AGENT, rule_id=f"CONSIST-{claim.control.upper()}",
                kind="question", control_mappings=[claim.id]))
        elif check.status in ("missing", "unclear"):
            out.append(Finding(
                section=claim.section, domain=claim.domain, severity="LOW",
                issue=(f"The LLD does not clearly show {claim.label.lower()} as the "
                       f"HLD describes it. HLD: “{claim.text[:160]}”"),
                recommendation="Confirm with the author how this control is realised.",
                evidence_excerpt=claim.text,
                origin=ORIGIN_AGENT, rule_id=f"CONSIST-{claim.control.upper()}",
                kind="question", control_mappings=[claim.id]))
    return out


def summary(checks: Sequence[ControlCheck]) -> Dict[str, Any]:
    counts = {s: 0 for s in STATUSES}
    for c in checks:
        counts[c.status] = counts.get(c.status, 0) + 1
    total = len(checks)
    verified = counts["implemented"]
    return {
        "commitments": total,
        **counts,
        "coverage": round(verified / total, 3) if total else 0.0,
        "by_control": {
            key: sum(1 for c in checks if c.claim.control == key)
            for key in sorted({c.claim.control for c in checks})},
    }
