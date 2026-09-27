"""Threat modeling agent - STRIDE and/or MAESTRO over an approved DFD.

Design (pattern borrowed from awslabs/threat-designer, Apache-2.0: pick a
framework per run, generate threats, let a human edit, replay; everything
here runs on a local model through Ollama):

  applicability  Python. Which categories apply to which DFD element
                 ("STRIDE per element", as in Microsoft's Threat Modeling
                 Tool). Guarantees coverage: the model cannot skip a
                 category, and cannot invent one that does not apply.
  rule_threats   Python. Structural facts the engineer confirmed in the
                 DFD ("internet -> service, auth none") become threats with
                 no model involved. These are the most trustworthy output.
  stride_llm     Local LLM, one small call per in-scope element: specific
                 threats for that element's applicable STRIDE categories.
  maestro_llm    Local LLM, only for AI components (llm / agent / vector_db):
                 threats per applicable MAESTRO layer.
  consolidate    Python. Drop near-duplicates, score likelihood x impact.

Only an approved DFD may be modeled (dfd.status == "approved"); the run is
stamped with that DFD version so results trace back to the facts they used.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from typing_extensions import TypedDict

from . import dfd as D

# --------------------------------------------------------------------------
# Frameworks
# --------------------------------------------------------------------------
STRIDE = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege",
}
# STRIDE per element (Microsoft Threat Modeling Tool convention).
STRIDE_BY_KIND = {
    "external_party": "SR", "user_group": "SR",
    "datastore": "TRID", "vector_db": "TRID",
}
STRIDE_PROCESS = "STRIDE"
STRIDE_FLOW = "TID"

# MAESTRO (Cloud Security Alliance, agentic AI threat modeling): seven layers.
MAESTRO = {
    "L1": "Foundation models", "L2": "Data operations", "L3": "Agent frameworks",
    "L4": "Deployment and infrastructure", "L5": "Evaluation and observability",
    "L6": "Security and compliance", "L7": "Agent ecosystem",
}
MAESTRO_BY_KIND = {
    "llm": ["L1", "L2", "L4", "L5", "L6"],
    "agent": ["L3", "L4", "L5", "L6", "L7"],
    "vector_db": ["L2", "L4", "L6"],
}

LEVELS = ("low", "medium", "high")
RISK = {("high", "high"): "CRITICAL", ("high", "medium"): "HIGH", ("medium", "high"): "HIGH",
        ("medium", "medium"): "MEDIUM", ("high", "low"): "MEDIUM", ("low", "high"): "MEDIUM"}
UNTRUSTED = {"internet", "partner", "dmz"}
WEAK_AUTH = {"password", "shared_secret", "api_key"}
MAX_LLM_TARGETS = 25


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------
@dataclass
class Threat:
    id: str
    framework: str               # STRIDE / MAESTRO
    category: str                # e.g. "Spoofing" or "L3 Agent frameworks"
    target_type: str             # flow / component
    target_id: str
    target_label: str
    title: str
    description: str = ""
    boundary: str = ""           # "Internet → DMZ" when a flow crosses zones
    likelihood: str = "medium"
    impact: str = "medium"
    risk: str = "MEDIUM"
    mitigations: List[str] = field(default_factory=list)
    source: str = "llm"          # rule / llm / human
    status: str = "open"         # open / accepted / disputed / mitigated
    reviewer_note: str = ""


@dataclass
class ThreatModelRun:
    document: str
    dfd_version: int
    frameworks: List[str]
    model: str
    threats: List[Threat] = field(default_factory=list)
    started_at: str = field(default_factory=_now)
    finished_at: str = ""
    seconds: float = 0.0
    llm_calls: int = 0
    llm_errors: int = 0
    targets_skipped: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ThreatModelRun":
        threats = [Threat(**t) for t in d.get("threats", [])]
        return cls(threats=threats, **{k: v for k, v in d.items() if k != "threats"})


def risk_of(likelihood: str, impact: str) -> str:
    if impact == "low" and likelihood == "low":
        return "LOW"
    return RISK.get((likelihood, impact), "LOW" if "low" in (likelihood, impact) else "MEDIUM")


# --------------------------------------------------------------------------
# Applicability (Python)
# --------------------------------------------------------------------------
@dataclass
class Target:
    type: str                    # flow / component
    id: str
    label: str
    stride: str                  # applicable STRIDE letters
    maestro: List[str]           # applicable MAESTRO layers
    boundary: str = ""
    context: str = ""


def _label(dfd: D.DFD, cid: str) -> str:
    c = dfd.component(cid)
    return c.name if c else cid


def applicability(dfd: D.DFD) -> List[Target]:
    """Every DFD element with the categories that apply to it.

    In scope: boundary-crossing flows, components that touch one, and every
    AI component. Ordered so the riskiest land first under the LLM cap.
    """
    boundary = dfd.boundary_flows()
    touching = {f.source for f in boundary} | {f.target for f in boundary}
    targets: List[Target] = []
    for f in boundary:
        zs, zt = dfd.zone_of(f.source), dfd.zone_of(f.target)
        targets.append(Target(
            "flow", f.id, f"{_label(dfd, f.source)} → {_label(dfd, f.target)}",
            STRIDE_FLOW, [],
            boundary=f"{D.ZONE_LABELS.get(zs, zs)} → {D.ZONE_LABELS.get(zt, zt)}",
            context=(f"protocol={f.protocol or 'unknown'}, authentication={f.auth}, "
                     f"encrypted={f.encrypted}")))
    for c in dfd.components:
        if c.id not in touching and c.kind not in D.AI_KINDS:
            continue
        targets.append(Target(
            "component", c.id, c.name,
            STRIDE_BY_KIND.get(c.kind, STRIDE_PROCESS), MAESTRO_BY_KIND.get(c.kind, []),
            boundary=D.ZONE_LABELS.get(c.zone, c.zone),
            context=(f"kind={c.kind}, zone={c.zone}, public={c.public}, "
                     f"sensitive data={', '.join(c.data) or 'none'}")))

    def priority(t: Target) -> tuple:
        if t.type == "flow":
            f = dfd.flow(t.id)
            return (0 if D.flow_risky(dfd, f) else 1, 0)
        c = dfd.component(t.id)
        return (0 if (c.public or c.data or c.kind in D.AI_KINDS) else 2, 1)
    return sorted(targets, key=priority)


# --------------------------------------------------------------------------
# Deterministic threats from confirmed DFD facts
# --------------------------------------------------------------------------
def rule_threats(dfd: D.DFD) -> List[Threat]:
    out: List[Threat] = []

    def add(**kw):
        kw.setdefault("framework", "STRIDE")
        kw["risk"] = risk_of(kw["likelihood"], kw["impact"])
        out.append(Threat(id="", source="rule", **kw))

    for f in dfd.boundary_flows():
        zs, zt = dfd.zone_of(f.source), dfd.zone_of(f.target)
        lbl = f"{_label(dfd, f.source)} → {_label(dfd, f.target)}"
        bnd = f"{D.ZONE_LABELS.get(zs, zs)} → {D.ZONE_LABELS.get(zt, zt)}"
        common = dict(target_type="flow", target_id=f.id, target_label=lbl, boundary=bnd)
        if f.auth == "none":
            add(category="Spoofing", title=f"Unauthenticated access across {bnd}",
                description=f"{lbl} accepts requests without authentication while crossing "
                            f"a trust boundary; any caller in {D.ZONE_LABELS.get(zs, zs)} can "
                            f"reach {_label(dfd, f.target)}.",
                likelihood="high", impact="high",
                mitigations=["Require authentication (OAuth 2.0 / mTLS) on every request",
                             "Allow anonymous access only to endpoints with no business data"],
                **common)
        elif f.auth in WEAK_AUTH:
            add(category="Spoofing", title=f"Static {f.auth.replace('_', ' ')} across {bnd}",
                description=f"{lbl} authenticates with a long-lived {f.auth.replace('_', ' ')}; "
                            "a leaked secret lets anyone impersonate the caller.",
                likelihood="medium", impact="high",
                mitigations=["Replace static secrets with workload identity, mTLS or "
                             "short-lived tokens", "Store and rotate any remaining secret in a vault"],
                **common)
        if f.encrypted == "no":
            add(category="Information disclosure", title=f"Cleartext traffic across {bnd}",
                description=f"{lbl} is not encrypted in transit; data and credentials can be "
                            "read or altered on the path.",
                likelihood="medium" if zs not in UNTRUSTED else "high", impact="high",
                mitigations=["Enforce TLS 1.2+ (or IPsec) and disable the cleartext option"],
                **common)
        if dfd.zone_of(f.target) == "management" and zs in UNTRUSTED:
            add(category="Elevation of privilege",
                title=f"Management interface reachable from {D.ZONE_LABELS.get(zs, zs)}",
                description=f"{_label(dfd, f.target)} sits in the management zone but accepts "
                            f"connections from {D.ZONE_LABELS.get(zs, zs)}.",
                likelihood="medium", impact="high",
                mitigations=["Restrict management access to a PAM jump host in the "
                             "management zone"], **common)
    for c in dfd.components:
        if c.kind in ("datastore", "vector_db") and c.public and c.data:
            add(category="Information disclosure", target_type="component", target_id=c.id,
                target_label=c.name, boundary=D.ZONE_LABELS.get(c.zone, c.zone),
                title=f"Publicly reachable store holding {', '.join(c.data)} data",
                description=f"{c.name} holds {', '.join(c.data)} data and is marked publicly "
                            "reachable.",
                likelihood="high", impact="high",
                mitigations=["Remove public exposure; use a private endpoint",
                             "Front the store with an authenticated service"])
    return out


# --------------------------------------------------------------------------
# LLM prompts
# --------------------------------------------------------------------------
THREAT_SYSTEM = """You are a senior security architect performing threat modeling on a data flow diagram (DFD) that an engineer has reviewed and approved.

You will get ONE element of the DFD (a data flow or a component), its properties, its neighbours, and the threat categories that apply to it. Return ONLY a JSON object:

{"threats": [{"category": <one of the given categories, exactly>,
              "title": <short, specific, max 12 words>,
              "description": <2-3 sentences: who attacks, how, what they gain - specific to THIS element>,
              "likelihood": "low" | "medium" | "high",
              "impact": "low" | "medium" | "high",
              "mitigations": [<1-3 concrete controls>]}]}

Rules:
- At most one threat per category, and only when it is plausible for this element with the stated properties. Omit a category rather than write a generic threat.
- Use the stated properties. If authentication is "token" or "mtls", do not claim the flow is unauthenticated. If encrypted is "yes", do not claim cleartext.
- "unknown" properties are a reason for a threat only if the unknown would matter; say so explicitly ("if the connection is not encrypted...").
- No generic advice ("follow best practices"). Name the component and the mechanism.
- Output compact JSON."""

THREAT_USER = """DOCUMENT: {document}
FRAMEWORK: {framework}
ELEMENT: {target_type} "{label}"
TRUST BOUNDARY: {boundary}
PROPERTIES: {context}
NEIGHBOURS:
{neighbours}

APPLICABLE CATEGORIES (use these names exactly):
{categories}"""


def _neighbours(dfd: D.DFD, t: Target) -> str:
    if t.type == "flow":
        f = dfd.flow(t.id)
        ids = {f.source, f.target}
    else:
        ids = {t.id}
    lines = []
    for f in dfd.flows:
        if f.source in ids or f.target in ids:
            lines.append(f"- {_label(dfd, f.source)} ({dfd.zone_of(f.source)}) → "
                         f"{_label(dfd, f.target)} ({dfd.zone_of(f.target)}): "
                         f"{f.protocol or '?'}, auth={f.auth}, encrypted={f.encrypted}")
    return "\n".join(lines[:12]) or "- (none)"


def _parse(text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", text or "", re.S)
        try:
            data = json.loads(m.group(0)) if m else {}
        except Exception:  # noqa: BLE001
            data = {}
    items = data.get("threats", []) if isinstance(data, dict) else []
    return [i for i in items if isinstance(i, dict)]


def _message_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content)
    return str(content or "")


def _llm_threats(llm: Any, dfd: D.DFD, t: Target, framework: str,
                 categories: Dict[str, str], state: Dict[str, Any]) -> List[Threat]:
    names = list(categories.values())
    user = THREAT_USER.format(
        document=dfd.document, framework=framework, target_type=t.type, label=t.label,
        boundary=t.boundary or "none", context=t.context, neighbours=_neighbours(dfd, t),
        categories="\n".join(f"- {n}" for n in names))
    state["llm_calls"] = state.get("llm_calls", 0) + 1
    try:
        raw = _message_text(llm.invoke([("system", THREAT_SYSTEM), ("human", user)]))
    except Exception:  # noqa: BLE001
        state["llm_errors"] = state.get("llm_errors", 0) + 1
        return []
    out = []
    lower = {n.lower(): n for n in names}
    for item in _parse(raw):
        cat = lower.get(str(item.get("category", "")).strip().lower())
        title = str(item.get("title", "")).strip()
        if not cat or not title:
            continue                      # not an applicable category: discard
        lk = str(item.get("likelihood", "medium")).lower()
        im = str(item.get("impact", "medium")).lower()
        lk, im = (lk if lk in LEVELS else "medium"), (im if im in LEVELS else "medium")
        mit = item.get("mitigations") or []
        out.append(Threat(
            id="", framework=framework, category=cat, target_type=t.type, target_id=t.id,
            target_label=t.label, boundary=t.boundary, title=title[:120],
            description=str(item.get("description", ""))[:800], likelihood=lk, impact=im,
            risk=risk_of(lk, im), mitigations=[str(m)[:200] for m in mit][:3]
            if isinstance(mit, list) else [str(mit)[:200]], source="llm"))
    return out


# --------------------------------------------------------------------------
# Consolidation
# --------------------------------------------------------------------------
def _tokens(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 3}


def consolidate(threats: List[Threat]) -> List[Threat]:
    """Drop near-duplicates on the same element and category; rules win."""
    kept: List[Threat] = []
    for t in sorted(threats, key=lambda x: (x.source != "rule",
                                             ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.risk))):
        dup = False
        for k in kept:
            if k.target_id == t.target_id and k.category == t.category:
                a, b = _tokens(k.title + " " + k.description), _tokens(t.title + " " + t.description)
                if k.source == "rule" or (a and b and len(a & b) / len(a | b) >= 0.35):
                    dup = True
                    break
        if not dup:
            kept.append(t)
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    kept.sort(key=lambda x: (order.index(x.risk), x.framework, x.target_label))
    for i, t in enumerate(kept, start=1):
        t.id = f"T-{i:03d}"
    return kept


# --------------------------------------------------------------------------
# Agent (LangGraph)
# --------------------------------------------------------------------------
class ThreatState(TypedDict, total=False):
    targets: List[Target]
    threats: List[Threat]
    llm_calls: int
    llm_errors: int
    skipped: int


def run_threat_model(dfd: D.DFD, llm: Any, frameworks: Sequence[str], model_name: str = "",
                     progress: Optional[Callable[[str, float], None]] = None,
                     max_targets: int = MAX_LLM_TARGETS) -> ThreatModelRun:
    """Threat-model an APPROVED DFD with the chosen frameworks."""
    from langgraph.graph import END, START, StateGraph

    if dfd.status != "approved":
        raise ValueError("Approve the DFD before threat modeling.")
    fws = [f for f in ("STRIDE", "MAESTRO") if f in set(frameworks)]
    if not fws:
        raise ValueError("Choose STRIDE, MAESTRO or both.")
    emit = progress or (lambda msg, frac: None)
    started = time.time()

    def n_applicability(state: ThreatState) -> Dict[str, Any]:
        emit("Working out which categories apply to each element", 0.02)
        targets = applicability(dfd)
        return {"targets": targets, "threats": [], "llm_calls": 0, "llm_errors": 0,
                "skipped": max(0, len(targets) - max_targets)}

    def n_rules(state: ThreatState) -> Dict[str, Any]:
        emit("Checking confirmed DFD facts", 0.05)
        found = rule_threats(dfd) if "STRIDE" in fws else []
        return {"threats": state["threats"] + found}

    def n_stride(state: ThreatState) -> Dict[str, Any]:
        found: List[Threat] = []
        todo = [t for t in state["targets"][:max_targets] if t.stride]
        for i, t in enumerate(todo):
            emit(f"STRIDE · {t.label}", 0.08 + 0.72 * i / max(1, len(todo)))
            cats = {k: STRIDE[k] for k in t.stride}
            found += _llm_threats(llm, dfd, t, "STRIDE", cats, state)
        return {"threats": state["threats"] + found, "llm_calls": state["llm_calls"],
                "llm_errors": state["llm_errors"]}

    def n_maestro(state: ThreatState) -> Dict[str, Any]:
        found: List[Threat] = []
        todo = [t for t in state["targets"] if t.maestro]
        for i, t in enumerate(todo):
            emit(f"MAESTRO · {t.label}", 0.80 + 0.15 * i / max(1, len(todo)))
            cats = {k: f"{k} {MAESTRO[k]}" for k in t.maestro}
            found += _llm_threats(llm, dfd, t, "MAESTRO", cats, state)
        return {"threats": state["threats"] + found, "llm_calls": state["llm_calls"],
                "llm_errors": state["llm_errors"]}

    def n_consolidate(state: ThreatState) -> Dict[str, Any]:
        emit("Removing duplicates and scoring", 0.97)
        return {"threats": consolidate(state["threats"])}

    g = StateGraph(ThreatState)
    g.add_node("applicability", n_applicability)
    g.add_node("rules", n_rules)
    g.add_node("stride", n_stride)
    g.add_node("maestro", n_maestro)
    g.add_node("consolidate", n_consolidate)
    g.add_edge(START, "applicability")
    g.add_edge("applicability", "rules")
    g.add_conditional_edges("rules", lambda s: "stride" if "STRIDE" in fws else "maestro",
                            {"stride": "stride", "maestro": "maestro"})
    g.add_conditional_edges("stride", lambda s: "maestro" if "MAESTRO" in fws else "consolidate",
                            {"maestro": "maestro", "consolidate": "consolidate"})
    g.add_edge("maestro", "consolidate")
    g.add_edge("consolidate", END)
    final = g.compile().invoke({})

    emit("Done", 1.0)
    return ThreatModelRun(
        document=dfd.document, dfd_version=dfd.version, frameworks=fws, model=model_name,
        threats=final.get("threats", []), finished_at=_now(),
        seconds=round(time.time() - started, 1), llm_calls=final.get("llm_calls", 0),
        llm_errors=final.get("llm_errors", 0), targets_skipped=final.get("skipped", 0))


def build_threat_llm(config: Any) -> Any:
    from langchain_ollama import ChatOllama
    name = str(config.models.get("threat_model") or config.models["llm"])
    return ChatOllama(
        model=name, base_url=config.models["ollama_host"], temperature=0.1,
        num_ctx=int(config.models.get("num_ctx", 8192)),
        num_predict=int(config.models.get("max_output_tokens", 2048)), format="json",
        client_kwargs={"timeout": float(config.models.get("request_timeout_s", 300))})


# --------------------------------------------------------------------------
# Storage and findings
# --------------------------------------------------------------------------
def save_run(run: ThreatModelRun, root: Path = D.DEFAULT_ROOT) -> Path:
    d = root / D.slug(run.document)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"threats_v{run.dfd_version}_{'-'.join(run.frameworks).lower()}.json"
    p.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    return p


def load_runs(document: str, root: Path = D.DEFAULT_ROOT) -> List[ThreatModelRun]:
    d = root / D.slug(document)
    runs = [ThreatModelRun.from_dict(json.loads(p.read_text(encoding="utf-8")))
            for p in sorted(d.glob("threats_v*.json"))]
    return sorted(runs, key=lambda r: (r.dfd_version, r.finished_at))


def to_findings(run: ThreatModelRun) -> List[Any]:
    """Accepted and rule threats as Findings, so they join triage and scoring.

    Rule threats come from engineer-confirmed DFD facts, so they count as
    confirmed (origin rules_engine semantics); LLM threats count only once
    a human accepts them (verifier_status CONFIRMED).
    """
    from .models import Finding, ORIGIN_RULES
    out = []
    for t in run.threats:
        if t.status in ("disputed", "mitigated"):
            continue
        if t.source != "rule" and t.status != "accepted":
            continue
        f = Finding(
            section=f"DFD v{run.dfd_version}: {t.target_label}", domain="security",
            severity=t.risk, issue=f"[{t.framework} · {t.category}] {t.title}",
            recommendation="; ".join(t.mitigations) or "See threat model.",
            evidence_excerpt=t.description, origin=ORIGIN_RULES if t.source == "rule" else "threat_model",
            rule_id=f"TM-{t.id}", confidence=0.9 if t.source == "rule" else 0.7)
        if t.source != "rule":
            f.verifier_status = "CONFIRMED"
            f.verifier_reason = "Accepted by a reviewer in the threat model"
        out.append(f)
    return out
