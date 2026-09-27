"""Deterministic rules over the extracted system model.

The rules engine in rules.py reads prose with regexes, which is why it tops
out around 15% recall: the same defect can be phrased a hundred ways. These
rules read structure instead - "a flow from the internet to a component
with no authentication" - so phrasing no longer matters. The model supplies
the facts (each with a verbatim quote, see system_model.py); every judgement
below is plain Python, reproducible and unit-testable.
"""

from __future__ import annotations

from typing import Callable, List

from .models import Finding
from .system_model import Component, Flow, SystemModel

ORIGIN_SYSTEM_MODEL = "system_model"

UNTRUSTED_ZONES = {"internet", "partner", "dmz"}
WEAK_CROSS_ZONE_AUTH = {"password", "shared_secret", "api_key"}


def _finding(rule_id: str, severity: str, domain: str, issue: str,
             recommendation: str, section: str, evidence: str,
             reference: str = "", kb_source: str = "") -> Finding:
    return Finding(
        section=section or "System model", domain=domain, severity=severity,
        issue=issue, recommendation=recommendation,
        standard_reference=reference, kb_source=kb_source,
        evidence_excerpt=evidence, origin=ORIGIN_SYSTEM_MODEL,
        rule_id=rule_id, confidence=0.8,
    )


def _source_untrusted(model: SystemModel, f: Flow) -> bool:
    src = model.component(f.source)
    if src is None:
        return f.source.strip().lower() in {"internet", "public", "anyone",
                                             "anonymous users", "customers"}
    return (src.zone in UNTRUSTED_ZONES or src.kind == "external_party"
            or src.exposure == "public")


def _crosses_zone(model: SystemModel, f: Flow) -> bool:
    a, b = model.zone_of(f.source), model.zone_of(f.target)
    return "unknown" not in (a, b) and a != b


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def unauthenticated_from_untrusted(model: SystemModel) -> List[Finding]:
    out = []
    for f in model.flows:
        if f.auth == "none" and _source_untrusted(model, f):
            out.append(_finding(
                "SM-AUTH-001", "CRITICAL", "application",
                f"{f.target} accepts unauthenticated connections from {f.source} "
                f"(an untrusted zone).",
                "Require authentication on every request crossing into the "
                "trusted zone; allow anonymous access only to listed endpoints "
                "that return no business data.",
                f.section, f.evidence,
                "Application Security Architecture Standard §3.1",
                "application/application-security-standard.md"))
    return out


def sensitive_store_publicly_exposed(model: SystemModel) -> List[Finding]:
    out = []
    for c in model.components:
        if c.kind == "datastore" and c.exposure == "public" and c.sensitive:
            out.append(_finding(
                "SM-DATA-001", "CRITICAL", "cloud_data",
                f"{c.name} holds {', '.join(c.data)} data and is publicly exposed.",
                "Remove public exposure; reach the store through a private "
                "endpoint or an authenticated service in front of it.",
                c.section, c.evidence,
                "Cloud Data Protection Standard §2.3",
                "cloud_data/cloud-data-protection-standard.md"))
    return out


def cleartext_across_zones(model: SystemModel) -> List[Finding]:
    out = []
    for f in model.flows:
        if f.encrypted == "no" and (_crosses_zone(model, f) or _source_untrusted(model, f)):
            out.append(_finding(
                "SM-ENC-001", "HIGH", "network",
                f"Traffic from {f.source} to {f.target}"
                + (f" ({f.protocol})" if f.protocol else "")
                + " crosses a trust boundary unencrypted.",
                "Encrypt the flow (TLS 1.2+, IPsec or the protocol's secure "
                "variant) and disable the cleartext option.",
                f.section, f.evidence))
    return out


def weak_auth_across_zones(model: SystemModel) -> List[Finding]:
    out = []
    for f in model.flows:
        if f.auth in WEAK_CROSS_ZONE_AUTH and (_crosses_zone(model, f)
                                               or _source_untrusted(model, f)):
            tgt = model.component(f.target)
            sev = "HIGH" if tgt is not None and tgt.sensitive else "MEDIUM"
            out.append(_finding(
                "SM-AUTH-002", sev, "security",
                f"{f.source} authenticates to {f.target} across a trust boundary "
                f"with a static {f.auth.replace('_', ' ')}.",
                "Replace static secrets with workload identity, mTLS or "
                "short-lived tokens issued per caller.",
                f.section, f.evidence))
    return out


def management_reachable_from_untrusted(model: SystemModel) -> List[Finding]:
    out = []
    for f in model.flows:
        if model.zone_of(f.target) == "management" and _source_untrusted(model, f):
            out.append(_finding(
                "SM-MGMT-001", "HIGH", "network",
                f"Management component {f.target} is reachable from {f.source}.",
                "Restrict management interfaces to a dedicated management zone "
                "reached only through a PAM jump host.",
                f.section, f.evidence))
    return out


def stated_weakened_controls(model: SystemModel) -> List[Finding]:
    """A control the document itself says is absent or weakened, on a
    component that is public or holds sensitive data."""
    out = []
    for ctl in model.controls:
        if ctl.status not in ("absent", "weakened"):
            continue
        tgt: Component | None = model.component(ctl.target) if ctl.target else None
        if tgt is None or not (tgt.sensitive or tgt.exposure == "public"):
            continue
        out.append(_finding(
            "SM-CTRL-001", "HIGH", "security",
            f"{ctl.control} is {ctl.status} for {tgt.name}, which is "
            + ("publicly exposed." if tgt.exposure == "public"
               else f"holding {', '.join(tgt.data)} data."),
            f"Restore {ctl.control} for {tgt.name} or record a risk "
            "acceptance with a named owner and expiry.",
            ctl.section, ctl.evidence))
    return out


MODEL_RULES: List[Callable[[SystemModel], List[Finding]]] = [
    unauthenticated_from_untrusted,
    sensitive_store_publicly_exposed,
    cleartext_across_zones,
    weak_auth_across_zones,
    management_reachable_from_untrusted,
    stated_weakened_controls,
]


def run_model_rules(model: SystemModel) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for rule in MODEL_RULES:
        for f in rule(model):
            key = (f.rule_id, f.issue)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    findings.sort(key=lambda f: (f.rule_id, f.section.lower(), f.issue))
    return findings
