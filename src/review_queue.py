"""One review queue - findings and threats in a single list.

Before this, the architect reviewed text findings on one page and DFD
threats on another, often the same weakness twice ("webhook has no
authentication" as a finding and as a Spoofing threat). The queue merges
both sources, collapses near-duplicates into one item, orders the list so
the most trustworthy and most severe items come first, and applies one
decision to every underlying record (feedback log for findings, threat
status for threats), so the prelim register and scoring see it everywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
THREAT_DOMAIN = {"network": "network", "device": "network", "datastore": "cloud_data",
                 "vector_db": "cloud_data", "identity": "security", "external_party": "security",
                 "user_group": "security"}


@dataclass
class QueueItem:
    key: str                      # "F:<fingerprint>" or "T:<dfd version>/<threat id>"
    kind: str                     # finding / threat
    severity: str
    domain: str
    title: str
    where: str                    # section or DFD element
    source: str                   # rule / model / threat-rule / threat-model
    status: str                   # open / accepted / disputed / mitigated
    evidence: str = ""
    recommendation: str = ""
    reference: str = ""
    merged: List[str] = field(default_factory=list)   # other keys this item stands for

    @property
    def confirmed_source(self) -> bool:
        return self.source in ("rule", "threat-rule")


STOP = {"that", "this", "with", "from", "into", "which", "there", "their", "have", "been",
        "will", "should", "could", "would", "each", "every", "only", "also", "than", "then",
        "when", "where", "while", "does", "such", "some", "more", "most", "other", "being",
        "across", "allows", "attacker", "attack", "risk", "threat", "implement", "ensure",
        "unknown", "described", "design", "document", "stated", "states", "using", "used"}
SYNONYM = {"authentication": "auth", "authenticated": "auth", "unauthenticated": "noauth",
           "anonymous": "noauth", "authorization": "authz", "authorisation": "authz",
           "encryption": "crypt", "encrypted": "crypt", "unencrypted": "plaintext",
           "cleartext": "plaintext", "plain": "plaintext", "credential": "secret",
           "credentials": "secret", "password": "secret", "passwords": "secret",
           "secrets": "secret", "key": "secret", "keys": "secret", "token": "secret",
           "tokens": "secret", "impersonation": "spoof", "spoofing": "spoof", "forged": "spoof",
           "intercepted": "intercept", "interception": "intercept", "eavesdropper": "intercept",
           "sniffing": "intercept", "logging": "log", "logs": "log", "logged": "log",
           "audit": "log", "flooding": "dos", "ddos": "dos", "exhaustion": "dos"}


def _norm(w: str) -> str:
    w = SYNONYM.get(w, w)
    for suf in ("ing", "ed", "es", "s"):
        if len(w) > 5 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def _tokens(text: str) -> set:
    return {_norm(w) for w in re.findall(r"[a-z0-9]+", (text or "").lower())
            if (len(w) > 3 or w in ("tls", "mfa", "vpn", "api", "dos", "sso", "pii"))
            and w not in STOP}


def _text(i: "QueueItem") -> str:
    title = re.sub(r"\[[^\]]*\]$", "", i.title)       # drop "[STRIDE · Spoofing]"
    return f"{title} {title} {i.recommendation}"


def _score(a: "QueueItem", b: "QueueItem") -> float:
    """Similarity of a finding and a threat, 0..1.

    Overlap coefficient on normalised content words (a finding and a threat
    describe the same weakness in different vocabularies, so Jaccard over
    raw words almost never fired), plus a bonus when the threat's DFD
    element is named in the finding - same weakness, same place.
    """
    x, y = _tokens(_text(a)), _tokens(_text(b))
    if len(x) < 4 or len(y) < 4:
        return 0.0
    sim = 2 * len(x & y) / (len(x) + len(y))        # Dice
    threat = a if a.kind == "threat" else b
    other = b if threat is a else a
    place = _tokens(threat.where.split(":", 1)[-1])
    if sim >= 0.2 and place and place & _tokens(other.title + " " + other.where
                                                 + " " + other.evidence):
        sim += 0.15
    return min(sim, 1.0)


MERGE_AT = 0.4

# Weakness class - words alone over-merge ("gateway" in an authorisation
# finding and a gateway flooding threat), so both sides must also be about
# the same kind of weakness.
CLASS_WORDS = {
    "authn": r"auth(?!ori[sz])|unauthenticat|anonymous|mfa|multi-factor|spoof|imperson|"
             r"password|credential|identity theft|phish|login|sign-in",
    "authz": r"authori[sz]|privilege|least|rbac|access control|another user|idor|elevat",
    "crypto": r"encrypt|plaintext|cleartext|plain http|tls|intercept|eavesdrop|mitm|"
              r"sniff|in transit|at rest",
    "secret": r"secret|keys?|token|certificate|vault|rotat",
    "logging": r"log|audit|monitor|denies|repudiat|siem|alert",
    "dos": r"flood|dos|ddos|denial|rate.limit|exhaust|availability",
    "exposure": r"reachable|public|internet|segment|firewall|isolat|port",
    "integrity": r"tamper|integrity|signed|signature|modif|inject|validat",
}
STRIDE_CLASS = {"Spoofing": {"authn"}, "Tampering": {"integrity", "crypto"},
                "Repudiation": {"logging"}, "Information disclosure": {"crypto", "exposure",
                                                                        "secret", "authz"},
                "Denial of service": {"dos"}, "Elevation of privilege": {"authz", "authn"}}


def _classes(i: "QueueItem") -> set:
    text = re.sub(r"\[[^\]]*\]$", "", i.title).lower()
    out = {c for c, rx in CLASS_WORDS.items() if re.search(rx, text)}
    if i.kind == "threat":
        m = re.search(r"· ([^\]]+)\]$", i.title)
        if m:
            out |= STRIDE_CLASS.get(m.group(1).strip(), set())
    return out


def _same_problem(a: QueueItem, b: QueueItem) -> bool:
    if a.kind == b.kind:
        return False                      # only merge a finding with a threat
    if not _classes(a) & _classes(b):
        return False
    return _score(a, b) >= MERGE_AT


def build_queue(findings: Iterable[Any], decisions: Dict[str, Dict[str, Any]],
                threat_runs: Iterable[Any] = (), dfd: Any = None) -> List[QueueItem]:
    items: List[QueueItem] = []
    for f in findings:
        e = decisions.get(f.fingerprint, {})
        d = e.get("decision")
        if d == "accepted" and "[mitigated]" in (e.get("note") or ""):
            d = "mitigated"               # stored as accepted, see apply_decision
        items.append(QueueItem(
            key=f"F:{f.fingerprint}", kind="finding", severity=f.severity, domain=f.domain,
            title=f.issue, where=f.section,
            source="rule" if f.origin == "rules_engine" else "model",
            status=d if d in ("accepted", "disputed", "mitigated") else "open",
            evidence=f.evidence_excerpt, recommendation=f.recommendation,
            reference=f.standard_reference))
    runs = list(threat_runs)
    latest = max(runs, key=lambda r: (r.dfd_version, r.finished_at)) if runs else None
    if latest is not None:
        for t in latest.threats:
            domain = "security"
            if dfd is not None:
                cid = t.target_id
                if t.target_type == "flow":
                    fl = dfd.flow(t.target_id)
                    cid = fl.target if fl else cid
                c = dfd.component(cid)
                domain = THREAT_DOMAIN.get(c.kind, "application") if c else "security"
            items.append(QueueItem(
                key=f"T:{latest.dfd_version}/{t.id}", kind="threat", severity=t.risk,
                domain=domain, title=f"{t.title} [{t.framework} · {t.category}]",
                where=f"DFD v{latest.dfd_version}: {t.target_label}",
                source="threat-rule" if t.source == "rule" else "threat-model",
                status=t.status, evidence=t.description,
                recommendation="; ".join(t.mitigations)))

    # Collapse a finding and a threat about the same weakness into one item;
    # keep the more trustworthy, then more severe, as the visible one.
    def rank(i: QueueItem) -> Tuple:
        return (not i.confirmed_source, ORDER.index(i.severity) if i.severity in ORDER else 9)

    merged: List[QueueItem] = []
    for it in sorted(items, key=rank):
        twin = next((m for m in merged if _same_problem(m, it)), None)
        if twin is None:
            merged.append(it)
        else:
            twin.merged.append(it.key)
            if twin.status == "open" and it.status != "open":
                twin.status = it.status

    merged.sort(key=lambda i: (i.status != "open", not i.confirmed_source,
                               ORDER.index(i.severity) if i.severity in ORDER else 9,
                               i.domain, i.title))
    return merged


def apply_decision(item: QueueItem, decision: str, *, findings_by_fp: Dict[str, Any],
                   runs_by_version: Dict[int, Any], review_key: str, reason: str = "",
                   note: str = "", reviewer: str = "", record=None, save_run=None) -> int:
    """Apply accept / dispute / mitigated to every record behind the item.

    Findings go to the feedback log (mitigated is recorded as accepted: the
    finding is valid, the risk is handled). Threats get their status set and
    their run saved. Returns how many records changed.
    """
    if decision not in ("accepted", "disputed", "mitigated"):
        raise ValueError(decision)
    changed = 0
    touched_runs = set()
    for key in [item.key] + item.merged:
        kind, ref = key.split(":", 1)
        if kind == "F" and ref in findings_by_fp and record is not None:
            record(findings_by_fp[ref], review_key,
                   "disputed" if decision == "disputed" else "accepted",
                   reason=reason if decision == "disputed" else "",
                   note=(note + " [mitigated]" if decision == "mitigated" else note),
                   reviewer=reviewer)
            changed += 1
        elif kind == "T":
            version, tid = ref.split("/", 1)
            run = runs_by_version.get(int(version))
            t = next((x for x in run.threats if x.id == tid), None) if run else None
            if t is not None:
                t.status, t.reviewer_note = decision, note
                touched_runs.add(int(version))
                changed += 1
    if save_run is not None:
        for v in touched_runs:
            save_run(runs_by_version[v])
    return changed


def summary(items: List[QueueItem]) -> Dict[str, int]:
    out = {"open": 0, "accepted": 0, "disputed": 0, "mitigated": 0}
    for i in items:
        out[i.status] = out.get(i.status, 0) + 1
    return out
