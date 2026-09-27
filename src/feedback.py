"""Reviewer feedback - accept or dispute each finding.

Why this exists
---------------
Every precision number so far comes from a 12-document golden set that one
person labelled. Real reviews are the only way to learn which rules and
which model behaviours architects actually reject. So each decision is
appended to a JSON-lines log (append-only, so nothing is silently rewritten;
the latest decision for a finding wins) and summarised per rule and per
origin by scripts/feedback_report.py. Disputed findings with a reason are
also the raw material for new golden-set traps.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import Finding

DECISIONS = ("accepted", "disputed")
DISPUTE_REASONS = (
    "Already mitigated in the design",
    "Not what the document says",
    "Out of scope for this design",
    "Wrong severity",
    "Duplicate of another finding",
    "Too vague to act on",
    "Other",
)
DEFAULT_PATH = Path("data/feedback/feedback.jsonl")


def record_decision(finding: Finding, document: str, decision: str,
                    reason: str = "", note: str = "", reviewer: str = "",
                    path: Path = DEFAULT_PATH) -> Dict[str, Any]:
    """Append one decision and mirror it onto the finding's ack fields."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    entry = {
        "at": now, "document": document, "fingerprint": finding.fingerprint,
        "decision": decision, "reason": reason, "note": note.strip(),
        "reviewer": reviewer.strip(),
        "rule_id": finding.rule_id, "origin": finding.origin,
        "severity": finding.severity, "domain": finding.domain,
        "section": finding.section, "issue": finding.issue,
        "evidence": finding.evidence_excerpt,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    finding.acknowledged_by = entry["reviewer"] or "reviewer"
    finding.acknowledged_at = now
    finding.acknowledgment_reason = (
        "accepted" if decision == "accepted" else f"disputed: {reason}")
    return entry


def read_log(path: Path = DEFAULT_PATH) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue            # a torn last line must not break the page
    return out


def latest_decisions(document: Optional[str] = None,
                     path: Path = DEFAULT_PATH) -> Dict[str, Dict[str, Any]]:
    """{fingerprint: latest entry}, optionally for one document."""
    latest: Dict[str, Dict[str, Any]] = {}
    for e in read_log(path):
        if document is None or e.get("document") == document:
            latest[e["fingerprint"]] = e
    return latest


def summarise(entries: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Dispute rates per rule and per origin, over latest decisions only."""
    latest: Dict[tuple, Dict[str, Any]] = {}
    for e in entries:
        latest[(e.get("document"), e.get("fingerprint"))] = e
    by_key: Dict[str, Counter] = defaultdict(Counter)
    reasons: Counter = Counter()
    for e in latest.values():
        for key in (f"rule:{e['rule_id']}" if e.get("rule_id") else None,
                    f"origin:{e.get('origin')}"):
            if key:
                by_key[key][e["decision"]] += 1
        if e["decision"] == "disputed":
            reasons[e.get("reason") or "Other"] += 1
    rows = []
    for key, c in by_key.items():
        n = c["accepted"] + c["disputed"]
        rows.append({"key": key, "accepted": c["accepted"], "disputed": c["disputed"],
                     "dispute_rate": round(c["disputed"] / n, 3) if n else 0.0})
    rows.sort(key=lambda r: (-r["dispute_rate"], -r["disputed"], r["key"]))
    return {"decisions": len(latest), "by_key": rows, "reasons": dict(reasons.most_common())}
