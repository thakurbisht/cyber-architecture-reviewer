"""Reviewer accept/dispute log (src/feedback.py)."""

from __future__ import annotations

import pytest

from src.feedback import latest_decisions, read_log, record_decision, summarise
from src.models import Finding, ORIGIN_AGENT, ORIGIN_RULES


def _f(issue="Admin console lacks MFA.", rule_id="", origin=ORIGIN_AGENT, section="Identity"):
    return Finding(section=section, domain="security", severity="HIGH", issue=issue,
                   recommendation="Enforce MFA.", origin=origin, rule_id=rule_id)


def test_decision_is_appended_and_mirrored_on_finding(tmp_path):
    log = tmp_path / "fb.jsonl"
    f = _f()
    record_decision(f, "doc.md", "disputed", reason="Already mitigated in the design",
                    reviewer="PB", path=log)
    assert len(read_log(log)) == 1
    assert f.acknowledged_by == "PB"
    assert f.acknowledgment_reason.startswith("disputed")


def test_latest_decision_wins_and_is_per_document(tmp_path):
    log = tmp_path / "fb.jsonl"
    f = _f()
    record_decision(f, "doc.md", "disputed", reason="Other", path=log)
    record_decision(f, "doc.md", "accepted", path=log)
    record_decision(f, "other.md", "disputed", reason="Other", path=log)
    assert latest_decisions("doc.md", log)[f.fingerprint]["decision"] == "accepted"
    assert len(read_log(log)) == 3          # history is kept, not rewritten


def test_summary_ranks_rules_by_dispute_rate(tmp_path):
    log = tmp_path / "fb.jsonl"
    for i in range(3):
        record_decision(_f(issue=f"noisy {i}", rule_id="SEC-X-001", origin=ORIGIN_RULES,
                           section=f"S{i}"), "d.md", "disputed", reason="Other", path=log)
    record_decision(_f(issue="good", rule_id="SEC-Y-001", origin=ORIGIN_RULES),
                    "d.md", "accepted", path=log)
    rows = {r["key"]: r for r in summarise(read_log(log))["by_key"]}
    assert rows["rule:SEC-X-001"]["dispute_rate"] == 1.0
    assert rows["rule:SEC-Y-001"]["dispute_rate"] == 0.0
    assert rows["origin:rules_engine"]["disputed"] == 3


def test_torn_line_is_ignored(tmp_path):
    log = tmp_path / "fb.jsonl"
    record_decision(_f(), "d.md", "accepted", path=log)
    with log.open("a", encoding="utf-8") as fh:
        fh.write('{"half a line')
    assert len(read_log(log)) == 1


def test_unknown_decision_rejected(tmp_path):
    with pytest.raises(ValueError):
        record_decision(_f(), "d.md", "maybe", path=tmp_path / "fb.jsonl")
