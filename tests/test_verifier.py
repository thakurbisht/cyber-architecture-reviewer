"""A4 verifier: offline tests with a stub model (no Ollama)."""

from __future__ import annotations

import json

from src.models import Finding
from src.parser import parse_text
from src.verifier import (CONFIRMED, NEEDS_HUMAN, REFUTED, Verifier, _parse,
                          quote_in_document, split_by_verdict)

from conftest import FakeKB, FakeMessage, ScriptedLLM

DOC = """# Payments HLD

## 3. API

The reporting API has no authentication because it is internal.

## 7. Network

All internal APIs are reachable only through the service mesh, and every
call is authenticated with mutual TLS using workload certificates.
"""


class StubVerifierLLM:
    """Returns canned JSON replies in order and records what it was sent."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def invoke(self, messages):
        self.calls.append(messages)
        reply = self.replies.pop(0) if self.replies else ""
        if isinstance(reply, Exception):
            raise reply
        return FakeMessage(content=reply)


def _finding(issue, section="3. API", severity="HIGH"):
    return Finding(section=section, domain="application", severity=severity,
                   issue=issue, recommendation="Fix it.")


def _reply(*verdicts):
    return json.dumps({"verdicts": [
        {"id": i, "verdict": v, "reason": r, "quote": q}
        for i, (v, r, q) in enumerate(verdicts, 1)
    ]})


SECTIONS = parse_text(DOC, "hld.md")
MTLS = "every call is authenticated with mutual TLS using workload certificates"


def test_refutation_with_real_quote_is_accepted():
    f = _finding("Reporting API has no authentication.")
    llm = StubVerifierLLM(_reply((REFUTED, "Section 7 enforces mTLS.", MTLS)))
    Verifier(llm).verify([f], SECTIONS)
    assert f.verifier_status == REFUTED
    assert "mutual TLS" in f.verifier_reason


def test_refutation_without_document_quote_becomes_needs_human():
    f = _finding("Reporting API has no authentication.")
    llm = StubVerifierLLM(_reply((REFUTED, "Probably fine.", "the API uses OAuth everywhere")))
    Verifier(llm).verify([f], SECTIONS)
    assert f.verifier_status == NEEDS_HUMAN


def test_refutation_quoting_an_absence_becomes_needs_human():
    # The quote confirms the gap ("has no authentication"); it cannot be the
    # control that mitigates it.
    f = _finding("Reporting API has no authentication.")
    quote = "The reporting API has no authentication because it is internal"
    llm = StubVerifierLLM(_reply((REFUTED, "It is internal.", quote)))
    Verifier(llm).verify([f], SECTIONS)
    assert f.verifier_status == NEEDS_HUMAN
    assert "absence" in f.verifier_reason


def test_quote_asserts_absence():
    from src.verifier import quote_asserts_absence
    assert quote_asserts_absence("Traffic between VPCs does not pass through the inspection VPC")
    assert quote_asserts_absence("The Admin API has no authentication plugin configured")
    assert not quote_asserts_absence(MTLS)


def test_model_error_never_drops_findings():
    findings = [_finding("A"), _finding("B")]
    Verifier(StubVerifierLLM(RuntimeError("ollama down"))).verify(findings, SECTIONS)
    assert [f.verifier_status for f in findings] == [NEEDS_HUMAN, NEEDS_HUMAN]


def test_missing_verdict_in_batch_becomes_needs_human():
    findings = [_finding("A"), _finding("B")]
    llm = StubVerifierLLM(_reply((CONFIRMED, "Clear.", "")))  # only id 1 answered
    Verifier(llm).verify(findings, SECTIONS)
    assert [f.verifier_status for f in findings] == [CONFIRMED, NEEDS_HUMAN]


def test_batches_and_whole_document_are_sent():
    findings = [_finding(str(i)) for i in range(7)]
    llm = StubVerifierLLM(_reply(*[(CONFIRMED, "ok", "")] * 6), _reply((CONFIRMED, "ok", "")))
    Verifier(llm, batch_size=6).verify(findings, SECTIONS)
    assert len(llm.calls) == 2
    assert MTLS.split()[0] in llm.calls[0][1][1]  # section 7 text reaches the verifier
    assert all(f.verifier_status == CONFIRMED for f in findings)


def test_parse_tolerates_fences_and_rejects_unknown_verdicts():
    text = "```json\n" + _reply((CONFIRMED, "a", ""), ("MAYBE", "b", "")) + "\n```"
    parsed = _parse(text, 2)
    assert parsed[1].verdict == CONFIRMED and 2 not in parsed


def test_short_quotes_do_not_count_as_evidence():
    doc = "All internal APIs use TLS."
    assert not quote_in_document("use TLS", doc)
    assert quote_in_document("All internal APIs use TLS", doc)


def test_split_keeps_needs_human_and_unverified():
    a, b, c, d = (_finding(x) for x in "abcd")
    a.verifier_status, b.verifier_status, c.verifier_status = CONFIRMED, REFUTED, NEEDS_HUMAN
    kept, refuted = split_by_verdict([a, b, c, d])
    assert kept == [a, c, d] and refuted == [b]


def test_agent_removes_refuted_findings_from_score(config, fake_kb):
    config.raw["agent"]["enable_verifier"] = True
    llm = ScriptedLLM([FakeMessage(tool_calls=[{"name": "section_complete",
                                                "args": {"rationale": "ok"}, "id": "1"}])] * 8)
    from src.agent import ReviewAgent
    agent = ReviewAgent(config=config, kb=fake_kb or FakeKB(), llm=llm)

    class RefuteAll:
        def invoke(self, messages):
            n = messages[1][1].count("] severity=")
            return FakeMessage(content=_reply(*[(REFUTED, "mitigated", MTLS)] * n))

    agent.verifier_llm = RefuteAll()
    result = agent.review(parse_text(DOC, "hld.md"), "hld.md",
                          ["application", "security", "network"])
    assert result.findings == []
    assert result.refuted_findings, "refuted findings must be preserved, not deleted"
    assert result.rag_status == "GREEN"
