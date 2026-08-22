"""End-to-end agent graph tests using a scripted stub LLM.

No Ollama, no ChromaDB, no model download. These tests exercise the graph
wiring, the tool loop, every loop cap, citation verification, and the
tool-free report node - which is to say, every structural failure mode the
system has.
"""

from __future__ import annotations

import pytest

from src.agent import ReviewAgent, _extract_tool_calls, _split_narrative
from src.models import ORIGIN_AGENT, ORIGIN_RULES, RetrievedChunk
from src.parser import parse_text

from conftest import DEFAULT_REPORT, FakeKB, FakeMessage, ScriptedLLM

DESIGN = """# Campus Design

## 1. Access Layer

Floor 4 has two uplinks but both terminate on the same distribution switch
DIST-SW-A because the fibre count to that floor was insufficient at survey.

## 2. Management Plane

SNMPv2c is configured with community string public for the monitoring
platform, and management access uses telnet from engineer workstations.
"""


def _tool_call(name, args, call_id="1"):
    return {"name": name, "args": args, "id": call_id}


def _flag(issue, severity="CRITICAL", reference="Three-Tier LAN Standard §3.2"):
    return _tool_call("flag_finding", {
        "severity": severity,
        "issue": issue,
        "evidence": "both terminate on the same distribution switch DIST-SW-A",
        "standard_reference": reference,
        "recommendation": "Reroute one uplink to DIST-SW-B.",
        "domain": "network",
    })


def _complete():
    return _tool_call("section_complete", {"rationale": "Section reviewed."}, "2")


def _agent(script, config, kb=None, report=None):
    llm = ScriptedLLM(script, report_response=report)
    agent = ReviewAgent(config=config, kb=kb or FakeKB(), llm=llm)
    return agent, llm


def _completes(n):
    """n section_complete turns - enough to close every section quickly."""
    return [FakeMessage(tool_calls=[_complete()]) for _ in range(n)]


# ==========================================================================
# Happy path
# ==========================================================================
def test_full_review_produces_findings_and_report(config, fake_kb):
    script = [
        # section 1: flag then complete
        FakeMessage(tool_calls=[_flag("Floor 4 uplinks both land on DIST-SW-A.")]),
        FakeMessage(tool_calls=[_complete()]),
        # section 2: complete immediately
        FakeMessage(tool_calls=[_complete()]),
    ]
    report = FakeMessage(content=(
        "## Executive Summary\n\nThe design is not ready for approval.\n\n"
        "## Assurance Opinion\n\nThe status is driven by resilience gaps."
    ))
    agent, _llm = _agent(script, config, fake_kb, report=report)
    sections = parse_text(DESIGN, "campus.md")

    result = agent.review(sections, "campus.md", ["network"])

    assert result.findings, "no findings produced"
    assert result.rag_status == "RED"
    assert "The design is not ready for approval." in result.executive_summary
    assert "Assurance Opinion" in result.report_markdown
    assert result.report_markdown.startswith("# Architecture Assurance Review")


def test_rules_findings_present_without_any_model_findings(config, fake_kb):
    agent, _ = _agent(_completes(6), config, fake_kb)

    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    rule_ids = {f.rule_id for f in result.findings if f.origin == ORIGIN_RULES}
    assert "NET-MGMT-001" in rule_ids
    assert "NET-HA-002" in rule_ids


# ==========================================================================
# The report node must not be tool-bound
# ==========================================================================
def test_report_node_uses_unbound_model(config, fake_kb):
    """The bug the article spent hours on: report_node with llm_with_tools
    emits JSON instead of prose. Assert the handles differ."""
    agent, _ = _agent(
        _completes(6), config, fake_kb,
        report=FakeMessage(content="## Executive Summary\n\nPlain prose."))

    assert agent.reviewer is not agent.writer
    assert getattr(agent.reviewer, "bound_tools", None) is not None
    assert getattr(agent.writer, "bound_tools", None) is None

    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])
    assert "Plain prose." in result.executive_summary
    assert "{" not in result.executive_summary


# ==========================================================================
# Loop control
# ==========================================================================
def test_loop_cap_stops_a_runaway_agent(config, fake_kb):
    """Model never calls section_complete. The cap must break the loop."""
    config.raw["agent"]["max_tool_iterations"] = 3
    search = _tool_call("search_architectural_standards",
                        {"query": "uplink diversity requirement",
                         "domain": "network"}, "s")
    # 40 identical search turns - far more than the cap allows.
    script = [FakeMessage(tool_calls=[search]) for _ in range(40)]
    agent, _ = _agent(script, config, fake_kb)

    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    steps = [e.step for e in result.audit]
    assert "loop_cap_reached" in steps
    assert result.report_markdown  # completed rather than hanging


def test_duplicate_search_is_suppressed(config, fake_kb):
    search = _tool_call("search_architectural_standards",
                        {"query": "uplink diversity", "domain": "network"}, "s")
    script = [
        FakeMessage(tool_calls=[search]),
        FakeMessage(tool_calls=[search]),   # identical - must be suppressed
        FakeMessage(tool_calls=[_complete()]),
        FakeMessage(tool_calls=[_complete()]),
    ]
    agent, _ = _agent(script, config, fake_kb)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    assert "search_suppressed_duplicate" in [e.step for e in result.audit]


def test_search_budget_is_enforced(config, fake_kb):
    config.raw["agent"]["max_searches_per_section"] = 1
    config.raw["agent"]["max_tool_iterations"] = 8
    script = []
    for i in range(6):
        script.append(FakeMessage(tool_calls=[_tool_call(
            "search_architectural_standards",
            {"query": f"distinct question number {i}", "domain": "network"}, f"s{i}")]))
    script.extend(_completes(4))

    agent, _ = _agent(script, config, fake_kb)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    assert "search_budget_exhausted" in [e.step for e in result.audit]


# ==========================================================================
# Citation verification
# ==========================================================================
def test_verified_citation_is_grounded(config, fake_kb):
    script = [
        FakeMessage(tool_calls=[_flag("Uplinks lack diversity.",
                                      reference="Three-Tier LAN Standard §3.2")]),
        FakeMessage(tool_calls=[_complete()]),
        FakeMessage(tool_calls=[_complete()]),
    ]
    agent, _ = _agent(script, config, fake_kb)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    agent_findings = [f for f in result.findings if f.origin == ORIGIN_AGENT]
    assert agent_findings
    assert agent_findings[0].is_grounded
    assert agent_findings[0].kb_source == "three-tier-lan-standard.md"


def test_hallucinated_citation_is_marked_unverified(config, fake_kb):
    script = [
        FakeMessage(tool_calls=[_flag(
            "Uplinks lack diversity.",
            reference="Imaginary Nonexistent Standard §99.9")]),
        FakeMessage(tool_calls=[_complete()]),
        FakeMessage(tool_calls=[_complete()]),
    ]
    agent, _ = _agent(script, config, fake_kb)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    agent_findings = [f for f in result.findings if f.origin == ORIGIN_AGENT]
    assert agent_findings
    assert "(unverified)" in agent_findings[0].standard_reference
    assert not agent_findings[0].is_grounded
    assert "citation_unverified" in [e.step for e in result.audit]


# ==========================================================================
# Resilience
# ==========================================================================
def test_model_failure_does_not_abort_the_review(config, fake_kb):
    class BrokenLLM(ScriptedLLM):
        def invoke(self, messages):
            self.calls.append(list(messages))
            if len(self.calls) <= 2:
                raise RuntimeError("connection reset by peer")
            return FakeMessage(content="## Executive Summary\n\nPartial review.")

    llm = BrokenLLM([])
    agent = ReviewAgent(config=config, kb=fake_kb, llm=llm)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    assert result.report_markdown
    assert any("Model call failed" in w for w in result.warnings)
    # Deterministic findings survive a model outage.
    assert any(f.origin == ORIGIN_RULES for f in result.findings)


def test_retrieval_failure_is_recorded_not_fatal(config):
    class BrokenKB(FakeKB):
        def search(self, *a, **kw):
            raise RuntimeError("Nothing found on disk")

    agent, _ = _agent(_completes(6), config, BrokenKB())

    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])
    assert "retrieval_error" in [e.step for e in result.audit]
    assert result.report_markdown


def test_empty_knowledge_base_produces_warning(config):
    class EmptyKB(FakeKB):
        def status(self):
            return {"counts": {"network": 0, "application": 0, "security": 0,
                               "cloud_data": 0},
                    "total": 0, "embedding_model": "nomic-embed-text",
                    "persist_dir": "/tmp", "warnings": [
                        "No knowledge base chunks for: network"]}

        def search(self, *a, **kw):
            return []

    agent, _ = _agent(_completes(6), config, EmptyKB())

    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])
    assert any("No knowledge base chunks" in w for w in result.warnings)
    assert "Review Caveats" in result.report_markdown


# ==========================================================================
# Tool call extraction
# ==========================================================================
def test_extracts_native_tool_calls():
    msg = FakeMessage(tool_calls=[_flag("issue")])
    calls = _extract_tool_calls(msg)
    assert calls[0]["name"] == "flag_finding"


def test_recovers_tool_call_emitted_as_json_text():
    """Small local models often emit the call as text instead of a tool call.
    Without recovery, the review silently produces zero findings."""
    msg = FakeMessage(content=(
        'I found an issue. {"name": "flag_finding", "arguments": '
        '{"severity": "HIGH", "issue": "Single uplink present", '
        '"recommendation": "Add a second uplink"}}'
    ))
    calls = _extract_tool_calls(msg)
    assert calls
    assert calls[0]["name"] == "flag_finding"
    assert calls[0]["args"]["severity"] == "HIGH"


def test_plain_prose_yields_no_tool_calls():
    assert _extract_tool_calls(FakeMessage(content="Looks fine to me.")) == []


# ==========================================================================
# Narrative splitting
# ==========================================================================
def test_split_narrative_separates_sections():
    summary, opinion = _split_narrative(
        "## Executive Summary\n\nThe design has gaps.\n\n"
        "## Assurance Opinion\n\nRemediate before build."
    )
    assert summary == "The design has gaps."
    assert opinion == "Remediate before build."


def test_split_narrative_handles_missing_opinion():
    summary, opinion = _split_narrative("The design has gaps.")
    assert summary == "The design has gaps."
    assert opinion == ""


# ==========================================================================
# Cross-domain pass
# ==========================================================================
def test_correlation_pass_records_cross_domain_finding(config, fake_kb):
    mixed = DESIGN + """

## 3. API Gateway

The internal reporting API has no authentication because it is only
reachable from within the cluster and the internal network is trusted.
"""
    cross = _tool_call("flag_finding", {
        "severity": "HIGH",
        "issue": ("The application assumes network isolation the network "
                  "design does not provide."),
        "recommendation": "Authenticate the internal API.",
        "domain": "application",
    }, "x")

    script = _completes(6) + [
        FakeMessage(tool_calls=[cross]),
        FakeMessage(tool_calls=[_complete()]),
    ]
    agent, _ = _agent(script, config, fake_kb)
    result = agent.review(parse_text(mixed, "d.md"), "d.md",
                          ["network", "application", "security"])

    assert "correlation_complete" in [e.step for e in result.audit]


def test_correlation_skipped_for_single_domain(config, fake_kb):
    agent, _ = _agent(_completes(6), config, fake_kb)

    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])
    assert "correlation_skipped" in [e.step for e in result.audit]


# ==========================================================================
# Audit completeness
# ==========================================================================
def test_audit_trail_explains_every_finding(config, fake_kb):
    script = [
        FakeMessage(tool_calls=[_flag("Uplinks lack diversity.")]),
        FakeMessage(tool_calls=[_complete()]),
        FakeMessage(tool_calls=[_complete()]),
    ]
    agent, _ = _agent(script, config, fake_kb)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    steps = [e.step for e in result.audit]
    for required in ("triage", "retrieve", "model_turn", "tool_flag_finding",
                     "section_complete", "report_written", "review_complete"):
        assert required in steps, f"audit trail missing '{required}'"

    # Every retrieval records what it retrieved, not just that it happened.
    retrieves = [e for e in result.audit if e.step == "retrieve"]
    assert retrieves and "chunks" in retrieves[0].detail
    assert "query" in retrieves[0].detail


def test_report_node_flagged_as_tool_free_in_audit(config, fake_kb):
    agent, _ = _agent(_completes(6), config, fake_kb)
    result = agent.review(parse_text(DESIGN, "d.md"), "d.md", ["network"])

    written = [e for e in result.audit if e.step == "report_written"]
    assert written and written[0].detail["used_tool_free_model"] is True
