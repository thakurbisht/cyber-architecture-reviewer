"""Scoring, deduplication and report rendering tests."""

from __future__ import annotations

from src.models import (
    Finding,
    ORIGIN_AGENT,
    ORIGIN_RULES,
    ReviewResult,
    dedupe_findings,
    normalise_severity,
    sort_findings,
)
from src.report import build_report, compute_risk, diff_reviews, priority_actions


def _f(severity="HIGH", section="Access Layer", domain="network",
       issue="Two uplinks terminate on the same distribution switch.",
       reference="", kb_source="", origin=ORIGIN_AGENT, rule_id=""):
    return Finding(
        section=section, domain=domain, severity=severity, issue=issue,
        recommendation="Reroute one uplink to the peer switch.",
        standard_reference=reference, kb_source=kb_source,
        origin=origin, rule_id=rule_id,
    )


# -- severity normalisation ------------------------------------------------
def test_severity_aliases_normalise():
    assert normalise_severity("critical") == "CRITICAL"
    assert normalise_severity("Sev1") == "CRITICAL"
    assert normalise_severity("major") == "HIGH"
    assert normalise_severity("informational") == "LOW"
    assert normalise_severity("nonsense") == "MEDIUM"
    assert normalise_severity(None) == "MEDIUM"


def test_finding_coerces_bad_severity():
    assert _f(severity="blocker").severity == "CRITICAL"


# -- scoring ---------------------------------------------------------------
def test_no_findings_is_green(config):
    score, rag, counts = compute_risk([], config)
    assert score == 0.0
    assert rag == "GREEN"
    assert counts["CRITICAL"] == 0


def test_single_critical_forces_red(config):
    score, rag, _ = compute_risk([_f(severity="CRITICAL")], config)
    assert rag == "RED"
    assert score > 0


def test_many_lows_do_not_reach_red(config):
    findings = [_f(severity="LOW", section=f"S{i}") for i in range(12)]
    _score, rag, _ = compute_risk(findings, config)
    assert rag != "RED"


def test_critical_outranks_volume_of_lows(config):
    one_critical, _, _ = compute_risk([_f(severity="CRITICAL")], config)
    many_lows, _, _ = compute_risk(
        [_f(severity="LOW", section=f"S{i}") for i in range(15)], config)
    assert one_critical > many_lows


def test_score_saturates_below_ceiling(config):
    findings = [_f(severity="CRITICAL", section=f"S{i}") for i in range(50)]
    score, _, _ = compute_risk(findings, config)
    assert score <= 100.0


def test_score_is_monotonic(config):
    base = [_f(severity="HIGH", section=f"S{i}") for i in range(3)]
    more = base + [_f(severity="HIGH", section="S99")]
    assert compute_risk(more, config)[0] > compute_risk(base, config)[0]


def test_amber_band(config):
    findings = [_f(severity="HIGH", section=f"S{i}") for i in range(1)]
    _score, rag, _ = compute_risk(findings, config)
    assert rag in {"AMBER", "GREEN"}
    findings = [_f(severity="HIGH", section=f"S{i}") for i in range(3)]
    _score, rag, _ = compute_risk(findings, config)
    assert rag in {"AMBER", "RED"}


# -- ordering and dedup ----------------------------------------------------
def test_sort_is_severity_first():
    findings = [_f(severity="LOW"), _f(severity="CRITICAL", section="A"),
                _f(severity="MEDIUM", section="B")]
    ordered = sort_findings(findings)
    assert [f.severity for f in ordered] == ["CRITICAL", "MEDIUM", "LOW"]


def test_sort_is_stable_across_input_order():
    a = _f(severity="HIGH", section="Alpha")
    b = _f(severity="HIGH", section="Beta")
    c = _f(severity="CRITICAL", section="Gamma")
    assert [f.section for f in sort_findings([a, b, c])] == \
           [f.section for f in sort_findings([c, b, a])]


def test_dedupe_collapses_same_defect_worded_differently():
    a = _f(issue="Both uplinks terminate on the same distribution switch.")
    b = _f(issue="The same distribution switch terminates both uplinks.")
    assert len(dedupe_findings([a, b])) == 1


def test_dedupe_prefers_grounded_finding():
    ungrounded = _f()
    grounded = _f(reference="Three-Tier LAN Standard §3.2",
                  kb_source="network/three-tier-lan-standard.md")
    kept = dedupe_findings([ungrounded, grounded])[0]
    assert kept.is_grounded


def test_dedupe_keeps_distinct_sections():
    a = _f(section="Floor 4")
    b = _f(section="Floor 9")
    assert len(dedupe_findings([a, b])) == 2


def test_rule_findings_never_merge_across_rule_ids():
    a = _f(origin=ORIGIN_RULES, rule_id="NET-HA-001")
    b = _f(origin=ORIGIN_RULES, rule_id="NET-HA-002")
    assert len(dedupe_findings([a, b])) == 2


# -- priority --------------------------------------------------------------
def test_priority_prefers_critical_then_grounded():
    findings = [
        _f(severity="HIGH", section="B"),
        _f(severity="CRITICAL", section="A", reference="Std §1",
           kb_source="s.md"),
        _f(severity="CRITICAL", section="C"),
    ]
    top = priority_actions(sort_findings(findings), 3)
    assert top[0].severity == "CRITICAL"
    assert top[0].is_grounded


# -- report ----------------------------------------------------------------
def _result(findings):
    return ReviewResult(
        document_name="test-design.md",
        findings=findings,
        sections=[],
        audit=[],
        domains_reviewed=["network", "application"],
        kb_chunk_count=42,
    )


def test_report_contains_required_structure(config):
    result = _result([
        _f(severity="CRITICAL", reference="Three-Tier LAN Standard §3.2",
           kb_source="network/three-tier-lan-standard.md"),
        _f(severity="MEDIUM", domain="application", section="API"),
    ])
    build_report(result, config)
    md = result.report_markdown

    for heading in ("# Architecture Assurance Review",
                    "## Executive Summary",
                    "## Overall Status",
                    "## Top 3 Priority Actions",
                    "## Findings",
                    "## Review Coverage"):
        assert heading in md, f"missing {heading}"
    assert "RED" in md
    assert "Three-Tier LAN Standard §3.2" in md


def test_report_writes_fallback_summary_when_model_silent(config):
    result = _result([_f(severity="HIGH")])
    build_report(result, config, executive_summary="")
    assert "This review examined" in result.report_markdown


def test_report_uses_model_summary_when_present(config):
    result = _result([_f()])
    build_report(result, config,
                 executive_summary="The design is not fit for approval.")
    assert "The design is not fit for approval." in result.report_markdown


def test_report_flags_ungrounded_findings(config):
    result = _result([_f(), _f(section="Other")])
    build_report(result, config)
    assert "not tied to a knowledge base clause" in result.report_markdown


def test_report_pipes_are_escaped_in_tables(config):
    result = _result([_f(issue="Rule permits any | any traffic")])
    build_report(result, config)
    assert "any \\| any" in result.report_markdown


def test_empty_review_renders(config):
    result = _result([])
    build_report(result, config)
    assert result.rag_status == "GREEN"
    assert "No findings were raised" in result.report_markdown


def test_save_outputs_writes_both_files(config):
    from src.report import save_outputs

    result = _result([_f()])
    build_report(result, config)
    paths = save_outputs(result, config)
    assert paths["report"].exists()
    assert paths["audit"].exists()
    assert paths["report"].read_text(encoding="utf-8").startswith("# Architecture")


# -- diffing ---------------------------------------------------------------
def test_diff_ignores_wording_drift():
    previous = [_f(issue="Both uplinks terminate on the same switch.")]
    current = [_f(issue="The same switch terminates both of the uplinks.")]
    diff = diff_reviews(previous, current)
    assert len(diff["persisting"]) == 1
    assert not diff["new"]
    assert not diff["resolved"]


def test_diff_detects_genuine_change():
    previous = [_f(section="Floor 4")]
    current = [_f(section="Floor 9")]
    diff = diff_reviews(previous, current)
    assert len(diff["new"]) == 1
    assert len(diff["resolved"]) == 1


def test_priority_actions_prefer_distinct_problems():
    """Three lines about the same defect in three sections is one action."""
    findings = [
        _f(severity="CRITICAL", section="Sec A", rule_id="APP-SEC-001",
           origin=ORIGIN_RULES, issue="Secrets embedded in configuration."),
        _f(severity="CRITICAL", section="Sec B", rule_id="APP-SEC-001",
           origin=ORIGIN_RULES, issue="Secrets embedded in configuration."),
        _f(severity="CRITICAL", section="Sec C", rule_id="APP-TLS-001",
           origin=ORIGIN_RULES, issue="TLS 1.0 is enabled."),
        _f(severity="HIGH", section="Sec D", rule_id="SEC-LOG-001",
           origin=ORIGIN_RULES, issue="No SIEM forwarding."),
    ]
    top = priority_actions(sort_findings(findings), 3)
    assert len({f.rule_id for f in top}) == 3


def test_priority_actions_backfill_when_too_few_problems():
    findings = [
        _f(severity="CRITICAL", section="Sec A", rule_id="APP-SEC-001",
           origin=ORIGIN_RULES),
        _f(severity="CRITICAL", section="Sec B", rule_id="APP-SEC-001",
           origin=ORIGIN_RULES),
    ]
    assert len(priority_actions(sort_findings(findings), 3)) == 2
