"""Threat modeling agent with a fake LLM (src/threat_agent.py)."""

from __future__ import annotations

import json

import pytest

from src import dfd as D
from src import threat_agent as TA


def _dfd(approved=True, ai=False):
    d = D.DFD(document="shop.md", zones=["internet", "dmz", "internal", "restricted", "unknown"])
    d.components = [
        D.DFDComponent("customer", "Customer", kind="external_party", zone="internet"),
        D.DFDComponent("api", "Orders API", kind="service", zone="dmz"),
        D.DFDComponent("svc", "order-svc", kind="service", zone="internal"),
        D.DFDComponent("db", "orders DB", kind="datastore", zone="restricted", data=["pci"],
                       public=True),
        D.DFDComponent("cache", "cache", kind="datastore", zone="internal"),
    ]
    d.flows = [
        D.DFDFlow("f1", "customer", "api", protocol="HTTP", auth="none", encrypted="no"),
        D.DFDFlow("f2", "api", "svc", protocol="HTTPS", auth="token", encrypted="yes"),
        D.DFDFlow("f3", "svc", "db", protocol="5432", auth="password", encrypted="yes"),
        D.DFDFlow("f4", "svc", "cache", auth="unknown"),            # same zone: out of scope
    ]
    if ai:
        d.components.append(D.DFDComponent("bot", "Support LLM", kind="llm", zone="internal"))
        d.flows.append(D.DFDFlow("f5", "api", "bot", auth="token", encrypted="yes"))
    if approved:
        d.approve("PB")
    return d


class FakeLLM:
    """Echoes one threat per requested category, plus one invalid category."""

    def __init__(self, fail=False):
        self.prompts = []
        self.fail = fail

    def invoke(self, messages):
        user = messages[-1][1]
        self.prompts.append(user)
        if self.fail:
            raise RuntimeError("ollama down")
        cats = [ln[2:] for ln in user.split("APPLICABLE CATEGORIES")[1].splitlines()
                if ln.startswith("- ")]
        threats = [{"category": c, "title": f"{c} threat on element",
                    "description": f"Attacker abuses {c}.", "likelihood": "medium",
                    "impact": "high", "mitigations": ["fix it"]} for c in cats]
        threats.append({"category": "Made-up category", "title": "should be dropped"})
        return json.dumps({"threats": threats})


def test_requires_approved_dfd():
    with pytest.raises(ValueError):
        TA.run_threat_model(_dfd(approved=False), FakeLLM(), ["STRIDE"])


def test_applicability_scopes_boundary_elements_only():
    targets = TA.applicability(_dfd())
    ids = {t.id for t in targets}
    assert {"f1", "f2", "f3"} <= ids and "f4" not in ids and "cache" not in ids
    by = {t.id: t for t in targets}
    assert by["f1"].stride == "TID"                 # data flow
    assert by["customer"].stride == "SR"            # external entity
    assert by["db"].stride == "TRID"                # data store
    assert by["svc"].stride == "STRIDE"             # process


def test_rule_threats_from_confirmed_facts():
    rules = TA.rule_threats(_dfd())
    titles = " | ".join(t.title for t in rules)
    assert "Unauthenticated access" in titles
    assert "Cleartext traffic" in titles
    assert "Static password" in titles
    assert "Publicly reachable store" in titles
    assert not any(t.target_id == "f2" for t in rules)      # token + TLS: nothing to flag
    assert all(t.source == "rule" for t in rules)


def test_stride_run_discards_invalid_categories_and_numbers_threats():
    run = TA.run_threat_model(_dfd(), FakeLLM(), ["STRIDE"])
    assert run.frameworks == ["STRIDE"] and run.dfd_version == 1
    assert all(t.framework == "STRIDE" for t in run.threats)
    assert not any("Made-up" in t.category for t in run.threats)
    assert [t.id for t in run.threats][:2] == ["T-001", "T-002"]
    assert run.threats[0].risk == "CRITICAL"               # rule threat sorts first


def test_rule_threat_suppresses_llm_duplicate_on_same_element_and_category():
    run = TA.run_threat_model(_dfd(), FakeLLM(), ["STRIDE"])
    f1_disclosure = [t for t in run.threats if t.target_id == "f1"
                     and t.category == "Information disclosure"]
    assert len(f1_disclosure) == 1 and f1_disclosure[0].source == "rule"


def test_maestro_only_runs_on_ai_components():
    llm = FakeLLM()
    run = TA.run_threat_model(_dfd(ai=True), llm, ["MAESTRO"])
    assert run.threats and all(t.framework == "MAESTRO" for t in run.threats)
    assert {t.target_id for t in run.threats} == {"bot"}
    assert all(t.category.startswith("L") for t in run.threats)


def test_both_frameworks():
    run = TA.run_threat_model(_dfd(ai=True), FakeLLM(), ["STRIDE", "MAESTRO"])
    assert {t.framework for t in run.threats} == {"STRIDE", "MAESTRO"}


def test_llm_failure_still_returns_rule_threats():
    run = TA.run_threat_model(_dfd(), FakeLLM(fail=True), ["STRIDE"])
    assert run.llm_errors > 0
    assert run.threats and all(t.source == "rule" for t in run.threats)


def test_prompt_carries_confirmed_properties():
    llm = FakeLLM()
    TA.run_threat_model(_dfd(), llm, ["STRIDE"])
    f2 = next(p for p in llm.prompts if '"Orders API → order-svc"' in p)
    assert "authentication=token" in f2 and "encrypted=yes" in f2


def test_findings_only_rule_or_accepted(tmp_path):
    run = TA.run_threat_model(_dfd(), FakeLLM(), ["STRIDE"])
    llm_threat = next(t for t in run.threats if t.source == "llm")
    assert all(f.origin == "rules_engine" for f in TA.to_findings(run))
    llm_threat.status = "accepted"
    found = TA.to_findings(run)
    assert any(f.verifier_status == "CONFIRMED" for f in found)
    TA.save_run(run, tmp_path)
    again = TA.load_runs("shop.md", tmp_path)[0]
    assert len(again.threats) == len(run.threats)
