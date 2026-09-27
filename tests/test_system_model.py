"""System-model extraction (fake LLM) and deterministic model rules."""

from __future__ import annotations

import json

from src.model_rules import run_model_rules
from src.parser import parse_text
from src.system_model import SystemModel, extract_system_model, merge_extraction, _norm

DOC = """## Edge

The partner portal is internet-facing and accepts requests from partner users.
Partners call the orders API over HTTP with no authentication so that onboarding stays simple.

## Data

The customer database stores customer names, addresses and card numbers.
The customer database is configured as publicly accessible for the BI vendor.
"""


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        return json.dumps(self.payload)


PAYLOAD = {
    "components": [
        {"name": "Partner users", "kind": "external_party", "zone": "partner",
         "exposure": "public", "data": [],
         "evidence": "accepts requests from partner users"},
        {"name": "Orders API", "kind": "service", "zone": "internal",
         "exposure": "internal", "data": [],
         "evidence": "Partners call the orders API over HTTP with no authentication"},
        {"name": "Customer database", "kind": "datastore", "zone": "restricted",
         "exposure": "public", "data": ["pii", "pci"],
         "evidence": "The customer database is configured as publicly accessible for the BI vendor."},
        {"name": "Invented cache", "kind": "datastore", "zone": "internal",
         "evidence": "the cache replicates every five minutes across regions"},
    ],
    "flows": [
        {"source": "Partner users", "target": "Orders API", "protocol": "HTTP",
         "auth": "none", "encrypted": "no",
         "evidence": "Partners call the orders API over HTTP with no authentication"},
    ],
    "controls": [],
}


def _model():
    sections = parse_text(DOC, "t")
    return extract_system_model(sections, FakeLLM(PAYLOAD), "t"), sections


def test_ungrounded_facts_are_dropped():
    model, _ = _model()
    assert model.component("Invented cache") is None
    assert model.dropped_ungrounded == 1


def test_invalid_enum_values_fall_back_to_unknown():
    model = SystemModel()
    merge_extraction(model, {"components": [
        {"name": "X", "kind": "banana", "zone": "moon", "exposure": "??",
         "evidence": "The partner portal is internet-facing and accepts requests"}]},
        parse_text(DOC, "t"), _norm(DOC))
    c = model.component("X")
    assert (c.kind, c.zone, c.exposure) == ("other", "unknown", "unknown")


def test_structural_rules_fire():
    model, _ = _model()
    fired = {f.rule_id for f in run_model_rules(model)}
    assert {"SM-AUTH-001", "SM-DATA-001", "SM-ENC-001"} <= fired


def test_findings_carry_the_quote():
    model, _ = _model()
    for f in run_model_rules(model):
        assert f.evidence_excerpt and f.evidence_excerpt.lower() in DOC.lower()


def test_clean_model_raises_nothing():
    model = SystemModel()
    merge_extraction(model, {
        "components": [
            {"name": "API", "kind": "service", "zone": "internal", "exposure": "internal",
             "evidence": "Partners call the orders API over HTTP with no authentication"},
            {"name": "DB", "kind": "datastore", "zone": "restricted", "exposure": "internal",
             "data": ["pci"], "evidence": "The customer database stores customer names, addresses"}],
        "flows": [{"source": "API", "target": "DB", "auth": "mtls", "encrypted": "yes",
                   "evidence": "The customer database stores customer names, addresses"}],
    }, parse_text(DOC, "t"), _norm(DOC))
    assert run_model_rules(model) == []


def test_malformed_llm_output_does_not_crash():
    class Broken:
        def invoke(self, messages):
            return "not json at all"
    model = extract_system_model(parse_text(DOC, "t"), Broken(), "t")
    assert model.components == [] and run_model_rules(model) == []


def test_truncated_json_keeps_complete_items():
    from src.system_model import _parse_json
    text = ('{"components": [{"name": "A", "evidence": "x"}, {"name": "B", "evidence": "y"}, '
            '{"name": "C", "evid')
    data = _parse_json(text)
    assert [c["name"] for c in data["components"]] == ["A", "B"]


def test_truncated_json_does_not_leak_items_across_lists():
    from src.system_model import _parse_json
    text = ('{"components": [{"name": "A", "evidence": "x"}], "flows": [{"source": "A", '
            '"target": "B", "evidence": "z"}, {"source": "Q"')
    data = _parse_json(text)
    assert len(data["components"]) == 1 and len(data["flows"]) == 1
