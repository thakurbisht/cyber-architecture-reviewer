"""DFD model, canvas sync and storage (src/dfd.py)."""

from __future__ import annotations

import pytest

from src import dfd as D

MODEL = {
    "components": [
        {"name": "Customer", "kind": "external_party", "zone": "internet", "exposure": "public"},
        {"name": "Kong API GW", "kind": "service", "zone": "dmz"},
        {"name": "orders DB", "kind": "datastore", "zone": "restricted", "data": ["pci"]},
    ],
    "flows": [
        {"source": "Customer", "target": "Kong API GW", "protocol": "HTTPS", "auth": "token",
         "encrypted": "yes"},
        {"source": "Kong API GW", "target": "orders DB", "auth": "unknown"},
        {"source": "Kong API GW", "target": "orders DB", "auth": "password"},   # duplicate pair
        {"source": "Batch job", "target": "orders DB"},                          # unknown endpoint
    ],
}


def _dfd():
    return D.from_system_model(MODEL, "checkout.md")


def _canvas(dfd):
    nodes = [{"id": c.id, "x": c.x, "y": c.y, "label": c.name} for c in dfd.components]
    edges = [{"id": f.id, "source": f.source, "target": f.target} for f in dfd.flows]
    return nodes, edges


def test_draft_from_system_model():
    d = _dfd()
    assert {c.name for c in d.components} == {"Customer", "Kong API GW", "orders DB", "Batch job"}
    assert d.component("batch-job").zone == "unknown"      # invented endpoint needs a zone
    assert len(d.flows) == 3                               # duplicate pair dropped
    assert all(c.source == "ai" for c in d.components)


def test_every_component_is_laid_out_inside_its_zone():
    d = _dfd()
    for c in d.components:
        assert D.zone_at(d, c.x) == c.zone


def test_dragging_into_another_zone_changes_the_trust_boundary():
    d = _dfd()
    nodes, edges = _canvas(d)
    kong = next(n for n in nodes if n["id"] == "kong-api-gw")
    kong["x"] = D.zone_x(d, "internal") + 40
    changes = D.sync_from_canvas(d, nodes, edges)
    assert d.component("kong-api-gw").zone == "internal"
    assert d.component("kong-api-gw").edited
    assert any("DMZ → Internal" in c for c in changes)


def test_new_and_deleted_edges_sync():
    d = _dfd()
    nodes, edges = _canvas(d)
    edges = [e for e in edges if not (e["source"] == "kong-api-gw" and e["target"] == "orders-db")]
    edges.append({"id": "new1", "source": "customer", "target": "orders-db"})
    D.sync_from_canvas(d, nodes, edges)
    pairs = {(f.source, f.target) for f in d.flows}
    assert ("customer", "orders-db") in pairs
    assert ("kong-api-gw", "orders-db") not in pairs
    assert d.flow("new1").source_tag == "human"


def test_deleting_a_component_removes_its_flows():
    d = _dfd()
    nodes, edges = _canvas(d)
    nodes = [n for n in nodes if n["id"] != "kong-api-gw"]
    D.sync_from_canvas(d, nodes, edges)
    assert d.component("kong-api-gw") is None
    assert all("kong-api-gw" not in (f.source, f.target) for f in d.flows)


def test_warnings_flag_unknowns_on_boundary_flows():
    w = " ".join(_dfd().warnings())
    assert "no trust zone" in w and "unknown authentication" in w


def test_boundary_flows_and_risk():
    d = _dfd()
    risky = [f for f in d.boundary_flows() if D.flow_risky(d, f)]
    assert {(f.source, f.target) for f in risky} >= {("kong-api-gw", "orders-db")}
    safe = next(f for f in d.flows if f.source == "customer")
    assert not D.flow_risky(d, safe)


def test_edit_after_approval_reopens_draft():
    d = _dfd()
    d.approve("PB")
    assert (d.status, d.version) == ("approved", 1)
    D.add_component(d, "Redis cache", "datastore", "internal")
    assert d.status == "draft"


def test_approved_versions_are_immutable(tmp_path):
    d = _dfd()
    with pytest.raises(ValueError):
        D.save_approved(d, tmp_path)
    d.approve("PB", "ok")
    D.save_approved(d, tmp_path)
    with pytest.raises(FileExistsError):
        D.save_approved(d, tmp_path)
    d.approve("PB")
    D.save_approved(d, tmp_path)
    assert [v for v, _ in D.list_versions("checkout.md", tmp_path)] == [1, 2]
    loaded = D.load_latest("checkout.md", tmp_path)
    assert loaded.version == 2 and loaded.status == "approved"
    assert {c.id for c in loaded.components} == {c.id for c in d.components}


def test_add_zone_keeps_canonical_order():
    d = _dfd()
    D.add_zone(d, "management")
    assert d.zones.index("management") < d.zones.index("restricted")
    for c in d.components:
        assert D.zone_at(d, c.x) == c.zone


def test_facts_for_section_lists_confirmed_facts_for_mentioned_components():
    d = _dfd()
    d.flow("f1").auth, d.flow("f1").encrypted = "token", "yes"
    facts = D.facts_for_section(d, "Edge", "Customers reach the Kong API GW over HTTPS.")
    assert "Kong API GW: service, zone DMZ" in facts
    assert "Flow Customer -> Kong API GW" in facts and "authentication token" in facts
    assert D.facts_for_section(d, "Other", "Nothing relevant here.") == ""
    assert D.facts_for_section(None, "x", "y") == ""


def test_prompt_includes_facts_only_when_given():
    from src.models import Section
    from src.prompts import build_section_user
    s = Section(index=0, heading="Edge", body="Kong API GW routes traffic.", domain="application")
    assert "CONFIRMED ARCHITECTURE FACTS" not in build_section_user("d", s, [], [])
    assert "CONFIRMED ARCHITECTURE FACTS" in build_section_user("d", s, [], [], "- Kong: dmz")


def test_merge_draft_folds_a_second_source_in_without_overwriting():
    a = D.DFD(document="k")
    a.components = [D.DFDComponent("gw", "API Gateway", kind="service", zone="dmz",
                                   source="diagram")]
    a.flows = [D.DFDFlow("f1", "gw", "gw", auth="token", encrypted="unknown",
                         source_tag="diagram")]
    b = D.DFD(document="k")
    b.components = [D.DFDComponent("gw2", "API gateway", kind="other", zone="internal",
                                   source="ai"),
                    D.DFDComponent("db", "Orders DB", kind="datastore",
                                   zone="restricted", source="ai")]
    b.flows = [D.DFDFlow("fx", "gw2", "db", auth="none", encrypted="no",
                         source_tag="ai")]
    added_c, added_f = D.merge_draft(a, b)
    assert (added_c, added_f) == (1, 1)
    gw = next(c for c in a.components if c.name == "API Gateway")
    assert gw.zone == "dmz"                       # the first source wins
    assert gw.kind == "service" and gw.source == "text+diagram"
    new_flow = next(f for f in a.flows if f.id != "f1")
    assert (new_flow.source, new_flow.encrypted) == (gw.id, "no")


def test_merge_draft_fills_only_the_gaps_on_a_shared_flow():
    a = D.DFD(document="k")
    a.components = [D.DFDComponent("u", "User", zone="internet"),
                    D.DFDComponent("s", "Service", zone="internal")]
    a.flows = [D.DFDFlow("f1", "u", "s", auth="unknown", encrypted="yes",
                         source_tag="diagram")]
    b = D.DFD(document="k")
    b.components = [D.DFDComponent("u2", "user", zone="internet"),
                    D.DFDComponent("s2", "service", zone="internal")]
    b.flows = [D.DFDFlow("fx", "u2", "s2", auth="oauth", encrypted="no",
                         protocol="HTTPS", source_tag="ai")]
    assert D.merge_draft(a, b) == (0, 0)
    assert a.flows[0].auth == "oauth"             # gap filled
    assert a.flows[0].encrypted == "yes"          # existing value kept
    assert a.flows[0].protocol == "HTTPS"
    assert a.flows[0].source_tag == "text+diagram"
