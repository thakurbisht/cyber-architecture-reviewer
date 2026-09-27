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
