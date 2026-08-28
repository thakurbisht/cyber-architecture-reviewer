"""Topology diagram parsing (draw.io / Visio) and the graph-based
uplink-diversity rule.
"""

from __future__ import annotations

import base64
import zlib
from urllib.parse import quote
from xml.etree import ElementTree as ET

import pytest

from src.parser import parse_document
from src.rules import run_topology_rules
from src.topology import (
    Link,
    TopologyGraph,
    parse_drawio_xml,
    parse_visio_vsdx,
    sniff_drawio_xml,
)

# ---------------------------------------------------------------------------
# draw.io - uncompressed export (Extras > Edit Diagram, or File > Export > XML)
# ---------------------------------------------------------------------------
_DRAWIO_UNCOMPRESSED_SPOF = """<mxGraphModel>
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />
    <mxCell id="acc4" value="ACC-SW-4" style="shape=switch" vertex="1" parent="1" />
    <mxCell id="dista" value="DIST-SW-A" style="shape=switch" vertex="1" parent="1" />
    <mxCell id="distb" value="DIST-SW-B" style="shape=switch" vertex="1" parent="1" />
    <mxCell id="e1" style="edgeStyle=orthogonalEdgeStyle" edge="1" parent="1"
            source="acc4" target="dista" value="Uplink 1" />
    <mxCell id="e2" style="edgeStyle=orthogonalEdgeStyle" edge="1" parent="1"
            source="acc4" target="dista" value="Uplink 2" />
  </root>
</mxGraphModel>"""

_DRAWIO_UNCOMPRESSED_DIVERSE = """<mxGraphModel>
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />
    <mxCell id="acc9" value="ACC-SW-9" style="shape=switch" vertex="1" parent="1" />
    <mxCell id="dista" value="DIST-SW-A" style="shape=switch" vertex="1" parent="1" />
    <mxCell id="distb" value="DIST-SW-B" style="shape=switch" vertex="1" parent="1" />
    <mxCell id="e1" edge="1" parent="1" source="acc9" target="dista" value="Uplink 1" />
    <mxCell id="e2" edge="1" parent="1" source="acc9" target="distb" value="Uplink 2" />
  </root>
</mxGraphModel>"""


def test_drawio_uncompressed_parses_devices_and_links():
    graph = parse_drawio_xml(_DRAWIO_UNCOMPRESSED_SPOF)
    names = {d.name for d in graph.devices.values()}
    assert names == {"ACC-SW-4", "DIST-SW-A", "DIST-SW-B"}
    assert len(graph.links) == 2


def test_drawio_diversity_violation_detected_from_graph():
    graph = parse_drawio_xml(_DRAWIO_UNCOMPRESSED_SPOF)
    acc_id = next(d.id for d in graph.devices.values() if d.name == "ACC-SW-4")
    neighbours = graph.neighbours(acc_id)
    assert len(neighbours) == 2
    assert len(set(neighbours)) == 1  # both links land on the same device


def test_drawio_diverse_uplinks_are_not_a_violation():
    graph = parse_drawio_xml(_DRAWIO_UNCOMPRESSED_DIVERSE)
    acc_id = next(d.id for d in graph.devices.values() if d.name == "ACC-SW-9")
    neighbours = graph.neighbours(acc_id)
    assert len(set(neighbours)) == 2


def _compress_drawio_payload(xml_text: str) -> str:
    """Mirror draw.io's own encoding: url-encode -> raw deflate -> base64."""
    raw = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    compressed = raw.compress(quote(xml_text).encode("utf-8")) + raw.flush()
    return base64.b64encode(compressed).decode("ascii")


def test_drawio_compressed_diagram_payload_round_trips():
    payload = _compress_drawio_payload(_DRAWIO_UNCOMPRESSED_SPOF)
    mxfile = f'<mxfile><diagram id="p1" name="Page-1">{payload}</diagram></mxfile>'
    graph = parse_drawio_xml(mxfile)
    names = {d.name for d in graph.devices.values()}
    assert names == {"ACC-SW-4", "DIST-SW-A", "DIST-SW-B"}
    assert len(graph.links) == 2


def test_drawio_html_labels_are_cleaned():
    xml = """<mxGraphModel><root>
      <mxCell id="0" /><mxCell id="1" parent="0" />
      <mxCell id="a" value="ACC-SW-1&lt;br&gt;(rack 4)" vertex="1" parent="1" />
    </root></mxGraphModel>"""
    graph = parse_drawio_xml(xml)
    assert graph.devices["a"].name == "ACC-SW-1 (rack 4)"


def test_sniff_drawio_xml():
    assert sniff_drawio_xml(_DRAWIO_UNCOMPRESSED_SPOF)
    assert not sniff_drawio_xml("<openapi>not a diagram</openapi>")


def test_malformed_drawio_returns_empty_graph_not_an_exception():
    graph = parse_drawio_xml("not xml at all {{{")
    assert graph.is_empty()


# ---------------------------------------------------------------------------
# Decompression bomb resistance
# ---------------------------------------------------------------------------
def test_drawio_decompression_bomb_is_rejected():
    """A small payload that inflates past the cap must not be expanded."""
    import resource

    from src.topology import MAX_INFLATED_BYTES

    # 64 MB of zeros deflates to a few KB - well past MAX_INFLATED_BYTES.
    bomb = _compress_drawio_payload("A" * (64 * 1024 * 1024))
    assert len(bomb) < 200_000, "test payload should be small on the wire"

    mxfile = f'<mxfile><diagram id="p1">{bomb}</diagram></mxfile>'

    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    graph = parse_drawio_xml(mxfile)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    assert graph.is_empty()
    # Peak RSS must not have grown by anything like the inflated size.
    assert (after - before) * 1024 < MAX_INFLATED_BYTES * 2


def test_drawio_oversized_compressed_blob_is_rejected_before_decoding():
    from src.topology import MAX_COMPRESSED_PAYLOAD_BYTES

    oversized = "Q" * (MAX_COMPRESSED_PAYLOAD_BYTES + 1024)
    mxfile = f'<mxfile><diagram id="p1">{oversized}</diagram></mxfile>'
    assert parse_drawio_xml(mxfile).is_empty()


def test_vsdx_zip_bomb_is_rejected(tmp_path):
    import zipfile
    from pathlib import Path

    from src.topology import MAX_VSDX_TOTAL_BYTES

    path = Path(tmp_path) / "bomb.vsdx"
    # Ten pages of 32 MB each = 320 MB uncompressed, a few KB on disk.
    payload = "<PageContents>" + ("<!--" + "z" * (32 * 1024 * 1024) + "-->") + "</PageContents>"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(1, 11):
            zf.writestr(f"visio/pages/page{i}.xml", payload)

    assert path.stat().st_size < 1_000_000, "bomb should be small on disk"

    import resource
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    graph = parse_visio_vsdx(path)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    assert graph.is_empty()
    assert (after - before) * 1024 < MAX_VSDX_TOTAL_BYTES


def test_vsdx_page_count_is_capped(tmp_path):
    import zipfile
    from pathlib import Path

    from src.topology import MAX_VSDX_PAGES

    path = Path(tmp_path) / "many.vsdx"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(1, MAX_VSDX_PAGES + 50):
            zf.writestr(f"visio/pages/page{i}.xml", "<PageContents></PageContents>")

    # Must not raise or hang; simply stops at the cap.
    assert parse_visio_vsdx(path).is_empty()


def test_legitimate_diagram_still_parses_after_bomb_hardening(tmp_path):
    """The caps must not break normal-sized real diagrams."""
    payload = _compress_drawio_payload(_DRAWIO_UNCOMPRESSED_SPOF)
    mxfile = f'<mxfile><diagram id="p1">{payload}</diagram></mxfile>'
    graph = parse_drawio_xml(mxfile)
    assert {d.name for d in graph.devices.values()} == {
        "ACC-SW-4", "DIST-SW-A", "DIST-SW-B"}


# ---------------------------------------------------------------------------
# Visio .vsdx - built as an in-memory OOXML zip so the test needs no fixture
# ---------------------------------------------------------------------------
def _build_vsdx(tmp_path, spof: bool) -> "Path":  # noqa: F821
    import zipfile
    from pathlib import Path

    ns = 'xmlns="http://schemas.microsoft.com/office/visio/2012/main"'
    dist_a = '<Shape ID="10"><Text>DIST-SW-A</Text></Shape>'
    dist_b = '<Shape ID="11"><Text>DIST-SW-B</Text></Shape>'
    acc = '<Shape ID="20"><Text>ACC-SW-7</Text></Shape>'

    if spof:
        connects = (
            '<Connects>'
            '<Connect FromSheet="30" ToSheet="20"/>'
            '<Connect FromSheet="30" ToSheet="10"/>'
            '<Connect FromSheet="31" ToSheet="20"/>'
            '<Connect FromSheet="31" ToSheet="10"/>'
            '</Connects>'
        )
    else:
        connects = (
            '<Connects>'
            '<Connect FromSheet="30" ToSheet="20"/>'
            '<Connect FromSheet="30" ToSheet="10"/>'
            '<Connect FromSheet="31" ToSheet="20"/>'
            '<Connect FromSheet="31" ToSheet="11"/>'
            '</Connects>'
        )

    connector_shapes = (
        '<Shape ID="30"><Text>Uplink 1</Text></Shape>'
        '<Shape ID="31"><Text>Uplink 2</Text></Shape>'
    )

    page_xml = (
        f'<PageContents {ns}>'
        f'<Shapes>{dist_a}{dist_b}{acc}{connector_shapes}</Shapes>'
        f'{connects}'
        f'</PageContents>'
    )

    path = Path(tmp_path) / "topology.vsdx"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("visio/pages/page1.xml", page_xml)
    return path


def test_vsdx_spof_detected(tmp_path):
    path = _build_vsdx(tmp_path, spof=True)
    graph = parse_visio_vsdx(path)
    names = {d.name for d in graph.devices.values()}
    assert names == {"DIST-SW-A", "DIST-SW-B", "ACC-SW-7"}

    acc_id = next(d.id for d in graph.devices.values() if d.name == "ACC-SW-7")
    neighbours = graph.neighbours(acc_id)
    assert len(neighbours) == 2
    assert len(set(neighbours)) == 1


def test_vsdx_diverse_uplinks_not_flagged(tmp_path):
    path = _build_vsdx(tmp_path, spof=False)
    graph = parse_visio_vsdx(path)
    acc_id = next(d.id for d in graph.devices.values() if d.name == "ACC-SW-7")
    assert len(set(graph.neighbours(acc_id))) == 2


def test_vsdx_missing_file_returns_empty_graph():
    graph = parse_visio_vsdx("/nonexistent/path.vsdx")
    assert graph.is_empty()


# ---------------------------------------------------------------------------
# Integration: file on disk -> Section.topology -> run_topology_rules()
# ---------------------------------------------------------------------------
def test_parse_document_drawio_attaches_graph_to_section(tmp_path):
    from pathlib import Path

    p = Path(tmp_path) / "campus.drawio"
    p.write_text(_DRAWIO_UNCOMPRESSED_SPOF, encoding="utf-8")

    sections = parse_document(p)
    assert len(sections) == 1
    assert sections[0].topology is not None
    assert not sections[0].topology.is_empty()


def test_parse_document_xml_sniffed_as_drawio(tmp_path):
    from pathlib import Path

    p = Path(tmp_path) / "campus.xml"
    p.write_text(_DRAWIO_UNCOMPRESSED_SPOF, encoding="utf-8")

    sections = parse_document(p)
    assert sections[0].topology is not None


def test_parse_document_xml_not_a_diagram_raises(tmp_path):
    from pathlib import Path

    p = Path(tmp_path) / "openapi.xml"
    p.write_text("<not-a-diagram><foo>bar</foo></not-a-diagram>", encoding="utf-8")

    with pytest.raises(ValueError):
        parse_document(p)


def test_topology_rule_fires_critical_finding_from_diagram(tmp_path):
    from pathlib import Path

    p = Path(tmp_path) / "campus.drawio"
    p.write_text(_DRAWIO_UNCOMPRESSED_SPOF, encoding="utf-8")
    sections = parse_document(p)

    findings = run_topology_rules(sections)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "CRITICAL"
    assert f.rule_id == "NET-HA-002"
    assert "ACC-SW-4" in f.issue
    assert "DIST-SW-A" in f.issue
    assert f.origin == "rules_engine"


def test_topology_rule_silent_on_diverse_diagram(tmp_path):
    from pathlib import Path

    p = Path(tmp_path) / "campus.drawio"
    p.write_text(_DRAWIO_UNCOMPRESSED_DIVERSE, encoding="utf-8")
    sections = parse_document(p)

    assert run_topology_rules(sections) == []


def test_run_rules_includes_topology_findings_when_network_enabled(tmp_path):
    from pathlib import Path

    from src.rules import run_rules

    p = Path(tmp_path) / "campus.drawio"
    p.write_text(_DRAWIO_UNCOMPRESSED_SPOF, encoding="utf-8")
    sections = parse_document(p)

    findings = run_rules(sections, ["network"])
    assert any(f.rule_id == "NET-HA-002" and "diagram" in f.section
               for f in findings)


def test_run_rules_skips_topology_when_network_domain_disabled(tmp_path):
    from pathlib import Path

    from src.rules import run_rules

    p = Path(tmp_path) / "campus.drawio"
    p.write_text(_DRAWIO_UNCOMPRESSED_SPOF, encoding="utf-8")
    sections = parse_document(p)

    findings = run_rules(sections, ["application"])
    assert findings == []


def test_multiple_violating_devices_each_produce_a_distinct_finding():
    xml = """<mxGraphModel><root>
      <mxCell id="0" /><mxCell id="1" parent="0" />
      <mxCell id="a1" value="ACC-1" vertex="1" parent="1" />
      <mxCell id="a2" value="ACC-2" vertex="1" parent="1" />
      <mxCell id="core" value="CORE-SW" vertex="1" parent="1" />
      <mxCell id="e1" edge="1" parent="1" source="a1" target="core" />
      <mxCell id="e2" edge="1" parent="1" source="a1" target="core" />
      <mxCell id="e3" edge="1" parent="1" source="a2" target="core" />
      <mxCell id="e4" edge="1" parent="1" source="a2" target="core" />
    </root></mxGraphModel>"""
    graph = parse_drawio_xml(xml)
    from src.models import Section
    section = Section(index=0, heading="Diagram", body="", domain="network",
                       topic="topology", topology=graph)
    findings = run_topology_rules([section])
    assert len(findings) == 2
    assert {f.section.split(" (")[0] for f in findings} == {"ACC-1", "ACC-2"}
