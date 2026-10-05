"""Diagram reading and the merge into a DFD (src/diagram.py).

The vision call itself is stubbed: these tests pin the deterministic half -
classification, label reading, merging and conflict detection - which is
exactly the half that must not drift when the model changes.
"""

from __future__ import annotations

import pytest

from src import diagram as DG
from src.dfd import DFD, DFDComponent, DFDFlow


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,detail,expected", [
    ("Orders DB", "PostgreSQL 15", "datastore"),
    ("Backup Bucket", "s3://orders-bkp", "datastore"),
    ("API Gateway", "Kong 3.4", "service"),
    ("Admin Portal", "port 8001", "service"),          # a portal, not a person
    ("Administrators", "", "user_group"),
    ("Customer", "browser", "user_group"),
    ("Partner SFTP", "payments-co", "external_party"),
    ("Entra ID", "", "identity"),
    ("Branch Firewall", "", "network"),
    ("Scooter", "telemetry", "device"),
    ("Build Pipeline", "GitHub Actions", "pipeline"),
    ("Vector Store", "Chroma", "vector_db"),
    ("Something Else", "", "other"),
])
def test_classify_kind(name, detail, expected):
    assert DG.classify_kind(name, detail) == expected


@pytest.mark.parametrize("band,expected", [
    ("INTERNET", "internet"), ("DMZ", "dmz"), ("Internal", "internal"),
    ("DATA", "restricted"), ("Card Holder Data Environment", "restricted"),
    ("Corporate LAN", "internal"), ("AWS Account", "cloud"),
    ("Third-party", "partner"), ("Out-of-band management", "management"),
    ("", "unknown"), ("Blue Section", "unknown"),
])
def test_normalise_zone(band, expected):
    assert DG.normalise_zone(band) == expected


@pytest.mark.parametrize("label,encrypted,protocol", [
    ("HTTPS", "yes", "HTTPS"),
    ("TLS 1.2", "yes", "TLS 1.2"),
    ("plain FTP", "no", "FTP"),          # it is FTP, and it is not encrypted
    ("no TLS", "no", ""),                # names the missing control, not the protocol
    ("admin", "unknown", ""),
    ("", "unknown", ""),
])
def test_label_reading(label, encrypted, protocol):
    assert DG._encryption_from_label(label) == encrypted
    assert DG._protocol_from_label(label) == protocol


def test_auth_from_label():
    assert DG._auth_from_label("mTLS") == "mtls"
    assert DG._auth_from_label("OAuth 2.0") == "oauth"
    assert DG._auth_from_label("no auth") == "none"
    assert DG._auth_from_label("HTTPS") == "unknown"


# --------------------------------------------------------------------------
# Reading one image
# --------------------------------------------------------------------------
RAW = """{"zones": ["INTERNET", "DMZ", "DATA"],
 "boxes": [{"name": "Customer", "detail": "browser", "zone": "INTERNET"},
           {"name": "API Gateway", "detail": "Kong", "zone": "DMZ"},
           {"name": "Orders DB", "detail": "PostgreSQL", "zone": "DATA"}],
 "arrows": [{"from": "Customer", "to": "API Gateway", "label": "HTTPS"},
            {"from": "API Gateway", "to": "Orders DB", "label": "no TLS"}],
 "notes": ["Admin portal needs no MFA"]}"""


def _image():
    return DG.DiagramImage("page 1", b"not-a-real-png", 900, 600)


def test_read_diagram_derives_everything_the_model_was_not_asked_for():
    ex = DG.read_diagram(_image(), lambda img, prompt: RAW, "stub")
    assert ex.ok and ex.where == "page 1"
    kinds = {c["name"]: c["kind"] for c in ex.components}
    zones = {c["name"]: c["zone"] for c in ex.components}
    assert kinds == {"Customer": "user_group", "API Gateway": "service",
                     "Orders DB": "datastore"}
    assert zones["Orders DB"] == "restricted"          # "DATA" band normalised
    assert [f["encrypted"] for f in ex.flows] == ["yes", "no"]
    assert ex.notes == ["Admin portal needs no MFA"]


def test_read_diagram_accepts_a_fenced_reply():
    ex = DG.read_diagram(_image(), lambda img, prompt: f"```json\n{RAW}\n```", "stub")
    assert len(ex.components) == 3


def test_read_diagram_salvages_truncated_json():
    cut = RAW[:RAW.index('{"from": "API Gateway"')]
    ex = DG.read_diagram(_image(), lambda img, prompt: cut, "stub")
    assert len(ex.components) == 3 and len(ex.flows) == 1


def test_a_failing_image_is_recorded_not_raised():
    def boom(img, prompt):
        raise RuntimeError("model is down")

    ex = DG.read_diagram(_image(), boom, "stub")
    assert not ex.ok and "model is down" in ex.error


def test_empty_reply_is_an_error_not_a_clean_diagram():
    ex = DG.read_diagram(_image(), lambda img, prompt: "{}", "stub")
    assert not ex.ok and "no components" in ex.error


# --------------------------------------------------------------------------
# Merging into a text-derived DFD
# --------------------------------------------------------------------------
def _text_dfd():
    d = DFD(document="k")
    d.components = [
        DFDComponent("cust", "Customer", kind="user_group", zone="internet",
                     source="text"),
        DFDComponent("gw", "API Gateway", kind="service", zone="dmz", source="text"),
    ]
    d.flows = [DFDFlow("f1", "cust", "gw", auth="token", encrypted="yes",
                       source_tag="text")]
    return d


def _extraction(**over):
    ex = DG.DiagramExtraction(where="page 3", image_sha="abc", model="stub")
    ex.components = over.get("components", [
        {"name": "API Gateway", "detail": "", "kind": "service", "zone": "dmz"},
        {"name": "Orders DB", "detail": "", "kind": "datastore", "zone": "restricted"},
    ])
    ex.flows = over.get("flows", [
        {"source": "API Gateway", "target": "Orders DB", "label": "no TLS",
         "protocol": "", "encrypted": "no", "auth": "unknown"},
    ])
    ex.notes = over.get("notes", [])
    return ex


def test_merge_adds_what_only_the_diagram_shows():
    d = _text_dfd()
    added_c, added_f, conflicts = DG.merge_into(d, [_extraction()])
    assert (added_c, added_f) == (1, 1) and not conflicts
    db = next(c for c in d.components if c.name == "Orders DB")
    assert db.source == "diagram" and db.zone == "restricted"
    flow = next(f for f in d.flows if f.target == db.id)
    assert flow.encrypted == "no" and flow.source_tag == "diagram"
    assert "page 3" in flow.evidence


def test_a_component_in_both_sources_is_tagged_as_both():
    d = _text_dfd()
    DG.merge_into(d, [_extraction()])
    gw = next(c for c in d.components if c.name == "API Gateway")
    assert gw.source == "text+diagram"


def test_the_diagram_fills_in_what_the_text_left_unknown():
    d = _text_dfd()
    d.flows[0].encrypted = "unknown"
    DG.merge_into(d, [_extraction(flows=[
        {"source": "Customer", "target": "API Gateway", "label": "HTTPS",
         "protocol": "HTTPS", "encrypted": "yes", "auth": "unknown"}])])
    assert d.flows[0].encrypted == "yes" and d.flows[0].source_tag == "diagram"


def test_a_contradiction_is_reported_and_the_text_value_is_kept():
    d = _text_dfd()                      # text says the flow is encrypted
    _, _, conflicts = DG.merge_into(d, [_extraction(flows=[
        {"source": "Customer", "target": "API Gateway", "label": "no TLS",
         "protocol": "", "encrypted": "no", "auth": "unknown"}])])
    assert d.flows[0].encrypted == "yes"           # text value untouched
    assert len(conflicts) == 1
    c = conflicts[0]
    assert (c.kind, c.text_says, c.diagram_says) == ("encrypted", "yes", "no")
    assert "Customer" in c.element and c.where == "page 3"


def test_a_zone_contradiction_is_reported():
    d = _text_dfd()
    _, _, conflicts = DG.merge_into(d, [_extraction(components=[
        {"name": "API Gateway", "detail": "", "kind": "service", "zone": "internet"}],
        flows=[])])
    assert [c.kind for c in conflicts] == ["zone"]
    assert next(c for c in d.components if c.name == "API Gateway").zone == "dmz"


def test_failed_extractions_are_skipped():
    d = _text_dfd()
    bad = DG.DiagramExtraction(where="page 9", image_sha="x", model="stub",
                               error="model is down")
    assert DG.merge_into(d, [bad]) == (0, 0, [])


def test_diagram_notes_carry_their_source():
    ex = _extraction(notes=["Admin Portal is reachable without MFA"])
    assert DG.diagram_notes([ex]) == [("page 3", "Admin Portal is reachable without MFA")]


# --------------------------------------------------------------------------
# Image selection
# --------------------------------------------------------------------------
@pytest.mark.parametrize("w,h,keep", [
    (900, 600, True), (320, 220, True),
    (64, 64, False),                     # icon
    (1200, 80, False),                   # banner
    (200, 900, False),                   # sidebar rule
])
def test_only_diagram_sized_images_are_kept(w, h, keep):
    assert DG._keep(w, h) is keep


def test_unsupported_formats_yield_no_images(tmp_path):
    p = tmp_path / "design.md"
    p.write_text("# Design", encoding="utf-8")
    assert DG.extract_images(p) == []


@pytest.mark.parametrize("note,kept", [
    ("Admin Portal is reachable from the office VLAN without MFA", True),
    ("3. Branch topology (vector)", False),      # the page heading, not a note
    ("Figure 2: logical architecture", False),
    ("DMZ", False),                              # a band label
    ("", False),
])
def test_page_furniture_is_not_a_diagram_note(note, kept):
    assert DG._is_diagram_note(note) is kept
