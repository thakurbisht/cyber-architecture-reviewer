"""Projects, stages, content-addressed versions and sign-off (src/project.py)."""

from __future__ import annotations

import pytest

from src import dfd as D
from src import project as PJ


def test_same_filename_new_content_is_a_new_version(tmp_path):
    p = PJ.create_project("Checkout Platform", tmp_path)
    v1 = PJ.register_version(p, "a" * 64, "checkout-hld.pdf", "prelim", tmp_path)
    v2 = PJ.register_version(p, "b" * 64, "checkout-hld.pdf", "prelim", tmp_path)
    assert v1.review_key != v2.review_key
    assert len(p.stage_versions("prelim")) == 2


def test_same_content_reopens_the_same_review(tmp_path):
    p = PJ.create_project("Checkout", tmp_path)
    v1 = PJ.register_version(p, "a" * 64, "x.pdf", "prelim", tmp_path)
    again = PJ.register_version(p, "a" * 64, "renamed.pdf", "prelim", tmp_path)
    assert again is v1 and len(p.versions) == 1


def test_stage_is_part_of_the_key(tmp_path):
    p = PJ.create_project("Checkout", tmp_path)
    pre = PJ.register_version(p, "a" * 64, "x.pdf", "prelim", tmp_path)
    fin = PJ.register_version(p, "a" * 64, "x.pdf", "final", tmp_path)
    assert pre.review_key.startswith("checkout/prelim/")
    assert fin.review_key.startswith("checkout/final/")


def test_artefacts_of_two_versions_do_not_collide(tmp_path):
    """The original bug: v2 with the same filename reopened v1's DFD."""
    p = PJ.create_project("Checkout", tmp_path)
    v1 = PJ.register_version(p, "a" * 64, "hld.pdf", "prelim", tmp_path)
    v2 = PJ.register_version(p, "b" * 64, "hld.pdf", "prelim", tmp_path)
    d1 = D.DFD(document=v1.review_key)
    d1.components.append(D.DFDComponent("api", "API", zone="dmz"))
    D.save_draft(d1, tmp_path / "dfd")
    assert D.load_latest(v2.review_key, tmp_path / "dfd") is None
    assert D.load_latest(v1.review_key, tmp_path / "dfd").components[0].id == "api"


def test_provisional_until_signed_off(tmp_path):
    p = PJ.create_project("Checkout", tmp_path)
    v = PJ.register_version(p, "a" * 64, "x.pdf", "prelim", tmp_path)
    assert v.provisional
    PJ.sign_off(p, v.review_key, "recommendations_issued", "PB", "12 RECs issued", root=tmp_path)
    again = PJ.load_project("checkout", tmp_path).version(v.review_key)
    assert not again.provisional and again.signoff.reviewer == "PB"
    assert again.status == "signed_off"


def test_decisions_are_stage_specific(tmp_path):
    p = PJ.create_project("Checkout", tmp_path)
    v = PJ.register_version(p, "a" * 64, "x.pdf", "prelim", tmp_path)
    with pytest.raises(ValueError):
        PJ.sign_off(p, v.review_key, "approve", "PB", root=tmp_path)      # final-only decision
    with pytest.raises(ValueError):
        PJ.sign_off(p, v.review_key, "rejected", "  ", root=tmp_path)     # reviewer required


def test_final_review_links_to_latest_issued_prelim(tmp_path):
    p = PJ.create_project("Checkout", tmp_path)
    v1 = PJ.register_version(p, "a" * 64, "hld-v1.pdf", "prelim", tmp_path)
    PJ.sign_off(p, v1.review_key, "rejected", "PB", root=tmp_path)
    v2 = PJ.register_version(p, "b" * 64, "hld-v2.pdf", "prelim", tmp_path)
    assert p.latest_signed_prelim() is None
    PJ.sign_off(p, v2.review_key, "recommendations_issued", "PB", root=tmp_path)
    assert p.latest_signed_prelim().review_key == v2.review_key


def test_reopen_withdraws_signoff(tmp_path):
    p = PJ.create_project("Checkout", tmp_path)
    v = PJ.register_version(p, "a" * 64, "x.pdf", "final", tmp_path)
    PJ.sign_off(p, v.review_key, "approve", "PB", root=tmp_path)
    PJ.reopen(p, v.review_key, tmp_path)
    assert PJ.find_version(v.review_key, tmp_path).provisional


def test_duplicate_project_rejected(tmp_path):
    PJ.create_project("Checkout", tmp_path)
    with pytest.raises(ValueError):
        PJ.create_project("checkout", tmp_path)
