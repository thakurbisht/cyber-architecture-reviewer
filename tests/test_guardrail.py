"""Scope guardrail - rejecting inputs that aren't architecture designs."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.guardrail import assess_scope
from src.parser import parse_document, parse_text

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.mark.parametrize("filename", [
    "sample-campus-lan-lld.md",
    "sample-cloud-landing-zone-hld.md",
    "sample-payments-app-hld.md",
])
def test_real_design_documents_pass_the_guardrail(filename):
    sections = parse_document(SAMPLES / filename)
    result = assess_scope(sections)
    assert result.in_scope, result.reason
    assert result.distinct_topics >= 3
    assert result.architecture_score > 0


def test_recipe_is_rejected():
    text = """Chocolate Chip Cookies

Preheat the oven to 350F. In a large bowl, cream together the butter and
sugar until light and fluffy. Beat in the eggs one at a time, then stir in
the vanilla. Combine the flour, baking soda and salt; gradually blend into
the creamed mixture. Fold in the chocolate chips and walnuts. Drop rounded
tablespoons of dough onto ungreased cookie sheets. Bake for 8 to 10 minutes.
"""
    sections = parse_text(text, "recipe")
    result = assess_scope(sections)
    assert not result.in_scope
    assert result.distinct_topics == 0
    assert "does not read as" in result.reason


def test_meeting_notes_are_rejected():
    text = """Weekly Standup Notes

Attendees: Sarah, John, Priya. Sarah is on leave next week. John will follow
up with the vendor about the invoice. Priya raised that the office coffee
machine is broken again and facilities has been notified. Next meeting is
scheduled for Thursday at 10am in the usual room. No other business to
discuss this week, everyone please have a good weekend and see you then.
"""
    sections = parse_text(text, "notes")
    result = assess_scope(sections)
    assert not result.in_scope


def test_incidental_single_keyword_mention_does_not_pass():
    """One offhand technical word shouldn't flip an unrelated memo into scope."""
    text = """Vendor Contract Renewal Memo

This memo summarises the annual renewal terms for our facilities vendor
contract, covering cleaning services, catering, and building maintenance for
the next fiscal year. Pricing has increased by four percent over last year.
Legal has reviewed the terms and has no objections. Approval is requested
from finance by the end of the month.

As an aside, IT mentioned they will look at the firewall rules at some point.
"""
    sections = parse_text(text, "memo")
    result = assess_scope(sections)
    assert not result.in_scope
    assert result.distinct_topics < 3


def test_very_short_input_is_rejected_for_length_not_topic():
    sections = parse_text("This is a very short note.", "short")
    result = assess_scope(sections)
    assert not result.in_scope
    assert "too short" in result.reason


def test_minimal_genuine_design_note_passes():
    """A short but real LLD snippet should still clear the bar."""
    text = """VLAN Change Request

We are adding a new VLAN 220 for the guest wireless SSID on the access
switches. The access switch uplinks to the distribution pair remain
unchanged. A new firewall rule will permit DHCP and DNS only from this
VLAN, denying all other traffic by default.
"""
    sections = parse_text(text, "vlan-change")
    result = assess_scope(sections)
    assert result.in_scope


def test_empty_input_is_rejected():
    result = assess_scope([])
    assert not result.in_scope
    assert result.total_words == 0


def test_matched_topics_are_reported_for_a_passing_document():
    sections = parse_document(SAMPLES / "sample-campus-lan-lld.md")
    result = assess_scope(sections)
    assert result.matched_topics
    assert len(result.matched_topics) <= 6
