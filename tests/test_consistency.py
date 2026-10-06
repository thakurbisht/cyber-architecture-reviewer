"""HLD -> LLD commitment checking (src/consistency.py).

The model call is stubbed throughout. What is pinned here is the
deterministic half - which sentences become commitments, what they are
about, which LLD sections are consulted, which exception lines are shown
to the model, and what becomes a finding - because that is the half that
must not drift when the model changes.
"""

from __future__ import annotations

import pytest

from src import consistency as C
from src.models import Section


_N = iter(range(1, 10_000))


def _s(heading: str, body: str, domain: str = "security") -> Section:
    return Section(index=next(_N), heading=heading, body=body, domain=domain)


# --------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------
def test_numbered_steps_are_separate_sentences():
    """Splitting only before a capital glued numbered steps together, and the
    glued text matched a control three steps away."""
    text = ("The payment step collects the card number on the checkout page. "
            "4. payment-svc creates a payment intent and the browser completes "
            "3-D Secure authentication.")
    out = C.sentences(text)
    assert len(out) == 2
    assert out[1].startswith("4. payment-svc")


def test_bullets_and_blank_lines_split():
    assert len(C.sentences("- one thing here\n- another thing here")) == 2
    assert len(C.sentences("First para here.\n\nSecond para here.")) == 2


# --------------------------------------------------------------------------
# What is a commitment
# --------------------------------------------------------------------------
def test_a_plain_statement_about_a_control_is_a_commitment():
    """Design documents are written in the present indicative. Requiring a
    modal verb threw away 21 of 24 real commitments in gs-01."""
    claims = C.extract_claims([_s("4. Network", "Kong applies a rate limit of 60 "
                                                "requests per minute per client IP.")])
    assert len(claims) == 1 and claims[0].control == "rate_limiting"
    assert claims[0].strength == "stated"


def test_must_and_all_mark_a_commitment_as_mandatory():
    claims = C.extract_claims([_s("4. Crypto", "All traffic between tiers must use "
                                               "TLS 1.3 with modern ciphers.")])
    assert claims[0].strength == "mandatory"


def test_a_declined_control_is_not_a_commitment():
    """The HLD naming a control to decline it is a decision, and the rules
    engine already reports it in the HLD's own review."""
    body = ("MFA will not be required for service accounts in phase 1. "
            "The webhook route is configured with authentication disabled. "
            "Field-level encryption is deferred to a future release.")
    assert C.extract_claims([_s("4. Controls", body)]) == []


def test_front_matter_is_not_a_commitment():
    body = "**Classification:** Internal, covered by the encryption standard."
    assert C.extract_claims([_s("Header", body)]) == []


def test_ids_are_stable_and_duplicates_collapse():
    body = ("All data at rest is encrypted with customer-managed keys. "
            "All data at rest is encrypted with customer-managed keys.")
    claims = C.extract_claims([_s("4.1", body)])
    assert [c.id for c in claims] == ["HLD-C-001"]


# --------------------------------------------------------------------------
# What a commitment is about
# --------------------------------------------------------------------------
@pytest.mark.parametrize("sentence,control", [
    ("All traffic between tiers must use TLS 1.3.", "transit_encryption"),
    ("The RDS instance uses storage encryption with a customer-managed KMS key, "
     "and its parameter group sets rds.force_ssl to 1.", "rest_encryption"),
    ("Keys are rotated every 90 days.", "key_management"),
    ("Every administrative login requires phishing-resistant multi-factor "
     "authentication.", "mfa"),
    ("Service-to-service calls authenticate with mutual TLS.", "authentication"),
    ("No component of the data tier is reachable from the internet.",
     "private_access"),
    ("The data tier accepts connections only from the application tier.",
     "segmentation"),
    ("Secrets are never held in configuration files, images or pipeline "
     "variables.", "secrets"),
    ("Container images are scanned for vulnerabilities before release.",
     "patching"),
    ("All infrastructure is defined as code.", "change_control"),
    ("Backups are held as immutable copies for 35 days.", "backup_recovery"),
])
def test_control_classification(sentence, control):
    assert C.control_for(sentence)[0] == control


def test_the_earliest_match_decides_what_a_sentence_is_about():
    """A sentence's subject comes before its qualifiers."""
    sentence = ("All security-relevant events are forwarded to the group SIEM, "
                "including authentication events and authorisation failures.")
    assert C.control_for(sentence)[0] == "logging"


def test_an_authorization_header_is_about_logging_not_access_control():
    sentence = ("Kong access logs record method, path and status code; "
                "Authorization and Cookie headers are not logged.")
    assert C.control_for(sentence)[0] == "logging"


# --------------------------------------------------------------------------
# Which LLD sections get consulted
# --------------------------------------------------------------------------
def _claim(text="All traffic between tiers must use TLS 1.3.",
           control="transit_encryption"):
    return C.ControlClaim(id="HLD-C-001", control=control, text=text,
                          section="4.1 Encryption", domain="security",
                          strength="mandatory")


def test_the_section_naming_the_control_is_consulted_first():
    sections = [_s("2. Scope", "This document details the build of the platform."),
                _s("10. Logging", "Logs are written to a workspace."),
                _s("3. Edge", "The listener is configured with a minimum protocol "
                              "version of TLS 1.2 for the broker.")]
    assert C.candidate_sections(_claim(), sections)[0].heading == "3. Edge"


def test_a_claim_nothing_mentions_is_missing_without_a_model_call():
    def never_called(messages):
        raise AssertionError("the model should not be asked")

    check = C.check_claim(_claim(), [_s("2. Scope", "Nothing relevant at all here.")],
                          type("L", (), {"invoke": staticmethod(never_called)})(), "")
    assert check.status == "missing"


# --------------------------------------------------------------------------
# Exception lines
# --------------------------------------------------------------------------
EXCEPTION_SECTIONS = [
    _s("3. Edge", "The listener uses TLS 1.2. The broker platform does not support "
                  "TLS 1.3, so the broker listener permits TLS 1.2 to avoid breaking "
                  "their nightly batch."),
    _s("7. Data", "The audit store has public network access enabled, because the "
                  "reporting tool could not obtain a private link in time."),
]


def test_exception_lines_are_filtered_to_the_commitment_in_hand():
    """Showing the model every exception in the candidate sections made it far
    readier to report a contradiction, reaching for whichever one was in
    front of it."""
    lines = C.exception_lines(EXCEPTION_SECTIONS, _claim())
    assert any("TLS 1.3" in line for line in lines)
    assert not any("public network access" in line for line in lines)


def test_unfiltered_exception_lines_return_everything():
    assert len(C.exception_lines(EXCEPTION_SECTIONS)) == 2


def test_a_plain_statement_is_not_an_exception():
    assert C.exception_lines([_s("x", "The listener is configured for TLS 1.3.")]) == []


# --------------------------------------------------------------------------
# Believing the model
# --------------------------------------------------------------------------
class _LLM:
    def __init__(self, reply):
        self.reply = reply

    def invoke(self, messages):
        self.messages = messages
        return type("R", (), {"content": self.reply})()


LLD = [_s("3. Edge", "The listener is configured with a minimum protocol version "
                     "of TLS 1.2 for the broker integration.")]
LLD_NORM = "the listener is configured with a minimum protocol version of tls 1 2 " \
           "for the broker integration"


def test_a_contradiction_with_a_real_quote_is_believed():
    llm = _LLM('{"status": "contradicted", "evidence": "The listener is configured '
               'with a minimum protocol version of TLS 1.2", "reason": "weaker"}')
    check = C.check_claim(_claim(), LLD, llm, LLD_NORM)
    assert check.status == "contradicted" and check.grounded


def test_a_contradiction_whose_quote_is_not_in_the_lld_is_demoted():
    """An ungrounded contradiction is the model writing the LLD it expected."""
    llm = _LLM('{"status": "contradicted", "evidence": "The platform disables '
               'encryption entirely for all internal traffic", "reason": "x"}')
    check = C.check_claim(_claim(), LLD, llm, LLD_NORM)
    assert check.status == "unclear" and not check.grounded
    assert "not found in the LLD" in check.reason


def test_an_unparsable_or_unknown_answer_becomes_unclear():
    assert C.check_claim(_claim(), LLD, _LLM("I think maybe"), LLD_NORM).status \
        == "unclear"
    assert C.check_claim(_claim(), LLD, _LLM('{"status": "probably fine"}'),
                         LLD_NORM).status == "unclear"


def test_a_model_failure_is_recorded_not_raised():
    class Boom:
        def invoke(self, messages):
            raise RuntimeError("ollama is down")

    check = C.check_claim(_claim(), LLD, Boom(), LLD_NORM)
    assert check.status == "unclear" and "ollama is down" in check.reason


def test_missing_needs_no_quote():
    check = C.check_claim(_claim(), LLD, _LLM('{"status": "missing"}'), LLD_NORM)
    assert check.status == "missing"


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------
def _check(status, strength="mandatory", evidence="the LLD line"):
    return C.ControlCheck(claim=_claim(), status=status, evidence=evidence,
                          lld_section="3. Edge", grounded=True)


def test_a_contradiction_is_a_finding_carrying_both_halves():
    f = C.to_findings([_check("contradicted")])[0]
    assert f.kind == "finding" and f.severity == "HIGH"
    assert "TLS 1.3" in f.issue                      # the HLD half
    assert f.evidence_excerpt == "the LLD line"      # the LLD half
    assert f.control_mappings == ["HLD-C-001"]
    assert f.rule_id == "CONSIST-TRANSIT_ENCRYPTION"


def test_a_stated_commitment_contradicted_is_less_severe_than_a_mandatory_one():
    mandatory = C.to_findings([_check("contradicted", "mandatory")])[0]
    stated = _check("contradicted")
    stated.claim = C.ControlClaim(id="HLD-C-002", control="transit_encryption",
                                  text="Traffic uses TLS 1.3.", section="4.1",
                                  domain="security", strength="stated")
    assert mandatory.severity == "HIGH"
    assert C.to_findings([stated])[0].severity == "MEDIUM"


def test_an_unkept_mandatory_commitment_is_a_question_not_a_defect():
    """Silence is not proof, so an absence never scores - see triage.py."""
    f = C.to_findings([_check("missing")])[0]
    assert f.kind == "question" and f.severity == "MEDIUM"


def test_an_implemented_commitment_produces_nothing():
    assert C.to_findings([_check("implemented")]) == []


def test_summary_counts_coverage():
    s = C.summary([_check("implemented"), _check("implemented"),
                   _check("contradicted"), _check("missing")])
    assert s["commitments"] == 4 and s["implemented"] == 2
    assert s["coverage"] == 0.5
