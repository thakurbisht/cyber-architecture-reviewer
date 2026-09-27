"""Unified review queue (src/review_queue.py)."""

from __future__ import annotations

from src import dfd as D
from src import review_queue as Q
from src import threat_agent as TA
from src.models import Finding, ORIGIN_AGENT, ORIGIN_RULES


def _f(issue, sev="HIGH", domain="application", origin=ORIGIN_AGENT, rec=None):
    return Finding(section="API", domain=domain, severity=sev, issue=issue,
                   recommendation=rec or f"Fix {issue}", origin=origin)


def _run():
    d = D.DFD(document="k")
    d.components = [D.DFDComponent("pay", "PayCrest", kind="external_party", zone="partner"),
                    D.DFDComponent("kong", "Kong", kind="service", zone="dmz")]
    d.flows = [D.DFDFlow("f1", "pay", "kong", auth="none")]
    t1 = TA.Threat(id="T-001", framework="STRIDE", category="Spoofing", target_type="flow",
                   target_id="f1", target_label="PayCrest → Kong",
                   title="Unauthenticated webhook route accepts forged payment events",
                   risk="CRITICAL", mitigations=["Require webhook signature authentication"],
                   source="rule")
    t2 = TA.Threat(id="T-002", framework="STRIDE", category="Denial of service",
                   target_type="component", target_id="kong", target_label="Kong",
                   title="Gateway flooding", risk="MEDIUM", mitigations=["Rate limit"])
    return d, TA.ThreatModelRun(document="k", dfd_version=1, frameworks=["STRIDE"], model="m",
                                threats=[t1, t2])


def test_findings_and_threats_in_one_list_with_duplicates_merged():
    d, run = _run()
    dup = _f("Webhook route accepts unauthenticated forged payment events",
             rec="Require webhook signature authentication on the route")
    other = _f("Passwords may be six characters", "MEDIUM", "application", ORIGIN_RULES)
    items = Q.build_queue([dup, other], {}, [run], d)
    titles = [i.title for i in items]
    assert len(items) == 3                                    # 2 findings + 2 threats - 1 merge
    webhook = next(i for i in items if "webhook" in i.title.lower())
    assert webhook.source == "threat-rule" and len(webhook.merged) == 1
    assert any("Gateway flooding" in t for t in titles)


def test_order_open_then_confirmed_then_severity():
    d, run = _run()
    m = _f("Model says something critical", "CRITICAL")
    r = _f("Rule says something medium level here", "MEDIUM", origin=ORIGIN_RULES)
    items = Q.build_queue([m, r], {}, [run], d)
    assert items[0].confirmed_source                          # rule/threat-rule first
    assert items[-1].source in ("model", "threat-model")


def test_decisions_carry_over_from_feedback_and_threat_status():
    d, run = _run()
    f = _f("Some finding with several words to compare")
    run.threats[1].status = "disputed"
    items = Q.build_queue([f], {f.fingerprint: {"decision": "accepted"}}, [run], d)
    by = {i.key: i for i in items}
    assert by[f"F:{f.fingerprint}"].status == "accepted"
    assert by["T:1/T-002"].status == "disputed"
    assert Q.summary(items)["disputed"] == 1


def test_one_decision_updates_every_merged_record():
    d, run = _run()
    dup = _f("Webhook route accepts unauthenticated forged payment events",
             rec="Require webhook signature authentication on the route")
    items = Q.build_queue([dup], {}, [run], d)
    webhook = next(i for i in items if "webhook" in i.title.lower())
    recorded, saved = [], []
    n = Q.apply_decision(webhook, "accepted", findings_by_fp={dup.fingerprint: dup},
                         runs_by_version={1: run}, review_key="k",
                         record=lambda *a, **k: recorded.append((a, k)),
                         save_run=saved.append)
    assert n == 2 and len(recorded) == 1 and saved == [run]
    assert run.threats[0].status == "accepted"
    assert recorded[0][0][2] == "accepted"


def test_dispute_requires_nothing_else_and_mitigated_maps_to_accepted_for_findings():
    f = _f("Some finding with several words to compare")
    items = Q.build_queue([f], {})
    recorded = []
    Q.apply_decision(items[0], "mitigated", findings_by_fp={f.fingerprint: f},
                     runs_by_version={}, review_key="k",
                     record=lambda *a, **k: recorded.append((a, k)))
    assert recorded[0][0][2] == "accepted" and "[mitigated]" in recorded[0][1]["note"]
