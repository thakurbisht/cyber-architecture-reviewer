#!/usr/bin/env python3
"""Standalone unit test for src/threat_model.py - no Ollama, no LangGraph.

Run: python3 test_threat_model.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.models import Finding, Section
from src.threat_model import build_threat_model, classify_stride, infer_trust_zone

def check(cond, msg):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        raise SystemExit(1)

sections = [
    Section(index=0, heading="1. Internet-Facing API Gateway", body="Public endpoint...",
            domain="network", topic="perimeter"),
    Section(index=1, heading="2. Internal Payment Processing Service", body="Processes cards...",
            domain="application", topic="context_scope"),
    Section(index=2, heading="3. IAM Policy for Data Lake", body="Wildcard resource access...",
            domain="cloud_data", topic="access_control"),
]

findings = [
    Finding(section="1. Internet-Facing API Gateway", domain="network", severity="HIGH",
            issue="No MFA required on admin console access", recommendation="Enforce MFA",
            origin="skill_executor", rule_id="no_mfa_admin"),
    Finding(section="3. IAM Policy for Data Lake", domain="cloud_data", severity="CRITICAL",
            issue="IAM policy grants wildcard resource access (Resource: *)",
            recommendation="Scope resource ARNs explicitly",
            origin="skill_executor", rule_id="aws_wildcard_resource"),
    Finding(section="2. Internal Payment Processing Service", domain="application", severity="MEDIUM",
            issue="Application does not log administrative actions for audit purposes",
            recommendation="Add centralized audit logging", origin="agent"),
    Finding(section="2. Internal Payment Processing Service", domain="application", severity="LOW",
            issue="Some obscure thing that matches no keyword at all zzqx",
            recommendation="n/a", origin="agent"),
]

# -- classify_stride --------------------------------------------------------
check(set(classify_stride(findings[0])) == {"Spoofing", "Elevation of Privilege"},
      "no_mfa_admin classifies as Spoofing + Elevation of Privilege")
check(set(classify_stride(findings[1])) == {"Elevation of Privilege", "Information Disclosure"},
      "aws_wildcard_resource classifies as EoP + Info Disclosure")
check(set(classify_stride(findings[2])) == {"Repudiation"},
      "keyword fallback classifies missing audit logging as Repudiation")
check(classify_stride(findings[3]) == [],
      "unmatched finding classifies as empty (unclassified), not guessed")

# -- infer_trust_zone ---------------------------------------------------
check(infer_trust_zone(sections[0]) == "perimeter", "internet-facing gateway -> perimeter zone")
check(infer_trust_zone(sections[1]) == "internal", "internal service heading -> internal zone")
check(infer_trust_zone(sections[2]) == "cloud_zone", "cloud_data domain with no zone keyword -> cloud_zone default")

# -- build_threat_model ---------------------------------------------------
tm = build_threat_model(
    document_name="test-doc",
    sections=sections,
    findings=findings,
    domains=["network", "application", "cloud_data"],
)

check(len(tm.entities) == 3, "3 entities built (one per section)")
check(len(tm.trust_boundary_crossings) == 2,
      f"2 trust boundary crossings inferred (perimeter->internal, internal->cloud_zone), got {len(tm.trust_boundary_crossings)}")
check(tm.unclassified_findings == 1, "1 unclassified finding tracked separately")

# 3 classified findings -> threats (1 with 2 cats, 1 with 2 cats, 1 with 1 cat = 5 threat rows)
check(len(tm.threats) == 5, f"5 threat rows from STRIDE fan-out, got {len(tm.threats)}")
check(tm.stride_totals["Elevation of Privilege"] == 2, "2 EoP threats total (mfa + wildcard)")
check(tm.stride_totals["Repudiation"] == 1, "1 Repudiation threat (missing audit log)")
check(tm.stride_totals["Denial of Service"] == 0, "0 DoS threats (none raised)")

# blind spot: network domain has zero Tampering/Repudiation/DoS/InfoDisclosure threats
blind_cats_for_network = {b["stride_category"] for b in tm.blind_spots if b["domain"] == "network"}
check("Denial of Service" in blind_cats_for_network,
      "network domain flagged as blind spot for Denial of Service")

d = tm.to_dict()
check(isinstance(d, dict) and d["document_name"] == "test-doc", "to_dict() serialises cleanly")
check("caveats" in d and len(d["caveats"]) >= 1, "caveats present in serialised output")

import json
json.dumps(d)  # must not raise
print("\nAll threat_model.py unit tests passed.")
print(f"Sample output keys: {list(d.keys())}")
