"""Expert rules (src/rules_expert.py): each rule fires on its pattern and stays
quiet on the safe variant. Wording is deliberately different from the golden
set so these test the phrasing class, not memorised sentences."""

from __future__ import annotations

import pytest

from src.parser import parse_text
from src.rules import run_rules


def _kinds(text: str) -> dict:
    return {f.rule_id: f.kind for f in run_rules(parse_text(f"## Design\n\n{text}", "t"))}


CASES = [
    # (rule, fires-on, stays-quiet-on)
    ("SEC-EXC-001",
     "Signature validation on the partner callback is disabled because the partner "
     "platform cannot sign its requests.",
     "Signature validation on the partner callback is enforced for every request."),
    ("SEC-EXC-001",
     "The analytics database is publicly accessible so that the vendor's cloud tool can "
     "query it directly.",
     "The analytics database is reachable only through a private endpoint."),
    ("APP-AUTHZ-002",
     "The invoice endpoint returns the PDF for the requested invoice id; invoice ids are "
     "sequential integers.",
     "Invoice ids are random UUIDs and the service checks the invoice belongs to the caller."),
    ("SEC-IAM-004",
     "Every signed-in agent can issue refunds and export the customer list.",
     "Refunds can be issued only by the Refund Approver role."),
    ("SEC-IAM-004",
     "The admin application is assigned to the All Staff group to avoid access requests.",
     "The admin application is assigned to the Payments-Admins group only."),
    ("NET-EXPO-001",
     "Branch routers forward RDP 3389 on the public IP to the kiosk PC from any source.",
     "Vendor support connects through the PAM jump host with MFA and session recording."),
    ("NET-SEG-003",
     "The store firewall permits all traffic between the POS, office and CCTV VLANs.",
     "The store firewall allows only listed flows between the POS and office VLANs."),
    ("CLD-K8S-001",
     "The AKS API server endpoint is public so pipelines on hosted agents can deploy.",
     "The AKS API server endpoint is private and reached from self-hosted agents."),
    ("NET-EGR-001",
     "Outbound internet access from the application subnets is unrestricted.",
     "Outbound traffic passes through the egress proxy with a destination allow-list."),
    ("APP-SESS-001",
     "Refresh tokens remain valid for 30 days even after the user logs out.",
     "Logging out revokes the refresh token server-side."),
    ("SEC-PKI-001",
     "The code-signing private key is kept as a .pfx file on the build engineer's laptop.",
     "The code-signing key is non-exportable in the HSM and used only by the release job."),
    ("SEC-PKI-002",
     "Device certificates are valid for 15 years to match the product lifetime.",
     "Device certificates are valid for one year and renewed automatically."),
    ("APP-CICD-001",
     "Pull requests from forks automatically run the full test pipeline on the shared runners.",
     "Pull requests from forks wait for maintainer approval and run on ephemeral runners."),
    ("APP-CICD-001",
     "The deploy token is a protected variable available to all pipeline jobs.",
     "The deploy token is scoped to the protected release environment."),
    ("APP-CICD-002",
     "The build installs packages with pip using --extra-index-url for the private feed.",
     "The build installs packages only from the internal Artifactory proxy with hashes."),
    ("APP-CICD-003",
     "Kubernetes manifests reference each image by its version tag, and the registry uses "
     "mutable tags.",
     "Kubernetes manifests reference images pinned by digest and tag immutability is on."),
    ("OT-FW-001",
     "Gateways download update packages over plain HTTP from the CDN.",
     "Gateways download update packages over HTTPS and verify the vendor signature."),
    ("OT-DBG-001",
     "The JTAG port is left enabled on shipped controllers for field diagnostics.",
     "The JTAG port is fused off on shipped controllers."),
    ("APP-UPLOAD-001",
     "Customers can upload attachments in any file format to the support portal.",
     "Uploads are limited to PDF and PNG, checked by file signature and malware scanned."),
    ("APP-SSRF-001",
     "The preview service fetches the user-supplied URL to build a link thumbnail.",
     "The preview service fetches only allow-listed destination domains."),
    ("APP-PWD-001",
     "Passwords must be at least six characters long.",
     "Passwords must be at least 12 characters and are checked against breach lists."),
]


@pytest.mark.parametrize("rule,bad,good", CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_fires_on_bad_and_not_on_good(rule, bad, good):
    assert rule in _kinds(bad), f"{rule} should fire on: {bad}"
    assert rule not in _kinds(good), f"{rule} should NOT fire on: {good}"


def test_sequential_ids_alone_are_a_question_not_a_finding():
    kinds = _kinds("Order numbers are sequential and printed on labels.")
    assert kinds.get("APP-AUTHZ-002") == "question"


def test_bare_password_change_mention_does_not_fire_session_rule():
    assert "APP-SESS-001" not in _kinds("Users can request a password change from the portal.")
