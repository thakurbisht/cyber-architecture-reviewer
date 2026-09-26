"""Deterministic rules engine - the repeatability layer.

Why this exists
---------------
Agentic review is probabilistic. Run the same document twice and the model
may phrase a finding differently, order findings differently, or miss one it
caught last time. That is acceptable for judgement calls. It is not
acceptable for the things that are simply, flatly wrong - SNMPv2c with a
community string of 'public' is a finding every single time, and it should
never depend on whether the model felt thorough on that pass.

So the pipeline runs two layers:

  Layer 1 (this file)  Deterministic pattern rules. Same input -> byte
                       identical findings, always. Fast, free, auditable,
                       and testable with ordinary unit tests.

  Layer 2 (agent.py)   LLM reasoning over retrieved standards. Handles the
                       contextual judgement a regex cannot: "these two
                       uplinks are redundant on paper but land on the same
                       chassis", "this tier boundary contradicts the stated
                       trust model".

Layer 1 findings are also fed to the agent as prior context, which measurably
reduces the model's tendency to re-report the obvious and lets it spend its
reasoning budget on the subtle.

Rule anatomy
------------
  trigger          regex(es); any match fires the rule, unless suppressed
  hard_trigger     regex(es) constituting direct evidence of the defect;
                   fires regardless of suppressors
  suppressors      regex(es) that, if present un-negated, mean the design
                   already addresses the issue
  suppressor_guard when True, a negation grammatically attached to a
                   suppressor cancels the suppression rather than the finding
  topics           restrict the rule to particular section topics
  scope            "section" (per section) or "document" (once, whole doc)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Pattern, Sequence

from .models import Finding, ORIGIN_RULES, Section

FLAGS = re.IGNORECASE

# --------------------------------------------------------------------------
# Suppression guarding
# --------------------------------------------------------------------------
# Design documents habitually name a control in the same breath as declining
# to implement it:
#
#   "TACACS+ was considered but the AAA server project has slipped."
#   "Neighbour authentication is not configured."
#   "There is no dependency scanning, image scanning or SBOM generation."
#   "Nothing is forwarded to the enterprise SIEM."
#   "## 12. Threat Model  \n A threat model has not yet been produced."
#
# A naive suppressor sees the control name and cancels a real finding. That is
# the most dangerous failure mode this engine has, because it fails silently
# and in the reassuring direction.
#
# Rules that opt in with suppressor_guard=True have every suppressor match
# checked against context on BOTH sides - a lookahead alone cannot catch "no
# dependency scanning", where the negation precedes the term.
#
# The guard is deliberately narrow. A negation somewhere in the vicinity is
# not enough - "parameterised queries ... with no dynamic SQL" negates the
# defect, not the control, and must NOT cancel the suppression. So the
# negation has to be grammatically attached to the control term:
#
#   left-attached   "there is no  [dependency scanning]"
#   right-attached  "[TACACS+] was considered but ..."
#                   "[authentication] is not configured"
#
# Anything looser reintroduces false positives, which are worse than the
# misses: a report nobody trusts is a report nobody reads.
_LEFT_NEGATION = re.compile(
    r"\b(no|not|never|without|nothing|none|neither|nor|lack\s+of|"
    r"absence\s+of|lacking)\b[\s\w,]{0,12}$",
    FLAGS,
)
_RIGHT_NEGATION = re.compile(
    r"^[^\w\n]{0,3}\s*(?:\w+\s+){0,2}"
    r"(?:was|is|are|were|has|have|had|will|would|remains?)\s+"
    r"(?:been\s+|found\s+to\s+be\s+|going\s+to\s+be\s+)?"
    r"(?:not\b|never\b|no\b|considered|planned|proposed|evaluated|deferred|"
    r"descoped|de-scoped|rejected|abandoned|inflexible|unsuitable|optional|"
    r"exempt|unavailable|out\s+of\s+scope|on\s+the\s+roadmap|"
    r"a\s+(?:phase\s*2|future|later)\b)",
    FLAGS,
)
GUARD_WINDOW = 80     # characters inspected either side of a suppressor match


@dataclass(frozen=True)
class Rule:
    """A deterministic design-defect pattern."""

    id: str
    domain: str
    severity: str
    issue: str
    recommendation: str
    trigger: Sequence[str]
    standard_reference: str = ""
    kb_source: str = ""
    control_mappings: Sequence[str] = ()
    suppressors: Sequence[str] = ()
    # Patterns that constitute direct evidence of the defect. A hard trigger
    # fires regardless of suppressors: "MFA is optional for engineers" is
    # explicit evidence that outranks the word "MFA" appearing elsewhere in
    # the same section as circumstantial evidence of the control.
    hard_trigger: Sequence[str] = ()
    topics: Sequence[str] = ()          # limit rule to these section topics
    scope: str = "section"              # "section" or "document"
    mode: str = "presence"              # "presence" or "absence"
    suppressor_guard: bool = False      # negation context cancels suppression

    def compiled_trigger(self) -> List[Pattern]:
        return [re.compile(p, FLAGS) for p in self.trigger]

    def compiled_hard_trigger(self) -> List[Pattern]:
        return [re.compile(p, FLAGS) for p in self.hard_trigger]

    def compiled_suppressors(self) -> List[Pattern]:
        return [re.compile(p, FLAGS) for p in self.suppressors]

    def is_suppressed(self, text: str) -> bool:
        """True when the design demonstrably addresses this issue.

        A suppressor mention only counts as evidence of the control if it is
        not negated. One clean mention anywhere in the text is enough.
        """
        for pattern in self.compiled_suppressors():
            for match in pattern.finditer(text):
                if not self.suppressor_guard:
                    return True
                left = text[max(0, match.start() - GUARD_WINDOW):match.start()]
                right = text[match.end():match.end() + GUARD_WINDOW]
                if _LEFT_NEGATION.search(left) or _RIGHT_NEGATION.search(right):
                    continue        # the design names the control to decline it
                return True         # a clean mention: the control is real
        return False


# ==========================================================================
# NETWORK
# ==========================================================================
NETWORK_RULES: List[Rule] = [
    Rule(
        id="NET-MGMT-001",
        domain="network",
        severity="CRITICAL",
        issue="SNMP v1/v2c is actively configured or permitted in use.",
        recommendation=(
            "Migrate all managed devices to SNMPv3 with authPriv "
            "(SHA authentication, AES-128 or stronger privacy). Remove v1/v2c "
            "configuration entirely rather than leaving it as a fallback."
        ),
        trigger=[
            r"snmp\s+(?:is\s+)?(v?[12]c?|v1|v2c)[^\n]{0,40}(?:in use|enabled|configured|deployed|active)",
            r"(?:enable|configure|use|deploy)[^\n]{0,40}(?:snmp\s+)?v?[12]c",
            r"snmp\s*-?\s*v?[12]c?\s+(?:is\s+)?(enabled|configured|active|in\s+use)",
            r"community\s+string[^\n]{0,40}(?:required|used|enabled|configured)",
        ],
        suppressors=[
            r"snmpv3",
            r"snmp\s*v\s*3",
            r"snmp[^\n]{0,40}(?:migrate|upgrade|plan|transition|will\s+use)",
            r"(?:will|planned?|scheduled)\s+(?:to\s+)?(?:migrate|upgrade)\s+(?:to\s+)?(?:snmpv3|snmp\s*v3)",
            r"v?[12]c[^\n]{0,40}(?:deprecated|legacy|not\s+used|disabled|removed)",
        ],
        suppressor_guard=True,
        standard_reference="Secure Management Plane Standard §2.1",
        kb_source="network/network-management-standard.md",
        control_mappings=["NIST SP 800-53 SC-8", "ISO 27001 A.8.20", "CIS 4.x"],
    ),
    Rule(
        id="NET-MGMT-002",
        domain="network",
        severity="CRITICAL",
        issue=(
            "A default or guessable SNMP community string (public/private) "
            "is specified in the design."
        ),
        recommendation=(
            "Remove default community strings. Under SNMPv3 use per-device "
            "credentials issued from the credential vault with scheduled rotation."
        ),
        trigger=[r"community\s+string[^\n]{0,40}\b(public|private)\b",
                 r"\bsnmp[^\n]{0,40}\b(public|private)\b"],
        standard_reference="Secure Management Plane Standard §2.2",
        kb_source="network/network-management-standard.md",
        control_mappings=["NIST SP 800-53 IA-5", "ISO 27001 A.5.17"],
    ),
    Rule(
        id="NET-MGMT-003",
        domain="network",
        severity="HIGH",
        issue="Cleartext device management protocols (Telnet/TFTP) are actively configured or permitted.",
        recommendation=(
            "Permit SSHv2 and HTTPS only. Disable telnet, HTTP, FTP and TFTP "
            "transport on every managed device and block those ports at the "
            "management ACL."
        ),
        trigger=[
            r"telnet\s+(is\s+)?(enabled|permitted|allowed|configured|used|deployed)",
            r"permit\s+telnet",
            r"allow.*telnet",
            r"tftp\s+(is\s+)?(enabled|permitted|allowed|configured|used|deployed)",
            r"permit\s+tftp",
            r"allow.*tftp",
        ],
        suppressors=[
            r"telnet\s+(is\s+)?(disabled|denied|blocked|prohibited|not\s+used)",
            r"no\s+telnet",
            r"disable.*telnet",
            r"telnet.*(?:will|planned)\s+(?:be\s+)?(?:removed|disabled|migrated?)",
            r"migrat.*(?:from|to).*(?:telnet|ssh)",
            r"consider(?:ed)?.*telnet.*(?:but|however|rejected|instead)",
            r"legacy.*telnet.*(?:removed|retired|decommissioned)",
            r"tftp\s+(is\s+)?(disabled|denied|blocked|prohibited|not\s+used)",
            r"no\s+tftp",
            r"disable.*tftp",
        ],
        suppressor_guard=True,
        standard_reference="Secure Management Plane Standard §2.3",
        kb_source="network/network-management-standard.md",
        control_mappings=["NIST SP 800-53 AC-17", "ISO 27001 A.8.20"],
    ),
    Rule(
        id="NET-MGMT-004",
        domain="network",
        severity="HIGH",
        issue=(
            "Device administration actively uses local accounts or shared credentials "
            "rather than centralised AAA."
        ),
        recommendation=(
            "Integrate all network devices with TACACS+ (or RADIUS where "
            "TACACS+ is unavailable) backed by the enterprise directory, with "
            "command authorisation and per-user accounting. Retain exactly one "
            "break-glass local account with a vaulted, rotated password."
        ),
        trigger=[
            r"(?:use|deploy|configure)[^\n]{0,40}local\s+(?:admin|user)\s+accounts?\b",
            r"local\s+accounts?\s+(?:is\s+)?(?:used|required|enabled|configured)",
            r"shared\s+(?:admin|administrator|enable|root)\s+password(?:\s+is\s+)?(?:used|required)",
            r"same\s+(?:password|credentials?)\s+(?:on|across|for)\s+(?:all|multiple|every)",
        ],
        suppressors=[
            r"tacacs",
            r"\bradius\b[^\n]{0,60}(?:aaa|authentication)",
            r"local\s+accounts?\s+(?:only|are|will\s+be)\s+(?:for\s+)?(?:break-?glass|emergency|out-of-band)",
            r"(?:all\s+)?(?:regular\s+)?(?:admin|user)\s+accounts?\s+(?:will\s+)?(?:be\s+)?(?:centrali[sz]ed|managed\s+by)",
            r"(?:will|plan[s]?|scheduled)\s+(?:to\s+)?(?:integrat|switch)\s+(?:to\s+)?(?:tacacs|radius|aaa)",
            r"break-?glass.*only",
            r"legacy.*local.*(?:will\s+)?(?:be\s+)?(?:removed|migrated)",
        ],
        suppressor_guard=True,
        standard_reference="Secure Management Plane Standard §3.1",
        kb_source="network/network-management-standard.md",
        control_mappings=["NIST SP 800-53 AC-2", "ISO 27001 A.5.15"],
    ),
    Rule(
        id="NET-SEG-001",
        domain="network",
        severity="CRITICAL",
        issue=(
            "A permit-any-any firewall or ACL rule is present, defeating "
            "segmentation between zones."
        ),
        recommendation=(
            "Replace the any-any rule with explicit source/destination/port "
            "entries derived from the application flow matrix, terminated by an "
            "explicit deny-all with logging enabled."
        ),
        trigger=[
            r"permit\s+ip\s+any\s+any",
            r"allow\s+(?:all|any)\s+(?:traffic|to|from)\s",
            r"0\.0\.0\.0/0[^\n]{0,40}(?:allow|permit)",
            r"source[:\s]+any[^\n]{0,40}destination[:\s]+any[^\n]{0,40}(?:allow|permit)",
            r"\|\s*any\s*\|\s*any\s*\|\s*(?:allow|permit)",
            r"\|\s*any\s*\|\s*any\s*\|[^\n]*(?:allow|permit)",
            r"(?:firewall|policy)\s+default\s+is\s+permit",
            r"default\s+(?:action\s+)?is\s+permit",
        ],
        suppressors=[
            r"(?:deny|drop|reject|block)\s+any\s+any",
            r"\|\s*any\s*\|\s*any\s*\|\s*(?:deny|drop|reject|block)",
            r"any\s+any\s+(?:is\s+)?(?:denied|blocked|prohibited|dropped)",
            r"any-to-any\s+(?:denied|blocked|prohibited)",
            r"(?:no\s+)?permit.*any.*any",
        ],
        suppressor_guard=True,
        standard_reference="Network Segmentation Standard §4.1",
        kb_source="network/segmentation-standard.md",
        control_mappings=["NIST SP 800-53 SC-7", "ISO 27001 A.8.22",
                          "MITRE ATT&CK TA0008"],
        topics=("segmentation", "wan_edge", "cloud_network"),
    ),
    Rule(
        id="NET-SEG-002",
        domain="network",
        severity="HIGH",
        issue=(
            "The design relies on a flat VLAN or a single broadcast domain for "
            "differently-trusted workloads."
        ),
        recommendation=(
            "Separate workloads into zones by trust level and data "
            "classification, enforce inter-zone policy at a stateful device, "
            "and document the permitted flow matrix."
        ),
        trigger=[r"flat\s+(network|vlan|layer\s*2)",
                 r"single\s+vlan[^\n]{0,60}(all|entire|every)",
                 r"all\s+(servers|hosts|workloads)[^\n]{0,40}same\s+vlan"],
        standard_reference="Network Segmentation Standard §2.2",
        kb_source="network/segmentation-standard.md",
        control_mappings=["NIST SP 800-53 SC-7(21)", "ISO 27001 A.8.22"],
    ),
    Rule(
        id="NET-HA-001",
        domain="network",
        severity="CRITICAL",
        issue="A single uplink, single device, or acknowledged single point of failure exists in the path.",
        recommendation=(
            "Provide two uplinks terminating on two physically separate "
            "upstream devices. Validate that no single chassis, line card, "
            "power feed or path failure isolates the downstream segment."
        ),
        trigger=[r"single\s+uplink", r"one\s+uplink\b",
                 r"single\s+point\s+of\s+failure", r"\bspof\b",
                 r"single\s+(?:\S+\s+){0,3}"
                 r"(firewall|router|switch|circuit|link|device|path|core|"
                 r"supervisor|power\s+supply)\b",
                 r"no\s+redundan(cy|t)",
                 r"(second|redundant|backup)\s+\S{0,20}\s*"
                 r"(circuit|switch|router|firewall|link|supply)[^\n]{0,60}"
                 r"(removed\s+from\s+scope|not\s+(part|included|provided)|"
                 r"phase\s*2|deferred|descoped)"],
        suppressors=[r"eliminat\w+\s+the\s+single\s+point",
                     r"avoid\w*\s+single\s+point"],
        standard_reference="Three-Tier LAN Architecture Standard §3.1",
        kb_source="network/three-tier-lan-standard.md",
        control_mappings=["NIST SP 800-53 CP-2", "ISO 27001 A.8.14"],
    ),
    Rule(
        id="NET-HA-002",
        domain="network",
        severity="CRITICAL",
        issue=(
            "Two uplinks are described but both terminate on the same upstream "
            "device - redundancy in quantity without diversity."
        ),
        recommendation=(
            "Reroute one uplink so the pair terminates on two different "
            "upstream devices. Two links into one chassis do not survive that "
            "chassis failing."
        ),
        trigger=[
            r"(two|2|dual)\s+uplinks?[^\n]{0,120}?\bboth\b[^\n]{0,60}?same\s+"
            r"(switch|device|chassis|distribution|router)",
            r"both\s+uplinks?[^\n]{0,60}?terminate[^\n]{0,60}?same",
            r"uplink[- ]?1[^\n]{0,40}?(\bto\b|-->)\s*(\S+)[^\n]{0,80}?"
            r"uplink[- ]?2[^\n]{0,40}?(\bto\b|-->)\s*\2\b",
        ],
        standard_reference="Three-Tier LAN Architecture Standard §3.2",
        kb_source="network/three-tier-lan-standard.md",
        control_mappings=["NIST SP 800-53 CP-2", "ISO 27001 A.8.14"],
    ),
    Rule(
        id="NET-RTG-001",
        domain="network",
        severity="HIGH",
        issue="A dynamic routing protocol is deployed without neighbour authentication.",
        recommendation=(
            "Enable cryptographic neighbour authentication on every routing "
            "adjacency (OSPF HMAC-SHA, BGP TCP-AO or MD5 where AO is "
            "unsupported) and passive-interface on all user-facing ports."
        ),
        trigger=[r"\b(ospf|bgp|eigrp|is-?is)\b"],
        suppressors=[r"(authentication|md5|hmac|sha-?\d|key-?chain|tcp-ao)",
                     r"passive-interface"],
        suppressor_guard=True,
        topics=("routing", "wan_edge"),
        standard_reference="Routing Architecture Standard §5.3",
        kb_source="network/routing-standard.md",
        control_mappings=["NIST SP 800-53 SC-8", "ISO 27001 A.8.20"],
    ),
    Rule(
        id="NET-WAN-001",
        domain="network",
        severity="HIGH",
        issue="WAN or inter-site traffic traverses untrusted transport without encryption.",
        recommendation=(
            "Encrypt all inter-site traffic in transit (IPsec or MACsec) "
            "regardless of whether the carrier describes the circuit as private. "
            "Carrier-private is not the same as confidential."
        ),
        trigger=[r"(mpls|leased\s+line|carrier|circuit|wan)[^\n]{0,80}"
                 r"(unencrypted|clear\s*text|no\s+encryption|not\s+encrypted|"
                 r"plain)",
                 r"(unencrypted|not\s+encrypted)[^\n]{0,80}"
                 r"(mpls|leased\s+line|carrier|circuit|wan)",
                 r"encryption\s+is\s+not\s+(required|used|applied)[^\n]{0,40}wan",
                 r"trusted\s+(carrier|mpls|circuit)",
                 r"(carrier|mpls)\s+circuit\s+is\s+(private|dedicated)"],
        topics=("wan_edge",),
        standard_reference="WAN & Edge Standard §3.4",
        kb_source="network/routing-standard.md",
        control_mappings=["NIST SP 800-53 SC-8", "ISO 27001 A.8.24"],
    ),
    Rule(
        id="NET-WLS-001",
        domain="network",
        severity="HIGH",
        issue="Wireless uses a pre-shared key or a deprecated security mode for corporate access.",
        recommendation=(
            "Use WPA2-Enterprise or WPA3-Enterprise with 802.1X and "
            "certificate-based EAP-TLS for corporate SSIDs. Reserve PSK for "
            "isolated guest or IoT SSIDs with their own segment."
        ),
        trigger=[r"\bwep\b", r"wpa2?-?psk", r"pre-?shared\s+key[^\n]{0,40}"
                 r"(corporate|employee|staff|internal)", r"\bwpa\b(?!2|3)"],
        topics=("wireless",),
        standard_reference="Wireless Standard §2.1",
        kb_source="network/network-management-standard.md",
        control_mappings=["NIST SP 800-53 AC-18", "ISO 27001 A.8.20"],
    ),
]


# ==========================================================================
# APPLICATION
# ==========================================================================
APPLICATION_RULES: List[Rule] = [
    Rule(
        id="APP-SEC-001",
        domain="application",
        severity="CRITICAL",
        issue="Credentials, API keys or connection strings are embedded in code or configuration.",
        recommendation=(
            "Move every secret to the enterprise secret manager, inject at "
            "runtime via short-lived credentials or workload identity, and "
            "rotate anything that has ever been committed - it must be treated "
            "as compromised."
        ),
        trigger=[r"hard-?cod(ed|ing)[^\n]{0,40}(password|secret|key|credential|token)",
                 r"(password|api[_ -]?key|secret|token)\s*[:=]\s*[\"']?[A-Za-z0-9\-_/+]{8,}",
                 r"(credential|secret|password|api\s*key|encryption\s+key|"
                 r"private\s+key|access\s+key)s?\b[^\n]{0,60}?\b"
                 r"(stored|kept|held|embedded|placed|written|deployed)\b"
                 r"[^\n]{0,60}?\b(code|config\w*|configmap|repo\w*|source|"
                 r"properties|appsettings|\.env|environment\s+variable|"
                 r"pipeline\s+(secret|variable)|script|job\s+definition|"
                 r"design\s+document)\b",
                 r"connection\s+string[^\n]{0,60}(password|pwd)\s*=",
                 r"(?:static|long-lived)\s+(?:password|access\s+key)[^\n]{0,40}(?:stored|configured|used)"],
        suppressors=[r"(vault|secrets?\s+manager|key\s*vault|secrets?\s+store|"
                     r"parameter\s+store|managed\s+identity)"],
        standard_reference="Application Security Architecture Standard §6.1",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V6", "NIST SP 800-53 IA-5",
                          "ISO 27001 A.8.24", "MITRE ATT&CK T1552.001"],
    ),
    Rule(
        id="APP-AUTH-001",
        domain="application",
        severity="CRITICAL",
        issue="An API or service endpoint is exposed without authentication.",
        recommendation=(
            "Require authentication on every endpoint by default. If an "
            "endpoint must be anonymous (health probe, well-known metadata), "
            "document it explicitly, keep it free of business data, and rate-limit it."
        ),
        trigger=[r"(?:public|external|exposed|internet-?facing)[^\n]{0,80}(?:no|without|disabl\w+|not\s+required)[^\n]{0,30}authentication",
                 r"(?:unauthenticated|anonymous)[^\n]{0,40}(?:webhook|endpoint|api|post|get)[^\n]{0,40}(?:public|exposed|external|internet)",
                 r"\b(?:unauthenticated|anonymous)\s+(?:webhook|endpoint|api|post|get|request)\b",
                 r"(?:webhook|endpoint|api)[^\n]{0,80}(?:unauthenticated|anonymous|no\s+auth)",
                 r"(?:post|get)\s+/[^\n]{0,60}(?:unauthenticated|no\s+auth|anonymous)",
                 r"openly\s+(?:accepts|receives)[^\n]{0,40}unauthenticated"],
        suppressors=[r"(?:internal|private|trusted|behind\s+(?:firewall|vpn|api\s+gateway))[^\n]{0,40}(?:no\s+auth|unauthenticated|does\s+not\s+require)",
                     r"(?:health|heartbeat|liveness|readiness|probe)[^\n]{0,30}(?:no\s+auth|unauthenticated)",
                     r"(?:internal\s+only|not\s+exposed|private\s+network|cluster\s+internal)[^\n]{0,40}(?:do(?:es)?n['\"]?t|don['\"]?t)\s+require\s+auth",
                     r"(?:well-?known|metadata|openid-?configuration)[^\n]{0,30}(?:no\s+auth|unauthenticated)"],
        suppressor_guard=True,
        standard_reference="Application Security Architecture Standard §3.1",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V2", "OWASP API Top 10 API2",
                          "NIST SP 800-53 IA-2"],
    ),
    Rule(
        id="APP-AUTH-002",
        domain="application",
        severity="HIGH",
        issue="JWT or token handling lacks signature verification, expiry, or audience validation.",
        recommendation=(
            "Validate signature against a pinned JWKS, verify iss/aud/exp/nbf "
            "on every request, reject the 'none' algorithm, and keep access "
            "token lifetime under 15 minutes with refresh rotation."
        ),
        trigger=[r"jwt[^\n]{0,80}(not\s+validat|no\s+expir|never\s+expir|"
                 r"without\s+verif|decode\w*[^\n]{0,20}without)",
                 r"decode\w*[^\n]{0,30}without\s+verif",
                 r"token[^\n]{0,60}(does\s+not\s+expire|no\s+expiry|long-?lived|"
                 r"non-?expiring)",
                 r"token[^\n]{0,60}\b(\d+)\s*(day|week|month)s?\s+"
                 r"(expiry|lifetime|validity|ttl)",
                 r"\b(\d{2,})\s*day\s+expiry",
                 r"(local\s+storage|localstorage)[^\n]{0,40}(token|jwt|session)",
                 r"(token|jwt|session)[^\n]{0,40}(local\s+storage|localstorage)",
                 r"alg\s*[:=]\s*[\"']?none",
                 r"\bhs256\b[^\n]{0,60}shared\s+secret"],
        topics=("app_authn_authz", "api_integration"),
        standard_reference="Application Security Architecture Standard §3.4",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V3", "OWASP API Top 10 API2"],
    ),
    Rule(
        id="APP-AUTHZ-001",
        domain="application",
        severity="HIGH",
        issue=(
            "Authorisation appears to be enforced in the client or gateway only, "
            "with the service trusting inbound identity claims."
        ),
        recommendation=(
            "Enforce object-level authorisation in the service that owns the "
            "data, on every request. Gateway and UI checks are usability "
            "features, not security controls."
        ),
        trigger=[r"authoris?z?ation[^\n]{0,60}(front-?end|client|ui|browser)",
                 r"(gateway|front-?end)[^\n]{0,50}(handles|performs|enforces)"
                 r"[^\n]{0,30}authoris?z?ation",
                 r"trusts?\s+(the\s+)?[\w.\-]{0,30}\s*header",
                 r"trusts?\s+anything\s+(received|sent|passed)",
                 r"does\s+not\s+re-?(verify|validate|check)",
                 r"(validated|verified|enforced|checked)[^\n]{0,40}"
                 r"(only\s+)?at\s+the\s+(api\s+)?gateway",
                 r"(service|backend|microservice)s?\s+trusts?[^\n]{0,50}"
                 r"(header|claim|caller|internal|anything)",
                 r"does\s+not\s+check\s+that[^\n]{0,60}belongs\s+to"],
        standard_reference="Application Security Architecture Standard §3.6",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP API Top 10 API1", "OWASP ASVS V4",
                          "NIST SP 800-53 AC-3"],
    ),
    Rule(
        id="APP-DATA-001",
        domain="application",
        severity="CRITICAL",
        issue="Dynamic SQL is built by string concatenation, creating an injection path.",
        recommendation=(
            "Use parameterised queries or the ORM's binding API exclusively. "
            "Where dynamic identifiers are unavoidable, allow-list them against "
            "a fixed set rather than escaping."
        ),
        trigger=[r"(string\s+)?concat\w*[^\n]{0,40}(sql|query)",
                 r"dynamic\s+sql", r"sql[^\n]{0,40}built[^\n]{0,30}"
                 r"(from|using)[^\n]{0,30}(user|input|parameter)",
                 r"\"\s*\+\s*\w+\s*\+\s*\"[^\n]{0,20}(where|select|insert)"],
        suppressors=[r"parameteri[sz]ed", r"prepared\s+statement", r"bind\s+variable"],
        suppressor_guard=True,
        standard_reference="Application Security Architecture Standard §5.2",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V5", "OWASP Top 10 A03",
                          "MITRE ATT&CK T1190"],
    ),
    Rule(
        id="APP-DATA-002",
        domain="application",
        severity="HIGH",
        issue="Input validation is described as client-side or absent.",
        recommendation=(
            "Validate every input server-side against a positive schema "
            "(type, length, range, format) and reject on failure. Client-side "
            "validation is for user experience only."
        ),
        trigger=[r"(validat\w+|sanitis\w+|sanitiz\w+)[^\n]{0,50}"
                 r"(client|browser|front-?end|javascript|react|angular|vue|"
                 r"single\s+page|\bspa\b)",
                 r"server-?side\s+validation[^\n]{0,80}"
                 r"(descoped|de-scoped|removed|not\s+implemented|deferred|"
                 r"skipped|dropped)",
                 r"no\s+(input\s+)?validation",
                 r"input\s+is\s+(trusted|assumed)"],
        standard_reference="Application Security Architecture Standard §5.1",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V5", "NIST SP 800-53 SI-10"],
    ),
    Rule(
        id="APP-TLS-001",
        domain="application",
        severity="CRITICAL",
        issue="Plaintext HTTP or a deprecated TLS version is used for application traffic.",
        recommendation=(
            "Enforce TLS 1.2 as the minimum with TLS 1.3 preferred, HSTS on "
            "public endpoints, and redirect all HTTP to HTTPS. Disable TLS 1.0, "
            "1.1 and all SSL versions at the load balancer and the origin."
        ),
        trigger=[r"\btls\s*1\.[01]\b", r"\bssl\s*v?[23]\b",
                 r"http://(?!localhost|127\.0\.0\.1)",
                 r"(plain-?text|unencrypted)[^\n]{0,40}(http|traffic|internal)",
                 r"transport is plaintext http"],
        standard_reference="Cryptography Standard §2.1",
        kb_source="security/cryptography-key-management-standard.md",
        control_mappings=["OWASP ASVS V9", "NIST SP 800-52r2",
                          "ISO 27001 A.8.24", "PCI DSS 4.0 4.2.1"],
    ),
    Rule(
        id="APP-SDLC-001",
        domain="application",
        severity="MEDIUM",
        issue="No dependency, container or supply-chain scanning is described in the pipeline.",
        recommendation=(
            "Add SCA and container image scanning as blocking pipeline gates, "
            "publish an SBOM per release, and fail the build on new critical "
            "CVEs in direct dependencies."
        ),
        trigger=[r"(ci/?cd|pipeline|build\s+process|deployment\s+pipeline)"],
        hard_trigger=[
            r"\bno\b[^\n]{0,60}(dependency|container|image|vulnerability|"
            r"security)\s+scan",
            r"(dependency|container|image|security)\s+scanning[^\n]{0,60}"
            r"(is\s+)?(not|absent|missing|planned|deferred)",
            r"\bno\b[^\n]{0,40}\bsbom\b",
            r"scans?\s+are\s+(advisory|informational)\s+only",
        ],
        suppressors=[r"\bsca\b", r"\bsast\b", r"\bdast\b", r"\bsbom\b",
                     r"dependency\s+scan", r"image\s+scan", r"vulnerability\s+scan",
                     r"trivy|snyk|grype|dependabot|blackduck"],
        suppressor_guard=True,
        scope="document",
        standard_reference="Secure SDLC Standard §4.2",
        kb_source="application/secure-sdlc-standard.md",
        control_mappings=["NIST SSDF PW.4", "ISO 27001 A.8.28",
                          "MITRE ATT&CK T1195.002"],
    ),
    Rule(
        id="APP-LOG-001",
        domain="application",
        severity="HIGH",
        issue="Sensitive data is written to application logs.",
        recommendation=(
            "Mask or omit PII, card data, tokens and full request bodies in "
            "logs. Log identifiers and correlation IDs instead of payloads, and "
            "apply the same classification controls to log stores as to the "
            "source data."
        ),
        trigger=[r"log[^\n]{0,50}(password|token|card\s*number|pan\b|ssn|"
                 r"full\s+request|request\s+body|pii)",
                 r"(debug|verbose)\s+logging[^\n]{0,40}(production|prod)\b"],
        standard_reference="Logging & Detection Standard §3.3",
        kb_source="security/logging-detection-standard.md",
        control_mappings=["OWASP ASVS V7", "ISO 27001 A.8.15",
                          "PCI DSS 4.0 3.3"],
    ),
    Rule(
        id="APP-RES-001",
        domain="application",
        severity="MEDIUM",
        issue="No rate limiting or throttling is defined on externally reachable interfaces.",
        recommendation=(
            "Apply per-client and per-endpoint rate limits at the gateway, with "
            "quotas tied to the authenticated principal, plus circuit breakers "
            "on downstream calls."
        ),
        trigger=[r"(public|external|internet-?facing)[^\n]{0,60}(api|endpoint|service)"],
        suppressors=[r"rate\s*limit", r"throttl", r"quota", r"\bwaf\b",
                     r"circuit\s+breaker"],
        suppressor_guard=True,
        scope="document",
        standard_reference="Application Security Architecture Standard §7.2",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP API Top 10 API4", "NIST SP 800-53 SC-5"],
    ),
]


# ==========================================================================
# SECURITY / CYBER
# ==========================================================================
SECURITY_RULES: List[Rule] = [
    Rule(
        id="SEC-IAM-001",
        domain="security",
        severity="CRITICAL",
        issue="Privileged or administrative access is described without multi-factor authentication.",
        recommendation=(
            "Enforce phishing-resistant MFA (FIDO2 or certificate-based) for "
            "every administrative session, brokered through PAM with session "
            "recording and just-in-time elevation."
        ),
        trigger=[r"(?:mfa|multi-?factor|2fa)\s+(?:is\s+)?(?:optional|not\s+required|disabled)[^\n]{0,80}(?:engineer|admin|user|developer|staff)",
                 r"(?:engineer|admin|user)[^\n]{0,80}(?:mfa|multi-?factor|2fa)\s+(?:is\s+)?(?:optional|not\s+required|disabled)",
                 r"(?:root|admin|privileged)\s+(?:user|account|access)[^\n]{0,80}(?:access\s+key|automated|used\s+for)",
                 r"(?:admin|root|privileged)[^\n]{0,60}(?:password|access\s+key|credential)[^\n]{0,60}(?:used|stored|for\s+automation)",
                 r"(?:administratoraccess|admin\s+(?:role|policy))[^\n]{0,80}(?:applied|attached|deployed)"],
        hard_trigger=[
            r"(mfa|multi-?factor|2fa)[^\n]{0,60}"
            r"(optional|not\s+(required|enforced|enabled|mandatory)|exempt|"
            r"waived|disabled)",
            r"(do(es)?\s+not|no)\s+(require|need)[^\n]{0,20}"
            r"(mfa|multi-?factor|2fa)",
            r"without\s+(mfa|multi-?factor|2fa)",
        ],
        suppressors=[r"\bmfa\b", r"multi-?factor", r"\b2fa\b", r"fido",
                     r"passkey", r"smart\s*card", r"certificate-based\s+auth"],
        suppressor_guard=True,
        topics=("iam_privileged", "zero_trust", "app_authn_authz",
                "cloud_landing_zone", "network_management", "iac_posture"),
        standard_reference="Identity & Privileged Access Standard §2.1",
        kb_source="security/identity-access-standard.md",
        control_mappings=["NIST SP 800-53 IA-2(1)", "ISO 27001 A.8.5",
                          "MITRE ATT&CK T1078.002"],
    ),
    Rule(
        id="SEC-IAM-002",
        domain="security",
        severity="HIGH",
        issue="Shared, generic or service accounts are used by humans.",
        recommendation=(
            "Bind every human action to a named identity. Convert service "
            "accounts to workload identities with no interactive logon rights "
            "and vault any that must retain a password."
        ),
        trigger=[r"shared\s+(account|credential|login|user|token|secret|key|"
                 r"password|passphrase)",
                 r"generic\s+account",
                 r"(passphrase|token|password)[^\n]{0,60}"
                 r"(distributed|shared|circulated)[^\n]{0,40}"
                 r"(team|staff|service desk|chat|email)",
                 r"(team|group)\s+(share|uses)[^\n]{0,30}(account|credential)"],
        standard_reference="Identity & Privileged Access Standard §3.2",
        kb_source="security/identity-access-standard.md",
        control_mappings=["NIST SP 800-53 AC-2", "ISO 27001 A.5.16"],
    ),
    Rule(
        id="SEC-ZT-001",
        domain="security",
        severity="HIGH",
        issue=(
            "The design assumes implicit trust based on network location "
            "(\"internal is trusted\"), contradicting Zero Trust principles."
        ),
        recommendation=(
            "Remove location-based trust. Authenticate and authorise every "
            "request per session regardless of source network, and place a "
            "policy enforcement point in front of each protected resource."
        ),
        trigger=[r"internal\s+(network|traffic|users?|systems?)[^\n]{0,60}"
                 r"(trusted|no\s+auth|implicitly)",
                 r"trusted\s+(zone|network|segment)[^\n]{0,50}"
                 r"(no|without)[^\n]{0,30}(auth|inspect|control)",
                 r"behind\s+the\s+firewall[^\n]{0,50}(safe|trusted|secure)",
                 r"\b(considered|deemed|assumed|regarded\s+as|treated\s+as)\s+"
                 r"trusted\b",
                 r"(network|cluster|environment|subnet|vpc|segment)\s+"
                 r"(is|are)\s+trusted",
                 r"(stays|remains|all\s+of\s+it)\s+inside[^\n]{0,40}"
                 r"(network|cluster)",
                 r"once\s+(inside|authenticated)[^\n]{0,60}(full|unrestricted)\s+access"],
        standard_reference="Zero Trust Architecture Standard §2.1 (NIST SP 800-207)",
        kb_source="security/zero-trust-standard.md",
        control_mappings=["NIST SP 800-207 §2.1", "NIST SP 800-53 AC-3",
                          "MITRE ATT&CK TA0008"],
    ),
    Rule(
        id="SEC-CRYPTO-001",
        domain="security",
        severity="HIGH",
        issue="A broken or deprecated cryptographic algorithm is specified.",
        recommendation=(
            "Replace with approved algorithms: AES-256-GCM for symmetric "
            "encryption, SHA-256 or better for hashing, RSA-3072/ECDSA P-256 or "
            "better for signatures, and Argon2id/bcrypt for password storage."
        ),
        trigger=[r"\bmd5\b", r"\bsha-?1\b", r"\b3?des\b(?!ign)", r"\brc4\b",
                 r"\becb\s+mode\b", r"rsa-?1024", r"\bsha1\b"],
        suppressors=[r"(md5|sha-?1|des|rc4)[^\n]{0,40}"
                     r"(deprecat|prohibit|must not|removed|replaced|not permitted)"],
        standard_reference="Cryptography Standard §3.1",
        kb_source="security/cryptography-key-management-standard.md",
        control_mappings=["NIST SP 800-131A", "ISO 27001 A.8.24",
                          "PCI DSS 4.0 4.2"],
    ),
    Rule(
        id="SEC-CRYPTO-002",
        domain="security",
        severity="HIGH",
        issue="Encryption keys have no defined custody, rotation or escrow model.",
        recommendation=(
            "Store keys in an HSM or managed KMS with dual control, define a "
            "rotation period per key class, separate key custodians from data "
            "administrators, and document the recovery procedure."
        ),
        trigger=[r"(encryption|kms|key)\b"],
        suppressors=[r"key\s+rotation", r"rotate[sd]?\s+(every|annually|quarterly)",
                     r"\bhsm\b", r"key\s+custodian", r"dual\s+control",
                     r"key\s+management\s+(policy|procedure|standard)"],
        topics=("crypto_keys",),
        standard_reference="Cryptography Standard §5.2",
        kb_source="security/cryptography-key-management-standard.md",
        control_mappings=["NIST SP 800-57", "ISO 27001 A.8.24"],
    ),
    Rule(
        id="SEC-LOG-001",
        domain="security",
        severity="HIGH",
        issue="No central log aggregation or SIEM forwarding is described for security-relevant events.",
        recommendation=(
            "Forward authentication, authorisation, configuration-change and "
            "administrative events to the SIEM in near real time, with a "
            "documented retention period and write-once storage for the "
            "security log tier."
        ),
        trigger=[r"(logging|\blogs?\b|audit\s+trail|monitoring|syslog|"
                 r"cloudtrail)"],
        hard_trigger=[
            r"nothing\s+is\s+forwarded",
            r"\bno\b[^\n]{0,50}(siem|central\w*\s+log|log\s+aggregation|"
            r"log\s+forwarding)",
            r"(siem|central\w*\s+log\w*|log\s+forwarding)[^\n]{0,60}"
            r"(is\s+)?(a\s+)?(phase\s*2|not\s+in\s+scope|planned|deferred|"
            r"future)",
            r"logs?\s+(are\s+)?(written|stored|held)\s+(only\s+)?"
            r"(to\s+)?local",
            r"syslog\s+is\s+written\s+to\s+local",
        ],
        suppressors=[r"\bsiem\b", r"splunk|sentinel|qradar|elastic|opensearch|"
                     r"chronicle|sumo", r"central\w*\s+(syslog|log)",
                     r"log\s+aggregation",
                     r"forward\w*\s+to[^\n]{0,30}(siem|soc|central)"],
        suppressor_guard=True,
        # Document scope: "nowhere in this design is anything forwarded to the
        # SIEM" is a property of the document, not of one section.
        scope="document",
        standard_reference="Logging & Detection Standard §2.1",
        kb_source="security/logging-detection-standard.md",
        control_mappings=["NIST SP 800-53 AU-6", "ISO 27001 A.8.15",
                          "NIST CSF DE.CM"],
    ),
    Rule(
        id="SEC-LOG-002",
        domain="security",
        severity="MEDIUM",
        issue="Log retention is unspecified or shorter than the required minimum.",
        recommendation=(
            "Retain security logs for at least 12 months, with the most recent "
            "90 days immediately searchable. Confirm the period against any "
            "regulatory obligation applying to this system."
        ),
        trigger=[r"log[^\n]{0,40}retention[^\n]{0,30}\b\d+\s*(day|week)s?",
                 r"retention[^\n]{0,30}\b\d+\s*(day|week)s?[^\n]{0,30}log",
                 r"logs?\s+(are\s+)?(kept|retained)[^\n]{0,30}"
                 r"\b([1-9]|[1-9]\d|[12]\d\d)\s*days?"],
        standard_reference="Logging & Detection Standard §4.1",
        kb_source="security/logging-detection-standard.md",
        control_mappings=["NIST SP 800-53 AU-11", "ISO 27001 A.8.15"],
    ),
    Rule(
        id="SEC-VULN-001",
        domain="security",
        severity="HIGH",
        issue="End-of-life or unsupported software/firmware is part of the target state.",
        recommendation=(
            "Replace or upgrade the component before go-live. If a temporary "
            "exception is unavoidable, record it in the risk register with a "
            "compensating control, an owner and a fixed expiry date."
        ),
        trigger=[r"end[- ]of[- ](life|support)", r"\beol\b", r"\beos\b",
                 r"no\s+longer\s+supported", r"unsupported\s+(version|platform|os)",
                 r"windows\s+server\s+20(03|08|12)\b", r"centos\s*[67]\b",
                 r"python\s*:?\s*2[\.\b]", r"java\s*[678]\b",
                 r"openjdk\s*:?\s*-?\s*[678]\b", r"\bnode\s*:\s*8\b",
                 r"\bubuntu\s*:?\s*(14|16|18)\.04\b"],
        # An EOL component the design exists to remove is the remediation,
        # not the defect.
        suppressors=[r"(replac|retir|remov|decommission|upgrad)\w*"
                     r"[^\n]{0,50}(end[- ]of[- ](life|support)|\beol\b)",
                     r"(end[- ]of[- ](life|support)|\beol\b)[^\n]{0,60}"
                     r"(is|are|will\s+be)\s+(replac|retir|remov|"
                     r"decommission|upgrad)\w*"],
        standard_reference="Vulnerability Management Standard §3.1",
        kb_source="security/vulnerability-resilience-standard.md",
        control_mappings=["NIST SP 800-53 SI-2", "ISO 27001 A.8.8"],
    ),
    Rule(
        id="SEC-RES-001",
        domain="security",
        severity="HIGH",
        issue="Backups are described without immutability, offline copy, or a tested restore.",
        recommendation=(
            "Hold at least one immutable or air-gapped copy outside the "
            "production identity domain, and test restore at defined intervals "
            "with the result recorded against the stated RTO/RPO."
        ),
        trigger=[r"\bback-?ups?\b", r"\bbacked\s+up\b", r"\bbacking\s+up\b",
                 r"\bsnapshots?\s+(are\s+)?retained\b"],
        suppressors=[r"immutable", r"air-?gap", r"worm\b", r"offline\s+copy",
                     r"restore\s+(test|drill|exercis)", r"tested\s+restore",
                     r"object\s+lock"],
        # Deliberately not topic-restricted: backups get mentioned in network,
        # application and cloud sections alike, and the control gap is the
        # same wherever it appears.
        standard_reference="Resilience & Recovery Standard §4.3",
        kb_source="security/vulnerability-resilience-standard.md",
        control_mappings=["NIST SP 800-53 CP-9", "ISO 27001 A.8.13",
                          "MITRE ATT&CK T1490"],
    ),
    Rule(
        id="SEC-TM-001",
        domain="security",
        severity="MEDIUM",
        issue="No threat model or documented attack-surface analysis accompanies the design.",
        recommendation=(
            "Produce a STRIDE or equivalent threat model covering every trust "
            "boundary in the design, with mitigations traced to specific "
            "controls and residual risks accepted by a named owner."
        ),
        # Any design document at all: the absence of a threat model is a
        # completeness gap regardless of what the design covers.
        trigger=[r"\b(design|architecture|hld|lld|solution|topology|"
                 r"platform)\b"],
        hard_trigger=[
            r"(threat\s+model|risk\s+assessment|privacy\s+impact\s+assessment)"
            r"[^\n]{0,60}(has\s+)?(not|never)\b",
            r"\bno\b[^\n]{0,30}threat\s+model",
            r"threat\s+model[^\n]{0,60}(scheduled|planned)\s+(for\s+)?after",
        ],
        suppressors=[r"threat\s+model", r"\bstride\b", r"attack\s+surface",
                     r"abuse\s+case", r"risk\s+assessment", r"threat\s+analysis",
                     r"privacy\s+impact\s+assessment"],
        suppressor_guard=True,
        scope="document",
        standard_reference="Secure Design Standard §1.4",
        kb_source="security/zero-trust-standard.md",
        control_mappings=["NIST SSDF PW.1", "ISO 27001 A.8.27"],
    ),
]


# ==========================================================================
# CLOUD & DATA
# ==========================================================================
CLOUD_DATA_RULES: List[Rule] = [
    Rule(
        id="CLD-STOR-001",
        domain="cloud_data",
        severity="CRITICAL",
        issue="Object storage or a database is described as publicly accessible.",
        recommendation=(
            "Enable account-level public access blocking, serve external "
            "content through a CDN with signed URLs, and confirm no resource "
            "policy grants a wildcard principal."
        ),
        trigger=[r"(public(ly)?\s+(accessible|readable|available|exposed))"
                 r"[^\n]{0,60}(bucket|storage|blob|s3|database|db)",
                 r"(bucket|s3|blob|storage)[^\n]{0,60}public(ly)?\s+"
                 r"(accessible|readable|read)[^\n]{0,40}(?:policy|permission|grant)",
                 r"principal\s*[\"':=]{0,3}\s*[\"']?\*[^\n]{0,40}(?:s3|bucket|object|action)",
                 r"(?:s3\s+)?block\s+public\s+access\s+(?:is\s+)?disabled",
                 r"(?:bucket|blob|storage)[^\n]{0,40}(?:publicly|without\s+auth|unauthenticated)[^\n]{0,40}(?:policy|permission|grant)",
                 r"0\.0\.0\.0/0[^\n]{0,40}(?:database|sql|rds|3306|5432|1433)"],
        suppressors=[r"(?:signed\s+)?url", r"cloudfront|cdn", r"temporary\s+access",
                     r"(?:partner|external|regional\s+office|customer)[^\n]{0,60}(?:shared|access|read)(?:by\s+link)?",
                     r"shared\s+by\s+link[^\n]{0,40}(?:instead|not|block)"],
        suppressor_guard=True,
        standard_reference="Cloud Data Protection Standard §2.3",
        kb_source="cloud_data/cloud-data-protection-standard.md",
        control_mappings=["CIS AWS 2.1.5", "NIST SP 800-53 AC-3",
                          "ISO 27001 A.5.10", "MITRE ATT&CK T1530"],
    ),
    Rule(
        id="CLD-ENC-001",
        domain="cloud_data",
        severity="HIGH",
        issue="Data at rest encryption is absent, defaulted, or uses provider-managed keys for regulated data.",
        recommendation=(
            "Encrypt all data at rest. For regulated or restricted "
            "classifications use customer-managed keys with an independent "
            "rotation schedule and key access logged separately from data access."
        ),
        trigger=[r"(not|no|without)\s+encrypt\w*[^\n]{0,40}(at\s+rest|storage|disk)",
                 r"encryption\s+at\s+rest[^\n]{0,30}(not|no|disabled|optional)"],
        topics=("data_protection", "data_classification"),
        standard_reference="Cloud Data Protection Standard §3.1",
        kb_source="cloud_data/cloud-data-protection-standard.md",
        control_mappings=["NIST SP 800-53 SC-28", "ISO 27001 A.8.24",
                          "CIS AWS 2.1.1"],
    ),
    Rule(
        id="CLD-LZ-001",
        domain="cloud_data",
        severity="HIGH",
        issue=(
            "Production and non-production workloads share a cloud account, "
            "subscription or project."
        ),
        recommendation=(
            "Separate environments into distinct accounts/subscriptions under "
            "organisational units with preventative guardrails, so a "
            "non-production compromise cannot reach production data planes."
        ),
        trigger=[r"(single|same|one)\s+(aws\s+)?(account|subscription|project|tenant)"
                 r"[^\n]{0,80}(prod|dev|test|uat|non-?prod|all\s+environment)",
                 r"(prod\w*|dev\w*|test\w*)[^\n]{0,40}(and|,)[^\n]{0,40}"
                 r"(prod\w*|dev\w*|test\w*)[^\n]{0,40}(share|same)\s+"
                 r"(account|subscription|vpc|project)"],
        standard_reference="Cloud Landing Zone Standard §2.2",
        kb_source="cloud_data/cloud-landing-zone-standard.md",
        control_mappings=["CIS AWS 1.1", "NIST SP 800-53 SC-2",
                          "ISO 27001 A.8.31"],
    ),
    Rule(
        id="CLD-IAM-001",
        domain="cloud_data",
        severity="CRITICAL",
        issue="Wildcard IAM permissions or a broad managed admin role is granted to workloads.",
        recommendation=(
            "Replace wildcard grants with least-privilege policies scoped to "
            "the specific actions and resource ARNs the workload needs, "
            "generated from observed access and reviewed quarterly."
        ),
        trigger=[r"[\"']?action[\"']?\s*[:=]\s*[\"']?\*",
                 r"administrator\s*access[^\n]{0,30}(polic|role)",
                 r"\b(administratoraccess|poweruseraccess)\b",
                 r"(full|unrestricted|\*)\s+(admin\w*|permissions?|access)"
                 r"[^\n]{0,40}(role|service|workload|application)",
                 r"owner\s+role[^\n]{0,40}(subscription|service principal)",
                 r"wildcard\s+(iam\s+)?permission"],
        standard_reference="Cloud Landing Zone Standard §4.1",
        kb_source="cloud_data/cloud-landing-zone-standard.md",
        control_mappings=["CIS AWS 1.16", "NIST SP 800-53 AC-6",
                          "MITRE ATT&CK T1098"],
    ),
    Rule(
        id="CLD-NET-001",
        domain="cloud_data",
        severity="HIGH",
        issue="Management or database ports are reachable from the internet.",
        recommendation=(
            "Remove 0.0.0.0/0 ingress on administrative and data ports. Reach "
            "instances through a bastion or SSM-style session broker, and place "
            "data services on private subnets with private endpoints only."
        ),
        # Ports can appear either side of the CIDR depending on how the design
        # phrases the rule ("permits 5432 from 0.0.0.0/0" vs "0.0.0.0/0 -> 5432").
        trigger=[r"0\.0\.0\.0/0[^\n]{0,60}\b(22|3389|3306|5432|1433|6379|27017|9200)\b",
                 r"\b(22|3389|3306|5432|1433|6379|27017|9200)\b[^\n]{0,60}0\.0\.0\.0/0",
                 r"(ssh|rdp)[^\n]{0,50}(internet|0\.0\.0\.0/0|any\s+source|public)",
                 r"(database|rds|sql)[^\n]{0,60}public\s+subnet"],
        topics=("cloud_network", "segmentation"),
        standard_reference="Cloud Landing Zone Standard §5.3",
        kb_source="cloud_data/cloud-landing-zone-standard.md",
        control_mappings=["CIS AWS 5.2", "NIST SP 800-53 SC-7",
                          "MITRE ATT&CK T1133"],
    ),
    Rule(
        id="CLD-DATA-001",
        domain="cloud_data",
        severity="HIGH",
        issue=(
            "Sensitive or regulated data is handled without a stated "
            "classification, residency constraint or retention period."
        ),
        recommendation=(
            "Record the classification of every data set the system holds, the "
            "jurisdictions it may reside in, the lawful retention period, and "
            "the disposal method. Route regulated data only through services "
            "approved for that classification."
        ),
        trigger=[r"\b(pii|phi|pci|cardholder|personal data|customer data|"
                 r"sensitive data|gdpr|health record|passport|emirates id)\b",
                 r"\b(payment\s+)?card\s+numbers?\b",
                 r"\bnational\s+(identity|id)\s+numbers?\b",
                 r"\b(customer|patient|employee)\s+(name|record|profile)s?\b",
                 r"\bdate\s+of\s+birth\b"],
        hard_trigger=[
            r"classification[^\n]{0,60}(has|have)\s+not\s+been",
            r"\bno\b[^\n]{0,40}(data\s+)?classification",
            r"classification[^\n]{0,40}(is\s+)?(not\b|unspecified|undefined|"
            r"missing|absent|unrecorded)",
            r"(residency|sovereignty)[^\n]{0,60}(have|has)\s+not\s+been",
            r"\b(indefinite\w*\s+retention|retention\s+is\s+indefinite)\b",
            r"(production|live)\s+(data|database)[^\n]{0,80}"
            r"(test|uat|non-?prod|development)",
            r"(live|real)\s+(card\s+numbers|customer\s+records|production\s+data)",
        ],
        suppressors=[r"classif(y|ied|ication)", r"residency", r"data\s+sovereignty",
                     r"retention\s+(period|schedule|policy)"],
        suppressor_guard=True,
        topics=("data_classification", "data_protection"),
        standard_reference="Data Classification Standard §2.1",
        kb_source="cloud_data/cloud-data-protection-standard.md",
        control_mappings=["ISO 27001 A.5.12", "NIST SP 800-53 RA-2",
                          "GDPR Art.5"],
    ),
    Rule(
        id="CLD-IAC-001",
        domain="cloud_data",
        severity="MEDIUM",
        issue="Infrastructure is provisioned manually or IaC has no policy scanning / drift detection.",
        recommendation=(
            "Provision exclusively through reviewed IaC in version control, "
            "scan templates against policy-as-code in the pipeline, and alert "
            "on drift between deployed state and the repository."
        ),
        trigger=[r"manual\w*\s+(provision|deploy|configur|creat)\w*[^\n]{0,40}"
                 r"(cloud|console|portal|resource)",
                 r"(via|through|using)\s+the\s+(aws\s+)?(console|portal)\s+"
                 r"(manually|by hand)",
                 r"\b(terraform|cloudformation|bicep|pulumi)\b"],
        suppressors=[r"(checkov|tfsec|terrascan|opa|conftest|policy[- ]as[- ]code|"
                     r"sentinel)", r"drift\s+detect"],
        topics=("iac_posture", "cloud_landing_zone"),
        standard_reference="Cloud Landing Zone Standard §6.2",
        kb_source="cloud_data/cloud-landing-zone-standard.md",
        control_mappings=["NIST SP 800-53 CM-3", "ISO 27001 A.8.9"],
    ),
]


ALL_RULES: List[Rule] = (
    NETWORK_RULES + APPLICATION_RULES + SECURITY_RULES + CLOUD_DATA_RULES
)

RULES_BY_DOMAIN: Dict[str, List[Rule]] = {}
for _r in ALL_RULES:
    RULES_BY_DOMAIN.setdefault(_r.domain, []).append(_r)


# ==========================================================================
# Execution
# ==========================================================================
def _first_match_excerpt(text: str, pattern: Pattern, window: int = 220) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, m.start() - window // 2)
    end = min(len(text), m.end() + window // 2)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _rule_applies(rule: Rule, section: Section, enabled_domains: Iterable[str]) -> bool:
    if rule.domain not in set(enabled_domains):
        return False
    if rule.topics and section.topic not in rule.topics:
        # Allow a secondary-topic match so cross-cutting sections still get
        # checked (e.g. an app section that also discusses segmentation).
        if not set(rule.topics) & set(section.secondary_topics):
            return False
    return True


def run_rules(sections: List[Section],
              enabled_domains: Optional[Sequence[str]] = None) -> List[Finding]:
    """Execute every applicable rule over the parsed sections.

    Returns findings in a stable order (rule id, then section index) so two
    runs over the same document produce identical output.
    """
    domains = list(enabled_domains) if enabled_domains else [
        "network", "application", "security", "cloud_data"
    ]
    findings: List[Finding] = []
    full_text = "\n\n".join(f"{s.heading}\n{s.body}" for s in sections)
    doc_scope_fired: set[str] = set()

    for rule in ALL_RULES:
        triggers = rule.compiled_trigger()
        hard_triggers = rule.compiled_hard_trigger()

        if rule.scope == "document":
            if rule.domain not in set(domains):
                continue
            if rule.id in doc_scope_fired:
                continue
            hard = next((t for t in hard_triggers if t.search(full_text)), None)
            hit = hard or next((t for t in triggers if t.search(full_text)), None)
            if not hit:
                continue
            if hard is None and rule.is_suppressed(full_text):
                continue
            doc_scope_fired.add(rule.id)
            findings.append(_build_finding(rule, "Whole document",
                                           _first_match_excerpt(full_text, hit)))
            continue

        for section in sections:
            if not _rule_applies(rule, section, domains):
                continue
            haystack = f"{section.heading}\n{section.body}"
            hard = next((t for t in hard_triggers if t.search(haystack)), None)
            hit = hard or next((t for t in triggers if t.search(haystack)), None)
            if not hit:
                continue
            # A hard trigger is direct evidence and is never suppressed.
            if hard is None and rule.is_suppressed(haystack):
                continue
            findings.append(
                _build_finding(rule, section.heading,
                               _first_match_excerpt(haystack, hit))
            )

    findings.sort(key=lambda f: (f.rule_id, f.section.lower()))
    return findings


def _build_finding(rule: Rule, section_name: str, excerpt: str) -> Finding:
    return Finding(
        section=section_name,
        domain=rule.domain,
        severity=rule.severity,
        issue=rule.issue,
        recommendation=rule.recommendation,
        standard_reference=rule.standard_reference,
        kb_source=rule.kb_source,
        evidence_excerpt=excerpt,
        control_mappings=list(rule.control_mappings),
        origin=ORIGIN_RULES,
        rule_id=rule.id,
        confidence=1.0,
    )


def rules_summary() -> Dict[str, int]:
    """Rule counts per domain - displayed in the UI sidebar."""
    return {d: len(rs) for d, rs in sorted(RULES_BY_DOMAIN.items())}
