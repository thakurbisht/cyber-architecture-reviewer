"""Expert rules - the patterns a senior reviewer scans for first.

The original 39 rules mostly look for a named bad technology (SNMP v2c,
Telnet, WEP). Experienced reviewers read designs differently. The questions
that find most real defects are:

  1. Where did the author RELAX a control, and what reason did they give?
     ("authentication is disabled because the partner cannot present a
     token", "publicly accessible so that the SaaS tool can connect").
     A justified exception is still an exception - it is where most real
     defects live, and it is phrased the same way in every organisation.
  2. Who can do what to whose data?  (authorisation and blast radius:
     "every signed-in user can…", "assigned to All Staff", sequential IDs)
  3. What is reachable from where?  (any-source inbound, remote admin
     ports, public control planes, unrestricted egress)
  4. What lives forever?  (tokens not revoked, 20-year certificates, CA
     keys on a workstation, secrets available to every pipeline job)
  5. What runs code the author does not control?  (CI on fork PRs, mutable
     image tags, --extra-index-url, unsigned firmware over HTTP)

Each rule below encodes one of those questions as a text pattern, bounded
to a sentence ([^.\\n]) so evidence and suppressors stay local. Every rule
has positive and negative tests in tests/test_rules_expert.py, written in
wording different from the golden set.
"""

from __future__ import annotations

from typing import List

from .rules import Rule

S = r"[^.\n]"          # stay inside one sentence

EXPERT_RULES: List[Rule] = [
    # ------------------------------------------------------------------
    # 1. Justified exceptions
    # ------------------------------------------------------------------
    Rule(
        id="SEC-EXC-001",
        domain="security",
        severity="HIGH",
        issue=("A security control is relaxed with a business or technical justification "
               "(\"disabled because…\", \"public so that…\") - an exception that needs a "
               "compensating control and a recorded risk acceptance."),
        recommendation=(
            "Treat the justification as a requirement to solve, not a waiver: design a "
            "compensating control (signature verification, allow-listed source, private "
            "connectivity, broker), and if the exception stays, record it as a risk "
            "acceptance with an owner and expiry."),
        trigger=[],
        hard_trigger=[
            r"(authentication|auth|mfa|encryption|tls|verification|validation|logging|"
            r"signing|access control|authori[sz]ation)" + S + r"{0,40}"
            r"(disabled|turned off|not (enforced|required|enabled|configured|applied)|"
            r"bypass\w*|skipped|exempt\w*)" + S + r"{0,80}\b(because|so that|so as to|"
            r"in order to|to keep|to avoid|to allow|for convenience)\b",
            r"(publicly accessible|public(ly)? (exposed|reachable)|0\.0\.0\.0/0|from any "
            r"(source|address|ip)|any source address|open to the internet)" + S + r"{0,80}"
            r"\b(because|so that|so as to|in order to|to allow|for convenience)\b",
            r"(left enabled|kept enabled|remains? enabled|full access|administrator ?access|"
            r"all (staff|employees|users) (group|can))" + S + r"{0,80}"
            r"\b(because|so that|so as to|in order to|to allow|for convenience)\b",
        ],
        standard_reference="Secure Design Standard - exceptions and risk acceptance",
        kb_source="security/zero-trust-standard.md",
        control_mappings=["ISO 27001 A.5.36", "NIST SP 800-53 CA-7", "NIST CSF GV.RM"],
    ),

    # ------------------------------------------------------------------
    # 2. Who can do what to whose data
    # ------------------------------------------------------------------
    Rule(
        id="APP-AUTHZ-002",
        domain="application",
        severity="HIGH",
        issue=("Object identifiers are sequential or guessable and appear in requests - "
               "insecure direct object reference (BOLA) risk unless every access checks ownership."),
        recommendation=(
            "Check ownership of the requested object server-side on every request, return "
            "404 for objects the caller does not own, and prefer opaque random identifiers "
            "(UUIDv4) in external interfaces."),
        trigger=[r"(sequential|incrementing|auto-?increment\w*|bigserial|serial number"
                 r"s?|consecutive)" + S + r"{0,60}\b(ids?|identifiers?|integers?|numbers?)\b",
                 r"\b(ids?|identifiers?|numbers?)\b" + S + r"{0,40}(are|is) (sequential|incrementing|"
                 r"guessable|predictable)"],
        suppressors=[r"(uuid|random|opaque|unguessable)" + S + r"{0,30}(ids?|identifiers?)",
                     r"(check|verif)\w*" + S + r"{0,40}(owner|belongs to|matches the caller)"],
        soft_kind="question",
        hard_trigger=[r"(any|another|other) (user|customer|rider|caller)'?s?" + S + r"{0,60}"
                      r"(ride|order|record|account|trail|invoice|document)",
                      r"(returns?|serves?) the (full )?\w+ (of|for) the (given|requested|"
                      r"supplied) (id|\w+ id)"],
        standard_reference="Application Security Architecture Standard - object-level authorisation",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP API1:2023 BOLA", "OWASP ASVS V4.2", "NIST SP 800-53 AC-3"],
    ),
    Rule(
        id="SEC-IAM-004",
        domain="security",
        severity="HIGH",
        issue=("Access is granted to a whole population (\"all staff\", \"every signed-in user\", "
               "\"all dashboard users\") instead of by role - least privilege is not applied."),
        recommendation=(
            "Grant access by role and need: define roles, restrict high-impact actions "
            "(refunds, exports, remote commands, admin) to named roles, and review "
            "assignments periodically."),
        trigger=[],
        hard_trigger=[
            r"(assigned|granted|available|open) to (the )?(all[- ]staff|all employees|"
            r"everyone|all users|every user)",
            r"\b(every|all|any) (signed[- ]in |authenticated |dashboard |logged[- ]in )?"
            r"(users?|staff|employees?|engineers?|agents?|contractors?)\b" + S + r"{0,40}"
            r"\b(can|may|are able to|have)\b" + S + r"{0,60}(refund|export|delete|lock|unlock|"
            r"immobil|approve|change|modify|write|admin|view|replay|access)",
            r"single (permission|access|privilege) level",
        ],
        standard_reference="Identity & Privileged Access Standard §4.1",
        kb_source="security/identity-access-standard.md",
        control_mappings=["NIST SP 800-53 AC-6", "ISO 27001 A.5.15", "CIS Control 6"],
    ),

    # ------------------------------------------------------------------
    # 3. What is reachable from where
    # ------------------------------------------------------------------
    Rule(
        id="NET-EXPO-001",
        domain="network",
        severity="CRITICAL",
        issue=("A remote administration service (RDP, VNC, SSH, Telnet) is exposed to any "
               "source or the internet."),
        recommendation=(
            "Remove the public exposure. Provide vendor and admin access through a "
            "PAM-brokered jump host or ZTNA with MFA, time-bound approval and session "
            "recording."),
        trigger=[],
        hard_trigger=[
            r"(vnc|rdp|remote desktop|ssh|telnet|\b(5900|3389|22|23)\b)" + S + r"{0,100}"
            r"(any source|any address|0\.0\.0\.0/0|the internet|public ip|internet[- ]facing)",
            r"(any source|0\.0\.0\.0/0|the internet|public ip)" + S + r"{0,100}"
            r"(vnc|rdp|remote desktop|\bssh\b|telnet|\b(5900|3389)\b)",
            r"port[- ]?forward\w*" + S + r"{0,80}(from any|any source)",
        ],
        standard_reference="Secure Management Plane Standard §2.4",
        kb_source="network/network-management-standard.md",
        control_mappings=["CIS Control 12", "NIST SP 800-53 AC-17", "MITRE ATT&CK T1133"],
    ),
    Rule(
        id="NET-SEG-003",
        domain="network",
        severity="HIGH",
        issue=("All traffic is permitted between zones or segments that hold differently "
               "trusted systems (flat trust inside a zone)."),
        recommendation=(
            "Replace permit-all intra-zone policy with explicit allow rules per flow, and "
            "separate high-value systems (payments, OT controllers, management) into their "
            "own zones."),
        trigger=[],
        hard_trigger=[r"(permits?|allows?) all (traffic|communication|flows?)" + S + r"{0,60}"
                      r"\b(between|within|among|inside)\b",
                      r"(any|all)[- ]to[- ](any|all)" + S + r"{0,40}(within|between|inside)"],
        standard_reference="Network Segmentation Standard §2.1",
        kb_source="network/segmentation-standard.md",
        control_mappings=["NIST SP 800-53 SC-7", "CIS Control 12", "PCI DSS 1.3"],
    ),
    Rule(
        id="CLD-K8S-001",
        domain="cloud_data",
        severity="HIGH",
        issue="The Kubernetes / cloud control-plane API endpoint is publicly reachable.",
        recommendation=(
            "Make the control-plane endpoint private, or restrict it to a small allow-list; "
            "run deployments from runners inside the network (self-hosted or private "
            "connectivity) rather than opening the API to changing public IPs."),
        trigger=[],
        hard_trigger=[r"(eks|aks|gke|kubernetes|k8s|cluster) (api|control[- ]plane)"
                      r"( server)?( endpoint)?" + S + r"{0,40}(is |are )?(public|0\.0\.0\.0/0|"
                      r"internet)"],
        suppressors=[r"(api|endpoint)" + S + r"{0,30}(is |are )?private"],
        standard_reference="Cloud Landing Zone Standard - control plane exposure",
        kb_source="cloud_data/cloud-landing-zone-standard.md",
        control_mappings=["CIS EKS 5.4.2", "NIST SP 800-53 SC-7"],
    ),
    Rule(
        id="NET-EGR-001",
        domain="network",
        severity="MEDIUM",
        issue="Outbound internet access is unrestricted, leaving an easy exfiltration and C2 path.",
        recommendation=(
            "Route egress through a proxy or firewall with an allow-list of destinations, "
            "and log denied egress."),
        trigger=[],
        hard_trigger=[r"(outbound|egress)" + S + r"{0,80}(is |are )?(unrestricted|open|"
                      r"not restricted|allowed to any|permitted to any)",
                      r"(direct|unrestricted) (internet )?(breakout|egress)" + S + r"{0,60}"
                      r"(without|no) (proxy|filtering|inspection)"],
        standard_reference="Network Segmentation Standard - egress",
        kb_source="network/segmentation-standard.md",
        control_mappings=["NIST SP 800-53 SC-7(5)", "MITRE ATT&CK TA0010"],
    ),

    # ------------------------------------------------------------------
    # 4. What lives forever
    # ------------------------------------------------------------------
    Rule(
        id="APP-SESS-001",
        domain="application",
        severity="HIGH",
        issue=("Sessions or tokens stay valid after sign-out, password change or account "
               "disablement - stolen tokens cannot be revoked."),
        recommendation=(
            "Revoke tokens server-side on sign-out, password change and disablement "
            "(introspection with a revocation list, or short-lived tokens with refresh "
            "rotation)."),
        trigger=[],
        hard_trigger=[r"(token|session)" + S + r"{0,80}(remains?|stays?|still) valid" + S +
                      r"{0,80}(?:(sign|log)\w*[- ]?(out|off)|password change|disabl)",
                      r"(token|session)s? (is |are )?not (revoked|invalidated)",
                      r"(sign|log)[- ]?(out|off)" + S + r"{0,60}(only )?(deletes|clears|removes)"
                      r" the (token|cookie)" + S + r"{0,40}(app|client|browser|device)"],
        standard_reference="Application Security Architecture Standard - session management",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V3.3", "NIST SP 800-63B 7.1"],
    ),
    Rule(
        id="SEC-PKI-001",
        domain="security",
        severity="CRITICAL",
        issue=("A CA or code/firmware signing private key is held as a file, on a workstation "
               "or in a CI variable instead of an HSM or managed signing service."),
        recommendation=(
            "Move CA and signing keys to an HSM or managed KMS/signing service, sign only "
            "from protected release pipelines, and restrict who and what can request "
            "signatures."),
        trigger=[],
        hard_trigger=[r"(ca|issuing|signing|code[- ]signing|firmware signing) (private )?key"
                      + S + r"{0,100}(file|workstation|laptop|pkcs#?12|\.pfx|\.p12|ci/?cd "
                      r"variable|pipeline variable|environment variable|masked variable)"],
        suppressors=[r"\bhsm\b", r"(kms|key vault|cloudhsm)" + S + r"{0,30}(sign|non-exportable)"],
        suppressor_guard=True,
        standard_reference="Cryptography & Key Management Standard",
        kb_source="security/cryptography-key-management-standard.md",
        control_mappings=["NIST SP 800-57", "NIST SP 800-53 SC-12", "ISO 27001 A.8.24"],
    ),
    Rule(
        id="SEC-PKI-002",
        domain="security",
        severity="MEDIUM",
        issue="Certificates or credentials have very long validity (10+ years) with no rotation.",
        recommendation=(
            "Use short-lived certificates with automated renewal, and support revocation "
            "(CRL/OCSP or an allow-list the broker checks)."),
        trigger=[],
        hard_trigger=[r"(certificate|cert|credential|key)s?" + S + r"{0,60}valid (for )?"
                      r"(1\d|[2-9]\d) years"],
        standard_reference="Cryptography & Key Management Standard - lifetimes",
        kb_source="security/cryptography-key-management-standard.md",
        control_mappings=["NIST SP 800-57 5.3", "CA/B Forum baseline"],
    ),

    # ------------------------------------------------------------------
    # 5. Code the author does not control
    # ------------------------------------------------------------------
    Rule(
        id="APP-CICD-001",
        domain="application",
        severity="HIGH",
        issue=("CI runs untrusted code (pull requests from forks) on shared or long-lived "
               "runners, or signing secrets are exposed to every pipeline job."),
        recommendation=(
            "Run fork PRs on ephemeral isolated runners with no secrets; scope secrets and "
            "signing to protected branches and release jobs only; use one-job ephemeral "
            "runners."),
        trigger=[],
        hard_trigger=[r"(pull|merge) requests? from forks" + S + r"{0,80}(automatically|"
                      r"without (approval|review)|on (the )?(shared|same|self-hosted|long[- ]lived)"
                      r" runners)",
                      r"automatically (on|for) (pull|merge) requests? from forks",
                      r"(secret|key|token|variable)" + S + r"{0,80}available to all (pipeline )?"
                      r"(jobs|branches|pipelines)",
                      r"(including|incl\.?) jobs? (run )?for (merge|pull) requests",
                      r"runners? (are|is) (long[- ]lived|persistent|shared)" + S + r"{0,80}"
                      r"(public|fork|all repositories)"],
        standard_reference="Secure SDLC Standard - pipeline isolation",
        kb_source="application/secure-sdlc-standard.md",
        control_mappings=["SLSA Build L3", "NIST SSDF PS.1", "MITRE ATT&CK T1195.002"],
    ),
    Rule(
        id="APP-CICD-002",
        domain="application",
        severity="HIGH",
        issue=("Dependencies can resolve from a public index as well as the internal one "
               "(dependency confusion)."),
        recommendation=(
            "Use a single internal index that proxies public packages, reserve internal "
            "names on the public index, and pin with hashes."),
        trigger=[],
        hard_trigger=[r"--?extra-index-url",
                      r"resolve from both (the )?public" + S + r"{0,40}(and|&) (the )?internal"],
        standard_reference="Secure SDLC Standard - dependency sources",
        kb_source="application/secure-sdlc-standard.md",
        control_mappings=["NIST SSDF PW.4", "MITRE ATT&CK T1195.001"],
    ),
    Rule(
        id="APP-CICD-003",
        domain="application",
        severity="MEDIUM",
        issue="Deployments reference mutable image tags, so the running artefact can change silently.",
        recommendation="Deploy by immutable digest and enable tag immutability in the registry.",
        trigger=[],
        hard_trigger=[r"mutable (image )?tags?", r":latest\b",
                      r"(reference|deploy)\w*" + S + r"{0,40}(image|images) by (its |their )?"
                      r"(version )?tag"],
        suppressors=[r"(pinned|deploy\w*|referenced) by digest", r"tag immutability"],
        suppressor_guard=True,
        standard_reference="Secure SDLC Standard - artefact integrity",
        kb_source="application/secure-sdlc-standard.md",
        control_mappings=["SLSA", "NIST SSDF PS.2"],
    ),
    Rule(
        id="OT-FW-001",
        domain="security",
        severity="HIGH",
        issue="Firmware or software updates are delivered over plain HTTP or without signature verification.",
        recommendation=(
            "Deliver updates over TLS and verify a signature on the device before install; "
            "include anti-rollback."),
        trigger=[],
        hard_trigger=[r"(firmware|image|update|package|manifest)s?" + S + r"{0,80}"
                      r"(over|via) (plain )?http\b",
                      r"(firmware|update|image)s?" + S + r"{0,40}(unsigned|not signed|without "
                      r"(a )?signature)"],
        standard_reference="Secure Design Standard - update integrity",
        kb_source="security/vulnerability-resilience-standard.md",
        control_mappings=["NIST SP 800-193", "ETSI EN 303 645 5.3"],
    ),
    Rule(
        id="OT-DBG-001",
        domain="security",
        severity="HIGH",
        issue="A hardware debug interface or root console is left enabled on production devices.",
        recommendation=(
            "Disable or lock (authenticated) UART/JTAG/debug consoles on production builds; "
            "provide technicians a signed, audited diagnostic mode instead."),
        trigger=[],
        hard_trigger=[r"(uart|jtag|swd|debug (console|port|interface|shell))" + S + r"{0,80}"
                      r"(enabled|left on|kept|root shell|available)",
                      r"root shell" + S + r"{0,60}(production|field|devices?)"],
        suppressors=[r"(uart|jtag|debug)" + S + r"{0,40}(disabled|fused|locked|removed)"],
        suppressor_guard=True,
        standard_reference="Secure Design Standard - device hardening",
        kb_source="security/vulnerability-resilience-standard.md",
        control_mappings=["ETSI EN 303 645 5.6", "NIST IR 8259A"],
    ),

    # ------------------------------------------------------------------
    # Common application gaps the original set did not cover
    # ------------------------------------------------------------------
    Rule(
        id="APP-UPLOAD-001",
        domain="application",
        severity="HIGH",
        issue="File uploads accept any type without content validation or malware scanning.",
        recommendation=(
            "Allow-list file types, verify file signatures, scan in a quarantine store before "
            "use, and serve uploads from a separate domain as downloads."),
        trigger=[],
        hard_trigger=[r"upload\w*" + S + r"{0,80}(any|all) (common )?(file )?(types?|formats?)",
                      r"upload\w*" + S + r"{0,60}(without|no) (type|content|file) (validation|"
                      r"checks?)"],
        suppressors=[r"(allow|white)[- ]?list", r"(malware|antivirus|defender)" + S +
                     r"{0,30}scan", r"file signature", r"quarantine"],
        standard_reference="Application Security Architecture Standard - file handling",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP ASVS V12", "NIST SP 800-53 SI-3"],
    ),
    Rule(
        id="APP-SSRF-001",
        domain="application",
        severity="HIGH",
        issue="The service fetches a URL supplied by the user or caller (server-side request forgery).",
        recommendation=(
            "Allow-list destinations, resolve and block internal/metadata addresses, and "
            "fetch through an egress proxy."),
        trigger=[],
        hard_trigger=[r"(fetch|retriev|download|call|request)\w*" + S + r"{0,60}(user|customer|"
                      r"caller|client)[- ](supplied|provided|specified) (url|uri|address|link)",
                      r"(webhook|callback) url" + S + r"{0,40}(supplied|provided|registered) by "
                      r"(the )?(user|customer|tenant)"],
        suppressors=[r"allow[- ]?list" + S + r"{0,40}(destination|domain|host)"],
        standard_reference="Application Security Architecture Standard - outbound requests",
        kb_source="application/application-security-standard.md",
        control_mappings=["OWASP A10:2021 SSRF", "OWASP API7:2023"],
    ),
    Rule(
        id="APP-PWD-001",
        domain="application",
        severity="MEDIUM",
        issue="The password policy allows short passwords (under 8 characters).",
        recommendation=(
            "Require at least 8 (preferably 12+) characters, check against breached-password "
            "lists, and offer MFA or passkeys."),
        trigger=[],
        hard_trigger=[r"password" + S + r"{0,60}(at least|minimum( of)?|min\.?) (four|five|six|"
                      r"seven|[4-7]) char"],
        standard_reference="Identity & Privileged Access Standard - authenticators",
        kb_source="security/identity-access-standard.md",
        control_mappings=["NIST SP 800-63B 5.1.1", "OWASP ASVS V2.1"],
    ),
]
