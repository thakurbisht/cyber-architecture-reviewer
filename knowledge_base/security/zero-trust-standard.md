# Zero Trust Architecture Standard

Owner: Security Architecture
Applies to: all designs introducing or modifying access paths
Alignment: NIST SP 800-207

## 1.1 Purpose

This standard translates NIST SP 800-207 into requirements a design reviewer can test against a document. It is not a product standard — no product makes an architecture Zero Trust. It is a set of properties the design must exhibit.

## 1.2 The seven tenets, stated as review questions

1. Is every resource treated as a resource requiring authorisation, including internal ones?
2. Is every session secured regardless of network location?
3. Is access granted per session, not permanently?
4. Is the access decision based on policy including identity, device state, and behavioural attributes?
5. Is the integrity and security posture of assets monitored?
6. Is authentication and authorisation dynamic and strictly enforced before access?
7. Is telemetry collected and used to improve policy?

FINDING TRIGGER: If a design cannot answer questions 1, 2 and 3 affirmatively, flag as HIGH and name which tenet fails.

## 1.4 Threat modelling requirement

Requirement: Every design MUST be accompanied by a threat model covering each trust boundary, with mitigations traced to specific controls and residual risk owned by a named individual.

FINDING TRIGGER: If no threat model, STRIDE analysis, abuse case set or attack surface analysis accompanies the design, flag as MEDIUM.

## 2.1 No implicit trust from network location

Requirement: Network location MUST NOT confer trust. Being on the corporate LAN, behind the perimeter firewall, or inside a VPC grants no access rights by itself.

FINDING TRIGGER: If the design states or implies that internal traffic is trusted, that a service needs no authentication because it is internal, or that being behind the firewall is sufficient protection, flag as HIGH. Quote the phrase.

Compliant pattern: "Every call to the payments service presents a workload identity token that the service validates, whether the caller is in the same cluster or across the WAN."
Non-compliant pattern: "The internal API does not require authentication because it is only accessible from the corporate network."

## 2.2 Policy enforcement points

Requirement: Every protected resource MUST sit behind a policy enforcement point that consults a policy decision point per request or per session. The design MUST name both.

FINDING TRIGGER: If a protected resource has no identified enforcement point, flag as HIGH.
FINDING TRIGGER: If the enforcement point can be bypassed by reaching the resource directly on the network, flag as CRITICAL — an enforcement point that is optional is not one.

## 2.3 Per-session authorisation

Requirement: Authorisation MUST be evaluated per session and MUST expire. Standing access to a resource without re-evaluation is prohibited for anything classified Internal or above.

FINDING TRIGGER: If access, once granted, persists without re-evaluation, flag as MEDIUM.
FINDING TRIGGER: If a VPN grants broad network access after a single authentication, flag as HIGH — this is the classic implicit-trust-zone pattern SP 800-207 exists to replace.

## 3.1 Device posture

Requirement: Access to resources classified Confidential or above MUST consider device posture — managed status, patch level, disk encryption, EDR presence — in the access decision.

FINDING TRIGGER: If unmanaged devices can reach Confidential resources with only user credentials, flag as HIGH.

## 3.2 Continuous evaluation

Requirement: Sessions MUST be re-evaluated on material context change — device posture loss, impossible travel, risk score change — and terminated where policy requires.

FINDING TRIGGER: If no continuous or periodic re-evaluation is described for privileged sessions, flag as MEDIUM.

## 4.1 Micro-segmentation of workloads

Requirement: Workload-to-workload communication MUST be authorised by identity, not by IP address alone, wherever the platform supports it (service mesh, workload identity, security groups referencing identities).

FINDING TRIGGER: If workload authorisation is based solely on source IP or subnet, flag as MEDIUM. Raise to HIGH where the workloads process regulated data.

## 4.2 Encryption everywhere

Requirement: All sessions MUST be encrypted in transit including internal service-to-service traffic. "The traffic stays inside our network" is not an exception.

FINDING TRIGGER: If any internal session is unencrypted, flag as HIGH.

## 5.1 Assume breach

Requirement: The design MUST state what an attacker who compromises each major component can reach, and what limits them.

FINDING TRIGGER: If the design contains no blast radius analysis for its highest-value component, flag as MEDIUM.
FINDING TRIGGER: If compromise of any single component yields access to the whole environment, flag as CRITICAL.

## 5.2 Administrative paths

Requirement: Administrative access paths MUST be more strongly controlled than user paths — phishing-resistant MFA, dedicated privileged access workstations or brokered sessions, and full session recording.

FINDING TRIGGER: If administrative access uses the same path and controls as ordinary user access, flag as HIGH.

## 6.1 Telemetry into policy

Requirement: Access decisions and denials MUST be logged and fed to the SOC, and the design MUST state how policy is tuned from that telemetry.

FINDING TRIGGER: If access denials are not logged, flag as MEDIUM — you cannot detect an access-control attack you do not record.

Control mapping: NIST SP 800-207 §2.1, §3; NIST SP 800-53 AC-2, AC-3, AC-6, IA-2, SC-8; ISO/IEC 27001:2022 A.5.15, A.8.2, A.8.3, A.8.20; MITRE ATT&CK TA0008.
