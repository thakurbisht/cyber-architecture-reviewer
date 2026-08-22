# Identity and Privileged Access Standard

Owner: Security Architecture / IAM
Applies to: every design that creates, consumes or grants an identity

## 1.1 Principle

Identity is the primary control plane. Most successful intrusions do not defeat a control — they authenticate. A design is assessed on whether every action can be traced to a named principal and whether the standing privilege available to a compromised principal is bounded.

## 2.1 Multi-factor authentication

Requirement: MFA is mandatory for all interactive access to enterprise systems. Administrative and privileged access MUST use phishing-resistant factors — FIDO2 security keys, platform passkeys, or certificate-based authentication. SMS and voice OTP are not acceptable for privileged access.

FINDING TRIGGER: If administrative or privileged access is described without MFA, flag as CRITICAL.
FINDING TRIGGER: If privileged MFA relies on SMS, voice, or push-approval without number matching, flag as HIGH.
FINDING TRIGGER: If service accounts are exempted from MFA without a compensating control such as workload identity or IP restriction, flag as MEDIUM.

## 2.2 Single sign-on

Requirement: Applications MUST federate to the enterprise identity provider. Local credential stores are prohibited for workforce access.

FINDING TRIGGER: If an application maintains its own workforce credential store, flag as HIGH.

## 3.1 Named accountability

Requirement: Every human action MUST be attributable to a named individual. Shared and generic accounts are prohibited for human use.

FINDING TRIGGER: If shared, generic, or team accounts are described for human use, flag as HIGH.
FINDING TRIGGER: If administrators log in with a shared root, admin, or enable credential, flag as CRITICAL.

## 3.2 Service and workload identity

Requirement: Non-human identities MUST be workload identities (managed identity, IRSA, SPIFFE, or equivalent) with no interactive logon rights, no password where the platform supports it, and a named human owner.

FINDING TRIGGER: If a service account has interactive logon rights, flag as HIGH.
FINDING TRIGGER: If a service account has no named owner, flag as MEDIUM — it will never be reviewed or decommissioned.
FINDING TRIGGER: If a service account password never expires and is not vaulted, flag as HIGH.

## 4.1 Least privilege

Requirement: Every principal MUST hold only the permissions required for its function. Wildcard permissions and broad built-in administrator roles MUST NOT be assigned to workloads.

FINDING TRIGGER: If a workload or service principal is granted an administrator, owner, or wildcard-action role, flag as CRITICAL.
FINDING TRIGGER: If permissions are described as "full access for simplicity", flag as HIGH.

## 4.2 Privilege elevation

Requirement: Privileged roles MUST be granted just-in-time with a time limit, an approval, and a stated reason. Standing privileged access is permitted only for break-glass accounts.

FINDING TRIGGER: If privileged roles are permanently assigned, flag as HIGH.
FINDING TRIGGER: If there is no time bound on elevated access, flag as MEDIUM.

## 4.3 Privileged access workstations and brokering

Requirement: Administrative sessions MUST be brokered through a privileged access management solution with session recording, or originate from a dedicated privileged access workstation.

FINDING TRIGGER: If administrators connect to production from general-purpose workstations, flag as HIGH.
FINDING TRIGGER: If privileged sessions are not recorded, flag as MEDIUM.

## 4.4 Separation of duties

Requirement: The design MUST separate the ability to make a change from the ability to approve it, and separate security log administration from system administration.

FINDING TRIGGER: If one role can both change a system and alter or delete its audit log, flag as CRITICAL — this defeats every detective control that depends on that log.

## 5.1 Joiner, mover, leaver

Requirement: Access MUST be provisioned from an authoritative HR source and revoked automatically on termination. Role changes MUST remove access no longer required, not only add new access.

FINDING TRIGGER: If deprovisioning is described as a manual process, flag as MEDIUM.
FINDING TRIGGER: If accumulated access from role changes is not removed, flag as MEDIUM (privilege creep).

## 5.2 Access review

Requirement: Entitlements MUST be recertified at least every six months, and privileged entitlements every three months, by the resource owner rather than the line manager alone.

FINDING TRIGGER: If no access recertification is described for a system granting privileged access, flag as MEDIUM.

## 6.1 Break-glass

Requirement: Break-glass accounts MUST exist, be excluded from conditional access dependencies that could lock the organisation out, have vaulted credentials split under dual control, and generate a high-priority alert on use.

FINDING TRIGGER: If no break-glass path exists, flag as MEDIUM.
FINDING TRIGGER: If break-glass use does not raise an alert, flag as HIGH.

## 6.2 Directory dependencies

Requirement: The design MUST state what happens to access when the identity provider is unavailable, and MUST NOT create a circular dependency in which recovering the IdP requires authenticating to the IdP.

FINDING TRIGGER: If recovery of a system depends on the very identity system that may be compromised or unavailable, flag as HIGH.

## 7.1 Federation with third parties

Requirement: Partner and supplier identities MUST be federated rather than provisioned as internal accounts, MUST be scoped to specific resources, and MUST have an expiry date.

FINDING TRIGGER: If third-party staff receive internal directory accounts without expiry, flag as HIGH.

Control mapping: NIST SP 800-53 AC-2, AC-5, AC-6, IA-2(1), IA-4, IA-5; ISO/IEC 27001:2022 A.5.15, A.5.16, A.5.17, A.5.18, A.8.2, A.8.5; MITRE ATT&CK T1078, T1098, T1556.
