# Cloud Landing Zone Standard

Owner: Cloud Architecture / Security Architecture
Applies to: all designs deploying into public cloud
Alignment: CIS Foundations Benchmarks, NIST SP 800-53

## 1.1 Principle

Cloud security failures are overwhelmingly configuration failures at the control plane, not exploitation of the platform. The landing zone exists so that the secure configuration is the default and the insecure one requires deliberate effort and approval.

## 2.1 Organisational structure

Requirement: Accounts and subscriptions MUST be arranged under organisational units with preventative guardrails (SCPs, Azure Policy, Organisation Policy) applied at the OU level, not per account.

FINDING TRIGGER: If workloads are deployed outside the organisation structure or into a standalone account, flag as HIGH.
FINDING TRIGGER: If guardrails are described as detective only with no preventative controls, flag as MEDIUM.

## 2.2 Environment separation

Requirement: Production and non-production MUST occupy separate accounts or subscriptions. A shared account for all environments is prohibited.

FINDING TRIGGER: If production and non-production share an account, subscription or project, flag as HIGH — a compromise of a developer's test workload reaches the production control plane.
FINDING TRIGGER: If separation is by resource group, namespace or tag only, flag as HIGH; those are organisational constructs, not security boundaries.

Compliant pattern: "prod-payments (account 1234), nonprod-payments (account 5678), separate OUs, no cross-account trust except the read-only audit role."
Non-compliant pattern: "All payment environments live in one subscription, separated by resource group naming convention."

## 2.3 Blast radius

Requirement: The design MUST state what a compromise of each account can reach, and MUST NOT create cross-account roles that grant broad access.

FINDING TRIGGER: If a cross-account role grants administrative permissions, flag as CRITICAL.
FINDING TRIGGER: If no blast radius statement exists for a multi-account design, flag as MEDIUM.

## 3.1 Management account hygiene

Requirement: The management/root account MUST run no workloads, have MFA on the root credential, no access keys on the root user, and be monitored for any use.

FINDING TRIGGER: If workloads are described in the management account, flag as HIGH.
FINDING TRIGGER: If root account use is not alerted, flag as HIGH.

## 4.1 Workload permissions

Requirement: Workload identities MUST hold least-privilege policies scoped to specific actions and resource identifiers. Wildcard actions, wildcard resources, and built-in administrator roles MUST NOT be attached to workloads.

FINDING TRIGGER: If a policy grants "Action": "*", or an administrator/owner role is assigned to a workload or service principal, flag as CRITICAL.
FINDING TRIGGER: If permissions are not scoped to specific resources, flag as HIGH.
FINDING TRIGGER: If long-lived access keys are used instead of instance/workload roles, flag as HIGH.

## 4.2 Human access to cloud

Requirement: Human access MUST be federated from the enterprise IdP with MFA, granted just-in-time, and MUST NOT use IAM users with static credentials.

FINDING TRIGGER: If static IAM users are created for humans, flag as HIGH.
FINDING TRIGGER: If cloud console access lacks MFA, flag as CRITICAL.

## 4.3 Permission boundaries

Requirement: Delegated administrators MUST operate within permission boundaries preventing privilege escalation, including the ability to modify their own permissions or the guardrails.

FINDING TRIGGER: If a role can modify the policies that constrain it, flag as CRITICAL.

## 5.1 Network topology

Requirement: Cloud networks MUST follow the hub-and-spoke or transit pattern with centralised inspection of north-south and inter-spoke traffic. Spoke-to-spoke traffic MUST NOT bypass inspection.

FINDING TRIGGER: If spoke VPCs/VNets peer directly without inspection, flag as HIGH.
FINDING TRIGGER: If no egress inspection or filtering exists, flag as HIGH.

## 5.2 Private connectivity

Requirement: Access to platform data services (object storage, databases, key vaults) MUST use private endpoints. Public service endpoints MUST be disabled where the platform allows.

FINDING TRIGGER: If data services are reached over public endpoints, flag as HIGH.
FINDING TRIGGER: If a data service allows access from all networks, flag as CRITICAL.

## 5.3 Ingress exposure

Requirement: Administrative ports (22, 3389) and data ports (3306, 5432, 1433, 6379, 27017, 9200) MUST NOT be reachable from 0.0.0.0/0. Instance access MUST be via a session broker or bastion in a management subnet.

FINDING TRIGGER: If a security group or NSG permits 0.0.0.0/0 on any administrative or data port, flag as HIGH. Raise to CRITICAL if the target holds regulated data.
FINDING TRIGGER: If a database is placed in a public subnet, flag as HIGH.

## 5.4 Perimeter protections

Requirement: Internet-facing applications MUST sit behind a WAF with managed rule sets and DDoS protection enabled.

FINDING TRIGGER: If an internet-facing application has no WAF, flag as MEDIUM. Raise to HIGH if it handles authentication or payment.

## 6.1 Infrastructure as code

Requirement: All cloud resources MUST be provisioned by version-controlled, peer-reviewed IaC. Manual console changes are permitted only in a declared emergency and MUST be reconciled within five working days.

FINDING TRIGGER: If resources are provisioned manually through the console as the normal path, flag as MEDIUM.
FINDING TRIGGER: If IaC state files are stored without encryption, versioning and access control, flag as HIGH — the state file frequently contains secrets and describes the whole estate.

## 6.2 Policy as code and drift

Requirement: IaC MUST be scanned against policy-as-code in the pipeline before apply, and deployed state MUST be checked for drift from the repository.

FINDING TRIGGER: If IaC is used with no policy scanning, flag as MEDIUM.
FINDING TRIGGER: If drift detection is absent, flag as LOW.

## 7.1 Cloud security posture management

Requirement: A CSPM capability MUST monitor every account continuously against the benchmark, with findings routed to the owning team and a remediation SLA.

FINDING TRIGGER: If no posture monitoring is described, flag as MEDIUM.

## 7.2 Tagging and ownership

Requirement: Every resource MUST carry owner, environment, data classification and cost centre tags, enforced by policy.

FINDING TRIGGER: If a tagging standard is not applied, flag as LOW.
FINDING TRIGGER: If data classification is not recorded as a tag on data-bearing resources, flag as MEDIUM.

Control mapping: CIS AWS Foundations 1.1, 1.16, 2.1, 5.2; NIST SP 800-53 AC-6, CM-2, CM-3, SC-2, SC-7; ISO/IEC 27001:2022 A.5.23, A.8.9, A.8.31; MITRE ATT&CK T1098, T1133, T1530.
