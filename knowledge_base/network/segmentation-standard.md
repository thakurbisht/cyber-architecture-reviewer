# Network Segmentation Standard

Owner: Security Architecture
Applies to: campus, data centre, cloud and hybrid network designs

## 1.1 Principle

Segmentation exists to limit blast radius. Its purpose is not to stop the initial compromise — it is to ensure that a compromise of one workload does not become a compromise of the estate. A design is assessed on what an attacker who already holds one host can reach, not on what a well-behaved user can reach.

## 2.1 Zone model

Requirement: Every design MUST place each workload in a named security zone, and MUST state the trust relationship between zones. The minimum zone set is: Untrusted (internet), DMZ/Presentation, Application, Data, Management, and Out-of-Scope Third Party.

FINDING TRIGGER: If workloads are described without zone assignment, flag as MEDIUM.
FINDING TRIGGER: If a design places presentation, application and data tiers in the same zone, flag as HIGH — a web-tier compromise reaches the database with no policy boundary crossed.

## 2.2 Flat networks

Requirement: A single broadcast domain or a single security zone MUST NOT host workloads of differing trust level or data classification.

FINDING TRIGGER: If the design describes a flat network, a single VLAN for all servers, or all workloads in one subnet, flag as HIGH.

Compliant pattern: "Web tier in VLAN 210 (DMZ zone), application tier in VLAN 220 (App zone), database in VLAN 230 (Data zone), inter-zone traffic inspected by the internal firewall pair."
Non-compliant pattern: "All application servers reside in VLAN 200 with the databases for simplicity."

## 3.1 Policy enforcement point

Requirement: Traffic between zones MUST traverse a stateful enforcement point capable of logging. Access control lists on a routing device are acceptable only between sub-zones of equal trust.

FINDING TRIGGER: If inter-zone traffic is routed without a stateful inspection point, flag as HIGH.
FINDING TRIGGER: If a zone boundary is enforced only by VLAN separation with no policy device, flag as HIGH — VLANs are a segmentation construct, not a security control.

## 3.2 East-west traffic

Requirement: Server-to-server traffic within a zone SHOULD be constrained by micro-segmentation where the workloads support differing applications.

FINDING TRIGGER: If a data centre design describes no east-west controls at all, flag as MEDIUM.
FINDING TRIGGER: If the design states that intra-zone traffic is unrestricted because "it is all internal", flag as HIGH and reference the Zero Trust Architecture Standard §2.1.

## 4.1 Rule specificity

Requirement: Firewall and ACL rules MUST specify source, destination, protocol and port. Any-to-any rules are prohibited in all zones.

FINDING TRIGGER: If a rule permits any source to any destination, or 0.0.0.0/0 to a protected zone, flag as CRITICAL. State which zone boundary it defeats.

Compliant pattern: "Permit TCP 443 from DMZ-Web-Group to App-API-Group; deny all, log."
Non-compliant pattern: "permit ip any any" or "Source: Any, Destination: Any, Service: Any".

## 4.2 Default deny

Requirement: Every policy set MUST terminate in an explicit deny-all rule with logging enabled.

FINDING TRIGGER: If a firewall policy is described without a terminating deny-all-and-log, flag as HIGH.

## 4.3 Rule lifecycle

Requirement: Every rule MUST have a documented owner, a business justification, and a review date. Rules without traffic for 90 days MUST be reviewed for removal.

FINDING TRIGGER: If no rule review process is described for a design introducing more than 20 rules, flag as LOW.

## 4.4 Temporary rules

Requirement: Rules created for migration or testing MUST carry an expiry date in the design.

FINDING TRIGGER: If temporary or migration rules are described without an expiry, flag as MEDIUM — temporary rules become permanent by default.

## 5.1 Management segment

Requirement: The management zone MUST NOT be reachable from user or server zones. Access is from the out-of-band network or via a jump host only.

FINDING TRIGGER: If any user or server zone has a permitted path into the management zone, flag as CRITICAL.

## 5.2 Third-party and partner connectivity

Requirement: Third-party connections MUST terminate in a dedicated zone with an explicit flow matrix, and MUST NOT route transitively to any other zone.

FINDING TRIGGER: If a partner or supplier connection is described without a dedicated zone, flag as HIGH.
FINDING TRIGGER: If transitive routing between two third parties is possible through the enterprise, flag as CRITICAL.

## 5.3 Egress control

Requirement: Outbound traffic from server zones MUST be restricted to named destinations. Unrestricted internet egress from a server zone is prohibited.

FINDING TRIGGER: If server zones are described with unrestricted outbound internet access, flag as HIGH — this is the exfiltration and command-and-control path.

## 6.1 Flow matrix

Requirement: The design MUST include an application flow matrix listing source zone, destination zone, protocol, port, and business purpose for every permitted flow.

FINDING TRIGGER: If no flow matrix is present in a design that introduces inter-zone communication, flag as MEDIUM — without it the firewall policy cannot be reviewed or reproduced.

## 6.2 Segmentation validation

Requirement: The design MUST state how segmentation will be tested after implementation.

FINDING TRIGGER: If no segmentation validation or penetration test is planned, flag as LOW.

Control mapping: NIST SP 800-53 SC-7, SC-7(21), AC-4; ISO/IEC 27001:2022 A.8.22, A.8.23; MITRE ATT&CK TA0008 (Lateral Movement), T1210.
