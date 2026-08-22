# Three-Tier LAN Architecture Standard

Owner: Enterprise Network Architecture
Applies to: campus and data centre LAN designs (HLD and LLD)
Severity language: CRITICAL / HIGH / MEDIUM / LOW as defined in §1.3

## 1.1 Purpose

This standard defines the mandatory structure of enterprise LAN designs. It exists so that a reviewer can determine compliance from the design document alone, without asking the designer clarifying questions. Any requirement expressed with MUST is mandatory; SHOULD is a default that requires a recorded exception to depart from.

## 1.2 Scope of the review

A design is in scope for this standard if it describes wired campus access, distribution or core layers, or a leaf/spine data centre fabric. Wireless infrastructure is in scope only for its wired attachment.

## 1.3 Severity definitions

CRITICAL: a single component or link failure results in total loss of connectivity for a user population, a site, or a production service; or an unauthenticated path exists into a protected zone.
HIGH: a control required by this standard is absent and no compensating control is described.
MEDIUM: the requirement is partially met, or met by a mechanism the standard does not prefer.
LOW: documentation, naming or hygiene gap that does not affect the security or availability of the design.

## 2.1 Layer separation

Requirement: Access, distribution and core functions MUST be logically separated. Collapsed core is permitted only for sites under 250 ports, and the design MUST state the port count that justifies it.

FINDING TRIGGER: If the design describes a collapsed core without stating the site port count, flag as MEDIUM.
FINDING TRIGGER: If the design describes a collapsed core for a site over 250 ports, flag as HIGH.

## 2.2 Layer 3 boundary

Requirement: The Layer 3 boundary MUST sit at the distribution layer in campus designs. Access switches MUST NOT carry VLANs beyond their distribution pair.

FINDING TRIGGER: If a VLAN is described as spanning multiple distribution blocks or the entire campus, flag as HIGH — a campus-wide Layer 2 domain makes the failure domain the whole site.

Compliant pattern: VLAN 120 exists only within Distribution Block A, gateway on Dist-SW-A/B HSRP pair.
Non-compliant pattern: VLAN 120 is trunked across the campus so any user can be placed on it from any closet.

## 3.1 Uplink quantity

Requirement: Every access switch MUST have at least two uplinks. Every distribution switch MUST have at least two paths to the core.

FINDING TRIGGER: If any device in the design has a single uplink, flag as CRITICAL, naming the device.
FINDING TRIGGER: If the design uses the phrase "single point of failure" about a production path without an accompanying accepted-risk reference, flag as CRITICAL.

## 3.2 Uplink diversity

Requirement: The two uplinks from a device MUST terminate on two different upstream devices. Two uplinks from an access switch that both terminate on the same distribution switch do NOT satisfy this requirement, because failure of that single upstream device results in total loss of upstream connectivity.

FINDING TRIGGER: If two uplinks from the same device terminate on the same upstream device, flag as CRITICAL even though two uplinks exist. State explicitly that quantity is satisfied but diversity is not.

Compliant pattern:
    Access-SW-01 --uplink-1--> Dist-SW-A (port Gi1/0/1)
    Access-SW-01 --uplink-2--> Dist-SW-B (port Gi1/0/1)

Non-compliant pattern (flag as CRITICAL even though 2 uplinks exist):
    Access-SW-01 --uplink-1--> Dist-SW-A (port Gi1/0/1)
    Access-SW-01 --uplink-2--> Dist-SW-A (port Gi1/0/2)

Recommendation text to use: "Reroute one uplink from <device> to the peer distribution switch so the pair terminates on two separate chassis."

## 3.3 Physical path diversity

Requirement: Redundant uplinks SHOULD follow physically diverse cable paths and MUST NOT share a single conduit, patch panel, or line card where the design states availability targets of 99.9% or higher.

FINDING TRIGGER: If redundant links are described as terminating on the same line card or module, flag as HIGH.
FINDING TRIGGER: If an availability target of 99.9% or higher is stated and no physical diversity is described anywhere in the design, flag as MEDIUM.

## 3.4 Power and environmental redundancy

Requirement: Distribution and core devices MUST have dual power supplies fed from separate distribution boards.

FINDING TRIGGER: If a single power supply is described for a distribution or core device, flag as HIGH.

## 4.1 First-hop redundancy

Requirement: Every user or server VLAN gateway MUST be protected by a first-hop redundancy protocol (HSRP, VRRP or equivalent) or by a multi-chassis link aggregation arrangement that presents a single gateway.

FINDING TRIGGER: If a VLAN gateway is described on a single device with no first-hop redundancy protocol, flag as HIGH.
FINDING TRIGGER: If HSRP or VRRP is described without authentication, flag as MEDIUM.

## 4.2 Loop prevention

Requirement: Rapid PVST+ or MST MUST be enabled on all Layer 2 domains. Root bridge placement MUST be explicitly configured at the distribution layer, never left to election.

FINDING TRIGGER: If spanning tree is not mentioned anywhere in a design containing Layer 2 links, flag as MEDIUM.
FINDING TRIGGER: If root bridge priority is not explicitly set, flag as MEDIUM.
FINDING TRIGGER: If BPDU Guard and Root Guard are absent from the access port configuration, flag as HIGH — an unmanaged switch plugged into a user port can otherwise become root.

## 4.3 Convergence targets

Requirement: The design MUST state the expected convergence time for a single link failure and a single node failure, and the mechanism that achieves it.

FINDING TRIGGER: If availability or resilience is claimed without stated convergence times, flag as LOW.

## 5.1 Access port security

Requirement: Access ports serving end users MUST have port security or 802.1X, DHCP snooping, Dynamic ARP Inspection, and BPDU Guard enabled.

FINDING TRIGGER: If access ports are described without 802.1X or an explicit exception, flag as HIGH.
FINDING TRIGGER: If DHCP snooping and Dynamic ARP Inspection are absent from a design that includes user access VLANs, flag as MEDIUM.

## 5.2 Unused ports

Requirement: Unused access ports MUST be administratively shut down and assigned to an unrouted quarantine VLAN.

FINDING TRIGGER: If the design does not state the handling of unused ports, flag as LOW.

## 6.1 Oversubscription

Requirement: Access-to-distribution oversubscription MUST NOT exceed 20:1, and distribution-to-core MUST NOT exceed 4:1, unless a traffic study is referenced.

FINDING TRIGGER: If uplink bandwidth is stated and the computed oversubscription exceeds these ratios, flag as MEDIUM with the computed ratio shown.

## 6.2 Capacity headroom

Requirement: The design MUST show that a single uplink failure leaves sufficient capacity to carry peak load on the surviving path.

FINDING TRIGGER: If redundant uplinks are load-shared and the design does not confirm single-link peak capacity, flag as MEDIUM.

## 7.1 Documentation completeness

Requirement: An LLD MUST contain a device inventory, a port map for inter-device links, an IP address plan, and a VLAN table.

FINDING TRIGGER: If any of these four artefacts is absent from a document presented as an LLD, flag as LOW per missing artefact.

Control mapping for this standard: NIST SP 800-53 CP-2, SC-7; ISO/IEC 27001:2022 A.8.14, A.8.20, A.8.22.
