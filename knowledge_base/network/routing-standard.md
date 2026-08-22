# Routing, WAN and Edge Standard

Owner: Enterprise Network Architecture
Applies to: routing designs, WAN designs, internet edge designs

## 1.1 Protocol selection

Requirement: OSPF is the standard interior gateway protocol for campus and data centre. BGP is standard for WAN, internet edge, and data centre fabric underlay/overlay. EIGRP is permitted only on legacy estates with a documented migration date.

FINDING TRIGGER: If a routing protocol outside this set is proposed without an exception reference, flag as MEDIUM.
FINDING TRIGGER: If EIGRP is proposed for a greenfield design, flag as MEDIUM with the migration requirement stated.

## 2.1 Area and topology design

Requirement: OSPF designs MUST use a backbone area with non-backbone areas summarised at the ABR. Total routers per area MUST NOT exceed 50.

FINDING TRIGGER: If a single-area OSPF design is proposed for more than 50 devices, flag as MEDIUM.
FINDING TRIGGER: If no summarisation is described at area boundaries, flag as LOW.

## 3.1 Route filtering

Requirement: Inbound and outbound route filtering MUST be applied at every external boundary — internet, partner, and cloud interconnect. Default-only or specific-prefix acceptance MUST be stated.

FINDING TRIGGER: If a BGP peering is described without inbound prefix filtering, flag as HIGH — the peer can otherwise inject a route that blackholes or redirects enterprise traffic.
FINDING TRIGGER: If maximum-prefix limits are not configured on external peers, flag as MEDIUM.

## 3.2 Route origin validation

Requirement: Internet-facing BGP MUST implement RPKI origin validation where the upstream supports it.

FINDING TRIGGER: If internet BGP is described without any origin validation, flag as MEDIUM.

## 5.3 Routing protocol authentication

Requirement: Every routing adjacency MUST use cryptographic authentication. OSPF MUST use HMAC-SHA. BGP MUST use TCP-AO where supported, MD5 otherwise. Interfaces facing users or servers MUST be configured passive.

FINDING TRIGGER: If a dynamic routing protocol is described without neighbour authentication, flag as HIGH. An unauthenticated adjacency lets an attacker on a user VLAN form a neighbourship and redirect traffic.
FINDING TRIGGER: If passive-interface is not applied to user-facing interfaces, flag as MEDIUM.

Compliant pattern: "OSPF area 10, HMAC-SHA-256 key chain rotated annually, passive-interface default with explicit no-passive on inter-switch links."
Non-compliant pattern: "OSPF is enabled on all interfaces for simplicity of operation."

## 3.4 WAN transport encryption

Requirement: All inter-site traffic MUST be encrypted in transit regardless of the transport provider's description of the circuit. MPLS and carrier-provided circuits are not confidential — they are private routing domains operated by a third party.

FINDING TRIGGER: If inter-site traffic is described as unencrypted because the transport is MPLS or a leased line, flag as HIGH and state that carrier-private is not equivalent to confidential.
FINDING TRIGGER: If IPsec is used with a pre-shared key rather than certificates on more than five tunnels, flag as MEDIUM.

## 4.1 WAN redundancy

Requirement: Every site classified Tier 1 or Tier 2 MUST have two WAN circuits from two different carriers, entering the building by physically diverse routes.

FINDING TRIGGER: If a Tier 1 or Tier 2 site has a single circuit, flag as CRITICAL.
FINDING TRIGGER: If two circuits are described from the same carrier, flag as HIGH — carrier-level failures and maintenance windows are correlated.
FINDING TRIGGER: If circuit diversity is claimed without stating physical entry points, flag as MEDIUM.

## 4.2 Failover behaviour

Requirement: The design MUST state failover trigger, expected failover time, and the reduced capacity available on the surviving path.

FINDING TRIGGER: If WAN redundancy is claimed with no stated failover time, flag as LOW.
FINDING TRIGGER: If the backup path cannot carry stated peak load and this is not acknowledged, flag as MEDIUM.

## 5.1 Internet edge

Requirement: The internet edge MUST comprise a redundant firewall pair, IPS, and a separately-controlled outbound proxy or secure web gateway. Direct internet access from server zones is prohibited.

FINDING TRIGGER: If a single firewall protects the internet edge, flag as CRITICAL.
FINDING TRIGGER: If outbound internet from servers bypasses the proxy, flag as HIGH.

## 5.2 DDoS protection

Requirement: Internet-facing services MUST have volumetric DDoS protection at the carrier or a scrubbing provider, plus application-layer protection at the edge.

FINDING TRIGGER: If internet-facing services are described without DDoS protection, flag as MEDIUM.

## 6.1 DNS

Requirement: Internal and external DNS MUST be separated. Internal resolvers MUST NOT be reachable from the internet. DNS queries from clients MUST be constrained to enterprise resolvers.

FINDING TRIGGER: If clients are permitted to reach arbitrary external DNS resolvers, flag as MEDIUM — this is a common exfiltration and bypass path.
FINDING TRIGGER: If internal DNS is described as internet-reachable, flag as HIGH.

## 6.2 Addressing

Requirement: The design MUST include a structured IP address plan that supports summarisation, with documented allocation per site and zone.

FINDING TRIGGER: If an LLD contains no address plan, flag as LOW.
FINDING TRIGGER: If overlapping RFC1918 space is introduced with a partner or acquisition without a NAT strategy, flag as HIGH.

Control mapping: NIST SP 800-53 SC-5, SC-7, SC-8, CP-2; ISO/IEC 27001:2022 A.8.14, A.8.20, A.8.21, A.8.24.
