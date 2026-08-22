# Low Level Design: Meridian Tower Campus LAN Refresh

Document ID: LLD-NET-2026-014
Author: Infrastructure Delivery
Status: For design authority review
Site tier: Tier 1 (primary regional office, 1,400 users)

## 1. Introduction and Scope

This document describes the target state design for the campus LAN refresh at Meridian Tower. The refresh replaces end-of-life access switching across nine floors, introduces a new distribution layer, and re-homes the site onto the regional WAN. The design covers wired access, distribution, core, WAN edge, wireless attachment and the management plane. Application architecture is out of scope.

The site availability target is 99.95% for wired connectivity.

## 2. Physical Topology Overview

The design uses a three-tier model. Each floor has two access switch stacks located in the floor IDF. Access stacks connect to the distribution pair located in the basement MDF. The distribution pair connects to the two core switches, which in turn connect to the WAN edge routers.

Floors 1 through 8 follow the standard pattern. Floor 9 hosts the executive floor and the site data room.

## 3. Access Layer Design

Access switching is provided by 48-port stackable switches, two stacks per floor, delivering PoE+ to all user ports.

Uplink arrangement per floor:

| Floor | Access stack | Uplink 1 terminates on | Uplink 2 terminates on |
|---|---|---|---|
| 1 | ACC-F1-01 | DIST-SW-A Gi1/0/1 | DIST-SW-B Gi1/0/1 |
| 2 | ACC-F2-01 | DIST-SW-A Gi1/0/2 | DIST-SW-B Gi1/0/2 |
| 3 | ACC-F3-01 | DIST-SW-A Gi1/0/3 | DIST-SW-B Gi1/0/3 |
| 4 | ACC-F4-01 | DIST-SW-A Gi1/0/4 | DIST-SW-A Gi1/0/5 |
| 5 | ACC-F5-01 | DIST-SW-A Gi1/0/6 | DIST-SW-B Gi1/0/6 |
| 9 | ACC-F9-01 | DIST-SW-A Gi1/0/9 | DIST-SW-A Gi1/0/10 |

Floor 4 and Floor 9 have two uplinks each but both terminate on the same distribution switch, DIST-SW-A, because the fibre count to those floors was insufficient at the time of survey. This was accepted by the project to avoid delaying the cutover.

Access ports are configured with portfast. Port security is not enabled as the site operates an open desk policy and MAC learning was found to generate excessive support tickets. 802.1X is planned for a future phase and is not in scope for this refresh.

Unused ports remain in the default VLAN and administratively up to allow ad-hoc desk moves without a change request.

## 4. VLAN and Addressing Design

A single VLAN, VLAN 100, is used for all user devices across all nine floors to simplify the address plan and allow users to move between floors without re-addressing. VLAN 100 is trunked to both distribution switches and spans the entire campus.

Server devices in the floor 9 data room are placed in VLAN 100 alongside user devices, as the server count is small and the additional VLAN was judged unnecessary.

The gateway for VLAN 100 resides on DIST-SW-A. HSRP was considered but not implemented; DIST-SW-B is configured as a Layer 2 path only.

Spanning tree is left at default settings. Root bridge election is allowed to occur naturally as the distribution switches have the lowest MAC addresses.

## 5. Distribution and Core

The distribution pair, DIST-SW-A and DIST-SW-B, are chassis switches with dual supervisors. DIST-SW-A is fitted with a single power supply; the second bay is reserved for a future upgrade. DIST-SW-B has dual power supplies.

Both distribution switches connect to CORE-SW-01. CORE-SW-02 is planned for phase 2 and is not part of this delivery. The core is therefore a single device in the current design.

## 6. Routing Design

OSPF is used between distribution and core, in a single area 0. All interfaces are enabled for OSPF to simplify configuration, including the user-facing SVIs. Neighbour authentication is not configured as the campus is a trusted environment.

Static default route points from the core to the WAN edge.

## 7. WAN Edge and Internet

The site connects to the regional WAN over a single 1 Gbps MPLS circuit from Carrier A. A second circuit was priced but removed from scope during value engineering. MPLS traffic is not encrypted, as the carrier circuit is private and dedicated to our organisation.

Internet access is provided centrally from the regional hub; there is no local internet breakout at this site.

## 8. Firewall and Segmentation

An internal firewall pair sits between the campus and the data centre. The rule set for this design is:

| Rule | Source | Destination | Service | Action |
|---|---|---|---|---|
| 1 | Campus VLAN 100 | Data Centre Server Zone | Any | Allow |
| 2 | Any | Any | Any | Allow |
| 3 | Data Centre | Campus | Any | Allow |

Rule 2 was added during migration testing to resolve an application issue and has been retained to avoid regression. There is no terminating deny rule; the firewall default is permit for this policy set.

Management traffic to network devices traverses VLAN 100 alongside user traffic.

## 9. Wireless

Wireless is provided by controller-based access points attached to the access layer. Two SSIDs are defined:

- CORP-WIFI: WPA2-PSK, passphrase distributed to staff by the service desk and rotated annually.
- GUEST-WIFI: open SSID with captive portal, bridged onto VLAN 100.

Rogue AP detection is enabled on the controller.

## 10. Management Plane

Devices are managed in-band over VLAN 100. Management access is by telnet from the network team's workstations, as the legacy management tool does not support SSH key exchange with the older platform.

SNMPv2c is configured with community string "public" for read access by the monitoring platform, and "private" for write access used by the configuration backup tool.

Authentication to devices uses a local admin account. The same enable password is configured on all devices to simplify operations. TACACS+ was considered but the AAA server project has slipped and is not available for this delivery.

Configuration backup runs nightly over TFTP to the network management server.

Syslog is written to local buffer on each device. Central syslog forwarding is a phase 2 item.

NTP is not currently configured; devices use their internal clocks.

## 11. Availability and Convergence

The design targets 99.95% availability. Convergence times have not been measured but are expected to be within a few seconds based on vendor documentation.

Backup of device configurations is described in section 10. Restore has not been tested.

## 12. Assumptions

- The existing structured cabling is fit for purpose.
- Users accept a brief outage during cutover.
- The AAA server will be available in phase 2.
- 802.1X will be delivered in phase 2.
