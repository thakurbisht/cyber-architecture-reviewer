---
name: detecting-network-segmentation-weaknesses
domain: Network Security
subdomain: Network Segmentation & Zone Management
severity: CRITICAL
description: Analyze network architecture documents to identify over-permissive firewall rules, cleartext management protocols, improper network zone boundaries, unsecured device management access, and lack of network access controls. Review ACLs, DMZ configurations, and administrative network isolation.
tags: [network-security, segmentation, vlan, firewall, acl, device-management, zone-boundaries, cleartext-protocols]
author: pramod-singh-bisht
version: '1.0'
license: Apache-2.0
mitre_attack: [T1021.004, T1021.001, T1071.001, T1071.002, T1570]
nist_csf: [PR.AC.1, PR.PT.1, DE.CM.1, DE.CM.4]
mitre_d3fend: [D3-ACLS, D3-NGF, D3-NIA]
frameworks: [CSF, ATT&CK, D3FEND]
---

# Detecting Network Segmentation Weaknesses

## When to Use

- Reviewing network architecture diagrams with firewall and VLAN configurations
- Auditing network segmentation between security zones (DMZ, App tier, Data tier)
- Assessing device management network isolation
- Validating firewall ACL configurations for over-permissive rules
- Identifying cleartext protocol usage in administrative access

## Prerequisites

- Network architecture diagram or ACL configuration details
- Understanding of firewall rules, VLAN tagging, and network zones
- Knowledge of cleartext vs. encrypted protocols

## Instructions

### Step 1: Identify Over-Permissive Firewall Rules

Examine firewall ACLs for rules that are too broad:

**Critical Patterns to Find:**

**Rule Syntax Red Flags:**
- `permit ip any any` — unrestricted traffic from anywhere to anywhere (implicit)
- `permit tcp any any` — any TCP traffic allowed without port constraints
- `permit any any eq 22` — SSH allowed from any source IP to any destination
- `permit any any eq 3389` — RDP allowed from entire internet
- Rules with no protocol specification — assumes all protocols allowed
- Implicit permit at end of ACL before final deny (should be explicit deny-all)

**ACL Structure Issues:**
- Permit rules appearing AFTER deny rules (unreachable code)
- Multiple overlapping rules allowing same traffic (consolidate)
- Rules spanning multiple subnets when tighter scope possible
- Source IP 0.0.0.0/0 (any source) for sensitive ports (SSH, RDP, management)
- Destination IP 0.0.0.0/0 (any destination) for outbound traffic

**Example Bad ACL:**
```
! Line 10: Allows SSH from anywhere
permit tcp any any eq 22
! Line 20: Allows all traffic (too late, overrides line 30)
permit ip any any
! Line 30: Never reached — implicit deny
deny ip any any
```

**Example Good ACL:**
```
! Line 10: Allow SSH only from admin VLAN to bastion host
permit tcp 10.10.10.0 0.0.0.255 host 10.20.20.10 eq 22
! Line 20: Deny everything else (explicit)
deny ip any any
```

### Step 2: Check Cleartext Management Protocols

Identify insecure administrative access methods:

**Protocols to Flag:**

| Protocol | Status | Concern | Replacement |
|----------|--------|---------|-------------|
| Telnet | CRITICAL | Password transmitted in clear text | SSH (port 22) |
| HTTP (mgmt) | CRITICAL | Management interface unencrypted | HTTPS/TLS |
| FTP | CRITICAL | Credentials and data unencrypted | SFTP/SCP |
| TFTP | HIGH | Configuration uploaded unencrypted | SCP/secure copy |
| SNMPv1/v2c | HIGH | Community string in clear text | SNMPv3 with encryption |
| Rlogin/Rsh | CRITICAL | Trust-based auth, no encryption | SSH |
| HTTP API | HIGH | API tokens visible in transit | HTTPS/TLS + OAuth2 |

**Document Red Flags:**
- "Device management via Telnet" — should be SSH only
- "SNMP monitoring using community string" — should be SNMPv3
- "Config backup via FTP" — should use SFTP or SCP
- "HTTP API for device control" — should use HTTPS
- "Devices accessible via plaintext protocols for backwards compatibility" — unacceptable

### Step 3: Validate Network Zone Boundaries

Check for proper isolation between security zones:

**Standard Network Zones:**

```
┌─────────────────────────────────────────────────┐
│ INTERNET / EXTERNAL (Untrusted)                 │
└─────────────────┬───────────────────────────────┘
                  │ (Firewall / Intrusion Prevention)
┌─────────────────┴───────────────────────────────┐
│ DMZ / Public Zone                               │
│ - Web servers, reverse proxies                  │
│ - Public API endpoints                          │
│ - Email gateways                                │
└─────────────────┬───────────────────────────────┘
                  │ (Firewall / Application Gateway)
┌─────────────────┴───────────────────────────────┐
│ Application / Business Logic Zone               │
│ - Application servers                           │
│ - Business logic                                │
│ - Batch processing                              │
└─────────────────┬───────────────────────────────┘
                  │ (Database Firewall / Access Control)
┌─────────────────┴───────────────────────────────┐
│ Data / Database Zone                            │
│ - Databases                                     │
│ - Data warehouses                               │
│ - File storage                                  │
└─────────────────────────────────────────────────┘
                  │
┌─────────────────┴───────────────────────────────┐
│ MANAGEMENT Zone (Separate VLAN)                 │
│ - Admin jump host / bastion                     │
│ - Monitoring systems                            │
│ - Configuration management                      │
└─────────────────────────────────────────────────┘
```

**Zone Violation Patterns:**

- **DMZ directly connected to Data zone** — should route through Application zone
- **Management zone accessible from User zone** — should isolate completely
- **No firewall between zones** — should have ACLs between every zone boundary
- **Database accessible from internet** — should only be accessible from App zone
- **User zone directly accessing internal systems** — should use proxy/gateway

**Specific Checks:**

For each zone connection, verify:
- [ ] Firewall rule exists specifying allowed traffic
- [ ] Only necessary ports/protocols are open
- [ ] Source and destination IPs are specific (not 0.0.0.0/0)
- [ ] Return traffic is allowed (stateful firewall or explicit rules)
- [ ] Logging is enabled for all inter-zone traffic

### Step 4: Audit Device Management Access

Verify secure administrative network configuration:

**Checklist:**

- [ ] Out-of-band (OOB) management network isolated from production traffic
- [ ] Management VLAN separate from user/data VLANs (VLAN ID documented)
- [ ] Only authorized jump hosts can access management network
- [ ] All management access via SSH (not Telnet/Rsh)
- [ ] MFA required for jump host access
- [ ] Session recording enabled for all management connections
- [ ] Management console (physical) locked in secure area
- [ ] Default credentials changed on all devices
- [ ] SNMP read-only community string changed if used
- [ ] TACACS+ or RADIUS used for centralized authentication
- [ ] Management ports (SSH 22, HTTPS 443) not exposed to internet
- [ ] Syslog collection configured for audit trail

**Anti-Pattern Examples:**

❌ "Network administrators can SSH directly to any router from their laptop"  
✅ "Admins SSH to jump host, then SSH to routers from jump host only"

❌ "Telnet enabled on switches for backwards compatibility"  
✅ "SSH only, no Telnet. If device doesn't support SSH, replace device"

❌ "Management traffic flows through production network"  
✅ "Separate dedicated management VLAN (VLAN 99) with isolated uplinks"

### Step 5: Verify Network Access Controls

Confirm implementation of network access control mechanisms:

**Technology Patterns:**

- **802.1X Port-Based Authentication:** Are ports requiring authentication before allowing traffic?
- **MAC Address Filtering:** Is allowed MAC address list maintained and audited?
- **NAC (Network Access Control):** Are devices scanned for compliance before network access?
- **VLAN Assignments:** Are VLANs dynamically assigned based on device type/user role?
- **IP Address Validation:** Are DHCP addresses restricted to specific ranges per VLAN?

**Implementation Checklist:**

- [ ] 802.1X enabled on production switches
- [ ] Guest network isolated with limited access
- [ ] BYOD devices placed in restricted VLAN
- [ ] Rogue device detection configured
- [ ] DHCP snooping enabled
- [ ] Dynamic ARP Inspection (DAI) enabled
- [ ] Port security configured (MAC limit, aging)
- [ ] Spanning Tree Protocol protection enabled
- [ ] Storm control configured for broadcast/multicast

## Finding Template

```
Issue: [Description of segmentation weakness]
Severity: CRITICAL | HIGH | MEDIUM
Category: [Firewall Rules | Cleartext Protocols | Zone Boundaries | Device Management | Access Control]
Pattern Found: [Specific configuration from document]
MITRE ATT&CK: [T1021.004 lateral movement, T1571 non-standard port]
NIST CSF: [PR.AC.1, PR.PT.1 — Access Control and Protective Technology]

Recommendation:
[Specific remediation with ACL example or configuration]
```

## Examples

### Example 1: Over-Permissive Firewall Rule

**Document Section:**
```
Edge Firewall ACL Configuration:
...
210 permit tcp any any eq 22
220 permit ip any any
230 deny ip any any
```

**Finding:**
```
Issue: SSH (port 22) allowed from any source IP to any destination
Severity: CRITICAL
Pattern: "permit tcp any any eq 22" (line 210)
MITRE ATT&CK: T1021.004 (SSH and Remote Services)

Recommendation: Restrict SSH to authorized admin subnet:
! Existing (line 210):
210 permit tcp any any eq 22

! Replace with:
210 permit tcp 10.10.10.0 0.0.0.255 10.20.20.0 0.0.0.255 eq 22
220 deny tcp any any eq 22
230 deny ip any any

This restricts SSH to only the admin VLAN (10.10.10.0/24) accessing the internal network (10.20.20.0/24)
```

### Example 2: Cleartext Management Protocol

**Document Section:**
```
Device management approach:
- Network engineers access router configurations via Telnet
- Configuration backups uploaded via FTP to central server
- SNMP monitoring using community string "public"
```

**Finding:**
```
Issue: Multiple cleartext protocols used for device management
Severity: CRITICAL
Protocols: Telnet, FTP, SNMPv1/v2c
MITRE ATT&CK: T1071.002 (Plaintext Communication)

Recommendations:
1. Telnet → SSH only
   - Disable Telnet on all routers/switches
   - Configure SSH version 2
   - Restrict SSH source IPs to jump host

2. FTP → SCP (SSH File Copy)
   - Disable FTP daemon
   - Use SCP for configuration backups
   - Use SFTP for interactive file transfers

3. SNMP → SNMPv3
   - Replace SNMPv1/v2c monitoring with SNMPv3
   - Use authentication (SHA) and encryption (AES)
   - Example:
     snmp-server group admin v3 priv
     snmp-server user admin admin v3 auth sha AUTHPASS priv aes 256 ENCPASS
```

### Example 3: Missing Network Segmentation

**Document Section:**
```
Network Design:
- Web servers in DMZ connected directly to database servers
- Database access via port 3306 (MySQL)
- No firewall between DMZ and database tier
- Management traffic routed through production network
```

**Finding:**
```
Issue: Database tier directly accessible from DMZ without firewall segmentation
Severity: CRITICAL
MITRE ATT&CK: T1570 (Lateral Tool Transfer)

Recommendation: Implement proper network segmentation
Current State:
  DMZ (Web Servers) ──(no FW)──> Data Tier (Databases)

Desired State:
  DMZ (Web Servers) ──(Firewall)──> App Tier ──(Firewall)──> Data Tier
  
Firewall Rules Required:
  1. DMZ → App Tier: permit tcp any any eq 8080 (app traffic only)
  2. App Tier → Data Tier: permit tcp any any eq 3306 (database queries)
  3. Data Tier → DMZ: deny tcp any any (block return traffic in reverse)
  
Additional: Move management traffic to separate VLAN (VLAN 99) with own firewall rules
```

## Success Criteria

This skill successfully identifies network segmentation weaknesses when:

✓ Detects "permit any any" and "permit ip any any" patterns  
✓ Identifies Telnet, FTP, SNMPv1/v2c in management traffic  
✓ Finds missing firewalls between network zones  
✓ Validates separate management VLAN exists and is isolated  
✓ Confirms 802.1X or NAC controls are in place  
✓ Generates findings with specific ACL remediation examples  

## Reference Standards

- NIST CSF 2.0: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04232023.pdf
- CIS Network Segmentation: https://www.cisecurity.org/
- Cisco Best Practices: https://www.cisco.com/c/en/us/support/docs/security/
- SANS Network Security: https://www.sans.org/white-papers/
