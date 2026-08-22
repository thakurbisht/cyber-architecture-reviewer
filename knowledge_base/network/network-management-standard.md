# Secure Management Plane Standard

Owner: Enterprise Network Architecture / Security Architecture
Applies to: all managed network and security infrastructure

## 1.1 Principle

The management plane is the highest-value target in any network. An attacker who reaches it does not need to defeat the data plane controls — they can rewrite them. Management access is therefore treated as privileged access and inherits every control in the Identity & Privileged Access Standard.

## 2.1 SNMP

Requirement: SNMPv3 with authPriv (SHA-2 authentication, AES-128 or stronger privacy) MUST be used. SNMP v1 and v2c MUST NOT be configured on any device, including as a fallback for legacy monitoring tools.

FINDING TRIGGER: If SNMPv1 or SNMPv2c appears anywhere in the design, flag as CRITICAL. Community strings traverse the network in cleartext and grant read — and frequently write — access to device configuration.

Compliant pattern: "SNMPv3 authPriv, per-device credentials issued from CyberArk, rotated every 90 days."
Non-compliant pattern: "SNMPv2c read-only for the NMS."

## 2.2 Default credentials

Requirement: Default or guessable credentials MUST NOT appear in any design artefact. This includes SNMP community strings of `public` or `private`, and default device passwords.

FINDING TRIGGER: If a community string of `public` or `private` appears, flag as CRITICAL.
FINDING TRIGGER: If any credential value is written in the design document itself, flag as HIGH — the document is now a credential store with unknown distribution.

## 2.3 Management protocols

Requirement: Only SSHv2 and HTTPS (TLS 1.2 minimum) are permitted for device administration. Telnet, HTTP, FTP and TFTP MUST be disabled at the device, not merely unused.

FINDING TRIGGER: If telnet, HTTP device access, FTP or TFTP appears without an explicit statement that it is disabled, flag as HIGH.

## 3.1 Centralised authentication

Requirement: All device administration MUST authenticate against TACACS+ (preferred) or RADIUS, backed by the enterprise directory, with command authorisation and per-command accounting.

FINDING TRIGGER: If local accounts are described as the primary administrative access method, flag as HIGH.
FINDING TRIGGER: If a shared administrator or enable password is described, flag as HIGH — accountability is lost and offboarding cannot revoke access.

## 3.2 Break-glass access

Requirement: Exactly one local break-glass account per device is permitted. Its password MUST be vaulted, unique per device, rotated after every use, and its use MUST raise an alert.

FINDING TRIGGER: If no break-glass mechanism is described, flag as MEDIUM — a TACACS+ outage otherwise locks the team out of the network during an incident.
FINDING TRIGGER: If break-glass accounts share a password across devices, flag as HIGH.

## 3.3 Multi-factor authentication

Requirement: Administrative access to network infrastructure MUST require multi-factor authentication, enforced at the jump host or the AAA server.

FINDING TRIGGER: If administrative access is described without MFA anywhere in the path, flag as CRITICAL.

## 4.1 Out-of-band management

Requirement: A dedicated out-of-band management network SHOULD exist for core, distribution, WAN edge and security devices. Where in-band management is used, it MUST be on a dedicated VLAN/VRF with an ACL restricting source addresses to the management network and jump hosts.

FINDING TRIGGER: If management traffic shares a VLAN with user or server traffic, flag as HIGH.
FINDING TRIGGER: If no source restriction on management access is described, flag as HIGH.

## 4.2 Jump hosts

Requirement: Interactive administrative sessions MUST originate from a hardened jump host with session recording. Direct administrative access from an engineer's workstation is not permitted.

FINDING TRIGGER: If engineers are described as connecting directly to devices from their workstations, flag as HIGH.

## 5.1 Configuration backup

Requirement: Device configurations MUST be backed up automatically on change, stored in version control, and diffed for unauthorised change detection.

FINDING TRIGGER: If configuration backup is not described, flag as MEDIUM.
FINDING TRIGGER: If configuration backup is described over TFTP or FTP, flag as HIGH — the backup transport is cleartext and the archive contains credentials.

## 5.2 Time synchronisation

Requirement: All devices MUST synchronise to at least two internal NTP sources with authentication enabled. Correlated logs are impossible without it.

FINDING TRIGGER: If NTP is absent from a design that includes logging or auditing requirements, flag as MEDIUM.

## 5.3 Logging

Requirement: All devices MUST forward syslog at informational level or above to the central log platform, and authentication events to the SIEM.

FINDING TRIGGER: If device logging destinations are not described, flag as HIGH.
FINDING TRIGGER: If logs are stored only locally on the device, flag as HIGH — local logs are erased by the attacker who compromised the device.

## 6.1 Wireless authentication

Requirement: Corporate wireless MUST use WPA2-Enterprise or WPA3-Enterprise with 802.1X and EAP-TLS. Pre-shared keys are permitted only for guest and IoT SSIDs, which MUST be isolated in their own segment with no route to corporate resources.

FINDING TRIGGER: If a corporate SSID uses a pre-shared key, flag as HIGH.
FINDING TRIGGER: If WEP or WPA (original) appears, flag as CRITICAL.
FINDING TRIGGER: If a guest SSID is described without client isolation and a segment boundary, flag as HIGH.

## 6.2 Rogue detection

Requirement: Wireless infrastructure MUST perform rogue AP detection and report to the SOC.

FINDING TRIGGER: If wireless is in scope and rogue detection is not described, flag as LOW.

Control mapping: NIST SP 800-53 AC-2, AC-17, AC-18, IA-2(1), IA-5, SC-8, AU-6; ISO/IEC 27001:2022 A.5.15, A.5.17, A.8.5, A.8.15, A.8.20.
