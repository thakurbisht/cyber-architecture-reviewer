# Calderwick Plant IT/OT Network Architecture - High-Level Design

Owner: Plant Automation Engineering, Brennock Industries. Version 1.3, approved for build.

## 1. Purpose and Scope

This document describes the target network architecture for the Calderwick die-casting plant: the control network, site operations systems, the industrial DMZ, remote access, the warehouse scanner wireless network, and the supporting identity, patching, logging and backup services. Corporate networks are defined in the Brennock corporate network standard and appear here only where they connect to the plant.

## 2. Plant Overview and Zone Model

Calderwick produces aluminium gearbox and motor housings on three die-casting lines. Each line has a melting furnace, two casting cells, a trim press and an inspection station; Line 3 also includes two robotic welding cells. The network follows the Purdue reference model, summarised in Table 1.

Table 1 - Purdue levels at Calderwick

| Level | Contents | Addressing |
|---|---|---|
| 4 | Corporate LAN, ERP, email, corporate Active Directory | 10.40.0.0/16 |
| 3.5 | Historian replica, remote access gateway, file transfer server, patch relay, log relay | 172.20.35.0/24 |
| 3 | Site historian, OT domain controllers, OT file server, backup NAS, engineering workstations | 172.20.30.0/24 |
| 2 | Line HMIs and SCADA servers | VLANs 210-213 |
| 1 | PLCs, robot controllers, furnace controllers | VLANs 110-112 |
| 0 | Sensors, actuators and drives | Line fieldbus |

At Calderwick the corporate office network is carried on VLAN 412, which is part of the Level 4 corporate LAN and is routed to the corporate data centre over the site WAN link.

Figure 1 shows the physical topology. A pair of IT/OT firewalls separates the corporate LAN from the DMZ, and a second pair of OT firewalls separates the DMZ from Level 3. Each production line has its own Level 2 switch stack, uplinked to the Level 3 core switches in the plant server room.

## 3. Industrial DMZ (Level 3.5)

The DMZ is the only zone to which both corporate and plant systems may connect. No session crosses directly from Level 4 to Level 3 or below; every flow terminates on a DMZ host. Table 2 lists the permitted flows; all other traffic is denied and logged.

Table 2 - Permitted firewall flows

| Source | Destination | Port | Purpose |
|---|---|---|---|
| Site historian (L3) | Historian replica (DMZ) | TCP 5450 | Outbound data push |
| Corporate users and ERP (L4) | Historian replica (DMZ) | TCP 443 | Reporting |
| Internet, via corporate edge | Remote access gateway (DMZ) | TCP 443 | Remote sessions |
| Remote access gateway (DMZ) | Engineering workstations (L3) | TCP 3389 | Brokered RDP |
| Level 2 and 3 Windows hosts | Patch relay (DMZ) | TCP 8530, 8443 | Updates |
| Level 2 and 3 hosts, OT firewalls | Log relay (DMZ) | TCP 6514 | Syslog over TLS |
| OT file server (L3) | File transfer server (DMZ) | TCP 443 | Pull of released files |

Corporate users and the ERP integration never connect to the site historian. They read from the historian replica in the DMZ, which receives data only through the outbound push from Level 3 and has no connection path back into Level 3. The replica's web client uses corporate single sign-on.

Files needed in the plant, such as vendor firmware and recipes, are uploaded to the file transfer server with corporate single sign-on, scanned by two antivirus engines and a sandbox, and released after approval by a controls engineer. The OT file server then pulls released files from the DMZ.

## 4. Control Network (Levels 0-2)

Each line has a Level 1 VLAN for its PLCs, robot controllers and furnace controller, and a Level 2 VLAN for its HMIs and SCADA server. Controllers use EtherNet/IP for I/O and exchange interlocks with neighbouring cells through produced and consumed tags.

The furnace burner management systems, which are SIL 2 safety controllers, are connected to each line's Level 1 VLAN alongside the process PLCs so that HMIs can display flame status and send trip resets.

The Level 3 core switches route between Level 2 VLANs 210-213 and Level 1 VLANs 110-112 without access control lists, so that HMIs and SCADA servers on any line can read tags from controllers on the other lines.

Controller key switches on all lines are left in the REMOTE position so that logic changes can be downloaded from the engineering workstations without an electrician attending the cabinet.

Line HMIs start automatically at boot and log on with the local Windows account hmi-operator, so that operator screens are available immediately after a power cycle.

Unused access ports on the Level 1 and Level 2 switches are left enabled in the line's control VLAN so that maintenance contractors can connect laptops for drive tuning without raising a change request. Switches are managed over SSH and SNMPv3 from the network management station in Level 3.

## 5. Site Operations (Level 3)

The site historian collects about 18,000 tags at one-second resolution and keeps two years of data for OEE, energy and quality reporting. Quality and production engineers in the corporate offices use historian data every day for yield reporting, and the ERP system reads hourly production counts.

Four engineering workstations (EWS-01 to EWS-04) hold the controller, robot and HMI engineering software and are the only hosts from which logic is downloaded to controllers. Each engineering workstation has a second network interface on VLAN 412 so that engineers can reach the document management system and project schedule from the same machine.

Two OT domain controllers provide authentication, DNS and time for Levels 2 and 3. The OT file server holds released vendor files and PLC and HMI project archives.

## 6. Remote Access

Approved equipment vendors connect from the internet to the remote access gateway in the DMZ and open RDP sessions to the engineering workstations in Level 3. The gateway brokers each session with credentials held in its vault, so vendors never learn workstation passwords. Plant engineers working off site use the same gateway.

The two robotic welding cells on Line 3 are supported by their manufacturer, Varda Robotics, through an LTE router supplied with each cell. The router connects to the cell's Level 1 switch and gives Varda's support centre direct access to the robot controllers and cell PLC for diagnostics and program updates.

## 7. Wireless Scanning Network

Sixty handheld scanners are used in the warehouse and at line-side material stations to record ingot lots and finished part labels. Scans are posted to the SCADA servers, which link material lots to production orders. Access points cover the warehouse, the loading bays and each line.

The scanners connect to the SSID CAL-SCAN using WPA2-Personal with a single pre-shared key, and the SSID is bridged to VLAN 213 on the Level 3 core switches. The warehouse supervisor loads the key onto each scanner at enrolment.

## 8. Identity and Access Management

The OT Active Directory domain (ot.brennock.local) trusts the corporate domain through a one-way trust, so that controls engineers log on to OT systems with their corporate accounts. The corporate group Controls-Engineers is a member of the OT-Admins group, which has local administrator rights on all Level 2 and Level 3 Windows hosts.

Every session through the remote access gateway requires a FIDO2 security key and ends automatically after four hours; vendor sessions must also be approved in the gateway by the on-shift production supervisor. Vendor accounts are named individually and are disabled after 60 days without use.

The hmi-operator account is a standard user confined by a kiosk shell to the HMI runtime and has no network logon rights. Operators sign in to the HMI application with their badge, and each control action is recorded against the badge holder in the HMI audit trail.

## 9. Patching and Endpoint Protection

Level 2 and Level 3 Windows hosts receive vendor-qualified updates monthly from the WSUS server on the DMZ patch relay, and updates for vulnerabilities in the CISA Known Exploited Vulnerabilities catalogue within 14 days. They run application allowlisting in enforce mode and antivirus, and USB mass storage is disabled by device control policy. Controller and robot firmware is reviewed twice a year against vendor advisories.

## 10. Logging and Monitoring

Windows event logs from Level 2 and Level 3 hosts, OT firewall logs and switch syslog are collected by the log relay in the DMZ and forwarded to the corporate SIEM, where they are retained for 12 months. The SOC has alert rules for failed logons, new local administrator accounts, firewall rule changes and blocked connection attempts from the DMZ. The remote access gateway records every session as video with keystroke logs and keeps the recordings for 12 months.

## 11. Backup and Recovery

Nightly backups of the site historian, OT domain controllers, engineering workstations and all PLC and HMI projects are written to the backup NAS in Level 3, and a weekly copy is written to encrypted removable disks that are disconnected and stored in the site safe. Restores from both are tested twice a year. Recovery targets are eight hours for the historian and SCADA servers and four hours for a controller program.
