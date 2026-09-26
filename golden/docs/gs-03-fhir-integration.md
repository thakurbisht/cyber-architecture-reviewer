# Clinical Integration Platform - High-Level Design

Owner: Integration Services, St Aldric Regional Health. Version 1.1.

## 1. Purpose and Scope

St Aldric Regional Health operates three hospitals with 1,100 beds. This document describes the Clinical Integration Platform (CIP), which replaces point-to-point interfaces between clinical systems with a central integration engine and makes results available to patients and clinicians through a FHIR R4 API.

In scope are the inbound HL7v2 feeds from the laboratory and radiology systems, the integration engine, the message broker, the clinical data repository, the FHIR API, the back end of the My Health patient app, the clinician Results Viewer and vendor support access. The EHR, PACS image transfer and the mobile app code are out of scope.

## 2. Architecture Overview

Figure 1 shows the logical architecture. All components run in the St Aldric primary data centre, with a warm standby in the secondary data centre.

| Component | Technology | Location |
|---|---|---|
| Integration engine | Corvane Integrator 9, two nodes | Integration VLAN |
| Message broker | RabbitMQ 3.13, three-node cluster | Integration VLAN |
| Clinical data repository (CDR) | PostgreSQL 15 | Database VLAN |
| FHIR server | HAPI FHIR on the on-premises Kubernetes cluster | Application VLAN |
| Patient identity service | Keycloak, patients realm | Application VLAN |
| Results Viewer | Java web application | Application VLAN |
| Reverse proxy and WAF | NGINX with ModSecurity | DMZ |

## 3. Clinical Data Flows

### 3.1 Inbound feeds

The laboratory information system (LIS) and the radiology information system (RIS) send result messages (ORU) and order status messages (ORM) to the integration engine. Lab and radiology feeds use MLLP over plain TCP on ports 6661 and 6662, because the current LIS and RIS interface modules do not support MLLP over TLS. The LIS and RIS servers are in the general server VLAN and reach the integration VLAN through the core firewall.

### 3.2 Processing and distribution

Figure 2 shows the message flow. The engine validates each message against the St Aldric HL7 profile, maps it to FHIR R4 resources and publishes the resources to the clinical.events exchange in RabbitMQ.

Consumers of clinical.events are the CDR loader, the patient notification service, the bed-management system supplied by Wardflow Ltd, and the research extract job operated by the Aldric University research unit. The CDR loader writes every consumed resource into the CDR. The research job pseudonymises records before loading them into the university research warehouse. The notification service sends a push message saying that a new result is available, without clinical details.

Message storage is enabled on all engine channels with full message content, and pruning is disabled so that any historical message can be reprocessed.

A nightly engine channel exports the previous day's lab results, including patient name, MRN and result values, as CSV files to the lab-exports share on file server STAL-FS01. The laboratory quality team uses these files for turnaround-time reporting, and the share grants read access to the Domain Users group.

### 3.3 FHIR API

The FHIR server reads from the CDR and exposes read-only Patient, Observation, DiagnosticReport and Appointment endpoints, including full free-text radiology reports. The API is published to the internet at https://fhir.staldric.example through the DMZ reverse proxy for use by the My Health app.

### 3.4 Clinical data repository

The CDR runs PostgreSQL 15 on VMware virtual machines in the database VLAN, with a streaming replica in the secondary data centre, and holds demographics, results and reports for about 820,000 patients. Each service connects with its own PostgreSQL role: the CDR loader has write access and the FHIR server has read-only access.

## 4. Applications and Access

### 4.1 My Health patient app

Patients create an app account with an email address and password, then link it to their hospital record by entering their MRN, surname and date of birth. When the three values match an entry in the master patient index, the patient identity service stores the patient ID on the account and issues it as the patient claim in access tokens. A hospital record can be linked to more than one app account so that parents and carers can use their own logins.

The app uses the authorization code flow with PKCE. Access tokens are RS256-signed JWTs valid for 15 minutes, and refresh tokens are rotated on every use.

### 4.2 Results Viewer

The Results Viewer is published to the internet through the DMZ reverse proxy so that clinicians can review results from home and from affiliated GP practices. The Results Viewer backend obtains a token with the client-credentials grant and a system-level read scope, and uses this token for all FHIR queries made on behalf of signed-in clinicians.

### 4.3 Vendor support access

Corvane Systems provides third-line support for the integration engine under a 24x7 contract. To avoid VPN onboarding for Corvane staff, the engine administration console on HTTPS port 8443 is published through the DMZ reverse proxy at https://ie-admin.staldric.example. Corvane engineers sign in with the built-in admin account, whose password is held by the Corvane support desk and shared among its engineers. The console allows channel deployment, script editing and viewing of stored messages.

## 5. Identity and Authorisation

Clinicians sign in to the Results Viewer through the corporate IdP using SAML, and the IdP enforces number-matching MFA on every sign-in, from inside or outside the hospital network. Access to the Results Viewer requires membership of the Clinical Staff group, which HR offboarding removes on the leaver date.

The FHIR server restricts every request made with a patient token to the compartment of the patient in the token's patient claim, and returns 403 for any resource that belongs to another patient.

Integration team members sign in to the engine console with named Active Directory accounts. All producers and consumers connect to RabbitMQ with the shared cip-integration user, which has configure, write and read permissions on the default virtual host.

## 6. Network Design

The platform uses four VLANs behind the core firewall: DMZ, application, integration and database. Table 2 lists the permitted flows; all other traffic between VLANs is denied.

| Source | Destination | Port | Purpose |
|---|---|---|---|
| Internet | Reverse proxy | 443 | FHIR API, Results Viewer, engine console |
| Reverse proxy | Application VLAN | 8443 | FHIR server, Results Viewer |
| Reverse proxy | Integration VLAN | 8443 | Engine console |
| LIS and RIS servers | Integration VLAN | IPsec (MLLP 6661-6662) | Result feeds |
| Wardflow server, university VPN | RabbitMQ | 5671 | Broker consumers |
| Application VLAN | Database VLAN | 5432 | FHIR server to CDR |
| Integration VLAN | Database VLAN | 5432 | CDR loader to CDR |
| Integration VLAN | STAL-FS01 | 445 | Lab export files |

The DMZ reverse proxy terminates TLS 1.2 or higher and runs ModSecurity with the OWASP Core Rule Set in blocking mode for fhir.staldric.example and results.staldric.example. The research extract server connects from the university network over a site-to-site IPsec VPN that permits only port 5671.

## 7. Data Protection

TLS 1.2 or higher protects the FHIR API, the Results Viewer, AMQPS connections to RabbitMQ and PostgreSQL connections to the CDR, which use sslmode=verify-full. Because the LIS and RIS cannot use TLS, MLLP traffic between those servers and the engine nodes is carried in host-to-host IPsec transport-mode tunnels using IKEv2 with certificates and AES-256-GCM.

Backups are encrypted with AES-256 by the backup software before they leave St Aldric, using keys held in the hospital key management server, and Hollin Data Services never has access to the keys. Backup copies at Hollin are immutable for 35 days, and a data processing agreement covering health data is in place.

## 8. Environments

The test environment mirrors production at a smaller scale. It uses synthetic patient data generated from the St Aldric HL7 profile, and production data is never copied into it.

## 9. Logging and Audit

The FHIR server writes a FHIR AuditEvent for every request, recording the timestamp, OAuth client ID, patient ID, resource type and outcome. The AuditEvent store is the system of record for the privacy office's investigations of access to patient records.

Engine, RabbitMQ, operating system and firewall logs are forwarded to the hospital SIEM and retained for two years, with alerts for repeated failed logins and firewall rule changes.

## 10. Availability and Recovery

The integration engine runs active-passive across its two nodes, and RabbitMQ uses quorum queues across the three-node cluster. The recovery objectives are an RPO of 5 minutes and an RTO of 2 hours, met by failing over to the CDR replica and the standby engine in the secondary data centre. Nightly full backups of the CDR and the engine database are copied to Hollin Data Services, an external backup provider, for off-site retention of 90 days.
