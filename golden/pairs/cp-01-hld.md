# Claims Processing Platform — High Level Design

**Company:** Ravenscourt Mutual (fictional)
**Document:** HLD v1.4, approved at the design authority
**Classification:** Internal

## 1. Purpose and scope

Ravenscourt Mutual is replacing its mainframe claims workflow with a cloud
platform that accepts claims from brokers and the member portal, assesses them,
and issues payments. The platform handles member personal data, medical
summaries and bank details, and is in scope for the group data protection
standard.

This document sets out the architecture and the security controls the detailed
design must implement.

## 2. Context

Brokers submit claims through a partner API. Members submit claims through the
member portal. Assessors and payment officers work in an internal case
management application. Payments leave through the existing treasury gateway.

## 3. Logical architecture

The platform runs in a dedicated cloud subscription with four tiers: an edge
tier facing the internet, an application tier, an integration tier that speaks
to the treasury gateway, and a data tier.

The edge tier terminates client connections and applies abuse protection. The
application tier holds the claims API, the assessment service and the case
management back end. The integration tier holds the payment adapter. The data
tier holds the claims store, the document store and the audit store.

## 4. Security controls

### 4.1 Encryption

All traffic between tiers must use TLS 1.3. Connections from brokers and from
the member portal must use TLS 1.3 with modern cipher suites only.

All data at rest is encrypted with customer-managed keys held in the platform
key vault. Keys are rotated every 90 days.

### 4.2 Identity and access

Every administrative and assessor login requires phishing-resistant multi-factor
authentication. Access to the case management application is granted by role,
and no role may both assess a claim and approve its payment.

Service-to-service calls authenticate with mutual TLS. No service may call
another using a shared static credential.

### 4.3 Network

The four tiers are segmented from one another, and traffic between them is
permitted only on the specific ports each service needs. The data tier accepts
connections only from the application and integration tiers.

No component of the data tier is reachable from the internet. Storage accounts
and database endpoints are exposed through private endpoints only.

### 4.4 Secrets

Application secrets and the treasury gateway credentials are held in the
platform secret store. Secrets are never held in configuration files, images or
pipeline variables.

### 4.5 Logging and detection

All security-relevant events are forwarded to the group SIEM, including
authentication events, authorisation failures, payment approvals and
administrative actions. Logs are retained for 18 months.

Alerts are raised on repeated authentication failure, on payment approval
outside business hours, and on any change to a firewall rule.

### 4.6 Resilience

The platform runs active-active across two availability zones. RPO is 15
minutes and RTO is 2 hours.

Backups of the claims store are taken nightly and held as immutable copies for
35 days. A restore is tested every quarter.

### 4.7 Change control

All infrastructure is defined as code. Every change to production requires a
reviewed pull request and an approval from someone other than the author.
Container images are scanned for vulnerabilities before release.

## 5. Data protection

Member medical summaries are classified Restricted. Restricted data is not
copied to non-production environments. Bank details are tokenised before they
are stored.

## 6. Assumptions

The treasury gateway is out of scope for this design and is covered by its own
assurance. The group SIEM, the identity provider and the platform key vault are
existing shared services.
