# Data Classification and Cloud Data Protection Standard

Owner: Data Governance / Security Architecture
Applies to: every design that stores, processes or transmits enterprise data

## 1.1 Principle

Controls follow classification. A design that does not say what data it holds cannot say whether its controls are adequate, and cannot be reviewed. Classification is the first question, not the last.

## 2.1 Classification requirement

Requirement: Every data set in the design MUST carry a classification: Public, Internal, Confidential, or Restricted. Restricted covers regulated categories — payment card data, health data, government identity numbers, and biometric data.

FINDING TRIGGER: If the design references personal data, customer data, payment data or health data without stating a classification, flag as HIGH.
FINDING TRIGGER: If a data flow crosses a boundary and the classification of what crosses is not stated, flag as MEDIUM.

## 2.2 Data residency and sovereignty

Requirement: The design MUST state the permitted jurisdictions for each data set at rest and in processing, including where backups, replicas, logs and support access originate.

FINDING TRIGGER: If regulated data is stored without a stated residency constraint, flag as HIGH.
FINDING TRIGGER: If backups or replicas may reside outside the permitted jurisdiction, flag as HIGH — the copy is subject to the same constraint as the original.
FINDING TRIGGER: If vendor support staff can access data from outside the permitted jurisdiction and this is not addressed, flag as MEDIUM.

## 2.3 Public exposure

Requirement: Object storage, databases and data services MUST NOT be publicly accessible. Account-level public access blocking MUST be enabled and enforced by policy so that an individual bucket cannot be opened by an engineer.

FINDING TRIGGER: If any storage bucket, blob container or database is described as publicly accessible or readable, flag as CRITICAL.
FINDING TRIGGER: If a resource policy grants a wildcard principal, flag as CRITICAL.
FINDING TRIGGER: If account-level public access blocking is not enabled, flag as HIGH.

Compliant pattern: "S3 block public access enabled at the account and enforced by SCP; public assets served through CloudFront with an origin access identity."
Non-compliant pattern: "The assets bucket is public so the CDN can read it."

## 3.1 Encryption at rest

Requirement: All data at rest MUST be encrypted. Restricted data MUST use customer-managed keys so that key access is separable from data access, and key use MUST be logged.

FINDING TRIGGER: If encryption at rest is absent or disabled, flag as HIGH.
FINDING TRIGGER: If Restricted data uses provider-managed keys, flag as MEDIUM, stating the customer-managed key requirement.
FINDING TRIGGER: If snapshots, exports or read replicas are not explicitly covered by the encryption requirement, flag as HIGH.

## 3.2 Encryption in transit

Requirement: All data in transit MUST be encrypted with TLS 1.2 minimum, including traffic between services inside the same VPC and traffic to platform data services.

FINDING TRIGGER: If any data path is unencrypted, flag as HIGH.

## 3.3 Tokenisation and masking

Requirement: Payment card numbers MUST be tokenised. Restricted data used in non-production MUST be masked, synthesised, or tokenised — never copied in the clear.

FINDING TRIGGER: If production Restricted data is copied to non-production, flag as CRITICAL.
FINDING TRIGGER: If card data is stored rather than tokenised, flag as HIGH and reference the PCI scope implication.

## 4.1 Retention and disposal

Requirement: Every data set MUST have a defined retention period tied to a business or regulatory requirement, and an automated disposal mechanism at the end of it.

FINDING TRIGGER: If retention is unspecified for personal data, flag as HIGH — indefinite retention of personal data is a regulatory finding in its own right.
FINDING TRIGGER: If disposal is manual, flag as MEDIUM.
FINDING TRIGGER: If backups outlive the retention period of the data they contain and this is not addressed, flag as MEDIUM.

## 4.2 Subject rights

Requirement: Designs holding personal data MUST describe how access, correction, deletion and portability requests are fulfilled across all copies, including backups and analytics stores.

FINDING TRIGGER: If personal data is held with no described mechanism for deletion requests, flag as HIGH.

## 5.1 Data flow documentation

Requirement: The design MUST include a data flow description naming, for each flow: source, destination, classification, transport protection, and the legal basis where personal data is involved.

FINDING TRIGGER: If no data flow description exists in a design handling Confidential or Restricted data, flag as HIGH.

## 5.2 Third-party data sharing

Requirement: Any data leaving the enterprise boundary MUST be enumerated with recipient, classification, volume, purpose and contractual protection.

FINDING TRIGGER: If a third-party integration transfers enterprise data with no stated agreement or protection, flag as HIGH.
FINDING TRIGGER: If data is sent to an AI or analytics service without a stated position on training use and retention, flag as HIGH.

## 6.1 Access to data

Requirement: Access to Confidential and Restricted data MUST be role-based, logged, and reviewed. Bulk export MUST be restricted, alerted and require justification.

FINDING TRIGGER: If bulk data export is possible without alerting, flag as HIGH — this is the exfiltration path that matters most.
FINDING TRIGGER: If data access is not logged, flag as HIGH.

## 6.2 Data loss prevention

Requirement: Egress paths from environments holding Restricted data MUST be covered by DLP inspection or equivalent controls.

FINDING TRIGGER: If Restricted data is held in an environment with unrestricted egress, flag as HIGH.

## 7.1 Analytics and secondary use

Requirement: Data copied into a lake or warehouse retains its original classification and controls. Secondary use beyond the original purpose requires documented approval.

FINDING TRIGGER: If data is described as flowing into an analytics platform with weaker controls than the source, flag as HIGH.
FINDING TRIGGER: If personal data is used for a purpose beyond its collection basis without approval, flag as HIGH.

Control mapping: NIST SP 800-53 AC-3, AC-4, AU-2, MP-6, RA-2, SC-28; ISO/IEC 27001:2022 A.5.10, A.5.12, A.5.14, A.5.34, A.8.10, A.8.12; CIS AWS 2.1.1, 2.1.5; GDPR Articles 5, 15–20, 32; PCI DSS 4.0 3.x.
