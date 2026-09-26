# Kestrel Token Vault (KTV) Release 2 — High-Level Design

Payments Platform Engineering, Kestrel Merchant Services. Version 2.1.

## 1. Purpose and Scope

Kestrel Merchant Services processes card payments for about 18,000 merchants. The Kestrel Token Vault (KTV) replaces primary account numbers (PANs) with surrogate tokens at the point of entry, so that downstream systems such as reporting, fraud analytics and billing handle only tokens and stay out of PCI DSS scope.

Release 2 moves the vault from an on-premises appliance to AWS. This document covers the APIs, datastore, key management, cardholder data environment (CDE) network, access control, logging and recovery; the merchant gateway and authorisation switching have separate designs.

## 2. Architecture Overview

Figure 1 shows the logical architecture. KTV runs in the dedicated AWS account ktv-cde-prod, in eu-central-1 across three Availability Zones, with a warm standby in eu-west-1.

| Component | Technology | Purpose |
|---|---|---|
| Tokenization API | Go service on Amazon EKS | Accepts PANs and returns tokens |
| Detokenization API | Same codebase, separate deployment | Returns the PAN for a token to authorised callers |
| Vault datastore | Amazon Aurora PostgreSQL | Stores token records |
| HSM cluster | AWS CloudHSM (FIPS 140-2 Level 3), three HSMs | Holds keys; performs encryption, decryption and HMAC |
| Audit pipeline | Fluent Bit sidecars, Amazon Kinesis | Ships audit events to the SIEM |

Callers in the merchant gateway account reach KTV only through an AWS PrivateLink endpoint service. The CDE VPC has no internet gateway and no NAT gateway; its only outbound paths are VPC interface endpoints for AWS services.

Application and audit logs from the CDE are forwarded to the corporate SIEM, which is hosted in the shared security tooling account outside the cardholder data environment.

A nightly AWS Backup job copies vault database snapshots to a separate AWS account, ktv-backup, for long-term retention.

## 3. Data Flows

### 3.1 Tokenization

1. A merchant gateway service calls `POST /v2/tokens` with the PAN and expiry date.
2. The Tokenization API validates the input (length 13–19, Luhn check, known BIN range) and asks the HSM for an HMAC of the PAN, which is used to find an existing token.
3. If none exists, the service generates a token, the HSM encrypts the PAN and expiry date, and the token, ciphertext, HMAC value and merchant identifier are written to the vault datastore.
4. The token is returned to the caller.

Card numbers are stored in the vault database alongside the token, the card expiry date and the merchant identifier. Tokens are 16 digits long, deliberately fail the Luhn check, and keep the last four digits of the original card number so that receipts and customer-care screens can display them.

### 3.2 Detokenization

Settlement and chargeback processing need the full PAN for scheme clearing files. The Detokenization API accepts a token and returns the full PAN in the response body. The HSM decrypts the stored ciphertext, and the plaintext PAN exists in service memory only for the duration of the request.

## 4. Network Design

The CDE VPC (10.60.0.0/20) contains three subnet tiers in each Availability Zone: endpoint subnets for the PrivateLink Network Load Balancer, application subnets for the EKS worker nodes, and data subnets for Aurora and the CloudHSM network interfaces. Figure 2 shows the security group matrix. Security groups permit only NLB to pods on 8443, pods to Aurora on 5432, pods to CloudHSM on 2223–2225, and pods to VPC endpoints on 443. Network ACLs deny all other traffic between tiers.

The EKS cluster runs only KTV workloads and has a private-only API endpoint. There is no VPC peering or Transit Gateway attachment between the CDE VPC and any other VPC.

All caller traffic uses mutual TLS 1.2 or higher. The NLB passes TCP through and TLS terminates in the KTV pods. Pods connect to Aurora over TLS with full certificate verification, and the CloudHSM client uses its end-to-end encrypted channel to the HSMs.

## 5. Identity and Access Management

### 5.1 Service identity

Each caller presents a client certificate from the Payments private CA (AWS Private CA); KTV maps its subject alternative name to a client identity and applies a per-operation allowlist and per-client rate limit.

| Operation | Permitted client identities |
|---|---|
| Tokenize | merchant-gateway-ecom, merchant-gateway-pos, recurring-billing |
| Detokenize | settlement-batch, chargeback-svc |
| Token metadata (last four digits, card brand) | merchant-reporting, customer-care |

The detokenize operation is restricted to the settlement-batch and chargeback-svc identities; requests presenting any other certificate are rejected with HTTP 403 before the vault is queried.

Workload client certificates are issued by the Payments private CA with a three-year validity and are renewed manually by the platform team ahead of expiry. Revoked certificates are published in a CRL that KTV refreshes every 15 minutes.

Pods use IAM Roles for Service Accounts; the tokenize and detokenize deployments have separate roles, each limited to its own secrets and Kinesis stream. Tokenize pods use an HSM crypto user limited to encrypt and HMAC operations, and only the detokenize deployment holds the decrypt-capable HSM user. Aurora and HSM credentials are held in Secrets Manager and rotated every 30 days.

### 5.2 Human access

No engineer has standing access to ktv-cde-prod. Access is requested through the corporate PAM tool, approved by a second engineer, requires FIDO2 MFA at the corporate IdP and expires after four hours. PAM sessions are recorded.

HSM crypto-officer operations use CloudHSM quorum authentication: two of the three designated key custodians must approve each key-management command.

A break-glass IAM user exists for use when the IdP or PAM tool is unavailable; its password and hardware MFA token are split between two custodians and kept in the corporate safe. Break-glass sessions are reviewed during the monthly access review.

## 6. Data Protection and Key Management

The vault stores PANs and expiry dates only as AES-256-GCM ciphertext under data-encryption keys generated and held in the CloudHSM cluster; encryption and decryption happen inside the HSM and keys never leave it in plaintext. The HMAC lookup value uses a separate HSM-resident key, so the lookup column cannot be reversed or brute-forced without HSM access.

Token digits other than the last four are generated by the HSM random number generator and have no mathematical relationship to the PAN, so a token cannot be converted back without a vault lookup. Showing only the last four digits is within the masking permitted by PCI DSS Requirement 3.4.1.

Aurora storage, snapshots and worker-node volumes are also encrypted with customer-managed KMS keys that have automatic annual rotation. Data-encryption keys and the HMAC key are rotated annually under dual control, and a background job re-encrypts records and recomputes lookup values within 90 days of each rotation.

Key material is copied between HSM clusters only as encrypted CloudHSM backups; keys are never exported in plaintext outside an HSM boundary.

## 7. Logging and Monitoring

Every API call produces an audit event with client identity, operation, token, result and request ID. PANs, expiry dates and CVV values are never written to logs; the Fluent Bit sidecar also drops any 13–19 digit sequence that passes a Luhn check before events leave the pod. Events travel over TLS through Kinesis to the SIEM and are retained for 12 months, the latest three immediately searchable. CloudTrail for the account is delivered to the organisation log-archive account with S3 Object Lock.

The Security Operations Centre triages the following SIEM alerts 24x7:

| Alert | Trigger |
|---|---|
| Detokenize volume | A client exceeds 150% of its 30-day hourly baseline |
| Rejected caller | Any HTTP 403 on the detokenize operation |
| HSM administration | Any crypto-officer login or key-management command |
| CDE configuration change | Changes to IAM policies, security groups, NACLs or route tables |
| Production access | Any PAM access grant to ktv-cde-prod |

GuardDuty and Security Hub findings are forwarded to the SIEM.

## 8. Build and Platform Hardening

CI builds, scans and signs container images with cosign; an admission controller rejects unsigned images. Pods run as non-root with read-only root filesystems. Worker nodes use Bottlerocket, and critical patches are applied within 14 days. An external penetration test runs annually and after significant changes, and CDE segmentation testing runs every six months.

## 9. Backup and Disaster Recovery

Aurora point-in-time recovery covers 35 days. The ktv-backup account stores the nightly snapshots in an AWS Backup vault with Vault Lock in compliance mode and one-year retention. Snapshots contain only HSM-encrypted PANs and are additionally encrypted with a KMS key owned by the backup account, which is within the PCI DSS assessment scope and has no standing human access.

The warm standby in eu-west-1 uses an Aurora Global Database secondary and a second CloudHSM cluster. The CloudHSM cluster in eu-west-1 holds copies of all production data-encryption keys so that detokenization can continue after a regional failover. The RPO is five minutes and the RTO two hours. Failover is exercised twice a year, including a restore from the backup vault.
