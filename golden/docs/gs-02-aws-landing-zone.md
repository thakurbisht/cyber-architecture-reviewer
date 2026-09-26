# Harbourline Mutual - AWS Landing Zone Design

Owner: Cloud Platform Team, Harbourline Mutual. Version 2.0.

## 1. Purpose and Scope

This document defines the multi-account AWS landing zone for Harbourline Mutual. It covers the organisation structure, service control policies, workforce identity, shared networking, centralised logging, security tooling and the data lake account. Workload designs are documented separately.

Harbourline Mutual underwrites motor, home and health insurance in Ireland and Germany. Policyholder data must remain in the EU, so eu-west-1 is the primary region and eu-central-1 the secondary region.

## 2. Design Principles

- One workload and one environment per account, created through the account vending pipeline.
- Preventive guardrails through SCPs, and detective guardrails through AWS Config conformance packs.
- All human access goes through IAM Identity Center federated with the corporate IdP, which enforces FIDO2 security-key MFA on every sign-in to the AWS application.
- No long-lived IAM user credentials, except for break-glass access.
- Centralised egress, inspection and DNS in the network account.

## 3. Organisation Structure

Figure 1 shows the OU hierarchy. The management account hosts only AWS Organizations, consolidated billing and IAM Identity Center, and runs no workloads. The account vending pipeline enrols every new account in the security baseline.

| OU | Accounts | Purpose |
|---|---|---|
| Security | hlm-log-archive, hlm-security-tooling | Central logging and security services |
| Infrastructure | hlm-network, hlm-shared-services | Transit Gateway, DNS, CI/CD runners |
| Workloads/Prod | 14 accounts, for example hlm-claims-prod | Production workloads |
| Workloads/NonProd | 22 accounts, for example hlm-claims-test | Development, test and staging |
| Data | hlm-datalake-prod | Enterprise data lake |
| Sandbox | 9 accounts, one per product team | Experimentation, no production data |
| Suspended | Closed accounts | Accounts pending closure |

The Data OU was introduced in this version and contains hlm-datalake-prod, which holds claims, policy and medical underwriting data for all business lines.

## 4. Service Control Policies

| SCP | Effect | Attached to |
|---|---|---|
| DenyNonEURegions | Denies actions outside eu-west-1 and eu-central-1, except global services | Security, Infrastructure, Workloads, Sandbox |
| DenyLeaveOrganization | Denies organizations:LeaveOrganization | Security, Infrastructure, Workloads, Sandbox |
| DenyRootUser | Denies all actions by the root user | Security, Infrastructure, Workloads, Sandbox |
| ProtectBaseline | Denies changes to Config, GuardDuty, CloudTrail, Flow Logs and baseline IAM roles | Security, Infrastructure, Workloads, Sandbox |
| DenyInternetGateways | Denies creation of internet, NAT and egress-only gateways | Workloads, Sandbox |
| ProtectLogArchive | Denies deletion of log buckets and changes to their policies, Object Lock settings and KMS keys | Security |
| DenyAll | Denies all actions | Suspended |

SCPs are attached at OU level as listed in Table 2.

## 5. Workforce Identity and Access

### 5.1 IAM Identity Center

IAM Identity Center uses the corporate IdP as its external identity provider through SAML 2.0, with users and groups provisioned by SCIM. No MFA settings are configured in IAM Identity Center itself. Permission sets are assigned to IdP groups, never to individual users, as shown in Table 3.

| Permission set | Policy | Assigned to | Scope |
|---|---|---|---|
| ViewOnly | ViewOnlyAccess | All engineers | Workloads and Infrastructure accounts |
| Developer | PowerUserAccess | Product teams | Workloads/NonProd accounts |
| ProdOperator | Custom operations policy | On-call engineers | Workloads/Prod accounts |
| SandboxAdmin | AdministratorAccess | All developers | Sandbox accounts |
| DataEngineer | Custom Lake Formation and Glue policy | Data engineering team | hlm-datalake-prod |
| SecurityAudit | SecurityAudit and log read access | Security team | All accounts |
| PlatformAdmin | AdministratorAccess | Cloud Platform team | All accounts except management and log archive |

PlatformAdmin is not assigned permanently: engineers request it through the temporary elevated access workflow, which grants it for up to four hours after approval by a second team member. Every developer receives the SandboxAdmin permission set, which grants AdministratorAccess in the sandbox accounts so that teams can experiment without raising tickets.

### 5.2 Break-glass access

Break-glass access uses two IAM users, bg-admin-1 and bg-admin-2, in the management account with the AdministratorAccess policy, which lets them assume OrganizationAccountAccessRole in every member account. Their passwords are stored in the infrastructure team's shared vault folder, which all 25 members of the infrastructure team can open. MFA is not enabled on the break-glass users, so that access does not depend on a hardware token being available during an incident.

Root user credentials for member accounts are removed through centralised root access management. The management account root user has a hardware MFA key kept in the CISO's safe.

### 5.3 Third-party access

Loss adjusters reach the partner-exchange bucket only through an AWS Transfer Family SFTP server, with one user per adjuster, SSH key authentication and a home directory restricted to their firm's prefix.

The Costwise cost-optimisation service is onboarded by deploying the CostwiseAutomation role to every member account with StackSets. The role has the AdministratorAccess policy so that Costwise can apply rightsizing and scheduling recommendations automatically, and its trust policy names the Costwise AWS account as the only principal.

## 6. Network Architecture

The hlm-network account owns a Transit Gateway in each region, shares it with the organisation through AWS RAM, and hosts the inspection VPC, the egress VPC with NAT gateways and the central Route 53 Resolver endpoints. Figure 2 shows the topology.

Each workload VPC has a single default route, 0.0.0.0/0, pointing to its Transit Gateway attachment.

All VPC attachments from the Workloads and Sandbox accounts, as well as the Direct Connect gateway attachment for the Harbourline data centres, are associated with one Transit Gateway route table and propagate their routes into it. Traffic between VPCs does not pass through the inspection VPC, so that east-west latency stays low.

On-premises connectivity uses two 10 Gbps Direct Connect connections from the Dublin and Frankfurt data centres, without an IPsec overlay, to avoid the throughput limit of VPN tunnels.

## 7. Internet Egress and Inspection

Workload VPCs have no internet or NAT gateways. Internet-bound traffic is routed by the Transit Gateway to the inspection VPC, where AWS Network Firewall applies a domain allowlist per environment and drops all other egress, before leaving through the egress VPC. Inbound traffic for public applications enters only through CloudFront and AWS WAF in front of Application Load Balancers in the ingress VPC of the network account. The central web ACLs run the AWS managed rule groups in count mode, and application teams can ask for blocking mode once they have finished tuning false positives.

## 8. Centralised Logging

An organisation trail in CloudTrail records management events for all accounts and regions and delivers them to the log archive account. S3 data events are recorded for all data lake buckets through advanced event selectors. VPC Flow Logs, Network Firewall logs, AWS Config snapshots and Route 53 Resolver query logs are also delivered to the log archive account.

Log buckets use SSE-KMS and S3 Object Lock in compliance mode with a retention period of one year, after which objects move to S3 Glacier Deep Archive for a further six years. Only the SecurityAudit permission set has read access to the log archive account.

## 9. Security Tooling and Monitoring

The hlm-security-tooling account is the delegated administrator for GuardDuty, Security Hub, IAM Access Analyzer, Amazon Macie and the AWS Config aggregator. GuardDuty and Security Hub are enabled in every account and both regions. Findings from GuardDuty, Access Analyzer and Macie are aggregated in Security Hub and reviewed by the security operations team at a weekly triage meeting.

## 10. Data Lake Account

hlm-datalake-prod hosts the enterprise data lake: raw, curated and partner-exchange zones in Amazon S3, catalogued in AWS Glue and governed by AWS Lake Formation. The raw and curated zones hold claims, policy and medical underwriting records for about 1.4 million policyholders. Amazon Macie scans all data lake buckets weekly.

Ingestion jobs in workload accounts deliver data by assuming the datalake-etl role, which has read and write access to all zones. Its trust policy allows sts:AssumeRole for any principal in the organisation, using the aws:PrincipalOrgID condition, so that new source systems can be onboarded without trust policy changes.

The partner-exchange zone (bucket hlm-dl-partner-exchange) is used to share claim files, including medical reports and repair assessments, with external loss adjusters.

## 11. Encryption and Key Management

Each account has customer-managed KMS keys per data classification, with automatic annual rotation and key policies managed by the landing zone pipeline. All data lake buckets use SSE-KMS with these keys, and S3 Block Public Access is enforced at account level in every account. Both Direct Connect connections use MACsec encryption at layer 2, with the connectivity association keys stored in AWS Secrets Manager in the network account. All S3 buckets carry a bucket policy that denies requests not made over TLS.
