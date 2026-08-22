# High Level Design: Helios Cloud Landing Zone and Analytics Platform

Document ID: HLD-CLD-2026-007
Author: Cloud Platform Engineering
Status: For design authority review

## 1. Purpose and Scope

Helios establishes the organisation's landing zone in AWS and hosts the customer analytics platform. It covers account structure, network topology, identity, data storage, and the analytics pipeline that ingests customer transaction data from the on-premise estate.

## 2. Account Structure

All Helios workloads are deployed into a single AWS account, `helios-prod` (account 4455-6677-8899). Production, development and test workloads are separated by resource tags and by naming convention on resource groups. This keeps the account count low and avoids the operational overhead of cross-account role management.

The account is not currently under an AWS Organization. Guardrails such as Service Control Policies are planned for a later phase once the platform is stable.

The root user of the account is used by the platform team for occasional administrative tasks that the delegated roles do not permit. An access key exists on the root user for automation of billing exports.

## 3. Identity and Access

Engineers access the account through IAM users created manually, each with a console password and an access key. Federation to the corporate identity provider is on the roadmap for next year.

MFA is enabled for the platform team leads. Other engineers have MFA optional to reduce friction during the build phase.

The analytics application runs under an IAM role, `helios-analytics-role`, with the `AdministratorAccess` managed policy attached. This was applied during development to avoid permission errors and has not yet been narrowed, as determining the exact permission set requires effort that has not been scheduled.

The CI/CD pipeline uses an IAM user with a long-lived access key stored in the pipeline's secret store.

## 4. Network Topology

A single VPC, `helios-vpc` (10.40.0.0/16), hosts all workloads across three availability zones.

Subnet layout:

| Subnet | CIDR | Type | Contents |
|---|---|---|---|
| helios-public-a/b/c | 10.40.1-3.0/24 | Public | Load balancers, NAT gateways, analytics EC2 instances |
| helios-data-a/b/c | 10.40.11-13.0/24 | Public | RDS PostgreSQL cluster, Redis cache |
| helios-mgmt-a | 10.40.21.0/24 | Public | Bastion host |

The RDS cluster is placed in a public subnet so that the on-premise analytics team can connect directly with their desktop SQL tools during the migration period.

Security group `helios-db-sg` permits inbound TCP 5432 from 0.0.0.0/0, as the on-premise NAT addresses change frequently and maintaining an allow list was found to be operationally burdensome.

Security group `helios-bastion-sg` permits inbound TCP 22 from 0.0.0.0/0.

Egress from all subnets is unrestricted to the internet through the NAT gateways, as the analytics workloads pull open-source packages and public datasets at runtime.

There is no WAF in front of the public load balancer. The application load balancer's default protections are considered sufficient.

## 5. Data Platform

### 5.1 Ingestion

Customer transaction data is exported nightly from the on-premise core banking platform and uploaded to the S3 bucket `helios-raw-ingest`. The upload uses an IAM user access key embedded in the on-premise export script.

### 5.2 Storage

| Bucket | Purpose | Access |
|---|---|---|
| helios-raw-ingest | Landing zone for nightly exports | Bucket policy grants s3:GetObject to Principal "*" so the downstream partner analytics tool can read it without credential exchange |
| helios-curated | Cleaned datasets | Restricted to helios-analytics-role |
| helios-reports | Generated PDF reports for business users | Public read, so reports can be shared by link with regional offices |

S3 Block Public Access is disabled at the account level to allow the above bucket policies to take effect.

Default S3 encryption uses SSE-S3 with AWS-managed keys. Customer-managed keys were considered but add operational complexity.

The RDS cluster has encryption at rest enabled. Automated snapshots are retained for 7 days in the same account.

### 5.3 Data content

The ingested data contains customer names, national identity numbers, account numbers, transaction amounts and merchant details. The dataset also contains full payment card numbers for card transactions, as the source extract includes them and filtering them at source would require a change to the core banking export.

The data classification of these datasets has not been formally recorded. Data residency requirements have not been assessed; the account is deployed in eu-west-1 and buckets have cross-region replication enabled to us-east-1 for durability.

Retention is indefinite so that historical analysis remains possible.

## 6. Analytics Workloads

Analytics jobs run on EC2 instances in the public subnets with public IP addresses assigned, so that the data science team can SSH to them directly from home during on-call.

Instances are built from a community AMI selected for its pre-installed data science tooling. The AMI has not been reviewed against the hardening baseline. The base operating system is CentOS 7.

Jupyter notebooks run on the instances on port 8888, protected by a shared token that is distributed to the data science team via the team chat channel.

## 7. Infrastructure Provisioning

The initial environment was built by hand through the AWS console. Terraform has been introduced for new resources, but the existing estate has not been imported. There is no policy scanning of Terraform templates and no drift detection. Terraform state is stored in an S3 bucket without versioning enabled.

## 8. Logging and Monitoring

CloudTrail is enabled in eu-west-1 only, writing to a bucket in the same `helios-prod` account. Log file validation is not enabled.

VPC Flow Logs are not enabled. GuardDuty is not enabled. AWS Config is not enabled.

CloudWatch alarms exist for instance CPU and RDS storage. There are no security-related alarms and nothing is forwarded to the enterprise SIEM.

## 9. Backup and Recovery

RDS automated backups run daily with 7 day retention in the same account. S3 buckets have versioning disabled to control storage cost.

There is no immutable or offline backup copy. Restore procedures have not been documented or tested.

No RTO or RPO has been agreed with the business.

## 10. Compliance Position

The platform will hold regulated customer data. A privacy impact assessment has not been completed. No penetration test is planned before go-live.
