---
name: detecting-cloud-iam-misconfigurations
domain: Cloud Security
subdomain: Identity & Access Management
severity: CRITICAL
description: Analyze cloud architecture documents to identify overly permissive IAM policies, missing MFA enforcement, privilege escalation paths, and cross-account access vulnerabilities across AWS, Azure, and GCP. Review role definitions, policy statements, and service account configurations for OWASP Top 10 and NIST CSF violations.
tags: [cloud, iam, aws, azure, gcp, privilege-escalation, least-privilege, mfa]
author: pramod-singh-bisht
version: '1.0'
license: Apache-2.0
mitre_attack: [T1526.004, T1538, T1526, T1078.001]
nist_csf: [PR.AC.1, PR.AC.3, PR.AC.4, DE.CM.1]
mitre_d3fend: [D3-CSPM, D3-IAM]
frameworks: [CSF, ATT&CK, D3FEND]
platforms: [AWS, Azure, GCP]
---

# Detecting Cloud IAM Misconfigurations

## When to Use

- Reviewing cloud infrastructure architecture documents with IAM configuration details
- Assessing privilege management across AWS, Azure, or GCP cloud environments
- Auditing service account permissions and role definitions
- Validating compliance with least-privilege access principles
- Identifying privilege escalation paths in cloud environments

## Prerequisites

- Design document describing cloud infrastructure and IAM setup
- Understanding of cloud-specific IAM concepts (roles, policies, service accounts)
- Knowledge of NIST CSF and OWASP security principles

## Instructions

### Step 1: Identify Overly Permissive Policies

Look for patterns indicating excessive permissions:

**AWS Red Flags:**
- `"Effect": "Allow" + "Action": "*" + "Resource": "*"` — unrestricted access across all services
- `"Action": "iam:*"` without resource constraints — full IAM control
- `"Action": "s3:*"` on all buckets — no specific bucket scoping
- `"Action": "kms:Decrypt"` without key restrictions — decrypt any data
- Inline policies on roles (should use AWS managed or customer managed policies)
- Old AWS managed policies (PowerUserAccess, AdministratorAccess) without lifecycle review

**Azure Red Flags:**
- Owner role assigned at subscription level — should be scoped to resource group
- `Microsoft.Authorization/*` permissions without resource constraints
- Contributor role on shared subscriptions — no isolation between tenants
- No conditional access policies for privileged roles
- Service principal with permanent credentials (should use managed identity)
- Application secrets older than 6 months without rotation evidence

**GCP Red Flags:**
- `roles/owner` at project level — should be organization level with constraints
- `roles/editor` on service accounts — should use custom roles with specific permissions
- User-managed keys on service accounts (should use workload identity federation)
- `compute.instances.create` without image restrictions — could create instances with malware
- IAM bindings on individual resources instead of using folder-level hierarchy

### Step 2: Check MFA Enforcement

Verify multi-factor authentication is required for sensitive operations:

**AWS:**
- Are privileged users required to authenticate via MFA?
- Is MFA enforced for console login AND programmatic access (AWS API)?
- Are MFA-protected API actions defined in IAM policies?
- Example pattern: `"StringEquals": {"aws:MultiFactorAuthPresent": "true"}`

**Azure:**
- Is MFA enforced via conditional access policies?
- Are privileged roles (Global Admin, Privileged Role Admin) requiring MFA?
- Is passwordless sign-in (Windows Hello, FIDO2) in use?
- Example: Conditional Access policy requiring MFA for all users in "Admins" group

**GCP:**
- Are service accounts using workload identity or short-lived credentials?
- Is Cloud Identity enforcing MFA for all administrative users?
- Are API keys restricted (not using API keys for service-to-service auth)?

### Step 3: Detect Privilege Escalation Paths

Look for permission combinations that allow privilege escalation:

**AWS Escalation Patterns:**
- User with `iam:CreateAccessKey` but not `iam:ListAccessKeys` — can create unlimited keys
- User with `ec2:RunInstances` + `iam:PassRole` — can assume arbitrary roles via EC2
- User with `lambda:CreateFunction` + `iam:PassRole` — can execute code as privileged role
- User with `iam:AttachUserPolicy` — can attach policies to own account
- User with `sts:AssumeRole` + `iam:UpdateAssumeRolePolicy` — can escalate via role modification

**Azure Escalation Patterns:**
- Service principal with Directory.Write permissions — can modify Azure AD
- Service principal with Application.ReadWrite.All — can register new OAuth apps
- User with Privileged Role Administrator role — can enable activation for any role
- Custom role with `Actions: ["*"]` and no NotActions — full unrestricted access

**GCP Escalation Patterns:**
- Service account with `iam.serviceAccountUsers` — can impersonate other service accounts
- Service account with `resourcemanager.organizations.setIamPolicy` — can modify org-level IAM
- User with `compute.admin` and `iam.securityAdmin` — can create instances and assign permissions

### Step 4: Audit Cross-Account Access

Identify and validate cross-account/cross-tenant permissions:

**AWS:**
- Review `"Principal": {"AWS": "arn:aws:iam::ACCOUNT-ID:*"}` — restrict to specific principals
- Check S3 bucket policies for `"Principal": "*"` — should require specific account/principal
- Verify cross-account role assume policies use external ID (`sts:ExternalId`)
- Ensure CloudTrail logging captures cross-account API calls

**Azure:**
- Review cross-tenant access policies (B2B collaboration)
- Verify service principals can only access intended tenants
- Check for guest user access with excessive permissions
- Audit token lifetime policies for cross-tenant scenarios

**GCP:**
- Verify shared folder/project access requires explicit organization policy
- Check cross-project IAM bindings — should use custom roles, not predefined
- Review Service Account impersonation between projects — should be explicit per account
- Audit VPC-SC (VPC Service Controls) perimeters for proper isolation

### Step 5: Verify Service Account Hardening

Examine service account configurations for security gaps:

**AWS:**
- Are IAM user access keys rotated every 90 days?
- Does each service have its own dedicated IAM user/role?
- Are unused access keys disabled/deleted?
- Are programmatic access credentials stored in Secrets Manager, not in code?

**Azure:**
- Are managed identities used instead of service principal passwords?
- Do service principals have certificate credentials with expiration dates?
- Are service principal credentials stored in Key Vault?
- Are old/orphaned service principals deleted?

**GCP:**
- Are service accounts using Workload Identity Federation instead of key files?
- Do service account key files have restricted file permissions (0400)?
- Are external identity providers configured with proper audience/issuer?
- Are unused service accounts and keys deleted?

## Finding Template

When a misconfiguration is identified, document it with this structure:

```
Issue: [Description of misconfiguration]
Severity: CRITICAL | HIGH | MEDIUM
Affected: [Cloud Provider, Specific Component]
Pattern Found: [Exact text/configuration from document]
MITRE ATT&CK: [Specific tactic and technique]
NIST CSF: [Specific function and category]

Recommendation:
[Specific remediation steps with code example if applicable]

Example (AWS):
Pattern: "Effect": "Allow" + "Action": "s3:*" + "Resource": "*"
Remediation: Restrict to specific bucket and actions:
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

## Examples

### Example 1: AWS — Overly Permissive Policy

**Document Section:**
```
EC2 instances assume an IAM role named "application-role" with the following policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**Finding:**
```
Issue: IAM role "application-role" has unrestricted permissions (Action: *, Resource: *)
Severity: CRITICAL
Pattern: "Effect": "Allow", "Action": "*", "Resource": "*"
MITRE ATT&CK: T1526.004 (Enumerate Cloud Resources)
NIST CSF: PR.AC.1 (Processes and procedures)

Recommendation: Replace with least-privilege policy:
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "dynamodb:Query", "logs:CreateLogStream"],
  "Resource": [
    "arn:aws:s3:::app-bucket/data/*",
    "arn:aws:dynamodb:region:account:table/app-table",
    "arn:aws:logs:region:account:log-group:/aws/ec2/app-*"
  ]
}
```

### Example 2: Azure — Missing MFA for Admin Access

**Document Section:**
```
Azure setup includes:
- Global Admin accounts used for daily operations
- No conditional access policies enforcing MFA
- Legacy protocol access (ActiveSync, IMAP) allowed
```

**Finding:**
```
Issue: Global Admin accounts lack MFA enforcement
Severity: CRITICAL
MITRE ATT&CK: T1078.001 (Valid Accounts — Default Accounts)
NIST CSF: PR.AC.3 (Physical, logical, and cloud access)

Recommendation: Implement conditional access policy requiring MFA for all users with Global Admin role
```

### Example 3: GCP — Service Account Privilege Escalation

**Document Section:**
```
Service account "app-sa@project.iam.gserviceaccount.com" has roles:
- roles/iam.securityAdmin (can modify IAM policies)
- roles/compute.admin (can create/modify VMs)
```

**Finding:**
```
Issue: Service account has conflicting privileged roles (iam.securityAdmin + compute.admin)
Severity: CRITICAL
Pattern: Service account with T1078 valid account + T1526 enumerate permissions
MITRE ATT&CK: T1526 (Enumerate Cloud Resources), T1078.001 (Valid Accounts)
NIST CSF: PR.AC.4 (Access control policy)

Recommendation: Create separate service accounts with minimal roles:
- app-sa-compute: only roles/compute.instanceAdmin
- app-sa-iam: only roles/iam.securityReviewer (read-only)
```

## Success Criteria

This skill successfully identifies cloud IAM misconfigurations when:

✓ Detects Action: "*" patterns with unrestricted Resource scope  
✓ Identifies missing MFA on privileged user accounts  
✓ Finds privilege escalation chains (e.g., PassRole + CreateFunction)  
✓ Validates cross-account access uses explicit principals  
✓ Confirms service accounts use minimal privilege roles  
✓ Generates findings with MITRE ATT&CK and NIST CSF mappings  

## Reference Standards

- NIST CSF 2.0: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04232023.pdf
- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Azure Security Best Practices: https://docs.microsoft.com/en-us/azure/security/
- GCP Security Best Practices: https://cloud.google.com/docs/security
