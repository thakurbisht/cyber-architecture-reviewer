# PeopleHub HR Self-Service Portal — High-Level Design

Brightwater Logistics, HR Technology and Enterprise Architecture. Version 1.3.

## 1. Purpose and Scope

Brightwater Logistics employs about 3,000 people across its head office, 14 distribution centres and a field sales team. PeopleHub replaces paper forms and email-based HR requests with a single self-service portal. Employees view payslips, update personal and bank details, request leave and upload supporting documents; line managers approve requests for their teams; and approved pay-affecting changes are sent to the external payroll provider, Payfield Ltd.

This document covers the application, data stores, integrations, hosting, access control, data protection, operations and recovery. Payroll calculation, which Payfield performs, and recruitment are out of scope.

## 2. System Overview

Figure 1 shows the main components.

| Component | Technology | Responsibility |
|---|---|---|
| Web front end | React single-page app via Azure Front Door | Employee, manager and HR user interface |
| Portal API | .NET 8 on Azure App Service | Business logic, workflows, authorisation |
| HR database | Azure SQL Database | Employee master data, pay data, workflow state |
| Reporting replica | Azure SQL read-only replica | HR analytics and ad-hoc queries |
| Document store | Azure Blob Storage | Uploaded employee documents and payslips |
| Payroll export job | Azure Functions (timer trigger) | Nightly change file to Payfield |

PeopleHub is the system of record for employee data. The HR database holds national insurance numbers, bank account details, salary history and home addresses for all current employees and for former employees for six years after leaving.

Four user roles exist: Employee, Line Manager, HR Administrator and HR Analyst. Role membership is driven by groups in the corporate identity provider.

## 3. Key Workflows and Data Flows

### 3.1 Employee self-service

Employees update their address, emergency contacts and bank details, view and download payslips, and request leave. Employees can upload documents such as fit notes, certificates, right-to-work evidence and signed contracts, in any common office or image format.

### 3.2 Manager approvals

Line managers can view the salary, working pattern and absence history of employees in their organisation and approve or reject leave requests, overtime claims and pay changes. Approved pay changes then go to HR for final approval.

### 3.3 Payroll export

Every night at 01:00 the payroll export job builds a change file containing new starters, leavers, pay changes and updated bank account numbers and sort codes, and sends it to Payfield over the internet. The same job collects payslip PDFs from Payfield's SFTP server and stores them in the document store.

## 4. Hosting and Network Layout

PeopleHub runs in Azure UK South, with UK West as the recovery region. The portal is reachable from the internet at peoplehub.brightwater.co.uk so that distribution-centre and field staff can use it from personal phones and home computers.

Azure Front Door Premium is the only public entry point and connects to the App Service over Private Link. The App Service has public network access disabled and uses VNet integration for outbound traffic. Azure SQL, the storage account and Key Vault are reachable only through private endpoints in the PeopleHub VNet. Outbound internet traffic from the VNet, including the payroll export, passes through the central Azure Firewall with a static public IP address.

HR Analysts connect directly to the reporting replica with Power BI Desktop and SQL Server Management Studio to run ad-hoc queries, reaching the private endpoint from managed laptops over the corporate VPN.

## 5. Integrations

| Integration | Direction | Protocol | Purpose |
|---|---|---|---|
| Microsoft Entra ID | Inbound | OpenID Connect | Sign-in and group membership |
| Entra ID provisioning | Outbound | SCIM | Joiner, mover and leaver updates |
| Payfield Ltd | Outbound | SFTP | Change file upload, payslip download |
| Azure Communication Services | Outbound | HTTPS | Email notifications |

Notification emails contain only the request type and a link to the portal; they never include pay, bank or identity data.

## 6. Identity and Access Control

All users sign in through Microsoft Entra ID; PeopleHub has no local accounts. A Conditional Access policy requires phishing-resistant MFA for every PeopleHub sign-in, from both managed and personal devices, and blocks sign-ins from outside the UK and Ireland unless an exception is approved. Personal devices are limited to employee self-service: the HR Administrator role and manager views of team pay data are available only on compliant, Intune-managed devices, enforced by a Conditional Access device-compliance policy. The single-page app uses the authorisation code flow with PKCE and keeps tokens in memory only, and the API validates token signature, issuer and audience on every request. Idle sessions expire after 30 minutes.

Authorisation is enforced in the Portal API on every request. A line manager can read only records of employees who report to them directly or indirectly according to the reporting hierarchy held in PeopleHub; the API checks the requested employee ID against that hierarchy server-side, and bank details and national insurance numbers are never returned to the Line Manager role. Nobody can approve a request they raised themselves.

The HR Administrator role has no permanent members. It is activated through Entra Privileged Identity Management for up to eight hours with MFA and a written justification, and eligible assignments are reviewed quarterly. HR Administrators cannot change bank or salary fields on their own record, and every salary or bank-detail change they enter for any employee requires approval by a second HR Administrator before it reaches the payroll export.

HR Analysts sign in to the reporting replica with Entra ID accounts only; the HR-Analytics group can read a curated set of reporting views and has no access to base tables.

Changes to bank details require MFA re-authentication, trigger a notification to the employee's work and personal email addresses, and are held for 48 hours before being included in the payroll export.

Azure SQL uses Entra-only authentication, and the Portal API and the payroll export job use managed identities to access Azure SQL, Blob Storage and Key Vault, so no database passwords are stored. Leavers are disabled in Entra ID through SCIM within one hour of the termination being recorded.

## 7. Data Protection

Azure SQL uses Transparent Data Encryption with a customer-managed key in Key Vault (Premium, HSM-backed), and the storage account is encrypted with a customer-managed key. National insurance numbers and bank account details are additionally protected with Always Encrypted; the column master key is accessible only to the managed identities of the Portal API and the payroll export job, so these values remain ciphertext to database administrators and to anyone querying the reporting replica.

All client traffic uses TLS 1.2 or higher, terminated at Front Door and re-encrypted to the App Service; database and storage connections require TLS. Front Door applies a WAF policy with the managed OWASP rule set and rate limiting in prevention mode.

Uploaded files first land in a quarantine container. The API accepts only PDF, JPEG, PNG and DOCX files up to 20 MB and checks the file signature against the declared type. Microsoft Defender for Storage malware scanning must return a clean result before a file is moved to the main container. Files are served back as downloads from a separate domain with Content-Disposition: attachment, never rendered inline.

The payroll change file is signed with Brightwater's PGP key and encrypted with Payfield's PGP public key before transfer. It is uploaded by SFTP with key-based authentication to a single Payfield host whose host key is pinned, and Payfield allowlists Brightwater's firewall IP address. The SFTP key pair and the PGP signing key were generated during onboarding in 2023, are stored in Key Vault, and are replaced when Payfield requests a change.

## 8. Logging, Monitoring and Operations

Sign-in, PIM activation, role assignment and configuration-change events, together with Front Door WAF and Defender alerts, are forwarded to the corporate SIEM (Microsoft Sentinel) and retained for 12 months. The SOC has analytics rules for impossible travel, repeated MFA failures, PIM activations outside business hours and changes to the Conditional Access policy.

Record-level access events, recording which user viewed or changed which employee's pay, bank or identity data, are written by the Portal API to a Log Analytics workspace with 90-day retention. An Azure Monitor alert notifies the HR Systems team when a single user opens more than 50 distinct employee records within an hour.

Releases go through a CI/CD pipeline with pull-request review, static analysis and dependency scanning, and production deployments need approval from a second engineer. Test environments use synthetic data, and an external penetration test runs annually.

## 9. Backup and Disaster Recovery

Azure SQL point-in-time restore covers 35 days, and weekly long-term retention backups are kept for seven years in immutable storage. The storage account has versioning, soft delete and a time-based immutability policy on the document containers. The database is geo-replicated to UK West; the RPO is 15 minutes and the RTO four hours. Restores are tested every six months.
