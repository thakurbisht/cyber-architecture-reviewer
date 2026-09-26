# Tellwater Workforce Identity Platform - High-Level Design

Owner: Identity and Access Management team, Tellwater Group. Version 2.0.

## 1. Purpose and Scope

This document describes the workforce identity platform for Tellwater Group, which serves about 8,000 employees and 600 contractors in 14 countries. It covers the cloud identity provider (IdP), synchronisation with on-premises Active Directory, single sign-on, authentication and MFA, conditional access, privileged access, the joiner-mover-leaver process, helpdesk account recovery, service accounts and identity monitoring. Customer identity is out of scope and is described in a separate design.

## 2. Identity Landscape

The HR information system (HRIS), a SaaS product, is the authoritative source for employee and contractor records. On-premises Active Directory (corp.tellwater.net) remains in use for Windows servers, file shares and about 40 legacy applications. The cloud IdP is the sign-in service for all cloud and SaaS applications.

Figure 1 shows the main components and flows: the HRIS feeds the provisioning engine, which creates accounts in AD and the cloud IdP; the directory sync server keeps AD and the IdP aligned; and all identity logs flow to the SIEM.

Any employee can invite external guests into the tenant to collaborate in shared workspaces and document libraries, and guest accounts remain active until the inviting employee removes them.

## 3. Directory and Synchronisation

A directory synchronisation agent on the server IDSYNC01 synchronises users, groups and devices from AD to the cloud IdP every 30 minutes and uses password hash synchronisation, so that users have one password for both directories. The agent's AD connector account holds the Replicate Directory Changes and Replicate Directory Changes All permissions required for password hash synchronisation. The Tier 0 administrative OU is excluded from synchronisation, so AD administrative accounts do not exist in the cloud.

Legacy applications authenticate users with LDAP simple binds to the domain controllers on port 389; LDAP signing and channel binding are not enforced because several of these applications do not support them. Remote access to on-premises applications is provided only through the IdP application proxy, which applies the same conditional access policies as cloud applications.

## 4. Single Sign-On and Application Integration

Of the 64 business applications in scope, 53 use SAML 2.0 or OpenID Connect single sign-on through the cloud IdP, and user provisioning to 31 of them is automated with SCIM. The remaining 11 applications, including the expense platform, the contract repository and the design collaboration tool, keep local username and password accounts that each application owner creates on request.

In-house web applications integrate using OpenID Connect with the implicit grant, so that their single-page front ends receive access tokens directly in the redirect URL fragment.

SAML signing certificates are rotated every two years, and new certificates are published in the IdP metadata 30 days before they take effect.

## 5. Authentication and MFA

All users authenticate to the cloud IdP with a password and MFA. The standard method is authenticator app push with number matching; SMS and voice calls are not permitted. Administrators and the finance payments team use FIDO2 security keys. Passwords must be at least 14 characters, are checked against a banned-password list, and do not expire on a schedule.

New starters sign in for the first time with a temporary access pass rather than a password and MFA, and then register their authenticator app.

Basic authentication for IMAP, POP3 and SMTP AUTH remains enabled on the mail platform for all mailboxes, to support scan-to-email printers and two finance applications.

## 6. Conditional Access

Conditional access policies are evaluated for every sign-in to the cloud IdP. The baseline policy requires MFA for all users and all applications at all locations, for sign-ins from browsers and modern authentication clients. Sign-ins rated high risk are blocked, and medium-risk sign-ins require a fresh MFA challenge. Access from unmanaged devices is limited to browser sessions with downloads blocked, and the finance and HR applications require a compliant, company-managed device. Browser sessions last 12 hours, and refresh tokens are revoked when a password is reset or an account is disabled.

Two emergency access accounts are excluded from every conditional access policy, including the MFA requirement, so that administrators can recover the tenant if the policies or the MFA service fail.

Accounts in the Service-Accounts group are excluded from the baseline MFA policy because they cannot complete an interactive MFA challenge.

## 7. Privileged Access

Cloud administrative roles are held by separate cloud-only admin accounts and are assigned as eligible rather than active. Activation lasts at most four hours, requires a FIDO2 key and, for Global Administrator, approval by a second administrator. Six accounts are eligible for Global Administrator.

Each emergency access account signs in only with its own FIDO2 security key, and the two keys are held in separate safes by the CISO and the Head of Infrastructure. Any sign-in by either account raises a priority 1 alert to the SOC, and both accounts are tested every quarter.

Active Directory follows a tiered administration model. Tier 0 contains the domain controllers, the PAM vault and the AD certificate authority. All other Windows servers, including IDSYNC01, are Tier 1 and are administered by the 45-member Server Operations group. Tier 0 administrators use dedicated privileged access workstations, and Domain Admin credentials are checked out from the PAM vault for at most two hours with session recording.

## 8. Joiner, Mover, Leaver

The HRIS sends joiner, mover and leaver events to the provisioning engine through a webhook that is published on the internet, because the HRIS is hosted by its vendor. The webhook accepts an event when the payload contains a valid employee ID, and the provisioning engine then creates, updates or disables the matching AD and IdP accounts.

Joiner accounts are created five days before the start date, with birthright groups assigned from the department and job code. The temporary access pass is single-use, valid for eight hours, and issued in person by local IT after checking the new starter's government photo ID.

When an employee changes role, the provisioning engine adds the birthright groups for the new role, and access from the previous role is kept until it is removed in the annual access review.

When HR records a termination, the provisioning engine disables the user's AD and IdP accounts within one hour and revokes active IdP sessions and refresh tokens. Applications connected through SCIM receive the deactivation automatically. Contractor accounts expire on the contract end date held in the HRIS.

## 9. Helpdesk and Account Recovery

Users can reset a forgotten password themselves in the IdP portal after completing an MFA challenge, and the change is written back to AD. The service desk handles about 1,400 password and MFA calls per month from users who cannot self-serve.

Callers are verified by stating their employee ID and the name of their line manager. After verification, the agent can reset the password and remove the registered MFA methods for any user, so that the caller can register new methods at the next sign-in.

## 10. Service Accounts

About 350 AD service accounts support on-premises applications and scheduled jobs; each has a named owner and is reviewed annually. Group managed service accounts are used wherever the application supports them. Service accounts are blocked from all cloud IdP sign-ins by a dedicated conditional access policy, are denied interactive logon in AD, and use vaulted 32-character passwords rotated every 90 days.

Automation that calls the IdP administration API, including the provisioning engine, uses workload identities with certificate credentials and is granted only the roles it needs.

## 11. Logging and Monitoring

Cloud IdP sign-in and audit logs and AD security event logs are streamed to the SIEM and retained for 13 months. The SOC's identity detections cover impossible travel, password spraying, sign-ins from anonymising networks, changes to conditional access policies, federation settings and privileged role assignments, and any sign-in by the emergency access accounts. Access reviews run quarterly for privileged roles and annually for all other groups.
