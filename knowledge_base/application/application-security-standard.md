# Application Security Architecture Standard

Owner: Security Architecture / Application Architecture
Applies to: all internally developed and materially customised applications
Alignment: OWASP ASVS 4.0, OWASP API Security Top 10, NIST SSDF

## 1.1 Principle

An application design is assessed on where its trust boundaries sit and what happens when each one is crossed by an attacker rather than a user. Controls that live only in the user interface are usability features. Only controls enforced by the component that owns the data are security controls.

## 1.2 Trust boundary definition

Requirement: The design MUST identify every trust boundary — user to edge, edge to service, service to service, service to data store, and any boundary to a third party — and state the control enforced at each.

FINDING TRIGGER: If an application design contains no identified trust boundaries, flag as HIGH — no meaningful security review of the design is possible without them.

## 2.1 Tier separation

Requirement: Presentation, application and data tiers MUST be separately deployable and separately network-addressable. The data tier MUST NOT be reachable from the presentation tier.

FINDING TRIGGER: If the presentation tier connects directly to the database, flag as HIGH.
FINDING TRIGGER: If all tiers are described as sharing one host, one container, or one security group, flag as HIGH.

## 3.1 Authentication coverage

Requirement: Every endpoint MUST require authentication by default. Anonymous endpoints are permitted only for health probes and public metadata, MUST carry no business data, and MUST be individually listed in the design.

FINDING TRIGGER: If any API or service endpoint is described as unauthenticated, anonymous, or open, flag as CRITICAL unless it is on the listed exception set.
FINDING TRIGGER: If an internal API is unauthenticated because it is "only reachable internally", flag as CRITICAL and reference the Zero Trust Architecture Standard §2.1.

Compliant pattern: "All /api/v1 routes require a validated OAuth 2.0 access token; /health and /.well-known/jwks.json are anonymous and return no business data."
Non-compliant pattern: an endpoint is exempted from authentication on the grounds that only callers inside the network perimeter can reach it.

## 3.2 Authentication strength

Requirement: Interactive user authentication MUST use the enterprise identity provider via OIDC or SAML. Local application user stores are prohibited for employee-facing systems. Customer-facing systems MUST support MFA.

FINDING TRIGGER: If an application implements its own password store for employees, flag as HIGH.
FINDING TRIGGER: If password policy is described in the application rather than delegated to the IdP, flag as MEDIUM.

## 3.3 Machine-to-machine authentication

Requirement: Service-to-service calls MUST use short-lived credentials — workload identity, mTLS certificates, or the client-credentials grant with tokens under one hour. Static API keys are permitted only for third parties that cannot support OAuth, and MUST be rotated at least every 90 days.

FINDING TRIGGER: If a static, non-expiring API key is used for internal service-to-service calls, flag as HIGH.

## 3.4 Token handling

Requirement: JWT access tokens MUST be validated on every request for signature (against a pinned or cached JWKS), issuer, audience, expiry and not-before. The `none` algorithm MUST be rejected. Access token lifetime MUST NOT exceed 15 minutes; refresh tokens MUST rotate on use.

FINDING TRIGGER: If tokens are described as long-lived or non-expiring, flag as HIGH.
FINDING TRIGGER: If token validation is described as happening only at the gateway, flag as HIGH and cross-reference §3.6.
FINDING TRIGGER: If the algorithm is not pinned, flag as MEDIUM.

## 3.5 Session management

Requirement: Session cookies MUST be Secure, HttpOnly and SameSite=Lax or Strict. Session identifiers MUST be regenerated on privilege change. Idle timeout MUST NOT exceed 30 minutes for privileged sessions.

FINDING TRIGGER: If session cookie attributes are not specified in a design that uses cookie sessions, flag as MEDIUM.
FINDING TRIGGER: If session fixation protection is absent, flag as HIGH.

## 3.6 Authorisation enforcement

Requirement: Object-level and function-level authorisation MUST be enforced in the service that owns the resource, on every request. Gateway policy, UI element hiding, and client-side route guards are defence in depth only and never the primary control.

FINDING TRIGGER: If authorisation is described as enforced by the front end, the gateway alone, or by hiding UI elements, flag as HIGH.
FINDING TRIGGER: If a downstream service is described as trusting an identity header injected by an upstream component without verification, flag as HIGH — anything that can reach the service can forge that header.
FINDING TRIGGER: If the design does not state how a user is prevented from accessing another user's object by changing an identifier, flag as HIGH (OWASP API1: Broken Object Level Authorization).

## 4.1 Least privilege for the application

Requirement: The application's own identity MUST hold only the permissions it needs. Database accounts MUST NOT be schema owners or administrators.

FINDING TRIGGER: If the application connects to the database as a privileged or owner account, flag as HIGH.

## 5.1 Input validation

Requirement: All input crossing a trust boundary MUST be validated server-side against a positive (allow-list) schema covering type, length, range and format, and rejected on failure.

FINDING TRIGGER: If validation is described as client-side, flag as HIGH.
FINDING TRIGGER: If input is described as trusted because it originates from another internal service, flag as MEDIUM.

## 5.2 Injection prevention

Requirement: Database access MUST use parameterised queries or an ORM's binding API. Dynamic SQL built by string concatenation is prohibited. Operating-system command construction from input is prohibited.

FINDING TRIGGER: If dynamic SQL or string-concatenated queries are described, flag as CRITICAL.
FINDING TRIGGER: If user input reaches a shell, an eval, or a template engine without escaping, flag as CRITICAL.

## 5.3 Output encoding

Requirement: All output rendered into a browser context MUST be contextually encoded. A Content Security Policy MUST be defined for browser-delivered applications.

FINDING TRIGGER: If no CSP is described for a web application, flag as MEDIUM.

## 5.4 Deserialisation and file handling

Requirement: Untrusted data MUST NOT be deserialised into arbitrary types. Uploaded files MUST be type-verified by content, stored outside the web root, and scanned for malware.

FINDING TRIGGER: If file upload is described without content-type verification and malware scanning, flag as HIGH.

## 6.1 Secrets management

Requirement: No secret — password, API key, token, certificate private key, connection string — may appear in source code, configuration files committed to version control, container images, or design documents. Secrets MUST be held in the enterprise secret manager and injected at runtime, preferably via workload identity so no long-lived secret exists at all.

FINDING TRIGGER: If credentials are described as stored in code, configuration, environment files committed to the repository, or the design document itself, flag as CRITICAL.
FINDING TRIGGER: If secret rotation is not described, flag as MEDIUM.

Note for reviewers: a secret that has ever been committed is compromised and must be rotated, not merely removed. Recommendations should say so.

## 6.2 Certificate management

Requirement: TLS certificates MUST be issued from an approved CA with automated renewal. Self-signed certificates are permitted only inside a service mesh with its own trust anchor.

FINDING TRIGGER: If self-signed certificates are used on any boundary a user or partner crosses, flag as HIGH.
FINDING TRIGGER: If certificate expiry monitoring is not described, flag as LOW.

## 7.1 Error handling

Requirement: Error responses returned to clients MUST NOT contain stack traces, SQL, internal hostnames, or version information.

FINDING TRIGGER: If detailed errors are returned to clients, flag as MEDIUM.

## 7.2 Rate limiting and abuse

Requirement: Externally reachable endpoints MUST have per-principal rate limits, and resource-intensive operations MUST have quotas. Authentication endpoints MUST have lockout or progressive delay.

FINDING TRIGGER: If a public API is described without rate limiting, flag as MEDIUM.
FINDING TRIGGER: If a login endpoint has no brute-force protection, flag as HIGH.

## 7.3 Resilience

Requirement: Every outbound dependency call MUST have a timeout, a retry budget with jitter, and a circuit breaker. The design MUST state behaviour when each dependency is unavailable.

FINDING TRIGGER: If dependency failure behaviour is not described, flag as MEDIUM.
FINDING TRIGGER: If retries are described without backoff or a budget, flag as MEDIUM — retry storms convert a dependency blip into an outage.

## 8.1 Data in transit

Requirement: TLS 1.2 is the minimum, 1.3 preferred, for every hop including service-to-service inside the data centre. Plaintext HTTP is prohibited except on loopback.

FINDING TRIGGER: If plaintext HTTP or TLS below 1.2 appears anywhere, flag as CRITICAL.
FINDING TRIGGER: If internal service-to-service traffic is unencrypted because the network is trusted, flag as HIGH.

## 8.2 Logging from applications

Requirement: Applications MUST log authentication outcomes, authorisation failures, privilege changes and administrative actions in a structured format with a correlation identifier, and MUST NOT log secrets, full payloads, card data or personal data.

FINDING TRIGGER: If sensitive data is described as being written to logs, flag as HIGH.
FINDING TRIGGER: If security events are not logged, flag as HIGH — an incident in this application would be uninvestigable.

Control mapping: OWASP ASVS V2, V3, V4, V5, V6, V7, V9; OWASP API Top 10 API1, API2, API4, API8; NIST SP 800-53 AC-3, IA-2, IA-5, SI-10, SC-8, SC-28, AU-2; ISO/IEC 27001:2022 A.8.24, A.8.26, A.8.28.
