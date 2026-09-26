---
name: detecting-application-authentication-gaps
domain: Application Security
subdomain: Authentication & Session Management
severity: CRITICAL
description: Analyze application architecture to identify missing MFA enforcement, unauthenticated endpoints, weak credential handling, insufficient session management, and CSRF protection gaps. Review authentication boundaries, API design, and credential storage mechanisms.
tags: [application-security, authentication, mfa, api-security, credential-management, session-management, csrf]
author: pramod-singh-bisht
version: '1.0'
license: Apache-2.0
mitre_attack: [T1110, T1555, T1556.005, T1078, T1059.003]
nist_csf: [PR.AC.1, PR.AC.7, DE.CM.1]
mitre_d3fend: [D3-AUTH, D3-MFA, D3-CRED]
frameworks: [CSF, ATT&CK, D3FEND]
---

# Detecting Application Authentication Gaps

## When to Use

- Reviewing application architecture documentation for authentication flow
- Assessing user management and credential handling practices
- Auditing API authentication and authorization design
- Validating compliance with OWASP Top 10 authentication controls
- Checking session management implementation

## Prerequisites

- Application architecture diagram or design document
- API specifications or endpoint documentation
- Authentication flow description
- Credential handling and storage approach

## Instructions

### Step 1: Identify Unauthenticated Endpoints

Examine which endpoints require authentication:

**Critical Red Flags:**

**User Data Endpoints Without Auth:**
- User profile data accessible without login → IDOR (Insecure Direct Object Reference)
- User's personal data exported without ownership verification
- Search functions returning private user data in results
- History/activity logs accessible without authentication

**API Endpoints Missing Auth:**
- API endpoints with no API key/token requirement
- Webhooks callable without signature verification
- Admin API accessible with same auth as public API
- Debug/diagnostic endpoints left accessible in production
- `/api/users` endpoint returns all users without auth

**Administrative Functions Without Auth:**
- Admin panel accessible without login
- Configuration export/import without authentication
- User management (create/delete/modify) without auth check
- Permission modification without proper auth
- Backup/restore functions available to unauthenticated users

**Specific Patterns to Find:**

❌ `GET /api/users/{id}` — no auth header required, returns all user data  
✅ `GET /api/users/me` — requires auth header, returns authenticated user only  

❌ `POST /api/users` — no API key, anyone can create accounts  
✅ `POST /api/admin/users` — requires admin token, rate limited  

### Step 2: Verify MFA Enforcement

Check multi-factor authentication implementation:

**Mandatory MFA Scenarios:**

**Privileged Access (CRITICAL):**
- Administrative console login — MFA required
- User account creation/deletion — MFA required
- Role/permission changes — MFA required
- API key generation — MFA required
- System configuration changes — MFA required

**Sensitive Operations (HIGH):**
- Password changes — MFA recommended
- Email address changes — MFA recommended
- Billing information changes — MFA recommended
- Data export/bulk operations — MFA recommended
- Third-party app integrations — MFA recommended

**Document Checks:**

- [ ] MFA methods documented (SMS, TOTP, Hardware keys, Push notification)
- [ ] Fallback mechanism if MFA device unavailable
- [ ] MFA enforced for admin/privileged roles
- [ ] API tokens can only be generated with MFA
- [ ] MFA verified on every sensitive operation, not just login

**Implementation Gaps:**

❌ "MFA is optional; users can skip it"  
✅ "MFA is mandatory for all privileged users; cannot be disabled"

❌ "MFA required for login only"  
✅ "MFA required for both login AND sensitive operations"

❌ "SMS-only MFA"  
✅ "Multiple MFA options (authenticator app, hardware key, etc.)"

### Step 3: Audit Credential Handling

Examine how credentials are managed and stored:

**Secrets Management Issues:**

**In Code (CRITICAL):**
- API keys hardcoded in source files
- Database passwords in config files
- OAuth client secrets in version control
- AWS access keys in templates/examples
- Database connection strings with credentials

**In Logs (CRITICAL):**
- Passwords logged in application logs
- API keys included in debug output
- OAuth tokens logged on error
- Query parameters containing credentials

**In URLs (CRITICAL):**
- API keys as query parameters: `?api_key=abc123`
- Session tokens in URLs: `/page?sessionid=xyz`
- Passwords in POST URLs (rare but happens)

**In Browser Storage (HIGH):**
- API tokens stored in localStorage (should use HttpOnly cookies)
- Passwords stored in browser cache
- Credentials in IndexedDB without encryption

**In Transit (HIGH):**
- Credentials transmitted over HTTP (not HTTPS)
- API keys in request headers but unencrypted
- OAuth tokens visible in browser history

**Secure Patterns:**

✅ Credentials stored in Secrets Manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)  
✅ API tokens in HttpOnly, Secure cookies (not localStorage)  
✅ OAuth client secrets in environment variables (not code)  
✅ Database passwords rotated on schedule (every 90 days)  
✅ Credentials never logged, even on error  
✅ All credential transmission over HTTPS with TLS 1.2+  

**Document Patterns to Find:**

❌ "Database password stored in application.properties file"  
✅ "Database password retrieved from AWS Secrets Manager at startup"

❌ "API key stored in localStorage for persistent login"  
✅ "API key stored in HttpOnly cookie; refreshed via secure endpoint"

### Step 4: Verify Session Management

Check session security implementation:

**Cookie Attributes (CRITICAL):**

| Attribute | Purpose | Requirement |
|-----------|---------|-------------|
| HttpOnly | Prevent JavaScript access | MUST be set |
| Secure | HTTPS only | MUST be set |
| SameSite | CSRF protection | MUST be set (Strict or Lax) |
| Path | Scope of cookie | Should be restricted |
| Domain | Cookie scope | Should not be overly broad |
| Max-Age | Session duration | Should have expiration |

**Session Timeout (CRITICAL):**
- Active session timeout: 15-30 minutes for normal apps, 5-10 minutes for sensitive apps
- Idle session timeout: User inactive for N minutes → auto-logout
- Absolute session timeout: User logged in for N hours → forced re-login
- No "remember me" indefinite sessions

**Concurrent Session Limits (HIGH):**
- Only one active session per user account
- OR limited concurrent sessions (e.g., max 3 devices)
- Concurrent login attempts trigger security alert

**Session Fixation Prevention (HIGH):**
- Session ID changed on login (not reused)
- Old session ID invalidated after new one issued
- Session token unpredictable (cryptographically random)

**CSRF Protection (HIGH):**
- CSRF tokens included in all state-changing requests (POST, PUT, DELETE)
- CSRF token validated on server before action
- SameSite cookie attribute as secondary defense
- Origin/Referer header validation

**Anti-Pattern Examples:**

❌ Cookies without HttpOnly flag — vulnerable to XSS theft  
❌ Session timeout = 24 hours — too long, compromise window  
❌ No CSRF token, relying on SameSite cookie only  
❌ Session ID is sequential or predictable (1, 2, 3...)  
❌ Users can have 100 concurrent sessions  

✅ HttpOnly + Secure + SameSite=Strict  
✅ 20-minute inactivity timeout  
✅ CSRF tokens + SameSite cookie  
✅ Session ID is 256-bit random value  
✅ One session per user, old session invalidated on new login  

### Step 5: Check Authentication Architecture

Validate overall authentication design:

**Authentication Methods:**

**Session-Based (Traditional):**
- Username/password → session cookie
- Cookie sent with every request
- Server validates session ID
- Suitable for: Web applications, monolithic apps
- Risks: Session fixation, CSRF, man-in-the-middle

**Token-Based (OAuth 2.0, JWT):**
- Username/password → access token + refresh token
- Token sent in Authorization header
- Server validates token signature
- Suitable for: APIs, microservices, mobile apps
- Risks: Token theft, XSS if stored in localStorage

**Multi-Factor Authentication (MFA):**
- Primary credential + secondary verification
- Methods: SMS OTP, Time-based OTP (TOTP), Push notification, Hardware key
- Suitable for: Privileged accounts, sensitive operations
- Risks: SIM swapping (SMS), backup code compromise

**Passwordless Authentication:**
- WebAuthn/FIDO2: Cryptographic key authentication
- Magic links: Email-based one-time tokens
- Biometric: Fingerprint, face recognition
- Suitable for: High-security, modern applications
- Risks: Device compromise, backup recovery complexity

**Checklist:**

- [ ] Chosen authentication method documented
- [ ] Secondary authentication for sensitive operations
- [ ] Password requirements enforced (minimum length, complexity)
- [ ] Brute force protection implemented (rate limiting, account lockout)
- [ ] Password reset flow secure (email verification, not SMS)
- [ ] Account enumeration prevented (same response for valid/invalid user)
- [ ] Session invalidation on logout
- [ ] Failed login attempts logged
- [ ] Authentication provider (if third-party) PCI-DSS compliant

## Finding Template

```
Issue: [Description of authentication gap]
Severity: CRITICAL | HIGH | MEDIUM
Category: [Unauthenticated Endpoints | MFA Enforcement | Credential Handling | Session Management]
Pattern Found: [Specific endpoint or implementation]
MITRE ATT&CK: [T1110 brute force, T1078 valid accounts, T1556 modify auth]
NIST CSF: [PR.AC.1, PR.AC.7 Authentication and Access Controls]

Recommendation:
[Specific remediation steps with example code]
```

## Examples

### Example 1: Unauthenticated User Endpoint

**Document Section:**
```
API Endpoints:
- GET /api/users/{id} - Returns user profile (email, phone, address)
  No authentication required
  Anyone can query any user ID to get their personal data
```

**Finding:**
```
Issue: User profile endpoint accessible without authentication; exposes PII
Severity: CRITICAL
Endpoint: GET /api/users/{id}
MITRE ATT&CK: T1078 (Valid Accounts), T1087 (Account Discovery)

Recommendation: Implement authentication and authorization

Current (insecure):
app.get('/api/users/:id', (req, res) => {
  const user = db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(user);
});

Fixed (requires auth):
app.get('/api/users/:id', authenticate, authorize, (req, res) => {
  // Only allow users to view their own profile
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(user);
});
```

### Example 2: Missing MFA on Admin Access

**Document Section:**
```
Administrative Access:
- Admin panel available at /admin
- Login via username/password only
- No additional verification required
- Admins can create/delete user accounts and modify permissions
```

**Finding:**
```
Issue: Administrative functions not protected with MFA
Severity: CRITICAL
Functions: User management, permission changes, system configuration
MITRE ATT&CK: T1110 (Brute Force - password attack), T1556 (Modify Auth)

Recommendation: Enforce MFA for all administrative access

Implementation:
1. Generate OTP (TOTP using RFC 6238):
   const speakeasy = require('speakeasy');
   const secret = speakeasy.generateSecret({ name: 'MyApp Admin' });
   // Store secret.base32 in database

2. Verify TOTP on admin login:
   const token = '123456'; // From user's authenticator app
   const verified = speakeasy.totp.verify({
     secret: storedSecret,
     encoding: 'base32',
     token: token
   });
   if (!verified) return res.status(401).json({ error: 'Invalid MFA' });

3. Admin operations require MFA session:
   app.post('/admin/users', requireMFASession, (req, res) => {
     // Create user only if MFA session is valid
   });
```

### Example 3: Insecure Credential Storage

**Document Section:**
```
Database Configuration:
// In application.properties
db.username=admin
db.password=MyPassword123
db.url=jdbc:mysql://localhost:3306/app
```

**Finding:**
```
Issue: Database credentials hardcoded in configuration file
Severity: CRITICAL
File: application.properties
Credentials exposed: Username, password, server location
MITRE ATT&CK: T1555 (Credentials from Password Stores)

Recommendation: Use Secrets Manager

Before (hardcoded):
db.password=MyPassword123  # Exposed in file, git history, backups

After (using AWS Secrets Manager):
const secretsManager = new AWS.SecretsManager();
const secret = await secretsManager.getSecretValue({
  SecretId: 'prod/database/password'
}).promise();
const dbPassword = JSON.parse(secret.SecretString).password;

Benefits:
- Password never stored in code or config files
- Audit trail of access
- Automatic rotation capability
- Revocation without code change
```

### Example 4: Weak Session Management

**Document Section:**
```
Cookie Configuration:
Set-Cookie: sessionid=12345; Path=/; Max-Age=86400
```

**Finding:**
```
Issue: Session cookies lack HttpOnly and Secure flags; timeout too long
Severity: CRITICAL
Current: sessionid=12345; Path=/; Max-Age=86400 (24 hours)
Risks: XSS cookie theft, HTTPS bypass, prolonged compromise window

Recommendation: Secure session cookie attributes

Before:
Set-Cookie: sessionid=12345; Path=/; Max-Age=86400

After:
Set-Cookie: sessionid=<256-bit-random>; 
           Path=/; 
           Max-Age=1800; 
           HttpOnly; 
           Secure; 
           SameSite=Strict

Changes:
- HttpOnly: Prevents JavaScript access (blocks XSS theft)
- Secure: HTTPS only transmission
- SameSite=Strict: Prevents CSRF attacks
- Max-Age=1800: 30-minute timeout instead of 24 hours
- 256-bit random: Replace sequential IDs with cryptographic randomness
```

## Success Criteria

This skill successfully identifies authentication gaps when:

✓ Detects unauthenticated endpoints returning sensitive data  
✓ Identifies missing MFA on privileged operations  
✓ Finds hardcoded credentials in code/configs  
✓ Validates session cookie security attributes  
✓ Confirms CSRF token implementation  
✓ Generates findings with code remediation examples  

## Reference Standards

- OWASP Top 10 2021: https://owasp.org/Top10/
- NIST CSF 2.0: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04232023.pdf
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- RFC 6238 (TOTP): https://tools.ietf.org/html/rfc6238
- WebAuthn/FIDO2: https://www.w3.org/TR/webauthn-2/
