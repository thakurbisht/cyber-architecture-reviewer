# Cryptography and Key Management Standard

Owner: Security Architecture
Applies to: every design that encrypts, signs, hashes, or holds key material
Alignment: NIST SP 800-52r2, SP 800-57, SP 800-131A

## 1.1 Principle

Cryptography fails through key management far more often than through algorithm weakness. A design that names a strong algorithm but does not say who holds the key, where it lives, how it rotates, and what happens when it is lost has not addressed cryptography at all.

## 2.1 Transport security

Requirement: TLS 1.2 is the minimum permitted version; TLS 1.3 is preferred. SSL v2/v3 and TLS 1.0/1.1 MUST be disabled at every endpoint, including internal ones and load balancer back-ends.

FINDING TRIGGER: If TLS 1.0, TLS 1.1, or any SSL version appears in the design, flag as CRITICAL.
FINDING TRIGGER: If plaintext HTTP is used for anything other than loopback or a redirect to HTTPS, flag as CRITICAL.
FINDING TRIGGER: If the design terminates TLS at a load balancer and forwards in plaintext to the origin, flag as HIGH.

## 2.2 Cipher suites

Requirement: Only AEAD cipher suites with forward secrecy are permitted (ECDHE with AES-GCM or ChaCha20-Poly1305). Static RSA key exchange and CBC-mode suites are prohibited.

FINDING TRIGGER: If cipher suites are unspecified for an internet-facing service, flag as MEDIUM.
FINDING TRIGGER: If a prohibited suite is named, flag as HIGH.

## 2.3 HSTS and certificate handling

Requirement: Public web endpoints MUST send HSTS with a minimum age of one year. Certificates MUST be issued by an approved CA with automated renewal and expiry monitoring.

FINDING TRIGGER: If a public web endpoint is described without HSTS, flag as LOW.
FINDING TRIGGER: If certificate renewal is manual, flag as MEDIUM — expiry outages are among the most common self-inflicted incidents.

## 3.1 Approved algorithms

Requirement:
- Symmetric encryption: AES-256-GCM (AES-128-GCM acceptable)
- Hashing: SHA-256 or stronger
- Password storage: Argon2id, scrypt, or bcrypt with an appropriate work factor
- Digital signature: ECDSA P-256 or RSA-3072 minimum
- Key agreement: ECDHE P-256 or X25519

Prohibited: MD5, SHA-1, DES, 3DES, RC4, ECB mode, RSA below 2048, unsalted hashes.

FINDING TRIGGER: If a prohibited algorithm appears anywhere in the design, flag as HIGH. Raise to CRITICAL if it protects authentication material or regulated data.
FINDING TRIGGER: If passwords are described as hashed with a general-purpose hash such as SHA-256 without a password-hashing function, flag as HIGH.
FINDING TRIGGER: If encryption is described without naming the algorithm and mode, flag as MEDIUM.

## 3.2 Randomness

Requirement: All security-relevant random values MUST come from a cryptographically secure random number generator.

FINDING TRIGGER: If tokens, session identifiers or salts are generated from a non-cryptographic source, flag as HIGH.

## 4.1 Data at rest

Requirement: All persistent data MUST be encrypted at rest. Data classified Confidential or Restricted MUST use customer-managed keys where the platform supports them, so key access is independent of data access.

FINDING TRIGGER: If encryption at rest is absent, flag as HIGH.
FINDING TRIGGER: If regulated data uses provider-managed keys with no customer control, flag as MEDIUM and state the compensating requirement.
FINDING TRIGGER: If backups, snapshots, or replicas are not covered by the same encryption requirement as the primary, flag as HIGH — the copy is the weak point.

## 5.1 Key custody

Requirement: Keys MUST be generated and stored in an HSM or a managed KMS backed by FIPS 140-2 Level 2 or higher. Private keys MUST NOT exist in application configuration, source control, or on general-purpose file systems.

FINDING TRIGGER: If key material is described as stored in configuration files, source control, or on application servers, flag as CRITICAL.
FINDING TRIGGER: If key custody is not described at all in a design that encrypts data, flag as HIGH.

## 5.2 Key lifecycle

Requirement: Every key class MUST have a defined cryptoperiod, a rotation mechanism, a revocation path, and a documented recovery procedure. Data-encryption keys MUST rotate at least annually; key-encryption keys at least every three years. Rotation MUST NOT require an outage.

FINDING TRIGGER: If key rotation is not described, flag as HIGH.
FINDING TRIGGER: If rotation is described but requires re-encrypting all data with downtime, flag as MEDIUM — rotation that hurts will not happen.
FINDING TRIGGER: If there is no key recovery or escrow procedure, flag as HIGH — an unrecoverable key is a data-loss event waiting for a bad day.

## 5.3 Separation of duties for keys

Requirement: Key custodians MUST be separate from data administrators. Key administrative operations MUST require dual control and MUST be logged to a store the key administrators cannot alter.

FINDING TRIGGER: If the same role administers both the keys and the data they protect, flag as HIGH.
FINDING TRIGGER: If key usage and key administration are not logged separately from data access, flag as MEDIUM.

## 6.1 Secrets versus keys

Requirement: Application secrets MUST be held in the secret manager; cryptographic keys MUST be held in the key management service. The two are not interchangeable — a secret store is not a substitute for a key store for keys that must never leave hardware.

FINDING TRIGGER: If cryptographic key material is stored in a general secret manager and exported to the application, flag as MEDIUM, stating the requirement to keep the key inside the boundary and perform operations there.

## 7.1 Post-quantum readiness

Requirement: Designs with a data confidentiality requirement beyond 2032 MUST record a position on harvest-now-decrypt-later risk and a migration path to post-quantum key exchange.

FINDING TRIGGER: If long-lived confidential data is protected only by classical key exchange with no stated position, flag as LOW.

Control mapping: NIST SP 800-52r2, SP 800-57 Part 1, SP 800-131A; NIST SP 800-53 SC-8, SC-12, SC-13, SC-28; ISO/IEC 27001:2022 A.8.24; PCI DSS 4.0 3.5, 4.2.
