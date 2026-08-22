# Sample Designs: Answer Key

Every sample in this folder contains deliberately planted violations. This file
is the answer key — it is the regression suite for both the deterministic rules
engine and the agent.

How to use it:

```bash
python scripts/review_cli.py samples/sample-campus-lan-lld.md
```

Then compare the findings table against the relevant section below.

Two different expectations apply:

* **Rules-engine findings** must appear on *every* run, identically. If one is
  missing, a regex has broken — that is a straightforward bug with a
  straightforward fix.
* **Agent findings** should appear on *most* runs. Agentic review is
  probabilistic; wording and ordering will vary, and an occasional miss on a
  subtle item is expected behaviour, not a defect. Persistent absence of an
  agent finding usually means the knowledge base clause is too vague — fix the
  trigger sentence, not the prompt.

---

## sample-campus-lan-lld.md — Meridian Tower Campus LAN

Deterministic (rules engine) — expect all of these:

| # | Rule | Severity | Section |
|---|---|---|---|
| 1 | NET-HA-001 | CRITICAL | 5. Distribution and Core (single core switch) |
| 2 | NET-HA-001 | CRITICAL | 7. WAN Edge and Internet (single circuit) |
| 3 | NET-HA-002 | CRITICAL | 3. Access Layer Design (Floors 4 and 9 uplinks both on DIST-SW-A) |
| 4 | NET-MGMT-001 | CRITICAL | 10. Management Plane (SNMPv2c) |
| 5 | NET-MGMT-002 | CRITICAL | 10. Management Plane (community `public` / `private`) |
| 6 | NET-MGMT-003 | HIGH | 10. Management Plane (telnet, TFTP) |
| 7 | NET-MGMT-004 | HIGH | 10. Management Plane (local accounts, shared enable password) |
| 8 | NET-RTG-001 | HIGH | 6. Routing Design (OSPF without neighbour authentication) |
| 9 | NET-SEG-001 | CRITICAL | 8. Firewall and Segmentation (Any/Any/Allow rule) |
| 10 | NET-SEG-002 | HIGH | 4. VLAN and Addressing Design (single campus-wide VLAN) |
| 11 | NET-WAN-001 | HIGH | 7. WAN Edge and Internet (MPLS asserted trusted, unencrypted) |
| 12 | NET-WLS-001 | HIGH | 9. Wireless (CORP-WIFI on WPA2-PSK) |
| 13 | SEC-IAM-001 | CRITICAL | 10. Management Plane (admin access without MFA) |
| 14 | SEC-IAM-002 | HIGH | 9. Wireless (passphrase distributed by the service desk) |
| 15 | SEC-LOG-001 | HIGH | Whole document (no central log forwarding) |
| 16 | SEC-RES-001 | HIGH | 10. Management Plane (config backup, no immutability) |
| 17 | SEC-RES-001 | HIGH | 11. Availability and Convergence (restore never tested) |
| 18 | SEC-TM-001 | MEDIUM | Whole document (no threat model) |

Totals: 18 findings, 7 CRITICAL / 10 HIGH / 1 MEDIUM, risk score 99.9, status RED.

Agent — expect most of these, cited to the knowledge base:

- VLAN 100 spans the whole campus, contrary to Three-Tier LAN Standard §2.2 — the failure domain becomes the entire site.
- Servers share a VLAN with user devices — no policy boundary between differently-trusted workloads (Segmentation Standard §2.1).
- No first-hop redundancy: the VLAN 100 gateway sits on DIST-SW-A alone (§4.1).
- Spanning tree left at default with no explicit root bridge and no BPDU Guard (§4.2).
- DIST-SW-A has a single power supply (§3.4).
- Firewall policy has no terminating deny-all (Segmentation Standard §4.2).
- Rule 2 was a temporary migration rule retained permanently (§4.4).
- Management traffic shares VLAN 100 with user traffic (Management Standard §4.1).
- Guest SSID bridged onto the user VLAN with no isolation (§6.1).
- No NTP — correlated logging is impossible (§5.2).
- Unused ports left administratively up in the default VLAN (§5.2).
- 99.95% availability claimed but single core, single circuit and no measured convergence make it unachievable.
- No 802.1X, DHCP snooping or Dynamic ARP Inspection on access ports (§5.1).

Cross-domain pass:

- The stated 99.95% availability target contradicts the single-core, single-circuit topology; the target and the design cannot both stand.
- Management plane security is deferred to "phase 2" throughout while the design is presented as complete — the security posture depends on work that is not funded in this delivery.

---

## sample-payments-app-hld.md — Aurora Payments Platform

Deterministic (rules engine) — expect all of these:

| # | Rule | Severity | Section |
|---|---|---|---|
| 1 | APP-AUTH-001 | CRITICAL | 4. API Design (unauthenticated bank webhook and `/internal` routes) |
| 2 | APP-AUTH-002 | HIGH | 5. Authentication (30-day JWT, unverified downstream decode) |
| 3 | APP-AUTHZ-001 | HIGH | 4. API Design (services trust the `X-Merchant-Id` header) |
| 4 | APP-AUTHZ-001 | HIGH | 5. Authentication (validation only at the gateway) |
| 5 | APP-DATA-001 | CRITICAL | 6. Data Handling (string-concatenated SQL) |
| 6 | APP-DATA-002 | HIGH | 6. Data Handling (client-side validation only) |
| 7 | APP-LOG-001 | HIGH | 5. Authentication (bearer tokens logged) |
| 8 | APP-LOG-001 | HIGH | 8. Logging (full request bodies logged) |
| 9 | APP-RES-001 | MEDIUM | Whole document (no rate limiting) |
| 10 | APP-SDLC-001 | MEDIUM | Whole document (no SCA / image scanning / SBOM) |
| 11 | APP-SEC-001 | CRITICAL | 6. Data Handling (encryption key and DB password in a ConfigMap) |
| 12 | APP-SEC-001 | CRITICAL | 7. Transport Security (static SFTP password in the job definition) |
| 13 | APP-SEC-001 | CRITICAL | 9. Build and Deployment (long-lived cloud key as a pipeline secret) |
| 14 | APP-TLS-001 | CRITICAL | 7. Transport Security (TLS 1.0, CDN-to-origin HTTP, internal plaintext) |
| 15 | CLD-DATA-001 | HIGH | 6. Data Handling (card data and PII, no classification) |
| 16 | CLD-DATA-001 | HIGH | 10. Environments (production data copied to UAT) |
| 17 | CLD-LZ-001 | HIGH | 11. Resilience (single subscription for all environments) |
| 18 | SEC-IAM-001 | CRITICAL | 5. Authentication (support console without MFA) |
| 19 | SEC-IAM-002 | HIGH | 5. Authentication (shared credential handling) |
| 20 | SEC-LOG-001 | HIGH | Whole document (no SIEM forwarding) |
| 21 | SEC-LOG-002 | MEDIUM | 8. Logging (30-day retention against a 12-month requirement) |
| 22 | SEC-RES-001 | HIGH | 11. Resilience (backups without immutability or tested restore) |
| 23 | SEC-TM-001 | MEDIUM | Whole document (threat model deferred to after go-live) |
| 24 | SEC-VULN-001 | HIGH | 9. Build and Deployment (`openjdk:8`, `node:latest`) |
| 25 | SEC-ZT-001 | HIGH | 4. API Design ("internal only, therefore trusted") |
| 26 | SEC-ZT-001 | HIGH | 7. Transport Security ("the cluster network is trusted") |

Totals: 26 findings, 7 CRITICAL / 13 HIGH / 6 MEDIUM, risk score 100.0, status RED.

Agent — expect most of these:

- Passwords hashed with SHA-256 rather than a password-hashing function (Cryptography Standard §3.1) — CRITICAL for a customer credential store.
- Broken object-level authorisation: `GET /v1/payments/{id}` verifies existence, not ownership (App Sec Standard §3.6, OWASP API1).
- Card numbers stored rather than tokenised, expanding PCI scope (Data Protection Standard §3.3).
- Encryption key never rotated since pilot and held outside a KMS (Cryptography Standard §5.1, §5.2).
- JWT in browser local storage rather than an HttpOnly cookie (§3.5).
- HS256 shared secret across services — any service holding it can mint tokens.
- `aurora_owner` schema-owner database account used by the application (§4.1).
- aurora-ops bypasses aurora-core and reaches the database directly, defeating the tier boundary (§2.1).
- All services in one namespace with no network policy — no workload isolation.
- Self-approved pull requests; no separation of duties (SDLC Standard §2.1).
- No timeouts and unlimited immediate retries on the bank API (§7.3).
- No DR provision for a payments platform; RTO/RPO stated but unsupported by 14-day backups with untested restore.

Cross-domain pass:

- The application relies on the cluster network being trusted for its unauthenticated `/internal` routes, while the platform design places all environments in one namespace with no network policy — the isolation the application assumes does not exist.
- Card data classification is absent in the application design while the cloud design applies only default encryption — neither document owns the control that PCI requires.

---

## sample-cloud-landing-zone-hld.md — Helios Landing Zone

Deterministic (rules engine) — expect all of these:

| # | Rule | Severity | Section |
|---|---|---|---|
| 1 | APP-SDLC-001 | MEDIUM | Whole document (no IaC policy scanning) |
| 2 | APP-SEC-001 | CRITICAL | 5.1 Ingestion (access key embedded in the export script) |
| 3 | CLD-DATA-001 | HIGH | 5.3 Data content (classification never recorded, indefinite retention) |
| 4 | CLD-DATA-001 | HIGH | 10. Compliance Position (regulated data, no assessment) |
| 5 | CLD-IAM-001 | CRITICAL | 3. Identity and Access (`AdministratorAccess` on the workload role) |
| 6 | CLD-LZ-001 | HIGH | 2. Account Structure (single account for prod, dev and test) |
| 7 | CLD-NET-001 | HIGH | 4. Network Topology (0.0.0.0/0 on TCP 5432 and TCP 22) |
| 8 | CLD-STOR-001 | CRITICAL | 5.2 Storage (`Principal: "*"`, public read, block-public-access off) |
| 9 | SEC-IAM-001 | CRITICAL | 2. Account Structure (root user in routine use) |
| 10 | SEC-IAM-001 | CRITICAL | 3. Identity and Access (MFA optional for engineers) |
| 11 | SEC-IAM-002 | HIGH | 6. Analytics Workloads (shared Jupyter token via team chat) |
| 12 | SEC-LOG-001 | HIGH | Whole document (nothing forwarded to the SIEM) |
| 13 | SEC-RES-001 | HIGH | 5.2 Storage (no immutable copy, versioning disabled) |
| 14 | SEC-TM-001 | MEDIUM | Whole document (no threat model or privacy impact assessment) |
| 15 | SEC-VULN-001 | HIGH | 6. Analytics Workloads (CentOS 7, unreviewed community AMI) |

Totals: 15 findings, 5 CRITICAL / 6 HIGH / 4 MEDIUM, risk score 99.6, status RED.

Agent — expect most of these:

- Root user in routine use with an access key attached (Landing Zone Standard §3.1) — CRITICAL.
- No AWS Organization and no preventative guardrails (§2.1).
- RDS in a public subnet (§5.3).
- S3 Block Public Access disabled at account level (Data Protection Standard §2.3).
- Cross-region replication to us-east-1 with no residency assessment (§2.2) — a likely regulatory breach, not merely a gap.
- Full card numbers ingested because filtering at source was inconvenient (§3.3).
- Indefinite retention of personal data (§4.1).
- Terraform state bucket without versioning or encryption (Landing Zone Standard §6.1).
- CloudTrail single-region, in the workload account, without log file validation (Logging Standard §7.1).
- GuardDuty, AWS Config and VPC Flow Logs all absent (§6.2).
- Community AMI never assessed against the hardening baseline (Vulnerability Standard §2.1).
- Public IPs on analytics instances for direct SSH from home (Zero Trust Standard §5.2).
- Access key embedded in the on-premise export script (§6.1 App Sec).
- Unrestricted egress from all subnets — the exfiltration path (Segmentation Standard §5.3).
- No penetration test or privacy impact assessment before go-live.

Cross-domain pass:

- The analytics platform holds regulated data under a landing zone with no guardrails, no posture monitoring and no organisational structure — the data classification the platform requires has no control plane capable of enforcing it.
- Backups, snapshots and cross-region replicas all live inside the single account whose root credential is in routine use; compromise of one credential is loss of both production and every recovery copy.

---

## Regression discipline

Run all three samples after changing rules, prompts, or knowledge base content:

```bash
for f in samples/sample-*.md; do
  python scripts/review_cli.py "$f" --json-out "data/regression/$(basename "$f" .md).json"
done
```

Then diff against the previous run:

```bash
python scripts/review_cli.py samples/sample-campus-lan-lld.md \
  --compare data/regression/sample-campus-lan-lld.json
```

The comparison uses finding fingerprints, so wording drift between runs is
ignored and only genuine changes surface.
