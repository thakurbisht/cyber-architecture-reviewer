# Secure SDLC and Supply Chain Standard

Owner: Application Architecture / Security Engineering
Applies to: every pipeline that builds or deploys code or infrastructure
Alignment: NIST SSDF (SP 800-218), SLSA, ISO/IEC 27001:2022 A.8.25–A.8.31

## 1.1 Principle

The pipeline is production. Anything that can change what runs in production has the same value to an attacker as production itself, and is protected accordingly.

## 2.1 Source control

Requirement: All code and infrastructure definitions MUST live in version control with branch protection on the default branch, mandatory peer review, and no direct pushes.

FINDING TRIGGER: If direct commits to the main branch are permitted, flag as MEDIUM.
FINDING TRIGGER: If code review is not required before merge, flag as HIGH.
FINDING TRIGGER: If a single person can author and approve their own change to production, flag as HIGH — separation of duties is absent.

## 2.2 Commit integrity

Requirement: Commits to protected branches SHOULD be signed. Release tags MUST be signed.

FINDING TRIGGER: If release artefacts are not signed or attested, flag as MEDIUM.

## 3.1 Pipeline identity and secrets

Requirement: Pipelines MUST authenticate to cloud and registry targets using short-lived federated credentials (OIDC workload identity). Long-lived deployment keys stored as pipeline variables are prohibited.

FINDING TRIGGER: If a pipeline uses a long-lived cloud access key, flag as HIGH.
FINDING TRIGGER: If pipeline secrets are described without a masking and audit mechanism, flag as MEDIUM.

## 3.2 Build isolation

Requirement: Build agents MUST be ephemeral, MUST NOT be shared between production and non-production pipelines, and MUST NOT have inbound network access.

FINDING TRIGGER: If a persistent shared build agent serves both production and non-production, flag as HIGH.

## 4.1 Security gates

Requirement: Every pipeline MUST include, as blocking gates: static analysis (SAST), software composition analysis (SCA) of direct and transitive dependencies, secret scanning, and container image scanning where images are produced. IaC templates MUST be scanned with policy-as-code.

FINDING TRIGGER: If a CI/CD pipeline is described with no security scanning, flag as MEDIUM. Raise to HIGH if the application is internet-facing or handles regulated data.
FINDING TRIGGER: If scans are described as advisory only, with no failure condition, flag as MEDIUM — a gate that cannot fail is a report, not a gate.

## 4.2 Failure thresholds

Requirement: The pipeline MUST fail on any new critical or high severity finding in a direct dependency, and on any detected secret.

FINDING TRIGGER: If no failure threshold is stated, flag as LOW.

## 4.3 Dependency provenance

Requirement: Dependencies MUST be pulled from an internal proxy registry, not directly from public registries. Base images MUST come from the approved internal image catalogue.

FINDING TRIGGER: If builds pull directly from public package registries, flag as MEDIUM — this is the dependency-confusion and typosquatting path.
FINDING TRIGGER: If a base image is unpinned (`:latest`), flag as MEDIUM.

## 4.4 Software bill of materials

Requirement: An SBOM MUST be generated per release and retained for the supported life of the release.

FINDING TRIGGER: If no SBOM is produced, flag as MEDIUM.

## 5.1 Environment separation

Requirement: Non-production environments MUST NOT hold production data, MUST NOT share credentials with production, and MUST NOT have network paths into production.

FINDING TRIGGER: If production data is copied to a test environment without masking or tokenisation, flag as CRITICAL.
FINDING TRIGGER: If the same service account is used across environments, flag as HIGH.

## 5.2 Deployment approval

Requirement: Production deployment MUST require an approval from someone other than the change author, and MUST be recorded with the artefact hash deployed.

FINDING TRIGGER: If production deployment is fully automatic with no approval and no automated rollback criteria, flag as MEDIUM.

## 5.3 Rollback

Requirement: Every deployment MUST have a tested rollback path and stated maximum rollback time.

FINDING TRIGGER: If rollback is not described, flag as MEDIUM.

## 6.1 Third-party and SaaS components

Requirement: Third-party services in the solution MUST have a completed security assessment, a documented data flow, and contractual breach notification terms.

FINDING TRIGGER: If a third-party service processes enterprise data and no assessment is referenced, flag as HIGH.
FINDING TRIGGER: If data leaving to a third party is not described with classification and volume, flag as MEDIUM.

## 6.2 Open source licensing and maintenance

Requirement: Dependencies MUST be actively maintained. Components with no release in 24 months or a known unpatched critical vulnerability MUST NOT be introduced.

FINDING TRIGGER: If the design introduces an unmaintained or end-of-life component, flag as HIGH.

Control mapping: NIST SSDF PO.5, PS.1, PS.2, PW.4, PW.7, PW.8, RV.1; ISO/IEC 27001:2022 A.8.25, A.8.28, A.8.29, A.8.30, A.8.31; MITRE ATT&CK T1195.002, T1554.
