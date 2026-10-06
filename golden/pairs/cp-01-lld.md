# Claims Processing Platform — Low Level Design

**Company:** Ravenscourt Mutual (fictional)
**Document:** LLD v0.9, for cyber review
**Classification:** Internal

## 1. Scope

This document details the build of the claims platform described in HLD v1.4.
It covers the subscription layout, the services, the data stores, the network
design and the operational tooling.

## 2. Subscription and resource groups

The platform occupies subscription `rm-claims-prod` with four resource groups:
`rg-edge`, `rg-app`, `rg-int` and `rg-data`. A separate subscription
`rm-claims-nonprod` holds development and test.

## 3. Edge tier

The front door is an application gateway `agw-claims-prod` with the WAF module
in prevention mode using the managed ruleset. It listens on 443 and applies a
rate limit of 120 requests per minute per source address to the public claim
submission routes.

The listener is configured with a minimum protocol version of TLS 1.2. The
broker partner `Halloway Brokers` runs an integration platform that does not
support TLS 1.3, so the broker listener permits TLS 1.2 to avoid breaking their
nightly submission batch.

## 4. Application tier

Three services run on the managed Kubernetes cluster `aks-claims-prod`:

| Service | Purpose | Ingress |
|---|---|---|
| claims-api | Accepts and validates claim submissions | From the gateway |
| assessment-svc | Scores and routes claims | From claims-api |
| casemgmt-api | Back end for the assessor application | From the gateway |

Service-to-service calls inside the cluster use mutual TLS through the service
mesh. Certificates are issued by the mesh certificate authority with a 24 hour
lifetime.

`claims-api` validates every submission against a JSON schema before it is
queued, and rejects payloads above 8 MB.

## 5. Integration tier

`payment-adapter` runs in `rg-int` and calls the treasury gateway over a private
link. The treasury gateway accepts only a client certificate issued by the
treasury certificate authority; the certificate and its private key are held in
the platform secret store and mounted at start-up.

## 6. Identity and access

Assessors, payment officers and administrators sign in through the corporate
identity provider. A conditional access policy requires multi-factor
authentication, satisfied by the authenticator application or a FIDO2 security
key.

Application roles are `claims.submit`, `claims.assess`, `claims.approve` and
`claims.admin`, assigned through directory groups. The `claims.assess` and
`claims.approve` roles are mutually exclusive and the directory enforces this
through an access package policy.

Four break-glass accounts exist for platform recovery. These accounts are
excluded from the conditional access policy so that recovery is possible during
an identity provider outage; their credentials are held in a sealed envelope in
the operations safe.

## 7. Data tier

| Store | Technology | Contents |
|---|---|---|
| claims-store | Managed PostgreSQL flexible server | Claim records, member references |
| document-store | Storage account `stclaimsdocs` | Medical summaries, correspondence |
| audit-store | Storage account `stclaimsaudit` | Application audit events |

The PostgreSQL server and `stclaimsdocs` are reached through private endpoints
and have public network access disabled. Disk encryption uses customer-managed
keys from `kv-claims-prod`.

`stclaimsaudit` is configured with public network access enabled, because the
group reporting tool is hosted outside the subscription and the team could not
obtain a private link in time for go-live. Access is controlled by a shared
access signature with a two year expiry.

Bank details are stored as tokens issued by the treasury gateway; the platform
never stores a full account number.

## 8. Network design

Each resource group has its own virtual network, peered through the hub. Network
security groups restrict traffic as follows:

| From | To | Ports |
|---|---|---|
| Internet | rg-edge | 443 |
| rg-edge | rg-app | 8443 |
| rg-app | rg-data | 5432, 443 |
| rg-int | rg-data | 443 |

The non-production subscription is peered to the production hub so that the test
team can reach the production claims store for data comparison during the
migration window.

## 9. Secrets

Application secrets are held in `kv-claims-prod` and retrieved at start-up using
a workload identity. No secrets are stored in container images. The build
pipeline reads its registry credentials from the pipeline's own variable group.

## 10. Logging

Application logs, gateway access logs and Kubernetes audit logs are written to a
Log Analytics workspace with a 90 day retention. Database query logs are kept on
the server for 7 days.

## 11. Resilience

The cluster runs across two availability zones with an active-active node pool.
PostgreSQL is configured as zone-redundant with automatic failover.

Nightly backups of `claims-store` are written to a geo-redundant storage account
and kept for 35 days.

## 12. Build and release

Infrastructure is defined in Terraform in the `rm-claims-infra` repository.
Pipelines run plan and apply stages. Branch policy on `main` requires one
reviewer approval before merge.

Container images are built in the shared build pipeline and pushed to the
platform registry.

## 13. Non-production

`rm-claims-nonprod` is loaded from a nightly copy of the production claims
database so that assessment scoring can be tested against realistic data.
