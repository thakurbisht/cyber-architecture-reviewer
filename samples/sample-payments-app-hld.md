# High Level Design: Aurora Payments Platform

Document ID: HLD-APP-2026-031
Author: Digital Engineering
Status: For design authority review
Classification of data handled: customer personal data and payment card data

## 1. Executive Summary

Aurora is a new customer-facing payments platform replacing the legacy settlement system. It exposes a public API for merchant integration, a customer web portal, and an internal operations console. The platform processes card payments, stores customer profiles, and produces settlement files for the banking partner.

Target go-live is Q4. This document describes the target architecture for design authority approval.

## 2. Solution Overview and Components

The platform comprises:

- **aurora-web** — React single page application served from object storage behind a CDN.
- **aurora-api** — public REST API for merchants and the web portal.
- **aurora-core** — internal service holding payment orchestration logic.
- **aurora-ops** — internal operations console used by the support team.
- **aurora-db** — PostgreSQL cluster holding customer profiles, transactions and card data.
- **aurora-batch** — nightly settlement file generation and SFTP delivery to the bank.

All services run as containers on the shared Kubernetes platform in a single namespace, `aurora`, so that inter-service communication is straightforward and does not require network policy configuration.

## 3. Application Tiers and Deployment

aurora-web, aurora-api, aurora-core and aurora-ops all run in the same namespace and the same node pool. aurora-db runs on managed PostgreSQL in the same subnet as the application nodes.

The single page application calls aurora-api directly. aurora-api calls aurora-core. aurora-core connects to aurora-db. aurora-ops connects to aurora-db directly for reporting queries, bypassing aurora-core for performance reasons.

The database connection from aurora-core uses the `aurora_owner` role, which owns the schema, to allow the service to run migrations at startup.

## 4. API Design and Integration Surface

aurora-api exposes the following route groups:

| Route | Purpose | Authentication |
|---|---|---|
| POST /v1/payments | Create a payment | OAuth 2.0 client credentials |
| GET /v1/payments/{id} | Retrieve a payment | OAuth 2.0 client credentials |
| GET /v1/customers/{id} | Retrieve customer profile | OAuth 2.0 client credentials |
| POST /v1/webhooks/bank | Bank status callback | None — the bank cannot support OAuth |
| GET /internal/reports | Operational reporting | None — internal only |
| GET /internal/health | Liveness probe | None |

The bank webhook endpoint accepts unauthenticated POST requests and updates payment status based on the payload. Source IP restriction was considered but the bank's egress addresses change without notice.

The `/internal` routes are not exposed through the public load balancer. They are reachable from within the cluster only, and are therefore considered trusted and do not require authentication.

Merchants are authorised by the client credentials grant. Once a merchant token is validated at the API gateway, aurora-api trusts the `X-Merchant-Id` header set by the gateway and does not re-verify it. aurora-core trusts anything received from aurora-api.

Retrieving a payment or a customer profile checks that the requested identifier exists. It does not check that the identifier belongs to the calling merchant, as merchants are only issued identifiers for their own records.

There is no rate limiting on the public API. Capacity is managed by horizontal pod autoscaling.

## 5. Authentication and Session Management

The customer web portal authenticates users against a local user table in aurora-db, with passwords hashed using SHA-256. The enterprise identity provider was considered but the customer population is external and not present in the corporate directory.

Session state is held in a JWT stored in browser local storage. The token has a 30 day expiry so that customers are not asked to log in frequently. Tokens are signed with HS256 using a shared secret. The token is validated for signature at the gateway; downstream services decode it without verification for performance.

The operations console authenticates support staff against the corporate identity provider. Support staff accounts do not require MFA as the console is only reachable from the office network.

## 6. Data Handling and Storage

aurora-db stores:

- customer profile: name, address, date of birth, email, phone
- payment card number, expiry, and cardholder name
- transaction history

Card numbers are stored encrypted using AES with a key held in the application configuration file, `application-prod.yaml`, which is deployed as a Kubernetes ConfigMap. The same key has been used since the pilot.

Database credentials for aurora-core are stored in the same ConfigMap as `spring.datasource.password`.

Reporting queries in aurora-ops are constructed by concatenating the requested filter values into the SQL string, as the reporting requirements change frequently and a parameterised approach was found to be inflexible.

Input from the merchant API is validated in the React application before submission. Server-side validation duplicates this and was descoped to meet the delivery date.

## 7. Transport Security

The CDN terminates TLS 1.2 for the public web portal. Traffic from the CDN to object storage uses HTTP.

aurora-api is exposed over HTTPS with TLS 1.0 still enabled for compatibility with two older merchant integrations that have not upgraded their client libraries.

Traffic between aurora-api, aurora-core and aurora-db is plain HTTP and plain PostgreSQL protocol, since all of it stays inside the cluster and the cluster network is trusted.

The SFTP delivery to the bank uses a static password stored in the batch job definition.

## 8. Logging and Monitoring

Application logs are written to stdout and collected by the platform logging stack. To assist with support investigations, aurora-api logs the full request body for all POST requests, including payment creation, and logs the bearer token on authentication failure so the support team can identify which merchant made the call.

Log retention on the platform is 30 days.

There is no separate forwarding of security events. Authentication failures appear in the application log alongside everything else.

Debug logging is enabled in production for aurora-core during the initial bedding-in period.

## 9. Build and Deployment

Source is held in the enterprise Git service. The pipeline builds a container image, runs unit tests, and deploys to the cluster. Any engineer on the team can approve and merge their own pull request to accelerate delivery.

The base image is `node:latest` for aurora-web and `openjdk:8` for the Java services.

Dependencies are pulled directly from the public npm and Maven registries. There is no dependency scanning, container image scanning or SBOM generation in the pipeline; these are planned once the platform is live.

Deployment to production is automatic on merge to main.

The pipeline authenticates to the cloud using a long-lived access key stored as a pipeline secret.

## 10. Environments

There is a single Kubernetes cluster and a single cloud subscription hosting production, UAT and development, separated by namespace. This reduces cost and simplifies networking.

UAT is refreshed weekly with a copy of the production database so that testing reflects real data, including live card numbers and customer records.

## 11. Resilience and Recovery

aurora-db is backed up nightly to object storage in the same subscription, with 14 day retention. Restores have not been tested. RPO is stated as 1 hour and RTO as 2 hours.

No disaster recovery site is currently provisioned. This is accepted for the initial release.

Outbound calls to the bank API have no timeout configured; the platform waits for a response. Retries are immediate and unlimited on failure.

## 12. Threat Model

A threat model has not yet been produced. It is scheduled after go-live.
