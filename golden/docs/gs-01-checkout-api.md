# Checkout Platform - High-Level Design

Owner: Checkout Engineering, Larkfield Outfitters.

## 1. Purpose and Scope

This document describes the high-level design of the Checkout Platform, which replaces the checkout module of the legacy Larkfield Outfitters web shop. It covers the customer-facing checkout APIs, the order-admin UI used by customer service, the data stores, and the integration with PayCrest, our payment provider. Catalogue, search and warehouse systems are out of scope.

Peak load is 400 checkouts per minute during seasonal sales.

## 2. Architecture Overview

Clients call the public API (Figure 1) through Amazon CloudFront and AWS WAF, using the AWS managed Core rule set and Known bad inputs rule groups. CloudFront forwards requests to a Kong API gateway in an Amazon EKS cluster, which routes them to the services in Table 1.

| Component | Technology | Responsibility |
|---|---|---|
| identity-svc | Node.js | Registration, sign-in and tokens |
| cart-svc | Java, Spring Boot | Basket, pricing and promotions |
| order-svc | Java, Spring Boot | Orders and invoices |
| payment-svc | Node.js | PayCrest integration and payment webhooks |
| order-admin | React SPA with Java backend | Order management for customer service |

The platform runs in the larkfield-checkout-prod AWS account in eu-west-1 across three availability zones.

## 3. Customer Checkout Flow

Figure 2 shows the checkout sequence:

1. The customer signs in, or continues as a guest by entering an email address and receives a guest token valid for two hours.
2. cart-svc prices the basket and reserves stock.
3. The payment step collects the customer's card number, expiry date and CVC on the checkout page.
4. payment-svc creates a PayCrest payment intent, and the browser completes 3-D Secure authentication with PayCrest.
5. PayCrest reports the outcome through the webhook route, and order-svc releases paid orders to fulfilment.
6. order-svc sends a confirmation email through Amazon SES.

No account or email verification is required for guest checkout, to keep conversion high.

## 4. API Layer

Kong exposes the routes in Table 2 under https://api.larkfield.example and redirects plain HTTP to HTTPS.

| Route | Method | Description |
|---|---|---|
| /v1/auth/register | POST | Customer self-registration |
| /v1/auth/login | POST | Email and password sign-in, returns an access token |
| /v1/cart | GET, PUT | Read and update the basket |
| /v1/checkout | POST | Submit the basket and start payment |
| /v1/orders | GET | List the caller's orders |
| /v1/orders/{orderId} | GET | Order detail |
| /v1/orders/{orderId}/invoice | GET | Invoice PDF |
| /v1/payments/webhook | POST | PayCrest event callback |

GET /v1/orders returns the orders whose customer_id matches the X-Customer-Id header set by Kong. order-svc returns an order or invoice only when its customer_id matches the X-Customer-Id header, and otherwise responds with 404.

Kong applies a rate limit of 60 requests per minute per client IP to the /v1/cart and /v1/checkout routes.

The /v1/payments/webhook route is configured in Kong with authentication disabled, because PayCrest cannot present a customer token.

The Kong Admin API on port 8001 is exposed through the internal order-admin load balancer under the /kong-admin path, so that customer service team leads can switch the shop into maintenance mode. The Admin API has no authentication plugin configured; access is limited by its network placement.

## 5. Data Stores

The orders database (RDS for PostgreSQL, Multi-AZ) is the system of record for customers and orders. Its customers and orders tables hold names, email addresses, phone numbers and delivery addresses for about 2.3 million customers. Order IDs are sequential BIGSERIAL values and are printed on invoices, confirmation emails and parcel labels. Each service has its own PostgreSQL role with privileges only on its own schema.

A read replica, checkout-reporting, serves the BI team's SaaS dashboard tool and is configured as publicly accessible so that the SaaS platform can connect to it directly. The BI tool uses a read-only database role.

ElastiCache for Redis stores sessions and basket state with a 24-hour TTL. Invoice PDFs are stored in the private S3 bucket larkfield-checkout-invoices, which has S3 Block Public Access enabled and default SSE-KMS encryption.

## 6. Network Design

The VPC has public subnets for NAT gateways and load balancers, and private subnets for EKS nodes, RDS and ElastiCache. Calico network policies allow ingress to the checkout services only from the Kong pods and, for order-svc, from the order-admin backend. The primary RDS instance and ElastiCache accept connections only from the EKS node security group and the Session Manager access instance. Outbound traffic from pods passes through an egress proxy that permits only PayCrest API hostnames and AWS service endpoints.

The checkout-reporting security group allows TCP 5432 from 0.0.0.0/0, because the BI provider does not publish a fixed list of source addresses.

The EKS API server endpoint is public and accepts connections from 0.0.0.0/0, because the GitHub-hosted runners that deploy with Helm use changing IP ranges.

The order-admin UI is served by an internal Application Load Balancer that is reachable only from the corporate network and the corporate VPN. Operational database access uses AWS Systems Manager Session Manager port forwarding through that instance, with sessions logged to CloudWatch.

## 7. Identity and Access

### 7.1 Customers

Customers register with an email address and a password of at least six characters; passwords are hashed with Argon2id. identity-svc issues opaque access tokens valid for 12 hours, which the web and mobile apps send in the Authorization header. Signing out deletes the token from the app; the token itself remains valid until it expires, including after a password change.

Kong validates each token against the identity-svc introspection endpoint and sets the X-Customer-Id header, overwriting any value supplied by the client. For guest tokens, Kong sets X-Customer-Id to the customer record that matches the guest email address, creating one if none exists, so that guest orders appear in the order history if the guest later registers.

### 7.2 PayCrest callbacks

payment-svc verifies the PayCrest-Signature header on every webhook, an HMAC-SHA256 over the timestamp and raw body using the endpoint signing secret, and discards events with an invalid signature or a timestamp older than five minutes. Before moving an order to PAID, payment-svc retrieves the payment intent from the PayCrest API to confirm that the payment has succeeded.

### 7.3 Staff

Customer service agents sign in to the order-admin SPA through the corporate IdP using OIDC, and the IdP enforces MFA. The OIDC application is assigned to the All Staff group so that new agents do not need an access request. The order-admin backend has a single permission level: every signed-in user can search orders, change delivery addresses, issue refunds and export customer lists to CSV.

Engineers use IAM Identity Center, federated with the corporate IdP, for AWS console and kubectl access.

### 7.4 Workload identity

Pods obtain AWS credentials from the EKS worker node instance profile. Besides the standard EKS worker policies, the node role has AmazonS3FullAccess and AmazonSESFullAccess attached, because order-svc writes invoices to S3 and sends email through SES.

## 8. Data Protection

TLS 1.2 or higher is enforced on CloudFront, on the Kong listener and on calls to PayCrest. The RDS instance uses storage encryption with a customer-managed KMS key, and its parameter group sets rds.force_ssl to 1 so that every client connection must use TLS. ElastiCache has encryption at rest, in-transit encryption and a Redis AUTH token enabled.

Card fields are rendered in iframes served by PayCrest hosted fields, so card data goes directly from the browser to PayCrest and is never received or stored by Larkfield systems.

## 9. Build and Deployment

GitHub Actions builds images, pushes them to Amazon ECR with scan on push enabled, and deploys them with Helm. The deploy job assumes an IAM role through GitHub OIDC federation restricted to the main branch of the checkout-deploy repository, and merges to main require one approving review. Dockerfiles use base images from an internal ECR mirror, pinned by digest.

Secrets such as database passwords and the PayCrest API key are held in AWS Secrets Manager and synchronised into Kubernetes by the External Secrets Operator, using its own narrowly scoped IAM role.

## 10. Logging and Monitoring

Fluent Bit ships service and gateway logs to the central OpenSearch cluster, where they are retained for 13 months. Kong access logs record method, path, status code, latency and client IP; Authorization and Cookie headers are not logged. Access to the checkout log indices is limited to the checkout team and security operations.

CloudTrail and GuardDuty are enabled for the account. Alerts on 5xx error rate, payment failure rate and high-severity GuardDuty findings page the on-call engineer.

## 11. Availability and Disaster Recovery

Each service runs at least three replicas across three availability zones. RPO is 15 minutes and RTO is 4 hours. AWS Backup copies nightly RDS snapshots to a vault in the separate larkfield-backup account in eu-central-1, protected by Vault Lock in compliance mode. The DR runbook was last tested in June 2026.
