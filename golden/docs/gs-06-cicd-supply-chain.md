# Parcelwise Build and Release Platform - High-Level Design

Owner: Platform Engineering, Parcelwise Ltd. Version 1.4.

## 1. Purpose and Scope

Parcelwise is a SaaS shipment-tracking platform used by about 1,900 retailers and logistics providers. Production runs on Amazon EKS in two AWS regions, and the production PostgreSQL databases hold shipment records for customers' end recipients, including names, delivery addresses and phone numbers.

This document describes how Parcelwise code is hosted, reviewed, built, packaged and deployed: source control, branch protection, CI runners, third-party dependencies, the artifact registry, secrets handling, infrastructure as code and production deployment. Runtime application security is covered in the individual service designs.

## 2. Source Control

All code is hosted in the Parcelwise organisation on a hosted Git service. Engineers sign in through the corporate IdP with SSO and FIDO2 MFA, and personal access tokens must be fine-grained, SSO-authorised and expire within 90 days. The organisation's 210 engineers all have write access to service repositories. Secret scanning with push protection is enabled on every repository.

Three client SDK repositories (parcelwise-js, parcelwise-python and parcelwise-go) are public so that customers can contribute fixes, and CI runs automatically on pull requests from forks to give contributors quick feedback.

## 3. Branch Protection and Code Review

Branch protection is applied through the organisation ruleset protect-default, which targets the default branch (main) of every repository. Changes to main require a pull request with two approvals, one of them from a code owner. Approvals are dismissed when new commits are pushed, all status checks must pass, force pushes and deletions are blocked, and repository administrators cannot bypass the ruleset.

Required status checks include unit and integration tests, static analysis, dependency vulnerability scanning and a licence check. Integration tests load a PostgreSQL database with about 50,000 shipment records, including recipient names, addresses and phone numbers, to exercise the tracking queries.

## 4. Build Runners

All CI jobs, for both private and public repositories, run on a shared pool of 16 self-hosted runners on EC2 instances in the build VPC. Runners are long-lived and process jobs one after another; the workspace directory is cleaned at the end of each job.

The runner instance profile allows pushing images to every ECR repository and reading secrets under the ci/ path in AWS Secrets Manager, which holds the tokens that pipelines use for SaaS integrations.

Runners sit in private subnets, and their outbound traffic passes through an egress proxy that allows only the Git service, package registries and AWS endpoints. Third-party CI actions are limited to an allowlist and are pinned to full commit SHAs.

## 5. Third-Party Dependencies

Services are written in TypeScript, Python and Go. JavaScript dependencies are locked with package-lock.json, and internal npm packages are published under the @parcelwise scope, which is registered on the public npm registry. Go modules are verified against the public checksum database. A dependency bot opens weekly pull requests for new versions, which go through normal review.

Python services install dependencies with pip using --extra-index-url pointing at the internal package repository, so that packages resolve from both public PyPI and the internal repository. Internal Python libraries are published there under plain names such as pw-geo and pw-auth-client, and requirements files specify minimum versions.

## 6. Artifact Registry and Container Images

Each service builds its container image from a multi-stage Dockerfile. Base images come from an internal mirror of approved distroless and slim images that is refreshed weekly. The build stage of each Dockerfile runs as root so that operating system packages and native build dependencies can be installed.

Images are pushed to Amazon ECR in the shared-services account. ECR scans every image on push, and images with critical vulnerabilities cannot be deployed. Each build publishes its container image to ECR and its test and coverage reports to the CI artifact store.

ECR repositories use mutable tags so that a version tag can be pushed again if a release build fails part-way. The production Helm values reference each service's image by its version tag, for example tracking-api:2026.09.2.

## 7. Secrets and Test Data

No long-lived AWS access keys are stored in the Git service or in CI variables. Pipelines read the secrets they need from AWS Secrets Manager at job start, and secret values are masked in job logs.

Runtime secrets are held in AWS Secrets Manager and synchronised into Kubernetes Secrets by the External Secrets Operator. EKS envelope encryption with a customer-managed KMS key is enabled, and RBAC allows only each namespace's workload service account to read its Secrets.

All datasets used in CI, staging and developer environments are synthetic and generated by the pw-fixtures library; production data is never copied into those environments.

## 8. Deployment to Production

Merges to main deploy automatically to the staging cluster. The staging and production EKS clusters run in the same AWS account, pw-workloads, and share its VPC and KMS keys; engineers have namespace-admin rights on the staging cluster for debugging.

Production releases are cut by creating a release branch from main, named release/ followed by the version, for example release/2026.09.2. The deploy workflow runs on every push to a branch whose name starts with release/ and builds and tests the commit, pushes the image to ECR, runs staging smoke tests and upgrades both production clusters with Helm. Hotfixes are pushed to the current release branch and merged back into main afterwards.

The deploy job obtains short-lived credentials for the ci-deploy role through OIDC federation, and the role's trust policy accepts only tokens issued for release branches of Parcelwise repositories. The EKS API endpoints are private and reachable only from the build VPC and the platform team's VPN.

Application pods read database credentials and third-party API keys from Kubernetes Secrets in their namespace. Namespaces have default-deny network policies. The production clusters enforce the Kubernetes restricted Pod Security Standard, so pods that run as root, request privileged mode or add Linux capabilities are rejected at admission.

Rollbacks and redeployments of an existing release can also be started from the #releases Slack channel with the /pw-deploy command. The release bot accepts the command from any member of the Slack workspace, which includes about 60 contractors from design and support agencies.

## 9. Infrastructure as Code

AWS accounts, networking, EKS clusters, RDS databases and IAM roles are defined in Terraform in the platform-infra repository. Plans run on pull requests, and the platform pipeline applies changes after merge to main using the tf-apply role, which trusts only the main branch of platform-infra.

Terraform state for all environments is stored in the S3 bucket pw-terraform-state, encrypted with SSE-KMS and versioned. Database master passwords are generated by Terraform with the random_password resource and then copied into AWS Secrets Manager. The Engineering SSO role, which every engineer can assume, has read access to the state bucket and decrypt permission on its KMS key so that engineers can run terraform plan locally.

## 10. Logging, Backup and Recovery

Git service audit logs, CI job logs, CloudTrail and EKS audit logs are sent to the SIEM and retained for 13 months. Repositories are mirrored nightly to an S3 bucket with Object Lock in a separate AWS account, and ECR images are replicated to the second region. The platform can be rebuilt from Terraform and the mirrored repositories within 24 hours.
