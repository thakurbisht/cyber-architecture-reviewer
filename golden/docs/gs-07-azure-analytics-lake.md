# Tidewater Analytics Platform — High-Level Design

Harbourline Bank, Data Platform Engineering. Version 1.3, submitted to the Architecture Review Board.

## 1. Purpose and Scope

The Tidewater Analytics Platform (TAP) replaces the on-premises Teradata warehouse as Harbourline Bank's central platform for customer analytics, financial crime model development and management reporting. This document describes the production design in Azure UK South: ingestion, storage, processing, reporting, network, identity, data protection, environments, monitoring and recovery. Deployment of models into real-time decisioning systems is out of scope.

TAP holds personal data (names, addresses, dates of birth, national insurance numbers, email addresses and phone numbers) and account and card transaction data for approximately 2.1 million retail customers. All TAP data is classified Confidential under the bank's information classification standard.

## 2. Architecture Overview

Figure 1 shows the logical architecture. Azure Data Factory (ADF) extracts source data into an Azure Data Lake Storage Gen2 account, Azure Databricks refines it into curated datasets, and analysts consume it through Azure Synapse serverless SQL and Power BI. Azure Key Vault holds secrets and the customer-managed key for the lake.

| Component | Azure service | Purpose |
|---|---|---|
| Ingestion | Data Factory (adf-tap-prd) with self-hosted integration runtime (SHIR) | Nightly batch extraction from on-premises sources |
| Streaming | Event Hubs (evh-tap-prd) | Card authorisation events |
| Lake | ADLS Gen2 (dlstapprd) | Raw and curated zones |
| Processing | Databricks Premium (dbw-tap-prd) | Transformation, feature engineering, model training |
| Serving | Synapse serverless SQL (syn-tap-prd) | SQL access to curated Delta tables |
| Reporting | Power BI Premium capacity | Management, branch and collections reporting |
| Partner exchange | Storage account (stexporttap) | File exchange with external agencies |
| Secrets and keys | Key Vault (kv-tap-prd) | Linked service credentials, customer-managed key |

## 3. Data Ingestion and Lake Zones

### 3.1 Sources and Pipelines

ADF pipelines run nightly at 01:00. The SHIR runs on two Windows VMs in the Farnborough data centre and extracts from the core banking Oracle replica, the card management system and the CRM SQL Server database. Card authorisation events are published by the card switch to Event Hubs and consumed by Databricks structured streaming jobs. The card switch and the card management system supply only tokenised card numbers, so no primary account numbers (PANs) reach Event Hubs or the lake.

Most linked services retrieve credentials from kv-tap-prd using the factory's system-assigned managed identity. The core banking linked service uses the Oracle account TAP_EXTRACT, whose password is held as the default value of the pipeline parameter pCoreBankingPwd so that the nightly trigger runs unattended. The factory definition, including pipeline parameters, is committed to the tap-adf repository in Azure Repos, which is readable by all members of the Data & Analytics DevOps project (about 180 users).

### 3.2 Lake Zones

| Zone | Container | Content | Written by |
|---|---|---|---|
| Raw | raw | Source extracts as received, including all personal data fields | ADF managed identity |
| Curated | curated | Cleansed, conformed Delta tables with pseudonymised identifiers | Databricks jobs |

The raw zone is the bank's long-term record of source extracts and retains seven years of history to meet regulatory record-keeping obligations. The source systems themselves keep only 13 months of transaction history online.

In the curated zone, direct identifiers (account number, sort code and national insurance number) are replaced with an unsalted SHA-256 hash of the original value, so that datasets from different domains can still be joined. Names, addresses and contact details are dropped from curated tables.

Once a week, a Databricks job writes a customer segment file containing customer name, email address, postcode and segment code to the exports container in stexporttap. The container's public access level is set to Container so that the bank's external marketing agency can download the file without an account in the bank's Azure AD tenant.

## 4. Processing and Serving

### 4.1 Databricks

The Databricks workspace is deployed with VNet injection into snet-dbw-host and snet-dbw-container. Each data science team has a shared interactive cluster; engineering pipelines run on job clusters created per run. About 60 data scientists, many of whom work from home several days a week, develop models against transaction-level data in Databricks notebooks from their laptops.

Both the job clusters and the shared interactive clusters access the lake as the service principal sp-tap-dbw, configured through the cluster Spark configuration. sp-tap-dbw holds Storage Blob Data Contributor on the dlstapprd storage account so that engineering jobs can read the raw zone and write curated tables.

### 4.2 Synapse and Power BI

Synapse serverless SQL exposes curated Delta tables as views for analysts, who connect with Azure AD authentication. Power BI Service, which runs outside the bank's network, queries the Synapse serverless SQL endpoint for scheduled dataset refreshes.

Around 400 report creators publish to Power BI workspaces. Reports in the Collections and Retail Performance workspaces contain customer-level account balances and arrears status. The Power BI tenant setting Publish to web is enabled for the entire organisation so that branch performance dashboards can be shown on intranet pages and branch displays without viewers signing in.

## 5. Network Design

Figure 2 shows the network topology. TAP resources are deployed in the spoke VNet vnet-tap-prd (10.40.0.0/20), peered to the bank's hub VNet, which terminates ExpressRoute private peering to the Farnborough data centre. All traffic between the data centre and Azure, including SHIR traffic, uses ExpressRoute; outbound internet traffic from the spoke is routed through Azure Firewall in the hub.

Public network access is disabled on dlstapprd, kv-tap-prd, evh-tap-prd and syn-tap-prd; these services are reached through private endpoints in snet-pe with private DNS zones linked to the hub. The Databricks workspace uses secure cluster connectivity with no public IPs on cluster nodes.

Power BI dataset refreshes run through a Power BI VNet data gateway delegated to snet-pbi-gw, which reaches Synapse through its private endpoint, so no public Synapse endpoint is required.

stexporttap is reachable on its public endpoint to support partner file exchange. All storage accounts require secure transfer and a minimum of TLS 1.2.

## 6. Identity and Access Model

All human access uses the bank's Azure AD tenant. A Conditional Access policy requires phishing-resistant MFA and an Intune-compliant device for Databricks, Synapse Studio, the Azure portal and Power BI. The Databricks front end is published only through front-end Private Link, which remote users reach through the bank's zero-trust network access client; notebook result download and the DBFS file browser are disabled.

| Persona | Count | Access |
|---|---|---|
| Data scientists | ~60 | Curated zone (read); team folders and shared cluster in Databricks |
| Data engineers | ~25 | Pipeline authoring; production changes only through CI/CD |
| Platform engineers | 6 | Subscription Contributor (eligible) |
| Report creators | ~400 | Power BI workspace Contributor |

Data scientists are granted read access to the curated zone only; the raw zone is restricted to the ingestion pipelines and the platform engineering team.

No standing privileged role assignments exist on the TAP subscriptions. Platform engineers activate Contributor through Privileged Identity Management, which requires MFA, a ticket reference and approval by a second platform engineer, and expires after four hours.

## 7. Data Protection and Secrets

dlstapprd is encrypted with a customer-managed RSA 3072 key in kv-tap-prd, with automatic annual rotation. Key Vault soft delete and purge protection are enabled, and shared key authorisation is disabled on dlstapprd. The sp-tap-dbw client secret and Event Hub credentials are held in a Key Vault-backed Databricks secret scope and referenced from cluster configuration, never written into notebooks.

## 8. Environments

TAP has development, test and production environments in separate subscriptions. Production changes are deployed through Azure DevOps release pipelines with approval gates.

The non-production lake (dlstapdev) is refreshed monthly with a full copy of the production raw and curated zones, so that pipelines can be tested against realistic volumes and edge cases. In non-production, all members of the TAP engineering group, including contractors from the offshore delivery partner, hold Storage Blob Data Contributor on dlstapdev.

## 9. Logging and Monitoring

Azure AD sign-in logs, Azure Activity logs, Key Vault audit logs and Databricks audit logs are forwarded to the bank's Microsoft Sentinel workspace and retained for 12 months. Diagnostic settings on dlstapprd and stexporttap send capacity and transaction metrics to the Log Analytics workspace log-tap-prd, which retains data for 30 days. Pipeline failures raise alerts to the platform on-call rota through Azure Monitor action groups.

## 10. Resilience and Disaster Recovery

dlstapprd uses zone-redundant storage (ZRS) in UK South. ADF, Databricks and Synapse definitions are held in Git and can be redeployed to UK West within the 24-hour RTO. The six platform engineers are eligible to activate the Contributor role on the TAP production subscription through PIM so that they can rebuild services during an incident. Recovery from accidental deletion or corruption of lake data is by re-running the ADF pipelines against the source systems.
