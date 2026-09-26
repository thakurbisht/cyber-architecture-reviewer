# Kestrel Fleet Telemetry Platform — High-Level Design

Kestrel Micromobility, Platform Engineering. Version 1.1, for architecture review.

## 1. Purpose and Scope

Kestrel operates about 40,000 shared electric scooters in 18 cities across the UK, Ireland and the Netherlands. The Fleet Telemetry Platform (FTP) connects every scooter to Kestrel's AWS environment in eu-west-1, collects telemetry, executes lock and unlock commands, delivers firmware updates, and feeds the operator dashboard and the customer app.

This document covers device provisioning, the MQTT broker, command and control, stream processing and storage, firmware updates, the operator dashboard, the customer app API, and cross-cutting security, build, data classification, monitoring and resilience. Payments and the rider account service are described in separate designs.

## 2. System Overview

Figure 1 shows the main components and data flows.

| Component | Technology | Role |
|---|---|---|
| Scooter IoT module | LTE-M modem and MCU running Kestrel OS (KOS) | Telemetry, lock control, motor controller interface |
| MQTT broker | EMQX cluster (3 nodes) on Amazon EKS behind an NLB | Device connectivity |
| Command Service | Go service on EKS | Issues commands to scooters |
| Stream processing | Amazon MSK (Kafka) and Apache Flink | Enrichment, geofencing, alerts |
| Time-series store | TimescaleDB on EC2 | Telemetry history |
| Trip Service | Go service with Aurora PostgreSQL | Rides and fares |
| Operator dashboard | React SPA and API on EKS | Fleet operations |
| Customer API | Amazon API Gateway with services on EKS | Customer mobile app |

## 3. Device Platform and Provisioning

Each scooter's IoT module controls the deck lock, lights, alarm and the motor controller's power enable line. Scooters are assembled by Voltaic Assembly, a contract manufacturer in Shenzhen.

During end-of-line testing, the provisioning workstation generates an ECDSA P-256 key pair for the scooter, issues its device certificate from the Kestrel Device Issuing CA, and writes the key and certificate to the modem's flash file system. The Device Issuing CA private key is stored as a password-protected PKCS#12 file on the provisioning workstation so that the line can keep running when the factory's internet link is down.

Device certificates are valid for 20 years, matching the maximum service life of the module, and carry the scooter serial number as the common name. Production scooters keep the UART debug console on the controller board enabled; it provides a root shell that field technicians use for diagnostics in the depots.

Scooters that are stolen or written off (about 1,200 a year) are marked Retired in the fleet registry, which removes them from the operator map, the customer app and billing.

## 4. MQTT Broker

Scooters connect to the broker over the public LTE-M network on TCP 8883. The broker requires mutual TLS 1.2 and accepts any client certificate that chains to the Kestrel Device Issuing CA. Internal services such as the ingest bridge and the Command Service connect from inside the VPC with their own certificates.

| Topic | Publisher | Subscriber |
|---|---|---|
| scooters/{serial}/telemetry | Scooter | Ingest bridge |
| scooters/{serial}/events | Scooter | Ingest bridge |
| scooters/{serial}/cmd | Command Service | Scooter |
| scooters/{serial}/cmd/ack | Scooter | Command Service |

The broker authorisation rule grants every client presenting a valid device certificate publish and subscribe rights on scooters/#.

## 5. Command and Control

The Command Service accepts requests from the Trip Service (unlock at ride start, lock at ride end), the OTA Service and the operator dashboard, and publishes them to the scooter's command topic. Supported commands are UNLOCK, LOCK, ALARM, SET_SPEED_LIMIT, OTA_NOTIFY and IMMOBILISE, which cuts motor power immediately.

Commands are JSON messages containing the command, a request ID and a timestamp; the firmware executes any well-formed command received on its command topic and replies on cmd/ack.

When a scooter has no cellular coverage, the customer app unlocks it directly over Bluetooth Low Energy.

## 6. Stream Processing and Storage

An ingest bridge subscribes to the telemetry and events topics of all scooters and writes the messages to Kafka. Flink jobs enrich events with city and zone data, enforce geofences such as slow zones and no-parking zones, and raise battery and tamper alerts.

While a ride is in progress, scooters report their GPS position every 5 seconds; when parked, every 5 minutes. Flink writes all telemetry to TimescaleDB hypertables, which are retained indefinitely for demand modelling and city reporting.

The Trip Service stores a ride record containing the rider account ID, scooter serial, start and end times and fare in the rides table in Aurora PostgreSQL.

TimescaleDB volumes, Aurora and MSK are encrypted at rest with AWS KMS keys, and all connections between services, Kafka and the databases use TLS.

## 7. Firmware OTA Updates

Release images are signed with the Kestrel firmware signing key (ECDSA P-256) in the GitLab release job, and the OTA Service rolls them out to the whole fleet in waves over 48 hours.

The OTA Service sends OTA_NOTIFY with a manifest URL, and the scooter downloads the manifest and image over plain HTTP from a CloudFront distribution, because TLS session setup over LTE-M adds significant time and energy for a 3 MB image.

## 8. Operator Dashboard and Customer App

### 8.1 Operator Dashboard

The dashboard is used by about 300 Kestrel operations staff and about 500 city contractors who collect, charge and redistribute scooters. Users sign in through the corporate identity provider with MFA.

All dashboard users, including city contractors, can view the live fleet map and replay the GPS trail of any scooter for any date range. Dashboard users can lock, unlock, sound the alarm on or immobilise any scooter from the fleet map.

### 8.2 Customer App API

| Endpoint | Purpose |
|---|---|
| GET /v1/scooters/nearby | Available scooters near a location |
| POST /v1/rides | Start a ride |
| POST /v1/rides/{rideId}/end | End a ride |
| GET /v1/rides/{rideId}/trail | GPS trail of a ride |

The nearby endpoint is callable without logging in, so that prospective customers can see scooter locations before they register.

Ride IDs are sequential integers assigned by the rides table, and GET /v1/rides/{rideId}/trail returns the full GPS trail of the given ride for the ride summary screen and receipt.

## 9. Security Controls

Customers authenticate with Amazon Cognito. The API Gateway validates the Cognito JWT signature, expiry and audience on every authenticated request; backend services trust requests forwarded by the gateway and do not repeat authorisation checks.

GET /v1/scooters/nearby returns only parked scooters that are available for hire, never scooters in an active ride, with positions rounded to 10 metres, and is rate-limited to 60 requests per minute per IP address.

Bluetooth unlock requires an unlock token issued by the Trip Service for a specific rider and scooter serial, signed with a Kestrel key that the firmware verifies, valid for 60 seconds and usable only once.

Before flashing, the bootloader verifies the image's ECDSA signature against the public key embedded in the bootloader and rejects any image whose version is lower than the installed version.

## 10. Build and Release

Firmware and cloud services are built in GitLab CI. The firmware signing private key is stored as a masked CI/CD variable in the kos-firmware GitLab project and is available to all pipeline jobs, including jobs run for merge requests from feature branches. About 45 Kestrel engineers and two external firmware contractors have the Developer role on the project.

## 11. Data Classification and Retention

Telemetry, including GPS positions, is classified as Internal (non-personal device data) and is therefore outside the controls applied to personal data, such as access reviews and the retention schedule. Rider account data (name, email address, phone number and payment token) is classified Confidential and is deleted 24 months after account closure.

## 12. Logging and Monitoring

Application and broker logs from all services are shipped to Amazon OpenSearch and retained for 14 days. CloudWatch alarms cover broker connection counts, Kafka consumer lag, API error rates and TimescaleDB replication lag, and page the on-call engineer.

## 13. Resilience

The EMQX nodes, MSK brokers and EKS node groups are spread across three availability zones. TimescaleDB runs a primary with a streaming replica in a second zone and takes encrypted daily snapshots. Scooters buffer up to 24 hours of telemetry locally when the broker is unreachable and continue to honour BLE unlock tokens.
