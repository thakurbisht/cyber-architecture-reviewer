# Logging, Monitoring and Detection Standard

Owner: Security Operations / Security Architecture
Applies to: every design that introduces a system, service or access path

## 1.1 Principle

A design is not complete when it can be built. It is complete when an analyst can tell, from the telemetry it produces, whether it is being attacked. Detection is a design property, not an operations afterthought.

## 2.1 Central aggregation

Requirement: Security-relevant events MUST be forwarded to the central SIEM in near real time. Local-only logging is not acceptable for any production component.

FINDING TRIGGER: If no central log aggregation or SIEM forwarding is described, flag as HIGH.
FINDING TRIGGER: If logs are held only on the system that generates them, flag as HIGH — the first action of a competent intruder is to clear them.

## 2.2 Mandatory event set

Requirement: Every system MUST log, at minimum:
- authentication success and failure, with source
- authorisation denials
- privilege escalation and role assignment changes
- account lifecycle events
- configuration and policy changes
- administrative and break-glass access
- data export or bulk read operations above a defined threshold
- security control state changes (agent stopped, logging disabled)

FINDING TRIGGER: If any of these categories is absent from the described logging, flag as MEDIUM per missing category; flag as HIGH if authentication or administrative events are missing.

## 2.3 Log content quality

Requirement: Events MUST include timestamp in UTC with source-synchronised time, actor identity, source address, target resource, action, and outcome. A correlation identifier MUST span the request path across components.

FINDING TRIGGER: If a distributed design has no correlation identifier, flag as MEDIUM — an incident spanning services becomes uninvestigable.
FINDING TRIGGER: If NTP synchronisation is not described, flag as MEDIUM.

## 3.1 Log integrity

Requirement: The security log tier MUST be write-once or append-only, and MUST NOT be alterable by the administrators of the systems that produce the logs.

FINDING TRIGGER: If system administrators can delete or modify their own system's security logs, flag as HIGH.
FINDING TRIGGER: If log integrity protection is not described, flag as MEDIUM.

## 3.3 Sensitive data in logs

Requirement: Logs MUST NOT contain passwords, tokens, full payment card numbers, health data, or unmasked personal data. Where a field must be logged for investigation, it MUST be tokenised or truncated.

FINDING TRIGGER: If sensitive data is described as logged, flag as HIGH.
FINDING TRIGGER: If debug or verbose logging is enabled in production, flag as MEDIUM.

## 4.1 Retention

Requirement: Security logs MUST be retained for a minimum of 12 months, with the most recent 90 days immediately searchable. Longer periods apply where regulation requires.

FINDING TRIGGER: If retention is unspecified, flag as MEDIUM.
FINDING TRIGGER: If retention is shorter than 12 months, flag as MEDIUM, stating the shortfall. Intrusions are frequently discovered months after they begin.

## 5.1 Detection coverage

Requirement: The design MUST state which detection use cases cover the system, mapped to MITRE ATT&CK techniques relevant to its exposure. A new internet-facing service MUST have detections for initial access and credential attacks before go-live.

FINDING TRIGGER: If no detection use cases accompany a new internet-facing service, flag as HIGH.
FINDING TRIGGER: If detection coverage is not mapped to any threat framework, flag as LOW.

## 5.2 Alerting and response

Requirement: Every alert MUST have an owner, a documented triage procedure, and a defined response time. Alerts with no runbook MUST NOT be enabled.

FINDING TRIGGER: If alerts are described with no response process, flag as MEDIUM.
FINDING TRIGGER: If alert destinations are email inboxes with no on-call rotation, flag as MEDIUM.

## 5.3 Monitoring the monitoring

Requirement: Loss of log flow from any source MUST itself raise an alert within one hour.

FINDING TRIGGER: If log-source health monitoring is not described, flag as MEDIUM — silent log loss is indistinguishable from silence.

## 6.1 Endpoint and workload telemetry

Requirement: Servers, containers and endpoints MUST run approved EDR with telemetry to the SOC. Container workloads MUST emit runtime telemetry.

FINDING TRIGGER: If production workloads have no endpoint or runtime detection, flag as HIGH.
FINDING TRIGGER: If EDR is described as optional or exempted for performance reasons without a compensating control, flag as HIGH.

## 6.2 Network telemetry

Requirement: Flow data MUST be collected at zone boundaries and internet egress, and DNS query logs MUST be retained.

FINDING TRIGGER: If no network flow visibility exists at zone boundaries, flag as MEDIUM.
FINDING TRIGGER: If DNS logging is absent, flag as MEDIUM — DNS is the most reliable indicator of command-and-control.

## 7.1 Cloud control plane

Requirement: Cloud control-plane audit logs MUST be enabled in every account and region, delivered to a separate logging account that workload administrators cannot access, and protected from deletion.

FINDING TRIGGER: If cloud audit logging is not enabled organisation-wide, flag as HIGH.
FINDING TRIGGER: If audit logs are stored in the same account as the workloads they record, flag as HIGH.

Control mapping: NIST SP 800-53 AU-2, AU-3, AU-6, AU-9, AU-11, SI-4; ISO/IEC 27001:2022 A.8.15, A.8.16; NIST CSF DE.AE, DE.CM; MITRE ATT&CK T1562.008, T1070.
