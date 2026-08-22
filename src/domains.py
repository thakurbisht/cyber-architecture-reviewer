"""Review domain taxonomy and section classification.

The original single-domain network reviewer issued one broad query per
section. This version classifies every section into one of four review
domains and a finer-grained *topic*, so retrieval can be pointed at the
right knowledge-base collection with a query built from domain vocabulary
rather than the raw heading text.

Classification is deterministic (keyword scoring). It never calls the LLM,
which means the same document always produces the same section map - an
important property when you need reviews to be comparable over time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

# --------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------
NETWORK = "network"
APPLICATION = "application"
SECURITY = "security"
CLOUD_DATA = "cloud_data"
GENERAL = "general"

DOMAIN_LABELS: Dict[str, str] = {
    NETWORK: "Network Architecture",
    APPLICATION: "Application Architecture",
    SECURITY: "Cyber / Security Architecture",
    CLOUD_DATA: "Cloud & Data Architecture",
    GENERAL: "General / Context",
}


@dataclass(frozen=True)
class Topic:
    """A fine-grained review topic within a domain."""

    key: str
    label: str
    domain: str
    keywords: Tuple[str, ...]
    # Extra vocabulary injected into the retrieval query for this topic.
    query_terms: Tuple[str, ...] = ()


# --------------------------------------------------------------------------
# Topic catalogue
# --------------------------------------------------------------------------
TOPICS: Tuple[Topic, ...] = (
    # ---- Network ---------------------------------------------------------
    Topic("access_layer", "Access Layer", NETWORK,
          ("access switch", "access layer", "edge switch", "user port",
           "wiring closet", "idf", "poe", "end user port"),
          ("uplink diversity", "redundant uplinks", "access to distribution")),
    Topic("distribution_core", "Distribution / Core", NETWORK,
          ("distribution", "core switch", "aggregation", "spine", "leaf",
           "collapsed core", "mdf"),
          ("layer 3 boundary", "core redundancy", "spine leaf")),
    Topic("routing", "Routing & Switching", NETWORK,
          ("routing", "ospf", "bgp", "eigrp", "isis", "static route",
           "vrf", "spanning tree", "stp", "hsrp", "vrrp", "gateway redundancy",
           "route map", "prefix list"),
          ("routing protocol authentication", "route filtering",
           "first hop redundancy")),
    Topic("wan_edge", "WAN & Internet Edge", NETWORK,
          ("wan", "mpls", "sd-wan", "sdwan", "internet edge", "circuit",
           "carrier", "leased line", "dia", "branch connectivity", "ipsec tunnel",
           "peering"),
          ("carrier diversity", "wan redundancy", "encrypted transport")),
    Topic("segmentation", "Segmentation & Micro-segmentation", NETWORK,
          ("vlan", "segmentation", "micro-segmentation", "microsegmentation",
           "security zone", "dmz", "east-west", "firewall", "acl",
           "security group", "nsg", "trust zone", "permit", "deny",
           "rule set", "policy set", "inbound", "any any"),
          ("zone based policy", "default deny", "lateral movement")),
    Topic("ha_resilience", "High Availability & Resilience", NETWORK,
          ("high availability", "redundancy", "failover", "resilience",
           "cluster", "active-active", "active-standby", "rpo", "rto",
           "single point of failure", "spof"),
          ("no single point of failure", "failover testing", "diverse path")),
    Topic("network_management", "Network Management & Monitoring", NETWORK,
          ("snmp", "syslog", "netflow", "tacacs", "radius", "aaa",
           "out-of-band", "oob", "management vlan", "ntp", "jump host",
           "device management", "telemetry"),
          ("secure management plane", "snmpv3", "out of band management")),
    Topic("wireless", "Wireless & Mobility", NETWORK,
          ("wireless", "wlan", "wi-fi", "wifi", "ssid", "access point",
           "wpa2", "wpa3", "802.1x", "captive portal"),
          ("wireless authentication", "guest isolation", "rogue ap")),
    Topic("dns_dhcp_ipam", "DNS / DHCP / IPAM", NETWORK,
          ("dns", "dhcp", "ipam", "ip addressing", "subnet plan",
           "address plan", "name resolution"),
          ("dns security", "address plan hygiene")),

    # ---- Application -----------------------------------------------------
    Topic("app_structure", "Application Structure & Tiers", APPLICATION,
          ("application architecture", "microservice", "monolith", "tier",
           "component diagram", "service mesh", "container", "kubernetes",
           "pod", "runtime", "middleware", "message queue", "event bus"),
          ("tier separation", "service boundary", "workload isolation")),
    Topic("api_integration", "APIs & Integration", APPLICATION,
          ("api", "rest", "graphql", "grpc", "soap", "endpoint", "webhook",
           "integration", "api gateway", "openapi", "swagger", "payload",
           "rate limit", "third party integration"),
          ("api authentication", "input validation", "rate limiting",
           "schema validation")),
    Topic("app_authn_authz", "Application AuthN / AuthZ", APPLICATION,
          ("authentication", "authorisation", "authorization", "oauth",
           "oidc", "saml", "jwt", "session", "token", "rbac", "abac",
           "login", "sso", "password policy", "service account"),
          ("token validation", "least privilege", "session management")),
    Topic("app_data_handling", "Application Data Handling", APPLICATION,
          ("input validation", "sanitisation", "sanitization", "sql",
           "orm", "serialisation", "deserialization", "file upload",
           "output encoding", "template", "xss", "injection"),
          ("injection prevention", "output encoding", "safe deserialisation")),
    Topic("secrets_config", "Secrets & Configuration", APPLICATION,
          ("secret", "credential", "api key", "connection string",
           "environment variable", "config file", "vault", "keystore",
           "hardcoded", "password in", ".env"),
          ("secret management", "no hardcoded credentials", "rotation")),
    Topic("sdlc_supplychain", "SDLC & Supply Chain", APPLICATION,
          ("ci/cd", "cicd", "pipeline", "build", "artifact", "dependency",
           "sbom", "third-party library", "open source component", "sast",
           "dast", "sca", "code review", "container image", "registry"),
          ("dependency scanning", "signed artifacts", "pipeline controls")),
    Topic("app_resilience", "Application Resilience & Performance", APPLICATION,
          ("scaling", "autoscal", "load balanc", "circuit breaker",
           "retry", "timeout", "caching", "throughput", "latency budget",
           "graceful degradation", "queue depth"),
          ("failure isolation", "backpressure", "capacity planning")),

    # ---- Security / Cyber ------------------------------------------------
    Topic("zero_trust", "Zero Trust & Access Control", SECURITY,
          ("zero trust", "ztna", "policy enforcement point", "policy decision",
           "implicit trust", "never trust", "conditional access",
           "device posture", "continuous verification"),
          ("policy enforcement point", "per-session authorisation",
           "device posture check")),
    Topic("iam_privileged", "Identity & Privileged Access", SECURITY,
          # NOTE: bare "identity" is deliberately excluded - it collides with
          # "national identity number" and pulls data sections into IAM.
          ("identity provider", "identity management", "iam", "privileged",
           "pam", "admin account", "administrative access", "mfa",
           "multi-factor", "break glass", "joiner mover leaver", "entitlement",
           "role assignment", "directory", "active directory", "service account",
           "least privilege"),
          ("privileged access management", "mfa enforcement",
           "separation of duties")),
    Topic("crypto_keys", "Cryptography & Key Management", SECURITY,
          ("encryption", "tls", "ssl", "cipher", "certificate", "pki",
           "hsm", "key management", "kms", "hashing", "at rest", "in transit",
           "mtls", "key rotation"),
          ("approved cipher suites", "key rotation", "certificate lifecycle")),
    Topic("logging_detection", "Logging, Monitoring & Detection", SECURITY,
          ("siem", "logging", "audit log", "soc", "detection", "alerting",
           "edr", "xdr", "log retention", "correlation rule", "use case",
           "threat hunting", "mitre att&ck", "attack technique"),
          ("log retention period", "detection coverage", "tamper-proof logs")),
    Topic("threat_model", "Threat Model & Attack Surface", SECURITY,
          ("threat model", "stride", "attack surface", "threat actor",
           "kill chain", "abuse case", "risk assessment", "residual risk",
           "attack path", "adversary"),
          ("threat modelling completeness", "attack surface reduction")),
    Topic("vuln_patch", "Vulnerability & Patch Management", SECURITY,
          ("vulnerability", "patch", "cve", "hardening", "baseline",
           "penetration test", "scan", "remediation sla", "end of life",
           "eol", "unsupported version"),
          ("patch sla", "hardening baseline", "eol software")),
    Topic("resilience_ir", "Resilience, Backup & Incident Response", SECURITY,
          ("incident response", "playbook", "backup", "restore", "disaster recovery",
           "business continuity", "ransomware", "immutable backup", "dr site",
           "runbook", "tabletop"),
          ("immutable backup", "tested restore", "incident escalation")),

    # ---- Cloud & Data ----------------------------------------------------
    Topic("cloud_landing_zone", "Cloud Landing Zone & Tenancy", CLOUD_DATA,
          ("landing zone", "account structure", "subscription", "tenant",
           "organisation unit", "guardrail", "scp", "azure policy",
           "resource group", "vpc", "vnet", "transit gateway", "region"),
          ("account separation", "preventative guardrails", "blast radius")),
    Topic("iac_posture", "Infrastructure as Code & Posture", CLOUD_DATA,
          ("terraform", "cloudformation", "bicep", "ansible", "pulumi",
           "infrastructure as code", "iac", "drift", "cspm", "posture management",
           "state file", "module registry"),
          ("iac scanning", "drift detection", "state file protection")),
    Topic("data_classification", "Data Classification & Residency", CLOUD_DATA,
          ("data classification", "pii", "phi", "pci", "sensitive data",
           "residency", "sovereignty", "cross-border", "gdpr", "data owner",
           "retention", "records management", "tokenis", "masking",
           "personal data", "customer data", "card number", "cardholder",
           "identity number", "national id", "date of birth",
           "customer record", "regulated data"),
          ("classification labels", "residency constraint", "retention schedule")),
    Topic("data_protection", "Data Protection & Storage", CLOUD_DATA,
          ("s3", "blob storage", "bucket", "database", "rds", "data lake",
           "warehouse", "snapshot", "replica", "public access", "object storage",
           "encryption at rest", "backup vault"),
          ("public access block", "encryption at rest", "snapshot protection")),
    Topic("cloud_network", "Cloud Network Controls", CLOUD_DATA,
          ("security group", "nacl", "private endpoint", "privatelink",
           "egress", "nat gateway", "public subnet", "private subnet",
           "load balancer", "waf", "cdn", "internet gateway"),
          ("egress control", "private connectivity", "waf coverage")),

    # ---- General ---------------------------------------------------------
    Topic("context_scope", "Context, Scope & Requirements", GENERAL,
          ("executive summary", "introduction", "scope", "assumption",
           "requirement", "background", "objective", "stakeholder",
           "document control", "version history", "glossary", "references"),
          ()),
)

TOPIC_BY_KEY: Dict[str, Topic] = {t.key: t for t in TOPICS}


def topics_for_domain(domain: str) -> List[Topic]:
    return [t for t in TOPICS if t.domain == domain]


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
_WORD_RE = re.compile(r"[a-z0-9&/\.\-\+]+")


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def score_topics(heading: str, body: str) -> Dict[str, float]:
    """Score every topic against a section.

    Heading matches are weighted 3x body matches - a section titled
    "Firewall Policy" is about segmentation even if the body mentions BGP
    once in passing.
    """
    h = _normalise(heading)
    b = _normalise(body)
    scores: Dict[str, float] = {}

    for topic in TOPICS:
        score = 0.0
        for kw in topic.keywords:
            if kw in h:
                score += 3.0
            # Count body occurrences but damp the tail: the 5th mention of
            # "vlan" tells us little more than the 2nd.
            count = b.count(kw)
            if count:
                score += min(count, 4) * 1.0
        if score:
            scores[topic.key] = score
    return scores


def classify_section(heading: str, body: str) -> Tuple[str, str, float, List[str]]:
    """Return (domain, topic_key, confidence, secondary_topic_keys).

    Confidence is the winning topic's share of total scored weight. A low
    confidence value is surfaced in the report so a human reviewer knows the
    agent was unsure which lens to apply.
    """
    scores = score_topics(heading, body)
    if not scores:
        return GENERAL, "context_scope", 0.0, []

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    total = sum(scores.values()) or 1.0
    top_key, top_score = ranked[0]
    confidence = round(top_score / total, 3)

    # Secondary topics that scored at least 50% of the winner get carried
    # forward - they drive supplementary retrieval queries and are how
    # cross-domain issues get caught.
    secondary = [k for k, v in ranked[1:5] if v >= top_score * 0.5]

    return TOPIC_BY_KEY[top_key].domain, top_key, confidence, secondary


def build_retrieval_query(heading: str, topic_key: str, body: str,
                          max_body_words: int = 120) -> str:
    """Build a targeted retrieval query for a section.

    Combines the heading, the topic's curated query vocabulary, and a
    truncated body sample. The curated vocabulary is what lifts retrieval
    above naive "embed the whole section" - it steers the query vector
    toward the language the standards are written in, not the language the
    design document happens to use.
    """
    topic = TOPIC_BY_KEY.get(topic_key)
    parts: List[str] = [heading.strip()]
    if topic:
        parts.append(topic.label)
        parts.extend(topic.query_terms)
    body_words = body.split()
    parts.append(" ".join(body_words[:max_body_words]))
    return " ".join(p for p in parts if p).strip()
