"""Deterministic rules engine tests.

These are the tests that must never be flaky. If the rules engine is not
byte-for-byte reproducible, the whole repeatability argument collapses.
"""

from __future__ import annotations

from src.parser import parse_text
from src.rules import ALL_RULES, run_rules, rules_summary


def _fire(text: str) -> set[str]:
    """Return the set of rule ids that fire for a snippet."""
    sections = parse_text(text, "test")
    return {f.rule_id for f in run_rules(sections)}


# -- network ---------------------------------------------------------------
def test_snmpv2c_is_critical():
    fired = _fire("## Management\n\nSNMPv2c is configured with community "
                  "string public for the monitoring platform to poll devices.")
    assert "NET-MGMT-001" in fired
    assert "NET-MGMT-002" in fired


def test_snmpv3_suppresses_snmp_rule():
    fired = _fire("## Management\n\nSNMPv3 authPriv is configured on all "
                  "devices with per device credentials rotated every 90 days.")
    assert "NET-MGMT-001" not in fired


def test_any_any_rule_is_critical():
    fired = _fire("## Firewall\n\nRule 2 is Source: Any Destination: Any "
                  "Service: Any Action: Allow retained after migration testing.")
    assert "NET-SEG-001" in fired


def test_uplinks_on_same_device_detected():
    fired = _fire(
        "## Access Layer\n\nFloor 4 and Floor 9 have two uplinks each but "
        "both terminate on the same distribution switch DIST-SW-A because "
        "the fibre count was insufficient."
    )
    assert "NET-HA-002" in fired


def test_single_uplink_detected():
    fired = _fire("## WAN\n\nThe site connects over a single circuit from "
                  "Carrier A which is a single point of failure accepted by "
                  "the project team.")
    assert "NET-HA-001" in fired


def test_routing_without_authentication():
    fired = _fire("## Routing\n\nOSPF is used between distribution and core "
                  "in a single area zero for the campus network design.")
    assert "NET-RTG-001" in fired


def test_routing_with_authentication_suppressed():
    fired = _fire("## Routing\n\nOSPF area zero uses HMAC-SHA authentication "
                  "on every adjacency with passive-interface default applied.")
    assert "NET-RTG-001" not in fired


# -- application -----------------------------------------------------------
def test_hardcoded_secret_detected():
    fired = _fire("## Data Handling\n\nThe encryption key is held in the "
                  "application configuration file which is deployed as a "
                  "Kubernetes ConfigMap alongside the database password.")
    assert "APP-SEC-001" in fired


def test_vault_suppresses_secret_rule():
    fired = _fire("## Secrets\n\nCredentials are stored in the enterprise "
                  "secrets manager and injected at runtime via workload "
                  "identity so no static secret exists in configuration.")
    assert "APP-SEC-001" not in fired


def test_unauthenticated_endpoint_detected():
    fired = _fire("## API\n\nThe bank webhook endpoint accepts unauthenticated "
                  "POST requests because the bank cannot support OAuth.")
    assert "APP-AUTH-001" in fired


def test_string_concatenated_sql_detected():
    fired = _fire("## Reporting\n\nReporting queries are constructed by "
                  "concatenating the requested filter values into the SQL "
                  "string because requirements change frequently.")
    assert "APP-DATA-001" in fired


def test_parameterised_queries_suppress_sql_rule():
    fired = _fire("## Reporting\n\nAll database access uses parameterised "
                  "queries through the ORM binding API with no dynamic SQL "
                  "construction anywhere in the codebase.")
    assert "APP-DATA-001" not in fired


def test_deprecated_tls_detected():
    fired = _fire("## Transport\n\nThe API is exposed over HTTPS with TLS 1.0 "
                  "still enabled for compatibility with older merchant client "
                  "libraries that have not upgraded.")
    assert "APP-TLS-001" in fired


# -- security --------------------------------------------------------------
def test_privileged_access_without_mfa():
    fired = _fire("## Identity\n\nSupport staff use the administrative console "
                  "with privileged access granted permanently through the "
                  "corporate directory group membership.")
    assert "SEC-IAM-001" in fired


def test_mfa_suppresses_privileged_rule():
    fired = _fire("## Identity\n\nAdministrative access requires FIDO2 "
                  "phishing resistant MFA brokered through the privileged "
                  "access management platform with session recording.")
    assert "SEC-IAM-001" not in fired


def test_implicit_trust_detected():
    fired = _fire("## API\n\nThe internal reporting API has no authentication "
                  "because internal traffic is trusted and it is only "
                  "reachable from the corporate network.")
    assert "SEC-ZT-001" in fired


def test_weak_crypto_detected():
    fired = _fire("## Storage\n\nPasswords are hashed using SHA-1 and legacy "
                  "records use MD5 checksums for integrity verification.")
    assert "SEC-CRYPTO-001" in fired


def test_weak_crypto_prohibition_is_suppressed():
    fired = _fire("## Cryptography\n\nMD5 and SHA-1 are prohibited and must "
                  "not be used anywhere in the solution under any "
                  "circumstances whatsoever.")
    assert "SEC-CRYPTO-001" not in fired


def test_eol_software_detected():
    fired = _fire("## Compute\n\nThe base operating system is CentOS 7 which "
                  "the community AMI was built on for the data science "
                  "tooling it includes.")
    assert "SEC-VULN-001" in fired


def test_backup_without_immutability():
    fired = _fire("## Recovery\n\nThe database is backed up nightly to object "
                  "storage in the same subscription with 14 day retention for "
                  "operational recovery purposes.")
    assert "SEC-RES-001" in fired


def test_backup_with_immutability_suppressed():
    fired = _fire("## Recovery\n\nBackups are written to an immutable vault "
                  "with object lock in a separate account and a tested restore "
                  "is performed quarterly against the stated RTO.")
    assert "SEC-RES-001" not in fired


def test_threat_model_absence_is_document_scope():
    text = ("## Solution Overview\n\nThe architecture overview describes the "
            "components and their interactions across the platform in detail "
            "for the design authority audience.")
    findings = [f for f in run_rules(parse_text(text, "t"))
                if f.rule_id == "SEC-TM-001"]
    assert len(findings) == 1
    assert findings[0].section == "Whole document"


# -- cloud -----------------------------------------------------------------
def test_public_bucket_detected():
    fired = _fire("## Storage\n\nThe reports bucket has public read access so "
                  "that generated reports can be shared by link with the "
                  "regional offices without credentials.")
    assert "CLD-STOR-001" in fired


def test_wildcard_iam_detected():
    fired = _fire("## Identity\n\nThe analytics role has the "
                  "AdministratorAccess managed policy attached which was "
                  "applied during development to avoid permission errors.")
    assert "CLD-IAM-001" in fired


def test_open_database_port_detected():
    fired = _fire("## Network\n\nSecurity group helios-db-sg permits inbound "
                  "TCP 5432 from 0.0.0.0/0 because the on premise NAT "
                  "addresses change frequently.")
    assert "CLD-NET-001" in fired


def test_shared_account_detected():
    fired = _fire("## Accounts\n\nThere is a single subscription hosting "
                  "production, UAT and development workloads separated by "
                  "namespace to reduce cost and simplify networking.")
    assert "CLD-LZ-001" in fired


def test_regulated_data_without_classification():
    fired = _fire("## Data\n\nThe ingested data contains customer names, "
                  "national identity numbers, account numbers and full "
                  "payment card numbers from the core banking export.")
    assert "CLD-DATA-001" in fired


# -- engine properties -----------------------------------------------------
def test_rules_are_deterministic():
    text = open("samples/sample-campus-lan-lld.md", encoding="utf-8").read()
    sections = parse_text(text, "sample")
    first = [(f.rule_id, f.section, f.severity, f.issue)
             for f in run_rules(sections)]
    second = [(f.rule_id, f.section, f.severity, f.issue)
              for f in run_rules(sections)]
    assert first == second
    assert len(first) > 8


def test_domain_filter_limits_rules():
    text = open("samples/sample-payments-app-hld.md", encoding="utf-8").read()
    sections = parse_text(text, "sample")
    only_app = run_rules(sections, ["application"])
    assert only_app
    assert {f.domain for f in only_app} == {"application"}


def test_every_rule_has_required_fields():
    for rule in ALL_RULES:
        assert rule.id and rule.issue and rule.recommendation
        assert rule.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        # Expert rules fire on hard evidence only (never suppressed), so a
        # rule needs a trigger OR a hard trigger.
        assert rule.trigger or rule.hard_trigger, f"{rule.id} has no trigger pattern"
        # A regex that fails to compile would break the run at review time.
        rule.compiled_trigger()
        rule.compiled_hard_trigger()
        rule.compiled_suppressors()


def test_rule_ids_are_unique():
    ids = [r.id for r in ALL_RULES]
    assert len(ids) == len(set(ids))


def test_rules_summary_covers_all_domains():
    summary = rules_summary()
    assert set(summary) == {"network", "application", "security", "cloud_data"}
    assert all(v > 0 for v in summary.values())


# -- phrasing coverage (2026-09-27 grilling) --------------------------------
# Each planted golden-set issue the rules missed, re-worded here so the tests
# check the phrasing class, not the golden sentence.
def _kinds(text: str) -> dict[str, str]:
    return {f.rule_id: f.kind for f in run_rules(parse_text(text, "test"))}


def test_snmp_v2c_polling_without_config_verb():
    fired = _fire("## Monitoring\n\nThe collector polls every router over "
                  "SNMP v2c using a read-write community shared by all sites.")
    assert {"NET-MGMT-001", "NET-MGMT-002"} <= fired


def test_snmp_migration_to_v3_is_not_flagged():
    fired = _fire("## Monitoring\n\nAll devices use SNMPv3 authPriv; the "
                  "former SNMP v2c configuration was removed in 2025.")
    assert "NET-MGMT-001" not in fired


def test_wpa2_personal_detected():
    fired = _fire("## Wireless\n\nHandheld terminals join the ops SSID with "
                  "WPA3-Personal and one passphrase for the whole fleet.")
    assert "NET-WLS-001" in fired


def test_psk_on_isolated_guest_ssid_is_accepted():
    fired = _fire("## Wireless\n\nThe guest SSID is isolated, internet-only, "
                  "and uses a pre-shared key rotated weekly.")
    assert "NET-WLS-001" not in fired


def test_secret_in_values_file_not_cancelled_by_vault_elsewhere():
    fired = _fire("## Deployment\n\nMost services read secrets from Key Vault. "
                  "The billing adapter's API key is set in the Helm "
                  "values-prod.yaml file in the platform repository.")
    assert "APP-SEC-001" in fired


def test_secret_held_as_pipeline_parameter_default():
    fired = _fire("## Pipelines\n\nThe warehouse loader's database password "
                  "is kept as the default value of a pipeline parameter.")
    assert "APP-SEC-001" in fired


def test_secret_in_vault_is_not_flagged():
    fired = _fire("## Pipelines\n\nThe loader's credentials are stored in the "
                  "secrets manager and injected at runtime via workload identity.")
    assert "APP-SEC-001" not in fired


def test_publicly_accessible_database_replica():
    fired = _fire("## Data\n\nA reporting replica of the orders database is "
                  "set to publicly accessible so the SaaS BI tool can reach it.")
    assert "CLD-STOR-001" in fired


def test_container_public_access_level():
    fired = _fire("## Storage\n\nThe downloads container's public access "
                  "level is set to Blob so partners can fetch files.")
    assert "CLD-STOR-001" in fired


def test_ldap_simple_bind_detected():
    fired = _fire("## Directory\n\nThe legacy CRM authenticates users with "
                  "LDAP simple binds against the directory on port 389.")
    assert "SEC-IAM-003" in fired


def test_ldaps_is_not_flagged():
    fired = _fire("## Directory\n\nAll LDAP traffic uses LDAPS on 636 with "
                  "channel binding enforced.")
    assert "SEC-IAM-003" not in fired


def test_pre_shared_key_is_not_a_shared_human_account():
    fired = _fire("## Wireless\n\nScanners use WPA2-Personal with a pre-shared key.")
    assert "SEC-IAM-002" not in fired


# -- findings vs questions ---------------------------------------------------
def test_absence_rules_are_questions():
    backups = _kinds("## Resilience\n\nDatabases are backed up nightly to "
                     "a second region.")
    no_threat_model = _kinds("## Design\n\nThe solution architecture uses "
                             "a web tier, an app tier and a database tier.")
    assert backups.get("SEC-RES-001") == "question"
    assert no_threat_model.get("SEC-TM-001") == "question"


def test_topic_only_hit_is_question_but_hard_evidence_is_finding():
    soft = _kinds("## Identity\n\nAdministrators use the privileged access "
                  "console for HSM administration.")
    hard = _kinds("## Identity\n\nMFA is optional for administrators using "
                  "the privileged access console.")
    assert soft.get("SEC-IAM-001") == "question"
    assert hard.get("SEC-IAM-001") == "finding"
