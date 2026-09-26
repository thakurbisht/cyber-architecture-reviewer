#!/usr/bin/env python3
"""
Patches src/agent.py to fix:
  AttributeError: 'SkillFinding' object has no attribute 'fingerprint'

Run this from D:\\cyber-architecture-reviewer (same folder as config.yaml):
    python fix_skillfinding_bug.py

It is safe to run more than once - each patch is skipped if already applied.
"""

import sys
from pathlib import Path

AGENT_PATH = Path("src/agent.py")

PATCH_1_OLD = """                            findings = executor.execute(section_text, section_name)
                            skill_findings.extend(findings)"""

PATCH_1_NEW = """                            findings = executor.execute(section_text, section_name)
                            # Stash the section name on each SkillFinding so it
                            # survives into review()'s conversion to a base
                            # Finding - SkillFinding itself has no section field.
                            for _sf in findings:
                                _sf._section_name = section_name
                            skill_findings.extend(findings)"""

PATCH_2_OLD = """        # Merge findings from all sources (rules, skills, agent)
        all_findings = final.get("findings", [])
        skill_findings = final.get("skill_findings", [])
        if skill_findings:
            all_findings.extend(skill_findings)"""

PATCH_2_NEW = """        # Merge findings from all sources (rules, skills, agent)
        all_findings = final.get("findings", [])
        skill_findings = final.get("skill_findings", [])
        if skill_findings:
            # skill_execution_node returns raw SkillFinding objects (a
            # separate dataclass from skill_executor_v2.py, not a Finding
            # subclass - it has no .fingerprint/.id-compatible shape for
            # dedupe_findings()/sort_findings()). Convert each one to a
            # base Finding before merging, or dedupe_findings() below
            # raises AttributeError the moment a skill actually matches
            # something (it stayed hidden until a real match occurred).
            all_findings.extend(
                self._skill_finding_to_finding(sf) for sf in skill_findings
            )"""

PATCH_3_OLD = """        except Exception as e:
            self.audit.record("skill_discovery_error", error=str(e))
            return {"selected_skills": [], "skill_rankings": []}

    def skill_execution_node(self, state: ReviewState) -> Dict[str, Any]:"""

PATCH_3_NEW = """        except Exception as e:
            self.audit.record("skill_discovery_error", error=str(e))
            return {"selected_skills": [], "skill_rankings": []}

    # Skill domain labels (e.g. "Cloud Security") don't match the four
    # short domain keys the rest of the pipeline uses for coverage/report
    # grouping and the config.domains toggles - map them here.
    _SKILL_DOMAIN_MAP = {
        "cloud security": "cloud_data",
        "network security": "network",
        "application security": "application",
    }

    def _skill_finding_to_finding(self, sf: Any) -> Finding:
        \"\"\"Convert a SkillFinding (skill_executor_v2's own dataclass) into
        the base Finding used everywhere else in the pipeline.

        SkillFinding is deliberately not a Finding subclass - it carries
        skill-specific fields (skill_id, skill_domain, mitre_attack, ...)
        produced by the deterministic pattern-matching layer. But
        dedupe_findings()/sort_findings() and the report renderer all
        expect a real Finding (in particular its .fingerprint property),
        so every skill finding has to pass through here before joining
        the rules_engine/agent/correlation findings.
        \"\"\"
        domain = self._SKILL_DOMAIN_MAP.get(
            (getattr(sf, "skill_domain", "") or "").strip().lower(), "security"
        )
        control_mappings = list(getattr(sf, "mitre_attack", []) or [])
        control_mappings += list(getattr(sf, "nist_csf", []) or [])
        control_mappings += list(getattr(sf, "mitre_d3fend", []) or [])
        return Finding(
            section=getattr(sf, "_section_name", "") or "",
            domain=domain,
            severity=getattr(sf, "severity", "MEDIUM"),
            issue=getattr(sf, "issue", ""),
            recommendation=getattr(sf, "recommendation", ""),
            standard_reference=getattr(sf, "standard_reference", ""),
            evidence_excerpt=getattr(sf, "evidence_excerpt", ""),
            control_mappings=control_mappings,
            origin=getattr(sf, "origin", "skill_executor") or "skill_executor",
            rule_id=getattr(sf, "skill_id", "") or "",
            confidence=0.7,
        )

    def skill_execution_node(self, state: ReviewState) -> Dict[str, Any]:"""

PATCHES = [
    ("stash section name on SkillFinding", PATCH_1_OLD, PATCH_1_NEW),
    ("convert SkillFinding before merging", PATCH_2_OLD, PATCH_2_NEW),
    ("add _skill_finding_to_finding() method", PATCH_3_OLD, PATCH_3_NEW),
]


def main():
    if not AGENT_PATH.exists():
        print(f"ERROR: {AGENT_PATH} not found. Run this from the cyber-architecture-reviewer folder.")
        return 1

    content = AGENT_PATH.read_text(encoding="utf-8")
    applied = 0
    skipped = 0

    for name, old, new in PATCHES:
        if new in content:
            print(f"SKIP  (already applied): {name}")
            skipped += 1
            continue
        if old not in content:
            print(f"FAIL  (anchor text not found - file may already differ): {name}")
            continue
        content = content.replace(old, new, 1)
        print(f"OK    applied: {name}")
        applied += 1

    if applied:
        AGENT_PATH.write_text(content, encoding="utf-8")
        print(f"\nWrote {AGENT_PATH} ({applied} patch(es) applied, {skipped} already present)")
    else:
        print(f"\nNo changes written ({skipped} patch(es) already present)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
