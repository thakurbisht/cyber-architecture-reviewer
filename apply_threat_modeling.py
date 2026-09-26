#!/usr/bin/env python3
"""
Adds threat modeling capability to cyber-architecture-reviewer:
  - New file: src/threat_model.py (STRIDE classification + trust-zone
    inference + coverage-gap detection - pure Python, no new LLM call)
  - Small patches to 6 existing files so the pipeline calls it and the
    report/exporter/config expose it.

Run this from D:\\cyber-architecture-reviewer (same folder as config.yaml):
    python apply_threat_modeling.py

Then place the new src/threat_model.py next to it (delivered alongside this
script) and the updated dashboard.html (also delivered separately - it's a
full-file replacement, not a patch, since the diff touches many scattered
places in a single large HTML/JS file).

Safe to run more than once - each patch is skipped if already applied.
"""

import sys
from pathlib import Path

FILES = {
    "config.yaml": [
        (
            "config",
            '  enable_skills: true\n'
            '  skills_dir: "./skills"\n'
            '  cache_dir: "./cache"\n',
            '  enable_skills: true\n'
            '  skills_dir: "./skills"\n'
            '  cache_dir: "./cache"\n'
            '  # Threat modeling: reframes the final finding set as STRIDE-classified\n'
            '  # threats + a trust-zone/coverage view (src/threat_model.py). Pure\n'
            '  # Python, no extra LLM call, so this is safe to leave on by default.\n'
            '  enable_threat_modeling: true\n',
        ),
    ],
    "src/config.py": [
        (
            "default enable_threat_modeling",
            '        "enable_cross_domain_pass": True,\n'
            '        "enable_rules_engine": True,\n'
            "    },",
            '        "enable_cross_domain_pass": True,\n'
            '        "enable_rules_engine": True,\n'
            '        "enable_threat_modeling": True,\n'
            "    },",
        ),
    ],
    "src/models.py": [
        (
            "ReviewResult.threat_model field",
            "    kb_chunk_count: int = 0\n"
            "    warnings: List[str] = field(default_factory=list)\n"
            "\n"
            "    def counts_by_severity(self) -> Dict[str, int]:",
            "    kb_chunk_count: int = 0\n"
            "    warnings: List[str] = field(default_factory=list)\n"
            "    # Populated by threat_model_node (see agent.py) when\n"
            "    # config.agent.enable_threat_modeling is true. A plain dict (already\n"
            "    # ThreatModel.to_dict()'s shape), not the dataclass, so it serialises\n"
            "    # for free wherever ReviewResult already does.\n"
            "    threat_model: Optional[Dict[str, Any]] = None\n"
            "\n"
            "    def counts_by_severity(self) -> Dict[str, int]:",
        ),
        (
            "ReviewResult.to_dict() exports threat_model",
            '            "findings": [f.to_dict() for f in self.findings],\n'
            '            "sections": [s.to_dict() for s in self.sections],\n'
            '            "audit": [a.to_dict() for a in self.audit],\n'
            "        }",
            '            "findings": [f.to_dict() for f in self.findings],\n'
            '            "sections": [s.to_dict() for s in self.sections],\n'
            '            "audit": [a.to_dict() for a in self.audit],\n'
            '            "threat_model": self.threat_model,\n'
            "        }",
        ),
    ],
    "src/report.py": [
        (
            "render_markdown() Threat Model Summary section",
            '        lines.append(assurance_opinion.strip())\n'
            '        lines.append("")\n'
            '\n'
            '    # -- priority actions -------------------------------------------------',
            '        lines.append(assurance_opinion.strip())\n'
            '        lines.append("")\n'
            '\n'
            '    # -- threat model summary ---------------------------------------------\n'
            '    tm = getattr(result, "threat_model", None)\n'
            '    if tm:\n'
            '        lines.append("## Threat Model Summary")\n'
            '        lines.append("")\n'
            '        lines.append(\n'
            '            f"{len(tm.get(\'threats\', []))} threats identified across "\n'
            '            f"{len(tm.get(\'trust_zones\', []))} inferred trust zones, with "\n'
            '            f"{len(tm.get(\'trust_boundary_crossings\', []))} trust-boundary "\n'
            '            f"crossings in the document flow."\n'
            '        )\n'
            '        lines.append("")\n'
            '        lines.append("**STRIDE coverage** (threats per category):")\n'
            '        lines.append("")\n'
            '        lines.append("| Category | Threats |")\n'
            '        lines.append("|---|---:|")\n'
            '        for cat, count in (tm.get("stride_totals") or {}).items():\n'
            '            lines.append(f"| {cat} | {count} |")\n'
            '        lines.append("")\n'
            '        blind_spots = tm.get("blind_spots") or []\n'
            '        if blind_spots:\n'
            '            lines.append(\n'
            '                f"**{len(blind_spots)} coverage gaps** - domain/category "\n'
            '                f"pairs with zero threats surfaced (see full threat model "\n'
            '                f"for detail; a gap means the review found nothing there, "\n'
            '                f"not that the design is confirmed safe there)."\n'
            '            )\n'
            '            lines.append("")\n'
            '        for note in tm.get("caveats") or []:\n'
            '            lines.append(f"> {note}")\n'
            '        lines.append("")\n'
            '\n'
            '    # -- priority actions -------------------------------------------------',
        ),
    ],
    "src/agent.py": [
        (
            "import build_threat_model",
            "from .retriever import KnowledgeBase\n"
            "\n"
            "# TIER 1 Hardening: Skills integration",
            "from .retriever import KnowledgeBase\n"
            "from .threat_model import build_threat_model\n"
            "\n"
            "# TIER 1 Hardening: Skills integration",
        ),
        (
            "build_threat_model() call in review()",
            '            kb_chunk_count=final.get("kb_chunk_count", 0),\n'
            '            warnings=final.get("warnings", []),\n'
            "        )\n"
            "        build_report(",
            '            kb_chunk_count=final.get("kb_chunk_count", 0),\n'
            '            warnings=final.get("warnings", []),\n'
            "        )\n"
            "\n"
            "        # Threat modeling runs on the FINAL, merged, deduplicated finding\n"
            "        # set - deliberately after the skill/rules/agent/correlation merge\n"
            "        # above, not as a graph node, so it sees every finding regardless\n"
            "        # of which stage produced it (skill_execution_node's raw\n"
            "        # SkillFinding objects aren't converted to base Finding until the\n"
            "        # merge just above runs). It needs no LLM call - see\n"
            "        # src/threat_model.py's module docstring for why that's deliberate.\n"
            '        if self.config.agent.get("enable_threat_modeling", True):\n'
            "            try:\n"
            "                result.threat_model = build_threat_model(\n"
            "                    document_name=document_name,\n"
            "                    sections=result.sections,\n"
            "                    findings=result.findings,\n"
            "                    domains=domains,\n"
            "                ).to_dict()\n"
            "            except Exception as exc:  # noqa: BLE001\n"
            '                self.audit.record("threat_model_error", error=str(exc))\n'
            "                result.warnings = result.warnings + [\n"
            '                    f"Threat modeling failed: {exc}"\n'
            "                ]\n"
            "\n"
            "        build_report(",
        ),
    ],
    "evaluate_skills_v3.py": [
        (
            "print threat model summary line",
            '        for origin, count in sorted(by_origin.items()):\n'
            '            print(f"  {origin}: {count}")\n'
            '\n'
            '        findings_full = []',
            '        for origin, count in sorted(by_origin.items()):\n'
            '            print(f"  {origin}: {count}")\n'
            '\n'
            '        if result.threat_model:\n'
            '            tm = result.threat_model\n'
            '            print(f"  threat model: {len(tm.get(\'threats\', []))} threats, "\n'
            '                  f"{len(tm.get(\'blind_spots\', []))} coverage gaps, "\n'
            '                  f"{len(tm.get(\'trust_boundary_crossings\', []))} trust-boundary crossings")\n'
            '\n'
            '        findings_full = []',
        ),
        (
            "export threat_model in JSON output",
            '            "by_origin": dict(by_origin),\n'
            '            "findings": findings_full,\n'
            "        }",
            '            "by_origin": dict(by_origin),\n'
            '            "findings": findings_full,\n'
            '            "threat_model": result.threat_model,\n'
            "        }",
        ),
    ],
}


def main():
    total_applied = 0
    total_skipped = 0
    had_failure = False

    for rel_path, patches in FILES.items():
        path = Path(rel_path)
        if not path.exists():
            print(f"ERROR: {path} not found. Run this from the cyber-architecture-reviewer folder.")
            return 1

        content = path.read_text(encoding="utf-8")
        file_applied = 0

        for name, old, new in patches:
            label = f"{rel_path}: {name}"
            if new in content:
                print(f"SKIP  (already applied): {label}")
                total_skipped += 1
                continue
            if old not in content:
                print(f"FAIL  (anchor text not found - file may already differ): {label}")
                had_failure = True
                continue
            content = content.replace(old, new, 1)
            print(f"OK    applied: {label}")
            file_applied += 1
            total_applied += 1

        if file_applied:
            path.write_text(content, encoding="utf-8")

    print()
    if not (Path("src") / "threat_model.py").exists():
        print("NOTE: src/threat_model.py is not present yet. This script only patches")
        print("      the 6 existing files - copy the delivered src/threat_model.py into")
        print("      the src/ folder as well (it's a brand new file, nothing to patch).")
        had_failure = True

    print(f"\n{total_applied} patch(es) applied, {total_skipped} already present"
         + (", 1+ FAILED - see above" if had_failure else ""))
    return 1 if had_failure else 0


if __name__ == "__main__":
    sys.exit(main())
