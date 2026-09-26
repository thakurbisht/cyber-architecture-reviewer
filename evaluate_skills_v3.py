#!/usr/bin/env python3
"""
Evaluate skills layer on sample documents.
Exports COMPLETE findings data (not just first 5) plus risk scoring,
for use with the dashboard.html viewer.
"""

import sys
import time
import json
from pathlib import Path
from collections import defaultdict
from dataclasses import asdict

sys.path.insert(0, str(Path(__file__).parent))

from src.agent import ReviewAgent
from src.config import load_config
from src.parser import parse_document
from src.report import compute_risk

def evaluate_sample(agent, name, path, config):
    """Evaluate agent on one sample, return full structured result."""
    print(f"\n{'='*70}")
    print(f"Evaluating: {name}")
    print(f"{'='*70}")

    try:
        sections = parse_document(path)
        print(f"Parsed {len(sections)} sections")
    except Exception as e:
        print(f"Parse error: {e}")
        return None

    start = time.time()
    try:
        result = agent.review(
            sections=sections,
            document_name=name,
            enabled_domains=["network", "application", "security", "cloud_data"]
        )
        elapsed = time.time() - start

        score, rag, counts = compute_risk(result.findings, config)

        by_origin = defaultdict(int)
        for f in result.findings:
            by_origin[f.origin] += 1

        print(f"\nResults ({elapsed:.1f}s): {len(result.findings)} findings, risk={score} ({rag})")
        for origin, count in sorted(by_origin.items()):
            print(f"  {origin}: {count}")

        if result.threat_model:
            tm = result.threat_model
            print(f"  threat model: {len(tm.get('threats', []))} threats, "
                  f"{len(tm.get('blind_spots', []))} coverage gaps, "
                  f"{len(tm.get('trust_boundary_crossings', []))} trust-boundary crossings")

        findings_full = []
        for f in result.findings:
            findings_full.append({
                "section": f.section,
                "domain": f.domain,
                "severity": f.severity,
                "issue": f.issue,
                "recommendation": f.recommendation,
                "standard_reference": f.standard_reference,
                "kb_source": f.kb_source,
                "evidence_excerpt": f.evidence_excerpt,
                "control_mappings": f.control_mappings,
                "origin": f.origin,
                "rule_id": f.rule_id,
                "confidence": f.confidence,
                "created_at": f.created_at,
            })

        return {
            "name": name,
            "elapsed_s": round(elapsed, 1),
            "sections_count": len(sections),
            "total_findings": len(result.findings),
            "risk_score": score,
            "rag_status": rag,
            "severity_counts": counts,
            "by_origin": dict(by_origin),
            "findings": findings_full,
            "threat_model": result.threat_model,
        }

    except Exception as e:
        print(f"Review error: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    print("="*70)
    print("Skills Layer Evaluation - Full Export")
    print("="*70)

    print("\n[1] Initializing agent...")
    try:
        config = load_config("config.yaml")
        agent = ReviewAgent(config=config)
        print(f"Agent initialized. Skills enabled: {agent.skill_index is not None}")
        if agent.skill_index:
            print(f"Skills loaded: {len(agent.skill_index.skills)}")
    except Exception as e:
        print(f"Init error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("\n[2] Loading samples...")
    samples = [
        ("cloud-landing-zone-hld", "samples/sample-cloud-landing-zone-hld.md"),
        ("campus-lan-lld", "samples/sample-campus-lan-lld.md"),
        ("payments-app-hld", "samples/sample-payments-app-hld.md"),
    ]

    results = []
    for sample_name, sample_path in samples:
        path = Path(sample_path)
        if path.exists():
            result = evaluate_sample(agent, sample_name, path, config)
            if result:
                results.append(result)
        else:
            print(f"\n{path} not found")

    print(f"\n{'='*70}")
    print("Summary")
    print(f"{'='*70}")

    if results:
        total_findings = sum(r["total_findings"] for r in results)
        total_time = sum(r["elapsed_s"] for r in results)

        print(f"\nEvaluated {len(results)}/{len(samples)} samples")
        print(f"Total findings: {total_findings}")
        print(f"Total time: {total_time:.1f}s")

        output = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "documents": results,
        }
        output_file = Path("evaluation_results.json")
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to {output_file}")
        print("Open dashboard.html and load this file to view results.")
    else:
        print("No samples evaluated")

    return 0

if __name__ == "__main__":
    sys.exit(main())
