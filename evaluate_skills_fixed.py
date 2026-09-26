#!/usr/bin/env python3
"""
Evaluate skills layer on three sample documents.
Measures: findings by origin, precision, execution time.
"""

import sys
import time
import json
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

from src.agent import ReviewAgent
from src.config import load_config
from src.parser import parse_document

def evaluate_sample(agent, name, path):
    """Evaluate agent on one sample."""
    print(f"\n{'='*70}")
    print(f"Evaluating: {name}")
    print(f"{'='*70}")

    # Parse document
    try:
        sections = parse_document(path)
        print(f"✅ Parsed {len(sections)} sections")
    except Exception as e:
        print(f"❌ Parse error: {e}")
        return None

    # Run review
    start = time.time()
    try:
        result = agent.review(
            sections=sections,
            document_name=name,
            enabled_domains=["network", "application", "security", "cloud_data"]
        )
        elapsed = time.time() - start

        # Aggregate by origin
        by_origin = defaultdict(int)
        by_severity = defaultdict(int)

        for finding in result.findings:
            by_origin[finding.origin] += 1
            by_severity[finding.severity] += 1

        print(f"\n📊 Results ({elapsed:.1f}s):")
        print(f"  Total findings: {len(result.findings)}")
        print(f"  By origin:")
        for origin, count in sorted(by_origin.items()):
            print(f"    - {origin}: {count}")
        print(f"  By severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_severity.get(sev, 0)
            if count > 0:
                print(f"    - {sev}: {count}")

        return {
            "name": name,
            "elapsed_s": round(elapsed, 1),
            "total_findings": len(result.findings),
            "by_origin": dict(by_origin),
            "by_severity": dict(by_severity),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "origin": f.origin,
                    "domain": f.domain,
                }
                for f in result.findings[:5]  # First 5 as sample
            ]
        }

    except Exception as e:
        print(f"❌ Review error: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    print("="*70)
    print("Skills Layer Evaluation")
    print("="*70)

    # Load config & agent
    print("\n[1] Initializing agent...")
    try:
        config = load_config("config.yaml")
        agent = ReviewAgent(config=config)
        print(f"✅ Agent initialized")
        print(f"   Skills enabled: {agent.skill_index is not None}")
        if agent.skill_index:
            print(f"   Skills loaded: {len(agent.skill_index.skills)}")
    except Exception as e:
        print(f"❌ Init error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Evaluate each sample
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
            result = evaluate_sample(agent, sample_name, path)
            if result:
                results.append(result)
        else:
            print(f"\n⚠️  {path} not found")

    # Summary
    print(f"\n{'='*70}")
    print("Summary")
    print(f"{'='*70}")

    if results:
        total_findings = sum(r["total_findings"] for r in results)
        total_time = sum(r["elapsed_s"] for r in results)

        print(f"\nEvaluated {len(results)}/{len(samples)} samples")
        print(f"Total findings across all samples: {total_findings}")
        print(f"Total execution time: {total_time:.1f}s")

        # Save results
        output_file = Path("evaluation_results.json")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n✅ Results saved to {output_file}")
    else:
        print("❌ No samples evaluated")

    return 0

if __name__ == "__main__":
    sys.exit(main())
