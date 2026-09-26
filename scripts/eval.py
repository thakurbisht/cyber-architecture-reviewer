#!/usr/bin/env python3
"""Automated evaluation harness."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
from typing import Dict, List
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.agent import ReviewAgent
from src.config import load_config
from src.llm import check_ollama
from src.models import Finding, SEVERITIES
from src.parser import parse_document
from src.report import build_report
from src.retriever import KnowledgeBase
from src.rules import run_rules

def extract_expected_findings(sample_path: Path) -> Dict[str, List[str]]:
    content = sample_path.read_text(encoding="utf-8")
    expected: Dict[str, List[str]] = {s: [] for s in SEVERITIES}
    pattern = r"<!--\s*EXPECTED\s+(\w+)\s*:?\s*-->\n(.*?)(?=<!--|$)"
    for match in re.finditer(pattern, content, re.DOTALL):
        severity = match.group(1).upper()
        block = match.group(2).strip()
        if severity not in expected:
            severity = "MEDIUM"
        for line in block.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                text = line[1:].strip()
                if text:
                    expected[severity].append(text)
    return expected

def normalize_for_comparison(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = " ".join(text.split())
    return text

def finding_matches_expected(finding: Finding, expected_text: str) -> bool:
    section_match = re.search(r'Section\s+"([^"]+)"', expected_text)
    expected_section = section_match.group(1).lower() if section_match else ""
    expected_issue = re.sub(r'Section\s+"[^"]+":\s*', "", expected_text).lower()
    found_section = finding.section.lower()
    found_issue = finding.issue.lower()
    section_ok = (not expected_section or expected_section in found_section or found_section in expected_section)
    expected_words = set(normalize_for_comparison(expected_issue).split())
    found_words = set(normalize_for_comparison(found_issue).split())
    if not expected_words or not found_words:
        return section_ok
    overlap = expected_words & found_words
    if overlap:
        overlap_ratio = len(overlap) / max(len(expected_words), len(found_words))
        return section_ok and overlap_ratio >= 0.3
    return False

def evaluate_sample(sample_path: Path, rules_only: bool = False, verbose: bool = False) -> Dict:
    config = load_config()
    sample_name = sample_path.name
    try:
        sections = parse_document(str(sample_path))
    except Exception as e:
        return {"sample": sample_name, "status": "ERROR", "error": str(e)}
    if not sections:
        return {"sample": sample_name, "status": "NO_CONTENT"}
    expected = extract_expected_findings(sample_path)
    total_expected = sum(len(v) for v in expected.values())
    if total_expected == 0:
        return {"sample": sample_name, "status": "NO_GROUND_TRUTH"}
    try:
        if rules_only:
            findings = run_rules(sections, config.enabled_domains)
        else:
            health = check_ollama(config)
            if not health["reachable"]:
                return {"sample": sample_name, "status": "OLLAMA_DOWN", "error": f"Ollama unreachable at {health['host']}"}
            kb = KnowledgeBase(config)
            agent = ReviewAgent(config=config, kb=kb)
            result = agent.review(sections, sample_name)
            findings = result.findings
    except Exception as e:
        return {"sample": sample_name, "status": "ERROR", "error": str(e)}
    results_by_severity: Dict[str, Dict] = {}
    for severity in SEVERITIES:
        expected_list = expected.get(severity, [])
        found_list = [f for f in findings if f.severity == severity]
        tp = 0
        fp = 0
        matched_expected = set()
        for found in found_list:
            best_match_idx = None
            for idx, exp in enumerate(expected_list):
                if idx in matched_expected:
                    continue
                if finding_matches_expected(found, exp):
                    best_match_idx = idx
                    break
            if best_match_idx is not None:
                tp += 1
                matched_expected.add(best_match_idx)
            else:
                fp += 1
        fn = len(expected_list) - len(matched_expected)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        results_by_severity[severity] = {
            "expected": len(expected_list),
            "found": len(found_list),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }
        if verbose:
            print(f"\n  {severity}:")
            print(f"    Expected: {len(expected_list)}")
            print(f"    Found: {len(found_list)}")
            print(f"    TP={tp}, FP={fp}, FN={fn}")
            print(f"    Precision: {precision:.1%}  Recall: {recall:.1%}  F1: {f1:.3f}")
    all_findings = [f for f in findings]
    total_expected_all = sum(len(v) for v in expected.values())
    tp_all = sum(r["tp"] for r in results_by_severity.values())
    fp_all = sum(r["fp"] for r in results_by_severity.values())
    fn_all = sum(r["fn"] for r in results_by_severity.values())
    precision_all = tp_all / (tp_all + fp_all) if (tp_all + fp_all) > 0 else 0.0
    recall_all = tp_all / (tp_all + fn_all) if (tp_all + fn_all) > 0 else 0.0
    f1_all = (2 * precision_all * recall_all) / (precision_all + recall_all) if (precision_all + recall_all) > 0 else 0.0
    return {
        "sample": sample_name,
        "status": "OK",
        "total_expected": total_expected_all,
        "total_found": len(all_findings),
        "tp": tp_all,
        "fp": fp_all,
        "fn": fn_all,
        "precision": round(precision_all, 3),
        "recall": round(recall_all, 3),
        "f1": round(f1_all, 3),
        "by_severity": results_by_severity,
    }

def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate review engine precision/recall")
    ap.add_argument("--sample", default=None, help="Run only this sample")
    ap.add_argument("--rules-only", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()
    samples_dir = Path(__file__).parent.parent / "samples"
    if not samples_dir.exists():
        print("ERROR: samples/ directory not found", file=sys.stderr)
        return 2
    if args.sample:
        sample_files = [samples_dir / args.sample]
        if not sample_files[0].exists():
            print(f"ERROR: sample not found: {sample_files[0]}", file=sys.stderr)
            return 2
    else:
        sample_files = sorted([p for p in samples_dir.glob("sample-*.md")])
    if not sample_files:
        print("ERROR: no samples found", file=sys.stderr)
        return 2
    print(f"\n{'='*78}")
    print(f"  EVALUATION: {len(sample_files)} sample(s)")
    print(f"  Engine: {'rules only' if args.rules_only else 'full (rules + LLM)'}")
    print(f"  {'='*78}\n")
    all_results = []
    for sample_file in sample_files:
        print(f"  {sample_file.name}...", end=" ", flush=True)
        result = evaluate_sample(sample_file, rules_only=args.rules_only, verbose=args.verbose)
        all_results.append(result)
        status = result.get("status", "?")
        if status == "OK":
            print(f"✓ P={result['precision']:.1%} R={result['recall']:.1%} F1={result['f1']:.3f}")
        else:
            print(f"✗ {status}")
    ok_results = [r for r in all_results if r.get("status") == "OK"]
    if ok_results:
        avg_precision = sum(r["precision"] for r in ok_results) / len(ok_results)
        avg_recall = sum(r["recall"] for r in ok_results) / len(ok_results)
        avg_f1 = sum(r["f1"] for r in ok_results) / len(ok_results)
        print(f"\n{'-'*78}")
        print(f"  SUMMARY ({len(ok_results)} samples evaluated)")
        print(f"  Average Precision: {avg_precision:.1%}")
        print(f"  Average Recall:    {avg_recall:.1%}")
        print(f"  Average F1:        {avg_f1:.3f}")
        print(f"{'-'*78}\n")
        severity_stats = {s: {"precision": [], "recall": [], "f1": []} for s in SEVERITIES}
        for r in ok_results:
            for sev, stats in r.get("by_severity", {}).items():
                if sev in severity_stats:
                    severity_stats[sev]["precision"].append(stats["precision"])
                    severity_stats[sev]["recall"].append(stats["recall"])
                    severity_stats[sev]["f1"].append(stats["f1"])
        print("  By Severity:")
        for sev in SEVERITIES:
            prec_list = severity_stats[sev]["precision"]
            rec_list = severity_stats[sev]["recall"]
            f1_list = severity_stats[sev]["f1"]
            if prec_list:
                avg_p = sum(prec_list) / len(prec_list)
                avg_r = sum(rec_list) / len(rec_list)
                avg_f = sum(f1_list) / len(f1_list)
                print(f"    {sev:8s} P={avg_p:.1%} R={avg_r:.1%} F1={avg_f:.3f}")
        print()
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
        print(f"  Results saved: {out}\n")
    if ok_results and all(r.get("f1", 0) >= 0.5 for r in ok_results):
        return 0
    else:
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
