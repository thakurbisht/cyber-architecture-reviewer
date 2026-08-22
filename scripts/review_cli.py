#!/usr/bin/env python3
"""Run a review from the command line. Suitable for CI/CD gating.

Usage
-----
    python scripts/review_cli.py design.md
    python scripts/review_cli.py design.docx --domain network --domain security
    python scripts/review_cli.py design.md --rules-only        # no LLM needed
    python scripts/review_cli.py design.md --fail-on CRITICAL  # exit non-zero
    python scripts/review_cli.py design.md --compare previous.json

Exit codes
----------
    0  review completed within the failure threshold
    1  review completed but the failure threshold was breached
    2  the review could not run (Ollama down, file unreadable, KB empty)

The --fail-on flag is what makes this usable as a pipeline gate: attach it to
a pull request that changes a design document and the build fails on a new
CRITICAL finding, the same way it would on a failing test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agent import ReviewAgent
from src.config import load_config
from src.domains import DOMAIN_LABELS
from src.llm import check_ollama
from src.models import Finding, SEVERITIES
from src.parser import parse_document
from src.report import build_report, diff_reviews, save_outputs
from src.retriever import KnowledgeBase

DOMAINS = ("network", "application", "security", "cloud_data")


def _print_findings(result) -> None:
    counts = result.counts_by_severity()
    print()
    print("=" * 78)
    print(f"  {result.document_name}")
    print(f"  Status: {result.rag_status}   Risk score: {result.risk_score}/100"
          f"   Findings: {len(result.findings)}")
    print(f"  " + "  ".join(f"{s}: {counts.get(s, 0)}" for s in SEVERITIES))
    print("=" * 78)

    if not result.findings:
        print("\n  No findings.\n")
        return

    current_domain = None
    for f in result.findings:
        if f.domain != current_domain:
            current_domain = f.domain
            print(f"\n  {DOMAIN_LABELS.get(f.domain, f.domain).upper()}")
            print("  " + "-" * 74)
        ref = f.standard_reference or "uncited"
        print(f"  [{f.severity:<8}] {f.section[:44]}")
        print(f"             {f.issue}")
        print(f"             ref: {ref}")
        print(f"             fix: {f.recommendation[:150]}")
        print()


def _load_previous(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: list[Finding] = []
    for d in data.get("findings", []):
        out.append(Finding(
            section=d.get("section", ""),
            domain=d.get("domain", ""),
            severity=d.get("severity", "MEDIUM"),
            issue=d.get("issue", ""),
            recommendation=d.get("recommendation", ""),
            standard_reference=d.get("standard_reference", ""),
            kb_source=d.get("kb_source", ""),
            origin=d.get("origin", "agent"),
            rule_id=d.get("rule_id", ""),
        ))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Review a design document")
    ap.add_argument("document", help="Path to the design document")
    ap.add_argument("--domain", choices=DOMAINS, action="append",
                    help="Restrict to these domains (repeatable)")
    ap.add_argument("--rules-only", action="store_true",
                    help="Run only the deterministic rules engine (no LLM)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default=None,
                    help="Exit 1 if any finding at or above this severity exists")
    ap.add_argument("--json-out", default=None, help="Write the full result JSON here")
    ap.add_argument("--compare", default=None,
                    help="Compare against a previous result JSON")
    ap.add_argument("--quiet", action="store_true", help="Suppress the findings list")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    cfg = load_config(args.config)
    domains = args.domain or cfg.enabled_domains

    try:
        sections = parse_document(args.document)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not read {args.document}: {exc}", file=sys.stderr)
        return 2

    if not sections:
        print(f"ERROR: no reviewable content found in {args.document}",
              file=sys.stderr)
        return 2

    print(f"Parsed {len(sections)} sections from {Path(args.document).name}")

    # ---------------------------------------------------------------- rules
    if args.rules_only:
        from src.models import ReviewResult, dedupe_findings, sort_findings
        from src.rules import run_rules

        findings = sort_findings(dedupe_findings(run_rules(sections, domains)))
        result = ReviewResult(
            document_name=Path(args.document).name,
            findings=findings,
            sections=sections,
            audit=[],
            domains_reviewed=list(domains),
        )
        build_report(result, cfg)
    # ---------------------------------------------------------------- full
    else:
        health = check_ollama(cfg)
        if not health["reachable"]:
            print(f"ERROR: Ollama unreachable at {health['host']}. "
                  f"Use --rules-only to run without a model.", file=sys.stderr)
            return 2
        if health["missing_models"]:
            print(f"ERROR: models not pulled: {', '.join(health['missing_models'])}",
                  file=sys.stderr)
            return 2

        kb = KnowledgeBase(cfg)
        if kb.total_chunks() == 0:
            print("WARNING: the knowledge base is empty. Findings will be "
                  "generic and uncitable. Run scripts/seed_kb.py first.",
                  file=sys.stderr)

        agent = ReviewAgent(config=cfg, kb=kb)
        agent.progress = lambda stage, pct: print(
            f"  [{int(pct * 100):>3}%] {stage}", flush=True)
        result = agent.review(sections, Path(args.document).name, domains)

    if not args.quiet:
        _print_findings(result)

    paths = save_outputs(result, cfg)
    print(f"Report: {paths['report']}")
    print(f"Audit:  {paths['audit']}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result.to_dict(), indent=2, default=str),
                       encoding="utf-8")
        print(f"JSON:   {out}")

    # ------------------------------------------------------------- compare
    if args.compare:
        try:
            previous = _load_previous(args.compare)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: could not read {args.compare}: {exc}", file=sys.stderr)
        else:
            diff = diff_reviews(previous, result.findings)
            print("\nChange since previous review")
            print("-" * 40)
            print(f"  new:        {len(diff['new'])}")
            print(f"  resolved:   {len(diff['resolved'])}")
            print(f"  persisting: {len(diff['persisting'])}")
            for f in diff["new"]:
                print(f"  + [{f.severity}] {f.section}: {f.issue[:80]}")
            for f in diff["resolved"]:
                print(f"  - [{f.severity}] {f.section}: {f.issue[:80]}")

    # ---------------------------------------------------------------- gate
    if args.fail_on:
        threshold = SEVERITIES.index(args.fail_on)
        breaching = [f for f in result.findings
                     if SEVERITIES.index(f.severity) <= threshold]
        if breaching:
            print(f"\nFAILED: {len(breaching)} finding(s) at or above "
                  f"{args.fail_on}.")
            return 1
        print(f"\nPASSED: no findings at or above {args.fail_on}.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
