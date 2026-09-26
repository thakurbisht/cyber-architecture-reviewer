#!/usr/bin/env python3
"""Manage finding acknowledgments for CI/CD gating."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

EXAMPLE_CI = """
# Example: Gitea CI/CD pipeline (in .gitea/workflows/review.yml)

- name: Run security review
  run: |
    python scripts/review_cli.py design.md \\
      --fail-on CRITICAL \\
      --acknowledge-file .approved-findings.json \\
      --json-out review.json

- name: Create acknowledgment for known non-blocker
  if: failure()
  run: |
    python scripts/acknowledge.py review.json \\
      --acknowledge abc123def456 \\
      --reason "mitigated" \\
      --by "reviewer@company.com" \\
      --output .approved-findings.json
    git add .approved-findings.json
    git commit -m "ack: approved findings"

The next run will skip the acknowledged finding in its --fail-on check.
"""


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Manage finding acknowledgments for CI/CD gating",
        epilog=EXAMPLE_CI,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings_json", help="Path to findings.json from review")
    ap.add_argument("--severity", default=None,
                    help="Filter to this severity (CRITICAL, HIGH, MEDIUM, LOW)")
    ap.add_argument("--acknowledge", nargs="+", default=[],
                    help="Fingerprints to acknowledge (space-separated)")
    ap.add_argument("--reason", choices=["mitigated", "false_positive", "not_applicable",
                                          "accept_risk", "defer"],
                    default="accept_risk",
                    help="Reason for acknowledgment")
    ap.add_argument("--by", default="unknown", help="Who is acknowledging (e.g., email)")
    ap.add_argument("--output", default=None,
                    help="Write acknowledgment JSON to this file (for use with review_cli.py)")
    ap.add_argument("--list-only", action="store_true",
                    help="Just list findings, don't acknowledge")
    args = ap.parse_args()

    try:
        findings_data = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: could not read {args.findings_json}: {e}")
        return 2

    findings = findings_data.get("findings", [])
    if not findings:
        print(f"No findings found in {args.findings_json}")
        return 0

    if args.severity:
        findings = [f for f in findings if f.get("severity") == args.severity]

    if not findings:
        print(f"No findings at severity {args.severity}")
        return 0

    if args.list_only or (not args.acknowledge and not args.output):
        print(f"\nFound {len(findings)} findings:\n")
        for f in findings:
            fp = f.get("fingerprint", "?")
            sev = f.get("severity", "?")
            section = f.get("section", "?")
            issue = f.get("issue", "?")[:60]
            print(f"  {fp:16s} | {sev:8s} | {section:20s} | {issue}")
        print()
        return 0

    if args.acknowledge:
        ack_set = set(args.acknowledge)
        now = datetime.utcnow().isoformat(timespec="seconds")

        ack_output = {
            "acknowledged": list(ack_set),
            "acknowledged_by": args.by,
            "acknowledged_at": now,
            "acknowledged_reason": args.reason,
            "count": len(ack_set),
        }

        output_path = Path(args.output) if args.output else Path(".acknowledged.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(ack_output, indent=2), encoding="utf-8")

        print(f"\nAcknowledged {len(ack_set)} findings")
        print(f"  Reason: {args.reason}")
        print(f"  By: {args.by}")
        print(f"  At: {now}")
        print(f"  File: {output_path}")
        print()
        print("Use with review_cli.py:")
        print(f"  python scripts/review_cli.py design.md \\")
        print(f"    --fail-on CRITICAL \\")
        print(f"    --acknowledge-file {output_path}")
        print()
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
