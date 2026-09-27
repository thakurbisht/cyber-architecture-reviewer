#!/usr/bin/env python
"""Which rules and pipeline stages do reviewers reject most?

    python scripts/feedback_report.py [--path data/feedback/feedback.jsonl]

A rule disputed more often than accepted is a candidate to narrow, demote to
a question, or retire; see src/rules.py (Rule.kind / soft_kind).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.feedback import DEFAULT_PATH, read_log, summarise  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--path", type=Path, default=DEFAULT_PATH)
    args = ap.parse_args()
    s = summarise(read_log(args.path))
    if not s["decisions"]:
        print(f"No decisions recorded yet in {args.path}.")
        return 0
    print(f"{s['decisions']} findings reviewed\n")
    print(f"{'rule / origin':32s} {'accepted':>8s} {'disputed':>8s} {'dispute rate':>13s}")
    for r in s["by_key"]:
        flag = "  <- review this rule" if r["key"].startswith("rule:") and r["dispute_rate"] > 0.5 else ""
        print(f"{r['key']:32s} {r['accepted']:8d} {r['disputed']:8d} {r['dispute_rate']:12.0%}{flag}")
    print("\nWhy findings were disputed:")
    for reason, n in s["reasons"].items():
        print(f"  {n:4d}  {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
