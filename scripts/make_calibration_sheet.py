#!/usr/bin/env python3
"""A6: build a ~50-row judge-calibration sheet from a scored run.

Why: every golden-set score comes from an LLM judge (gemma3:12b). If the
judge is lenient or wrong, every precision/recall number inherits that
error. A human labels a small sample; agreement (Cohen's kappa) tells us
whether the judge can be trusted.

Sampling: stratified by judge_status so each kind of decision is checked,
spread across documents, and weighted toward rows most likely to be wrong
(a "correct" whose wording barely overlaps the matched expected issue).

Usage:
    python scripts/make_calibration_sheet.py --run-name baseline-llama31 [--n 50]
Then open results/golden/<run>/calibration_sheet.csv in Excel and fill
`human_label` with: agree | disagree   (and optionally human_note).
"""
from __future__ import annotations

import argparse
import csv
import random
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results" / "golden"
STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are", "with",
        "not", "no", "by", "from", "as", "at", "be", "that", "this", "it", "its", "has"}


def words(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]{3,}", text.lower()) if w not in STOP}


def overlap(a: str, b: str) -> float:
    wa, wb = words(a), words(b)
    return len(wa & wb) / max(1, min(len(wa), len(wb)))


def _kappa(a: list, b: list) -> float:
    """Cohen's kappa for two label lists over the same items."""
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    labels = set(a) | set(b)
    pe = sum((a.count(k) / n) * (b.count(k) / n) for k in labels)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0


def score_sheet(run_name: str, sheet: str = "") -> int:
    """Agreement between the judge and the human labels.

    human_status (correct | TRAP | unmatched) is the label a reviewer would
    give; when it is blank it is inferred from human_label (agree = judge's
    status). Two kappas are reported:
      - 3-class: correct / TRAP / unmatched, what every metric is built on
      - binary:  "is this a real planted issue?", what recall/precision use
    A "disagree" with the same status means right status, wrong expected
    issue (a pairing error). The plan's bar for trusting the judge is
    kappa >= 0.7."""
    path = RESULTS / run_name / (sheet or "calibration_sheet.csv")
    rows = [r for r in csv.DictReader(open(path, encoding="utf-8-sig"))
            if r.get("human_label", "").strip().lower() in ("agree", "disagree")]
    if not rows:
        print(f"No labelled rows in {path}. Fill human_label with agree / disagree.")
        return 1

    def human_status(r):
        status = (r.get("human_status") or "").strip()
        if status:
            return status
        return r["judge_status"] if r["human_label"].strip().lower() == "agree" else "?"

    judge = [r["judge_status"] for r in rows]
    human = [human_status(r) for r in rows]
    known = [(j, h) for j, h in zip(judge, human) if h != "?"]
    n = len(rows)
    print(f"Sheet: {path.name} | labelled rows: {n}")
    by = defaultdict(lambda: [0, 0])
    for r in rows:
        by[r["judge_status"]][0] += r["human_label"].strip().lower() == "agree"
        by[r["judge_status"]][1] += 1
    for status, (agree, total) in sorted(by.items()):
        print(f"  judge said {status:10s}: human agrees {agree}/{total} ({agree / total:.0%})")

    if known:
        j3, h3 = [j for j, _ in known], [h for _, h in known]
        k3 = _kappa(j3, h3)
        print(f"3-class status agreement {sum(a == b for a, b in known) / len(known):.0%} "
              f"| kappa {k3:.2f}")
    jb = [j == "correct" for j in judge]
    hb = [h == "correct" if h != "?" else (j if r["human_label"].strip().lower() == "agree" else not j)
          for j, h, r in zip(jb, human, rows)]
    kb = _kappa(jb, hb)
    print(f"Binary 'real planted issue?' agreement {sum(a == b for a, b in zip(jb, hb)) / n:.0%} "
          f"| kappa {kb:.2f} -> "
          + ("judge is trustworthy (>= 0.7)" if kb >= 0.7 else "judge NOT trustworthy (< 0.7)"))
    credited = [h for j, h in zip(jb, hb) if j]
    if credited:
        print(f"When the judge says 'correct', a reviewer agrees it is a real planted issue "
              f"{sum(credited) / len(credited):.0%} of the time.")
    pairing = sum(1 for r, h in zip(rows, human)
                  if r["human_label"].strip().lower() == "disagree" and h == r["judge_status"])
    if pairing:
        print(f"Pairing errors (right status, wrong expected issue): {pairing}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-name", required=True)
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--kappa", action="store_true",
                    help="score a filled calibration sheet instead of creating one")
    ap.add_argument("--sheet", default="",
                    help="sheet file name under the run folder (default calibration_sheet.csv)")
    args = ap.parse_args()
    if args.kappa:
        return score_sheet(args.run_name, args.sheet)

    src = RESULTS / args.run_name / "review_sheet.csv"
    rows = [r for r in csv.DictReader(open(src, encoding="utf-8-sig")) if r["row"] == "prediction"]
    rng = random.Random(args.seed)

    by_status = defaultdict(list)
    for r in rows:
        r["_overlap"] = overlap(r["pred_text"], r["judge_matched"])
        by_status[r["judge_status"]].append(r)

    # Share of the sample per judge label: "correct" dominates the scores,
    # so it gets the most checks; every other label is still covered.
    quota = {"correct": 0.5, "TRAP": 0.25}
    rest = [s for s in by_status if s not in quota]
    for s in rest:
        quota[s] = 0.25 / max(1, len(rest))

    picked = []
    for status, share in quota.items():
        pool = by_status.get(status, [])
        k = min(len(pool), max(1, round(args.n * share)))
        if status == "correct":
            # Half the most suspicious (lowest wording overlap), half random.
            pool = sorted(pool, key=lambda r: r["_overlap"])
            suspicious, others = pool[: k // 2], pool[k // 2:]
            picked += suspicious + rng.sample(others, min(len(others), k - len(suspicious)))
        else:
            picked += rng.sample(pool, k)

    picked.sort(key=lambda r: (r["doc_id"], int(r["pred_no"])))
    out = RESULTS / args.run_name / "calibration_sheet.csv"
    cols = ["doc_id", "pred_no", "pred_severity", "pred_section", "pred_text",
            "judge_status", "judge_matched", "judge_reason", "human_label", "human_note"]
    with open(out, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in picked:
            w.writerow({**r, "human_label": "", "human_note": ""})

    counts = defaultdict(int)
    for r in picked:
        counts[r["judge_status"]] += 1
    print(f"Wrote {len(picked)} rows to {out}")
    print("By judge label:", dict(counts), "| docs:", len({r['doc_id'] for r in picked}))
    print("Fill human_label with agree / disagree, then run: "
          f"python scripts/make_calibration_sheet.py --kappa --run-name {args.run_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
