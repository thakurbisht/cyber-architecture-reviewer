#!/usr/bin/env python3
"""Validate the golden set: schema, verbatim evidence, coverage stats.

Usage:
    python golden/validate.py            # validate everything
    python golden/validate.py gs-01-...  # validate specific doc ids
Exit code 0 when every checked answer key is valid.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOMAINS = {"network", "application", "security", "cloud_data"}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
TYPES = {"defect", "gap"}
KINDS = {"flawed", "clean", "injection"}
STRIDE = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
          "Denial of Service", "Elevation of Privilege"}
FINDING_KEYS = {"id", "domain", "severity", "acceptable_severities", "type", "title",
                "description", "sections", "evidence", "cross_section", "stride", "keywords"}


def headings(doc_text):
    return {m.group(1).strip() for m in re.finditer(r"^#{2,3}\s+(.+)$", doc_text, re.M)}


def check_quote(q, doc_text, where, errors):
    if not isinstance(q, str) or not q.strip():
        errors.append(f"{where}: empty evidence quote")
        return
    if q not in doc_text:
        errors.append(f"{where}: quote not found verbatim: {q[:90]!r}")
        return
    if "\n" in q:
        errors.append(f"{where}: quote spans lines: {q[:60]!r}")
    n = len(q.split())
    if n < 5 or n > 45:
        errors.append(f"{where}: quote length {n} words (want 8-40): {q[:60]!r}")


def validate(doc_id):
    errors, warnings = [], []
    doc_path = ROOT / "docs" / f"{doc_id}.md"
    ans_path = ROOT / "answers" / f"{doc_id}.json"
    if not doc_path.exists():
        return [f"missing doc {doc_path.name}"], [], None
    if not ans_path.exists():
        return [f"missing answer key {ans_path.name}"], [], None
    doc = doc_path.read_text(encoding="utf-8")
    try:
        ans = json.loads(ans_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"answer key is not valid JSON: {e}"], [], None

    if "<!--" in doc:
        errors.append("document contains an HTML comment (answer leakage risk)")
    words = len(doc.split())
    if not 700 <= words <= 1900:
        warnings.append(f"document length {words} words (target 900-1500)")
    heads = headings(doc)

    if ans.get("doc_id") != doc_id:
        errors.append(f"doc_id mismatch: {ans.get('doc_id')!r}")
    kind = ans.get("doc_kind")
    if kind not in KINDS:
        errors.append(f"bad doc_kind {kind!r}")
    for d in ans.get("domains", []):
        if d not in DOMAINS:
            errors.append(f"bad domain in domains: {d!r}")

    ids = set()
    findings = ans.get("expected_findings", [])
    for f in findings:
        fid = f.get("id", "?")
        where = f"{fid}"
        if fid in ids:
            errors.append(f"duplicate id {fid}")
        ids.add(fid)
        missing = FINDING_KEYS - set(f)
        if missing:
            errors.append(f"{where}: missing keys {sorted(missing)}")
        if f.get("domain") not in DOMAINS:
            errors.append(f"{where}: bad domain {f.get('domain')!r}")
        if f.get("severity") not in SEVERITIES:
            errors.append(f"{where}: bad severity {f.get('severity')!r}")
        acc = f.get("acceptable_severities", [])
        if f.get("severity") not in acc or any(s not in SEVERITIES for s in acc):
            errors.append(f"{where}: acceptable_severities must include severity and be valid")
        if f.get("type") not in TYPES:
            errors.append(f"{where}: bad type {f.get('type')!r}")
        for s in f.get("stride", []):
            if s not in STRIDE:
                errors.append(f"{where}: bad STRIDE label {s!r}")
        for sec in f.get("sections", []):
            if sec not in heads:
                errors.append(f"{where}: section heading not found: {sec!r}")
        ev = f.get("evidence", [])
        if not ev:
            errors.append(f"{where}: no evidence")
        for q in ev:
            check_quote(q, doc, where, errors)
        if f.get("cross_section") and len(ev) < 2:
            errors.append(f"{where}: cross_section finding needs 2+ quotes")

    for n in ans.get("must_not_flag", []):
        nid = n.get("id", "?")
        if nid in ids:
            errors.append(f"duplicate id {nid}")
        ids.add(nid)
        for k in ("title", "why_not", "evidence"):
            if k not in n:
                errors.append(f"{nid}: missing {k}")
        if len(n.get("evidence", [])) < 2:
            errors.append(f"{nid}: must_not_flag needs the risky quote and the mitigating quote")
        for q in n.get("evidence", []):
            check_quote(q, doc, nid, errors)

    inj = ans.get("injection")
    if kind == "injection":
        if not inj or not inj.get("evidence"):
            errors.append("injection doc needs injection.evidence")
        else:
            for q in inj["evidence"]:
                if q not in doc:
                    errors.append(f"injection quote not found verbatim: {q[:80]!r}")
    n_f = len(findings)
    if kind in ("flawed", "injection") and not 6 <= n_f <= 10:
        warnings.append(f"{n_f} expected findings (target 6-10)")
    if kind == "clean" and n_f > 2:
        warnings.append(f"clean doc has {n_f} findings (target 0-2)")
    return errors, warnings, ans


def main():
    ids = sys.argv[1:] or sorted(p.stem for p in (ROOT / "docs").glob("*.md"))
    total_err = 0
    sev, dom, typ, kinds = Counter(), Counter(), Counter(), Counter()
    xsec = traps = nfind = 0
    for doc_id in ids:
        errors, warnings, ans = validate(doc_id)
        status = "OK  " if not errors else "FAIL"
        print(f"[{status}] {doc_id}")
        for e in errors:
            print(f"     error: {e}")
        for w in warnings:
            print(f"     warn:  {w}")
        total_err += len(errors)
        if ans:
            kinds[ans.get("doc_kind")] += 1
            for f in ans.get("expected_findings", []):
                sev[f.get("severity")] += 1
                dom[f.get("domain")] += 1
                typ[f.get("type")] += 1
                xsec += bool(f.get("cross_section"))
                nfind += 1
            traps += len(ans.get("must_not_flag", []))
    print()
    print(f"docs={len(ids)} kinds={dict(kinds)}")
    print(f"expected findings={nfind} cross_section={xsec} must_not_flag traps={traps}")
    print(f"severity={dict(sev)}")
    print(f"domain={dict(dom)}")
    print(f"type={dict(typ)}")
    print(f"\n{total_err} error(s)")
    return 1 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
