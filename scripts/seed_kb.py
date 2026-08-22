#!/usr/bin/env python3
"""Seed the knowledge base into ChromaDB.

Usage
-----
    python scripts/seed_kb.py                      # seed everything
    python scripts/seed_kb.py --domain network     # one domain
    python scripts/seed_kb.py --reset              # rebuild from scratch
    python scripts/seed_kb.py --status             # report only, no writes

Always check the chunk count printed at the end. A zero count means the seed
failed silently and every review in that domain will run on the model's
parametric memory alone - producing generic findings that look plausible and
cite nothing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import load_config
from src.llm import check_ollama
from src.retriever import KnowledgeBase, discover_kb_files, seed_knowledge_base

DOMAINS = ("network", "application", "security", "cloud_data")


def print_status(kb: KnowledgeBase) -> int:
    status = kb.status()
    print("\nKnowledge base status")
    print("=" * 60)
    print(f"  Store:           {status['persist_dir']}")
    print(f"  Embedding model: {status['embedding_model']}")
    print(f"  Total chunks:    {status['total']}")
    print()
    for domain, count in status["counts"].items():
        marker = "ok " if count else "EMPTY"
        print(f"  [{marker}] {domain:<14} {count:>6} chunks")
    if status["warnings"]:
        print("\nWarnings")
        print("-" * 60)
        for w in status["warnings"]:
            print(f"  ! {w}")
    print()
    return 0 if status["total"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed the architecture standards KB")
    ap.add_argument("--domain", choices=DOMAINS, action="append",
                    help="Seed only this domain (repeatable)")
    ap.add_argument("--reset", action="store_true",
                    help="Delete and rebuild the target collections")
    ap.add_argument("--status", action="store_true",
                    help="Show current status without seeding")
    ap.add_argument("--config", default=None, help="Path to config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    kb = KnowledgeBase(cfg)

    if args.status:
        return print_status(kb)

    health = check_ollama(cfg)
    if not health["reachable"]:
        print(f"ERROR: Ollama is not reachable at {health['host']}.")
        print(f"       {health.get('error', '')}")
        print("       Start it with: ollama serve")
        return 2
    if cfg.models["embedding"] in health["missing_models"]:
        print(f"ERROR: embedding model '{cfg.models['embedding']}' is not pulled.")
        print(f"       ollama pull {cfg.models['embedding']}")
        return 2

    files = discover_kb_files(cfg, args.domain)
    if not files:
        print(f"No knowledge base files found under {cfg.kb_root}")
        return 1

    total_files = sum(len(v) for v in files.values())
    print(f"Seeding {total_files} files across {len(files)} domains")
    print(f"Embedding model: {cfg.models['embedding']}")
    if args.reset:
        print("Reset requested - target collections will be rebuilt")
    print("=" * 60)

    seed_knowledge_base(cfg, domains=args.domain, reset=args.reset)
    return print_status(kb)


if __name__ == "__main__":
    raise SystemExit(main())
