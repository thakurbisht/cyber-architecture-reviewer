#!/usr/bin/env python3
"""Verify skill node implementation in agent.py"""

import sys
from pathlib import Path
import inspect

sys.path.insert(0, str(Path(__file__).parent))

from src.agent import ReviewAgent

def verify_skill_nodes():
    """Verify skill nodes are properly implemented."""
    print("=" * 70)
    print("Verifying Skill Node Implementation")
    print("=" * 70)

    # Check methods exist
    print("\n[Methods] Checking ReviewAgent has skill node methods...")

    has_skill_discovery = hasattr(ReviewAgent, 'skill_discovery_node')
    has_skill_execution = hasattr(ReviewAgent, 'skill_execution_node')

    print(f"  skill_discovery_node: {'✅ EXISTS' if has_skill_discovery else '❌ MISSING'}")
    print(f"  skill_execution_node: {'✅ EXISTS' if has_skill_execution else '❌ MISSING'}")

    if not (has_skill_discovery and has_skill_execution):
        print("\n❌ Required methods are missing!")
        return False

    # Check method signatures
    print("\n[Signatures] Checking method signatures...")

    discovery_sig = inspect.signature(ReviewAgent.skill_discovery_node)
    execution_sig = inspect.signature(ReviewAgent.skill_execution_node)

    print(f"  skill_discovery_node{discovery_sig}")
    print(f"  skill_execution_node{execution_sig}")

    # Check docstrings
    print("\n[Documentation] Checking docstrings...")

    discovery_doc = ReviewAgent.skill_discovery_node.__doc__
    execution_doc = ReviewAgent.skill_execution_node.__doc__

    if discovery_doc:
        print(f"  skill_discovery_node: ✅ Documented")
        print(f"    {discovery_doc.strip().split(chr(10))[0]}")
    else:
        print(f"  skill_discovery_node: ❌ No docstring")

    if execution_doc:
        print(f"  skill_execution_node: ✅ Documented")
        print(f"    {execution_doc.strip().split(chr(10))[0]}")
    else:
        print(f"  skill_execution_node: ❌ No docstring")

    # Check method bodies (look for key patterns)
    print("\n[Implementation] Checking method bodies...")

    discovery_source = inspect.getsource(ReviewAgent.skill_discovery_node)
    execution_source = inspect.getsource(ReviewAgent.skill_execution_node)

    discovery_checks = {
        "skill_index check": "self.skill_index" in discovery_source,
        "returns dict": "return {" in discovery_source,
        "selected_skills": "selected_skills" in discovery_source,
        "skill_rankings": "skill_rankings" in discovery_source,
    }

    execution_checks = {
        "skill_index check": "self.skill_index" in execution_source,
        "returns dict": "return {" in execution_source,
        "skill_findings": "skill_findings" in execution_source,
        "max_total_findings": "max_total_findings" in execution_source,
        "error handling": "except Exception" in execution_source,
    }

    print("  skill_discovery_node:")
    for check, passed in discovery_checks.items():
        print(f"    {check}: {'✅' if passed else '❌'}")

    print("  skill_execution_node:")
    for check, passed in execution_checks.items():
        print(f"    {check}: {'✅' if passed else '❌'}")

    all_passed = all(discovery_checks.values()) and all(execution_checks.values())

    if all_passed:
        print("\n✅ All verifications passed!")
    else:
        print("\n❌ Some verifications failed!")

    return all_passed

if __name__ == "__main__":
    success = verify_skill_nodes()
    sys.exit(0 if success else 1)
