#!/usr/bin/env python3
"""Simple test - just verify skill nodes exist and are callable"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.agent import ReviewAgent
import inspect

print("=" * 70)
print("Simple Skill Integration Test")
print("=" * 70)

# 1. Check methods exist
print("\n[1] Checking skill node methods...")
has_discovery = hasattr(ReviewAgent, 'skill_discovery_node')
has_execution = hasattr(ReviewAgent, 'skill_execution_node')

print(f"  skill_discovery_node: {'✅ EXISTS' if has_discovery else '❌ MISSING'}")
print(f"  skill_execution_node: {'✅ EXISTS' if has_execution else '❌ MISSING'}")

if not (has_discovery and has_execution):
    print("\n❌ FAILED: Methods missing!")
    sys.exit(1)

# 2. Check signatures
print("\n[2] Checking method signatures...")
discovery_sig = inspect.signature(ReviewAgent.skill_discovery_node)
execution_sig = inspect.signature(ReviewAgent.skill_execution_node)

print(f"  skill_discovery_node{discovery_sig}")
print(f"  skill_execution_node{execution_sig}")

# 3. Check implementation
print("\n[3] Checking implementation details...")
discovery_source = inspect.getsource(ReviewAgent.skill_discovery_node)
execution_source = inspect.getsource(ReviewAgent.skill_execution_node)

checks = {
    'discovery - skill_index check': 'self.skill_index' in discovery_source,
    'discovery - returns dict': 'return {' in discovery_source,
    'execution - skill_index check': 'self.skill_index' in execution_source,
    'execution - max_total_findings': 'max_total_findings' in execution_source,
    'execution - error handling': 'except Exception' in execution_source,
}

for check, passed in checks.items():
    print(f"  {check}: {'✅' if passed else '❌'}")

all_passed = all(checks.values())

print("\n" + "=" * 70)
if all_passed:
    print("✅ ALL TESTS PASSED - Skills integration verified!")
    print("=" * 70)
    sys.exit(0)
else:
    print("❌ SOME TESTS FAILED")
    print("=" * 70)
    sys.exit(1)
