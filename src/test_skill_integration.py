#!/usr/bin/env python3
"""Test skill integration in agent.py"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.agent import ReviewAgent
from src.models import Section
from src.config import load_config

def test_skill_integration():
    """Test that skill nodes integrate with the graph."""
    print("=" * 70)
    print("Testing Skill Integration in agent.py")
    print("=" * 70)

    # Load config
    config = load_config("config.yaml")

    # Initialize agent (ReviewAgent is a dataclass)
    agent = ReviewAgent(config=config)

    print(f"\n[Config] Skills enabled: {agent.skill_index is not None}")
    if agent.skill_index:
        print(f"[Config] Skills loaded: {len(agent.skill_index.skills)}")
        print(f"[Config] Cache directory: {agent.skill_cache.cache_dir if agent.skill_cache else 'None'}")

    # Check graph structure
    print("\n[Graph] Checking compiled graph...")
    graph = agent._compiled_graph()

    # Verify nodes exist
    has_skill_discovery = "skill_discovery" in graph.nodes
    has_skill_execution = "skill_execution" in graph.nodes

    print(f"  skill_discovery node: {'✅ FOUND' if has_skill_discovery else '❌ MISSING'}")
    print(f"  skill_execution node: {'✅ FOUND' if has_skill_execution else '❌ MISSING'}")

    # List all nodes
    print(f"\n[Graph] All nodes in compiled graph:")
    for i, node in enumerate(graph.nodes, 1):
        print(f"  {i}. {node}")

    # Test with minimal document
    print("\n[Test] Running minimal review...")

    section = Section(
        index=0,
        heading="Test Section",
        topic="security",
        domain="network",
        body="This is a test section for skill integration.",
        secondary_topics=[]
    )

    try:
        result = agent.review(
            document_name="test_doc",
            sections=[section],
            domains=["network"]
        )

        print(f"\n✅ Review completed successfully")
        print(f"  Findings from rules: {len([f for f in result.findings if f.origin == 'rules_engine'])}")
        print(f"  Findings from skills: {len([f for f in result.findings if f.origin == 'skill_executor'])}")
        print(f"  Findings from agent: {len([f for f in result.findings if f.origin == 'agent'])}")
        print(f"  Total findings: {len(result.findings)}")

        return True
    except Exception as e:
        print(f"\n❌ Review failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_skill_integration()
    sys.exit(0 if success else 1)
