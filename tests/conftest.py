"""Shared test fixtures, including a scripted stub LLM.

The stub is the important piece. It lets the whole graph - routing, tool
loop, loop caps, citation verification, report synthesis - be tested without
Ollama, a model download, or a vector database. Every structural bug the
article describes (report node emitting JSON, agents looping forever, tool
calls being dropped) is catchable here in milliseconds.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import load_config
from src.models import RetrievedChunk


class FakeMessage:
    """Stands in for an AIMessage."""

    def __init__(self, content: str = "", tool_calls: List[Dict[str, Any]] | None = None):
        self.content = content
        self.tool_calls = tool_calls or []


DEFAULT_REPORT = (
    "## Executive Summary\n\nThe design has material gaps.\n\n"
    "## Assurance Opinion\n\nRemediate before implementation."
)


class ScriptedLLM:
    """A chat model that replays a fixed script of responses.

    `bind_tools` returns a *separate* handle that shares the script and the
    call log but records that tools were bound. The unbound handle never
    consumes the script - it always returns `report_response`.

    That asymmetry is the point: it mirrors the real system, where the
    reasoning loop uses the tool-bound handle and the report node uses the
    bare one. A test that accidentally routes the report through the bound
    handle gets a tool call back instead of prose, exactly as the real model
    would do.
    """

    def __init__(self, script: List[FakeMessage],
                 report_response: FakeMessage | None = None,
                 name: str = "base"):
        self.script = list(script)
        self.report_response = report_response or FakeMessage(content=DEFAULT_REPORT)
        self.name = name
        self.calls: List[List[Any]] = []
        self.tool_turns = 0
        self.report_turns = 0
        self.bound_tools: List[Any] | None = None
        self._children: List["ScriptedLLM"] = []

    def bind_tools(self, tools):
        child = self.__class__(
            [], report_response=self.report_response, name="bound")
        child.script = self.script        # share the same list object
        child.bound_tools = tools
        child.calls = self.calls          # share the call log
        child._parent = self
        self._children.append(child)
        return child

    def invoke(self, messages):
        self.calls.append(list(messages))
        if self.bound_tools is None:
            self.report_turns += 1
            return self.report_response
        self.tool_turns += 1
        if self.script:
            return self.script.pop(0)
        # Script exhausted mid-loop: behave like a model that has nothing
        # further to say, so the graph advances rather than hanging.
        return FakeMessage(content="No further findings.")


class FakeKB:
    """In-memory stand-in for the ChromaDB-backed knowledge base."""

    def __init__(self, chunks: List[RetrievedChunk] | None = None):
        self._chunks = chunks if chunks is not None else [
            RetrievedChunk(
                chunk_id="c1",
                text=("[three-tier-lan-standard.md §3.2] Uplink diversity\n"
                      "The two uplinks from a device MUST terminate on two "
                      "different upstream devices."),
                source="three-tier-lan-standard.md",
                domain="network",
                clause="§3.2",
                similarity=0.82,
            ),
            RetrievedChunk(
                chunk_id="c2",
                text=("[network-management-standard.md §2.1] SNMP\n"
                      "SNMPv3 with authPriv MUST be used. SNMP v1 and v2c MUST "
                      "NOT be configured on any device."),
                source="network-management-standard.md",
                domain="network",
                clause="§2.1",
                similarity=0.71,
            ),
        ]
        self.searches: List[str] = []

    def search(self, query, domain, top_k=None, extra_domains=None):
        self.searches.append(query)
        return list(self._chunks)

    def status(self):
        return {
            "counts": {"network": 12, "application": 9, "security": 15,
                       "cloud_data": 11},
            "total": 47,
            "embedding_model": "nomic-embed-text",
            "persist_dir": "/tmp/fake",
            "warnings": [],
        }

    def total_chunks(self):
        return 47


@pytest.fixture
def config(tmp_path):
    cfg = load_config()
    cfg.raw["output"]["reports_dir"] = str(tmp_path / "reports")
    cfg.raw["output"]["audit_dir"] = str(tmp_path / "audit")
    cfg.raw["retrieval"]["persist_dir"] = str(tmp_path / "chroma")
    return cfg


@pytest.fixture
def fake_kb():
    return FakeKB()
