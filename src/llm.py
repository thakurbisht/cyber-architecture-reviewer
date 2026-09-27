"""LLM access and tool schemas.

Two model handles are created per run and they are NOT interchangeable:

  reviewer  = llm.bind_tools([...])   used inside the reasoning loop
  writer    = llm                     used by the report node, no tools bound

This distinction is load-bearing. If the report node is given a tool-bound
model, the model sees a callable in its context and emits a structured tool
call - raw JSON - instead of writing prose. The reasoning is already finished
by the time the report node runs; all it needs to do is write. Keeping the
two handles separate in one module makes the mistake hard to reintroduce.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol

from .config import Config, load_config


# ==========================================================================
# Tool schemas (JSON-schema form, provider agnostic)
# ==========================================================================
SEARCH_STANDARDS_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "search_architectural_standards",
        "description": (
            "Search the organisation's architectural standards knowledge base "
            "for clauses relevant to a specific question. Use this when you "
            "need to confirm what the standard actually requires before "
            "flagging a finding. Prefer a precise question over a broad topic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "The specific question or control to look up, e.g. "
                        "'minimum TLS version for external endpoints' or "
                        "'uplink diversity requirement for access switches'."
                    ),
                },
                "domain": {
                    "type": "string",
                    "enum": ["network", "application", "security", "cloud_data"],
                    "description": "Which standards corpus to search.",
                },
            },
            "required": ["query"],
        },
    },
}

FLAG_FINDING_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "flag_finding",
        "description": (
            "Record one specific violation of an architectural standard found "
            "in the design section under review. Call once per distinct "
            "violation. Only flag something you can tie to evidence in the "
            "design text. Do not flag general good practice that the design "
            "simply does not mention unless a retrieved standard clause "
            "requires it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": (
                        "CRITICAL: exploitable now, or a single failure causes "
                        "total loss of service/data. HIGH: significant control "
                        "gap requiring remediation before go-live. MEDIUM: "
                        "should be fixed, workaround exists. LOW: hygiene or "
                        "documentation gap."
                    ),
                },
                "issue": {
                    "type": "string",
                    "description": (
                        "The specific violation in one or two plain sentences. "
                        "Name the affected component. No generic advice."
                    ),
                },
                "evidence": {
                    "type": "string",
                    "description": (
                        "The exact phrase or line from the design document that "
                        "demonstrates the issue. Quote it, do not paraphrase."
                    ),
                },
                "standard_reference": {
                    "type": "string",
                    "description": (
                        "The clause from the retrieved standards that this "
                        "violates, e.g. 'Three-Tier LAN Standard §3.2'. Leave "
                        "empty if no retrieved clause covers it."
                    ),
                },
                "recommendation": {
                    "type": "string",
                    "description": (
                        "The specific remediation action. Must be actionable by "
                        "an engineer without further clarification."
                    ),
                },
                "domain": {
                    "type": "string",
                    "enum": ["network", "application", "security", "cloud_data"],
                    "description": "Which review domain this finding belongs to.",
                },
            },
            "required": ["severity", "issue", "recommendation"],
        },
    },
}

SECTION_COMPLETE_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "section_complete",
        "description": (
            "Declare that this section has been fully reviewed and no further "
            "findings remain. Call this exactly once when you are done with "
            "the section, including when you found nothing wrong."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rationale": {
                    "type": "string",
                    "description": (
                        "One sentence on what you checked and why you are "
                        "satisfied the section is fully reviewed."
                    ),
                }
            },
            "required": [],
        },
    },
}

REVIEW_TOOLS: List[Dict[str, Any]] = [
    SEARCH_STANDARDS_TOOL,
    FLAG_FINDING_TOOL,
    SECTION_COMPLETE_TOOL,
]


# ==========================================================================
# Model handles
# ==========================================================================
class ChatModel(Protocol):
    """Minimal surface the agent needs. Lets tests inject a stub."""

    def invoke(self, messages: List[Any]) -> Any: ...


def build_models(config: Optional[Config] = None,
                 llm: Optional[Any] = None):
    """Return (reviewer_with_tools, writer_without_tools).

    Pass `llm` to inject a stub or an alternative chat model in tests.
    """
    cfg = config or load_config()

    if llm is None:
        try:
            from langchain_ollama import ChatOllama
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "langchain-ollama is required. pip install langchain-ollama"
            ) from exc

        llm = ChatOllama(
            model=cfg.models["llm"],
            base_url=cfg.models["ollama_host"],
            temperature=float(cfg.models.get("temperature", 0.1)),
            # Keep the context generous: a design section plus four retrieved
            # clauses plus the system prompt overflows a 2k window quickly, and
            # silent truncation is indistinguishable from a model that ignored
            # the standards.
            num_ctx=8192,
            # Hard cap on reply length. Without it a model that falls into a
            # repetition loop generates until the context is exhausted:
            # qwen2.5:14b produced a single 14k-token reply (~10 min) on gs-01.
            # A tool call or a section's findings fit comfortably in 2048.
            num_predict=int(cfg.models.get("max_output_tokens", 2048)),
            # Enforce config.yaml's request_timeout_s, which was never passed
            # to the client before.
            client_kwargs={"timeout": float(cfg.models.get("request_timeout_s", 300))},
        )

    writer = llm
    reviewer = llm.bind_tools(REVIEW_TOOLS) if hasattr(llm, "bind_tools") else llm
    return reviewer, writer


def check_ollama(config: Optional[Config] = None) -> Dict[str, Any]:
    """Pre-flight: is Ollama up and are the required models pulled?"""
    cfg = config or load_config()
    result: Dict[str, Any] = {
        "reachable": False,
        "host": cfg.models["ollama_host"],
        "llm": cfg.models["llm"],
        "embedding": cfg.models["embedding"],
        "missing_models": [],
        "error": "",
    }
    try:
        import ollama
        client = ollama.Client(host=cfg.models["ollama_host"], timeout=15)
        listing = client.list()
        raw = listing.get("models", []) if isinstance(listing, dict) \
            else getattr(listing, "models", [])
        names = set()
        for m in raw:
            name = m.get("model") or m.get("name") if isinstance(m, dict) \
                else getattr(m, "model", None) or getattr(m, "name", None)
            if name:
                names.add(name)
                names.add(name.split(":")[0])
        result["reachable"] = True
        result["available_models"] = sorted(n for n in names if ":" in n)
        for required in (cfg.models["llm"], cfg.models["embedding"]):
            if required not in names and required.split(":")[0] not in names:
                result["missing_models"].append(required)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    return result
