"""Configuration loading.

Single source of truth for runtime settings. Everything is read from
config.yaml so the same code runs unchanged in a laptop demo, a hardened
on-prem VM, or a CI runner - only the YAML differs.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


# Fallback defaults so the package still imports if config.yaml is missing.
_DEFAULTS: Dict[str, Any] = {
    "models": {
        "llm": "llama3.2",
        "embedding": "nomic-embed-text",
        "ollama_host": "http://localhost:11434",
        "temperature": 0.1,
        "request_timeout_s": 300,
    },
    "retrieval": {
        "chunk_words": 220,
        "chunk_overlap_words": 40,
        "top_k": 4,
        "min_similarity": 0.25,
        "persist_dir": "./data/chroma",
        "collection_prefix": "car",
    },
    "agent": {
        "max_tool_iterations": 6,
        "max_searches_per_section": 3,
        "max_sections": 40,
        "enable_cross_domain_pass": True,
        "enable_rules_engine": True,
        "enable_threat_modeling": True,
    },
    "domains": {
        "network": True,
        "application": True,
        "security": True,
        "cloud_data": True,
    },
    "scoring": {
        "weights": {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1},
        "rag": {
            "red_at_score": 40,
            "amber_at_score": 12,
            "critical_forces_red": True,
        },
    },
    "output": {
        "reports_dir": "./data/reports",
        "audit_dir": "./data/audit",
        "include_evidence_excerpts": True,
        "max_excerpt_chars": 400,
    },
    "knowledge_base": {
        "root": "./knowledge_base",
        "folder_map": {
            "network": "network",
            "application": "application",
            "security": "security",
            "cloud_data": "cloud_data",
        },
    },
}


@dataclass
class Config:
    """Typed accessor over the merged configuration dictionary."""

    raw: Dict[str, Any] = field(default_factory=dict)

    # -- sections ---------------------------------------------------------
    @property
    def models(self) -> Dict[str, Any]:
        return self.raw["models"]

    @property
    def retrieval(self) -> Dict[str, Any]:
        return self.raw["retrieval"]

    @property
    def agent(self) -> Dict[str, Any]:
        return self.raw["agent"]

    @property
    def scoring(self) -> Dict[str, Any]:
        return self.raw["scoring"]

    @property
    def output(self) -> Dict[str, Any]:
        return self.raw["output"]

    @property
    def knowledge_base(self) -> Dict[str, Any]:
        return self.raw["knowledge_base"]

    @property
    def enabled_domains(self) -> list[str]:
        return [k for k, v in self.raw["domains"].items() if v]

    # -- paths ------------------------------------------------------------
    def path(self, value: str) -> Path:
        """Resolve a possibly-relative config path against the project root."""
        p = Path(value)
        return p if p.is_absolute() else (PROJECT_ROOT / p).resolve()

    @property
    def chroma_dir(self) -> Path:
        return self.path(self.retrieval["persist_dir"])

    @property
    def kb_root(self) -> Path:
        return self.path(self.knowledge_base["root"])

    @property
    def reports_dir(self) -> Path:
        return self.path(self.output["reports_dir"])

    @property
    def audit_dir(self) -> Path:
        return self.path(self.output["audit_dir"])

    def ensure_dirs(self) -> None:
        for d in (self.chroma_dir, self.reports_dir, self.audit_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from YAML, merged over built-in defaults.

    Environment overrides (useful in CI):
      CAR_LLM_MODEL, CAR_EMBED_MODEL, CAR_OLLAMA_HOST, CAR_CHROMA_DIR
    """
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    file_cfg: Dict[str, Any] = {}
    if cfg_path.exists():
        file_cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    merged = _deep_merge(_DEFAULTS, file_cfg)

    env_map = {
        "CAR_LLM_MODEL": ("models", "llm"),
        "CAR_EMBED_MODEL": ("models", "embedding"),
        "CAR_OLLAMA_HOST": ("models", "ollama_host"),
        "CAR_CHROMA_DIR": ("retrieval", "persist_dir"),
    }
    for env_key, (section, key) in env_map.items():
        if os.environ.get(env_key):
            merged[section][key] = os.environ[env_key]

    return Config(raw=merged)
