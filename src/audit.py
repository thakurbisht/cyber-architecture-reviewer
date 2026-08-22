"""Audit trail.

Governance rule: if you cannot explain why the agent flagged a finding, the
finding is worthless. Every retrieval, every tool call, every model decision
and every suppression is recorded here with enough detail that a reviewer
can reconstruct the reasoning without rerunning the agent.

The trail is append-only within a run and serialised alongside the report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .models import AuditEvent


class AuditTrail:
    """Append-only event log for one review run."""

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def record(self, step: str, **detail: Any) -> AuditEvent:
        event = AuditEvent(step=step, detail=_scrub(detail))
        self._events.append(event)
        return event

    @property
    def events(self) -> List[AuditEvent]:
        return list(self._events)

    def extend(self, events: List[AuditEvent]) -> None:
        self._events.extend(events)

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._events:
            counts[e.step] = counts.get(e.step, 0) + 1
        return counts

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self.to_list(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return p

    def render_markdown(self, limit: int = 400) -> str:
        """Human-readable trail for the UI's audit tab."""
        lines = ["| # | Step | Detail |", "|---|------|--------|"]
        for i, e in enumerate(self._events[:limit], start=1):
            detail = ", ".join(
                f"{k}={_short(v)}" for k, v in e.detail.items()
            )
            lines.append(f"| {i} | `{e.step}` | {detail} |")
        if len(self._events) > limit:
            lines.append(f"| ... | ... | {len(self._events) - limit} more events |")
        return "\n".join(lines)


_MAX_VALUE_CHARS = 600


def _scrub(detail: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the trail readable and JSON-serialisable."""
    out: Dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v[:_MAX_VALUE_CHARS] if isinstance(v, str) else v
        elif isinstance(v, (list, tuple)):
            out[k] = [
                (item[:200] if isinstance(item, str) else _safe(item))
                for item in list(v)[:25]
            ]
        elif isinstance(v, dict):
            out[k] = {kk: _safe(vv) for kk, vv in list(v.items())[:25]}
        else:
            out[k] = _safe(v)
    return out


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value[:_MAX_VALUE_CHARS] if isinstance(value, str) else value
    if hasattr(value, "to_dict"):
        try:
            return value.to_dict()
        except Exception:
            pass
    return str(value)[:_MAX_VALUE_CHARS]


def _short(value: Any, limit: int = 110) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = text.replace("\n", " ").replace("|", "\\|")
    return text[:limit] + ("..." if len(text) > limit else "")
