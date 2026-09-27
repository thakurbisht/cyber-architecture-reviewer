"""Data flow diagram (DFD) - the reviewed system model threat modeling runs on.

Why this exists
---------------
The extracted system model (src/system_model.py) is a draft: measured on the
golden set, the local model leaves authentication "unknown" on ~79% of flows
and encryption on ~89%. Threat modeling on that draft would be guesswork.

So the draft becomes a DFD that an engineer corrects in the DFD Editor -
moving components between trust zones, drawing or deleting flows, setting
protocol/auth/encryption - and then approves. Only an approved DFD version
feeds the threat model. Every element records where it came from ("ai",
"diagram", "text", "human") and whether a human edited it, so the draft's
accuracy can be measured from real use.

Everything here is pure Python (no Streamlit): the editor page converts the
canvas to plain dicts and calls sync_from_canvas.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ZONE_LABELS = {
    "internet": "Internet", "partner": "Partner", "dmz": "DMZ",
    "internal": "Internal", "management": "Management",
    "restricted": "Restricted / data", "cloud": "Cloud", "unknown": "Unassigned",
}
# Left to right: exposure first, crown jewels last, unassigned at the end.
ZONE_ORDER = ["internet", "partner", "dmz", "internal", "cloud", "management",
              "restricted", "unknown"]
KINDS = ("service", "datastore", "external_party", "user_group", "network",
         "device", "identity", "pipeline", "llm", "agent", "vector_db", "other")
AUTH = ("unknown", "none", "password", "shared_secret", "api_key", "token",
        "oauth", "mtls", "certificate", "kerberos", "sso")
ENCRYPTED = ("unknown", "yes", "no")
AI_KINDS = {"llm", "agent", "vector_db"}

# Canvas geometry (pixels). Zones are columns; a component belongs to the
# zone its centre falls in.
ZONE_WIDTH = 240          # one column of components
COLUMN_WIDTH = 190        # each extra column when a zone wraps
ZONE_GAP = 30
NODE_WIDTH = 160
ROW_HEIGHT = 70
TOP = 60
ROWS_PER_COLUMN = 7       # a zone wraps into another column after this many


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:48] or "item"


@dataclass
class DFDComponent:
    id: str
    name: str
    kind: str = "other"
    zone: str = "unknown"
    public: bool = False
    data: List[str] = field(default_factory=list)
    source: str = "ai"              # ai / diagram / text / human
    edited: bool = False
    evidence: str = ""
    x: float = 0.0
    y: float = 0.0


@dataclass
class DFDFlow:
    id: str
    source: str                     # component id
    target: str                     # component id
    protocol: str = ""
    auth: str = "unknown"
    encrypted: str = "unknown"
    source_tag: str = "ai"
    edited: bool = False
    evidence: str = ""


@dataclass
class DFD:
    document: str
    zones: List[str] = field(default_factory=lambda: ["internet", "dmz", "internal",
                                                      "restricted", "unknown"])
    components: List[DFDComponent] = field(default_factory=list)
    flows: List[DFDFlow] = field(default_factory=list)
    version: int = 0
    status: str = "draft"           # draft / approved
    approved_by: str = ""
    approved_at: str = ""
    approval_note: str = ""
    updated_at: str = field(default_factory=_now)

    # -- lookups -----------------------------------------------------------
    def component(self, cid: str) -> Optional[DFDComponent]:
        return next((c for c in self.components if c.id == cid), None)

    def flow(self, fid: str) -> Optional[DFDFlow]:
        return next((f for f in self.flows if f.id == fid), None)

    def zone_of(self, cid: str) -> str:
        c = self.component(cid)
        return c.zone if c else "unknown"

    def crosses_boundary(self, f: DFDFlow) -> bool:
        return self.zone_of(f.source) != self.zone_of(f.target)

    def boundary_flows(self) -> List[DFDFlow]:
        return [f for f in self.flows if self.crosses_boundary(f)]

    def has_ai_components(self) -> bool:
        return any(c.kind in AI_KINDS for c in self.components)

    # -- quality gates -----------------------------------------------------
    def warnings(self) -> List[str]:
        out = []
        unzoned = [c.name for c in self.components if c.zone == "unknown"]
        if unzoned:
            out.append(f"{len(unzoned)} component(s) have no trust zone: "
                       + ", ".join(unzoned[:5]) + ("…" if len(unzoned) > 5 else ""))
        bf = self.boundary_flows()
        no_auth = [f for f in bf if f.auth == "unknown"]
        no_enc = [f for f in bf if f.encrypted == "unknown"]
        if no_auth:
            out.append(f"{len(no_auth)} boundary-crossing flow(s) have unknown authentication")
        if no_enc:
            out.append(f"{len(no_enc)} boundary-crossing flow(s) have unknown encryption")
        dangling = [f.id for f in self.flows
                    if not self.component(f.source) or not self.component(f.target)]
        if dangling:
            out.append(f"{len(dangling)} flow(s) point at a missing component")
        return out

    def mark_edited(self) -> None:
        """Any edit after approval reopens the DFD as a new draft."""
        if self.status == "approved":
            self.status = "draft"
        self.updated_at = _now()

    def approve(self, reviewer: str, note: str = "") -> None:
        self.version += 1
        self.status = "approved"
        self.approved_by = reviewer.strip() or "reviewer"
        self.approved_at = _now()
        self.approval_note = note.strip()

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DFD":
        comps = [DFDComponent(**c) for c in d.get("components", [])]
        flows = [DFDFlow(**f) for f in d.get("flows", [])]
        rest = {k: v for k, v in d.items() if k not in ("components", "flows")}
        return cls(components=comps, flows=flows, **rest)


# --------------------------------------------------------------------------
# Draft from the extracted system model
# --------------------------------------------------------------------------
def _unique_id(base: str, taken: set) -> str:
    cid, n = base, 2
    while cid in taken:
        cid, n = f"{base}-{n}", n + 1
    taken.add(cid)
    return cid


def from_system_model(model: Dict[str, Any], document: str) -> DFD:
    """Build a draft DFD from SystemModel.to_dict()."""
    dfd = DFD(document=document)
    taken: set = set()
    by_name: Dict[str, str] = {}

    def ensure(name: str, **kw) -> str:
        key = slug(name)
        if key in by_name:
            return by_name[key]
        cid = _unique_id(key, taken)
        by_name[key] = cid
        dfd.components.append(DFDComponent(id=cid, name=name.strip()[:60], **kw))
        return cid

    for c in model.get("components", []):
        kind = c.get("kind", "other")
        ensure(c["name"], kind=kind if kind in KINDS else "other",
               zone=c.get("zone", "unknown") if c.get("zone") in ZONE_LABELS else "unknown",
               public=c.get("exposure") == "public", data=list(c.get("data", [])),
               source="ai", evidence=c.get("evidence", ""))
    seen_pairs = set()
    for f in model.get("flows", []):
        s, t = ensure(f["source"]), ensure(f["target"])
        if s == t or (s, t) in seen_pairs:
            continue
        seen_pairs.add((s, t))
        dfd.flows.append(DFDFlow(
            id=f"f{len(dfd.flows) + 1}", source=s, target=t,
            protocol=f.get("protocol", "") if f.get("protocol") != "unknown" else "",
            auth=f.get("auth") if f.get("auth") in AUTH else "unknown",
            encrypted=f.get("encrypted") if f.get("encrypted") in ENCRYPTED else "unknown",
            source_tag="ai", evidence=f.get("evidence", "")))
    used = {c.zone for c in dfd.components}
    dfd.zones = [z for z in ZONE_ORDER if z in used or z in ("internet", "internal", "unknown")]
    layout(dfd)
    return dfd


# --------------------------------------------------------------------------
# Canvas geometry and sync
# --------------------------------------------------------------------------
def _columns(dfd: DFD, zone: str) -> int:
    n = sum(1 for c in dfd.components if c.zone == zone)
    return max(1, -(-n // ROWS_PER_COLUMN))


def zone_width(dfd: DFD, zone: str) -> float:
    return ZONE_WIDTH + (_columns(dfd, zone) - 1) * COLUMN_WIDTH


def zone_x(dfd: DFD, zone: str) -> float:
    x = 0.0
    for z in dfd.zones:
        if z == zone:
            return x
        x += zone_width(dfd, z) + ZONE_GAP
    return x


def zone_height(dfd: DFD) -> float:
    rows = min(ROWS_PER_COLUMN, max([sum(1 for c in dfd.components if c.zone == z)
                                     for z in dfd.zones] or [0]))
    return max(360.0, TOP + rows * ROW_HEIGHT + 40)


def layout(dfd: DFD) -> None:
    """Place every component in its zone, wrapping into extra columns."""
    for z in dfd.zones:
        left = zone_x(dfd, z) + (ZONE_WIDTH - NODE_WIDTH) / 2
        for i, c in enumerate(c for c in dfd.components if c.zone == z):
            col, row = divmod(i, ROWS_PER_COLUMN)
            c.x = left + col * COLUMN_WIDTH
            c.y = TOP + row * ROW_HEIGHT


def zone_at(dfd: DFD, x: float) -> str:
    """The zone whose area contains a node placed at x (node centre)."""
    centre = x + NODE_WIDTH / 2
    for z in dfd.zones:
        left = zone_x(dfd, z)
        if left - ZONE_GAP / 2 <= centre <= left + zone_width(dfd, z) + ZONE_GAP / 2:
            return z
    return "unknown"


def sync_from_canvas(dfd: DFD, nodes: Iterable[Dict[str, Any]],
                     edges: Iterable[Dict[str, Any]]) -> List[str]:
    """Apply the canvas state (plain dicts) to the DFD; return change notes.

    nodes: {"id", "x", "y", "label"}   (zone background nodes excluded)
    edges: {"id", "source", "target"}
    """
    changes: List[str] = []
    node_ids = set()
    for n in nodes:
        node_ids.add(n["id"])
        c = dfd.component(n["id"])
        if c is None:
            continue
        c.x, c.y = float(n["x"]), float(n["y"])
        new_zone = zone_at(dfd, c.x)
        if new_zone != c.zone:
            changes.append(f"{c.name}: {ZONE_LABELS.get(c.zone, c.zone)} → "
                           f"{ZONE_LABELS.get(new_zone, new_zone)}")
            c.zone, c.edited = new_zone, True
        label = (n.get("label") or "").strip()
        if label and label != c.name:
            changes.append(f"Renamed {c.name} → {label}")
            c.name, c.edited = label[:60], True
    for c in [c for c in dfd.components if c.id not in node_ids]:
        changes.append(f"Deleted component {c.name}")
    dfd.components = [c for c in dfd.components if c.id in node_ids]

    edge_ids = set()
    for e in edges:
        edge_ids.add(e["id"])
        if dfd.flow(e["id"]) is None:
            if not dfd.component(e["source"]) or not dfd.component(e["target"]):
                continue
            dfd.flows.append(DFDFlow(id=e["id"], source=e["source"], target=e["target"],
                                     source_tag="human", edited=True))
            changes.append(f"Added flow {dfd.component(e['source']).name} → "
                           f"{dfd.component(e['target']).name}")
    for f in [f for f in dfd.flows if f.id not in edge_ids]:
        changes.append(f"Deleted flow {f.source} → {f.target}")
    dfd.flows = [f for f in dfd.flows if f.id in edge_ids
                 and dfd.component(f.source) and dfd.component(f.target)]
    if changes:
        dfd.mark_edited()
    return changes


def add_component(dfd: DFD, name: str, kind: str, zone: str) -> DFDComponent:
    cid = _unique_id(slug(name), {c.id for c in dfd.components})
    if zone not in dfd.zones:
        add_zone(dfd, zone)
    c = DFDComponent(id=cid, name=name.strip()[:60], kind=kind, zone=zone, source="human",
                     edited=True)
    dfd.components.append(c)
    layout(dfd)
    dfd.mark_edited()
    return c


def add_zone(dfd: DFD, zone: str) -> None:
    """Insert a zone in canonical order; components keep their zones."""
    if zone in dfd.zones:
        return
    dfd.zones = [z for z in ZONE_ORDER if z in set(dfd.zones) | {zone}] + \
                [z for z in dfd.zones if z not in ZONE_ORDER]
    layout(dfd)
    dfd.mark_edited()


def flow_label(f: DFDFlow) -> str:
    return f"{f.protocol or '?'} · {f.auth} · enc:{f.encrypted}"


def flow_risky(dfd: DFD, f: DFDFlow) -> bool:
    return dfd.crosses_boundary(f) and (f.auth in ("none", "unknown")
                                        or f.encrypted in ("no", "unknown"))


# --------------------------------------------------------------------------
# Storage: data/dfd/<document>/draft.json and v<N>.json per approval
# --------------------------------------------------------------------------
DEFAULT_ROOT = Path("data/dfd")


def _dir(document: str, root: Path) -> Path:
    return root / slug(document)


def save_draft(dfd: DFD, root: Path = DEFAULT_ROOT) -> Path:
    d = _dir(dfd.document, root)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "draft.json"
    p.write_text(json.dumps(dfd.to_dict(), indent=2), encoding="utf-8")
    return p


def save_approved(dfd: DFD, root: Path = DEFAULT_ROOT) -> Path:
    """Write the immutable approved version and refresh the draft copy."""
    if dfd.status != "approved":
        raise ValueError("only an approved DFD can be saved as a version")
    d = _dir(dfd.document, root)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"v{dfd.version}.json"
    if p.exists():
        raise FileExistsError(f"{p} already exists - approved versions are immutable")
    p.write_text(json.dumps(dfd.to_dict(), indent=2), encoding="utf-8")
    save_draft(dfd, root)
    return p


def load_latest(document: str, root: Path = DEFAULT_ROOT) -> Optional[DFD]:
    p = _dir(document, root) / "draft.json"
    if not p.exists():
        return None
    return DFD.from_dict(json.loads(p.read_text(encoding="utf-8")))


def list_versions(document: str, root: Path = DEFAULT_ROOT) -> List[Tuple[int, Path]]:
    d = _dir(document, root)
    out = []
    for p in d.glob("v*.json"):
        m = re.fullmatch(r"v(\d+)\.json", p.name)
        if m:
            out.append((int(m.group(1)), p))
    return sorted(out)


# --------------------------------------------------------------------------
# Review context: confirmed facts for the section reviewer
# --------------------------------------------------------------------------
def approved_version(document: str, root: Path = DEFAULT_ROOT) -> Optional[DFD]:
    """The latest APPROVED version (the working draft may have newer edits)."""
    versions = list_versions(document, root)
    if not versions:
        return None
    return DFD.from_dict(json.loads(versions[-1][1].read_text(encoding="utf-8")))


def facts_for_section(dfd: Optional[DFD], heading: str, body: str, limit: int = 12) -> str:
    """Engineer-confirmed facts about the components this section mentions.

    Given to the section reviewer so it does not contradict what the
    architect confirmed (zones, exposure, auth, encryption), and so
    "unknown" is read as "not stated" rather than as "absent".
    """
    if dfd is None:
        return ""
    text = f"{heading}\n{body}".lower()
    mentioned = [c for c in dfd.components
                 if len(c.name) >= 3 and c.name.lower() in text]
    ids = {c.id for c in mentioned}
    lines = []
    for c in mentioned[:limit]:
        lines.append(f"- {c.name}: {c.kind}, zone {ZONE_LABELS.get(c.zone, c.zone)}"
                     + (", publicly reachable" if c.public else "")
                     + (f", holds {', '.join(c.data)}" if c.data else ""))
    for f in dfd.flows:
        if f.source in ids or f.target in ids:
            s, t = dfd.component(f.source), dfd.component(f.target)
            lines.append(f"- Flow {s.name if s else f.source} -> {t.name if t else f.target}: "
                         f"{f.protocol or 'protocol not stated'}, authentication {f.auth}, "
                         f"encrypted {f.encrypted}"
                         + (" (crosses a trust boundary)" if dfd.crosses_boundary(f) else ""))
        if len(lines) >= limit * 2:
            break
    return "\n".join(lines)
