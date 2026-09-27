"""Projects, stages and document versions - the spine of the review lifecycle.

The organisation's process has two review gates for the same solution:

  prelim   design documents -> recommendations (REC-IDs) to stakeholders
  final    as-built evidence -> control verification -> risk register

Everything a review produces (DFD, threats, prelim register, accept/dispute
decisions) used to be keyed by the uploaded file NAME, so a revised design
uploaded under the same name silently reopened the previous version's DFD
and threats. Now each upload is a DocVersion identified by the SHA-256 of
its content and its stage, and every artefact is keyed by the version's
review_key: "<project>/<stage>/<sha12>".

A version's status is "in_review" until an architect signs it off; until
then the RAG status is provisional. Sign-off decisions per stage:

  prelim  recommendations_issued | rejected (design must be revised)
  final   approve | approve_with_risks | block
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .dfd import slug

STAGES = ("prelim", "final")
STAGE_LABELS = {"prelim": "Stage 1 · Prelim review (design)",
                "final": "Stage 3 · Final review (as-built)"}
DECISIONS = {
    "prelim": {"recommendations_issued": "Recommendations issued",
               "rejected": "Rejected - design to be revised"},
    "final": {"approve": "Approve for go-live",
              "approve_with_risks": "Approve with risks (risk register)",
              "block": "Block go-live"},
}
DEFAULT_ROOT = Path("data/projects")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def review_key(project_id: str, stage: str, sha256: str) -> str:
    return f"{project_id}/{stage}/{sha256[:12]}"


@dataclass
class SignOff:
    decision: str
    reviewer: str
    at: str
    note: str = ""
    conditions: List[str] = field(default_factory=list)


@dataclass
class DocVersion:
    sha256: str
    filename: str
    stage: str
    uploaded_at: str
    review_key: str
    status: str = "in_review"          # in_review / signed_off
    signoff: Optional[SignOff] = None

    @property
    def provisional(self) -> bool:
        return self.signoff is None


@dataclass
class Project:
    id: str
    name: str
    created_at: str = field(default_factory=_now)
    versions: List[DocVersion] = field(default_factory=list)

    def version(self, key: str) -> Optional[DocVersion]:
        return next((v for v in self.versions if v.review_key == key), None)

    def stage_versions(self, stage: str) -> List[DocVersion]:
        return [v for v in self.versions if v.stage == stage]

    def latest_signed_prelim(self) -> Optional[DocVersion]:
        """The prelim review the final review must verify against."""
        done = [v for v in self.stage_versions("prelim")
                if v.signoff and v.signoff.decision == "recommendations_issued"]
        return done[-1] if done else None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "Project":
        versions = []
        for v in d.get("versions", []):
            so = v.get("signoff")
            versions.append(DocVersion(**{**v, "signoff": SignOff(**so) if so else None}))
        return cls(id=d["id"], name=d["name"], created_at=d.get("created_at", _now()),
                   versions=versions)


# --------------------------------------------------------------------------
# Operations
# --------------------------------------------------------------------------
def create_project(name: str, root: Path = DEFAULT_ROOT) -> Project:
    name = name.strip()
    if not name:
        raise ValueError("Project name is required.")
    pid = slug(name)
    if load_project(pid, root) is not None:
        raise ValueError(f"A project with id '{pid}' already exists.")
    p = Project(id=pid, name=name)
    save_project(p, root)
    return p


def register_version(project: Project, sha256: str, filename: str, stage: str,
                     root: Path = DEFAULT_ROOT) -> DocVersion:
    """Return the version for this content + stage, creating it if new.

    Re-uploading identical content reopens the same review; different
    content under the same filename is a new version with its own key.
    """
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {STAGES}")
    key = review_key(project.id, stage, sha256)
    existing = project.version(key)
    if existing:
        return existing
    v = DocVersion(sha256=sha256, filename=filename, stage=stage, uploaded_at=_now(),
                   review_key=key)
    project.versions.append(v)
    save_project(project, root)
    return v


def sign_off(project: Project, key: str, decision: str, reviewer: str, note: str = "",
             conditions: Optional[List[str]] = None, root: Path = DEFAULT_ROOT) -> DocVersion:
    v = project.version(key)
    if v is None:
        raise KeyError(key)
    if decision not in DECISIONS[v.stage]:
        raise ValueError(f"'{decision}' is not a {v.stage} decision")
    if not reviewer.strip():
        raise ValueError("Reviewer name is required for sign-off.")
    v.signoff = SignOff(decision=decision, reviewer=reviewer.strip(), at=_now(),
                        note=note.strip(), conditions=[c for c in (conditions or []) if c.strip()])
    v.status = "signed_off"
    save_project(project, root)
    return v


def reopen(project: Project, key: str, root: Path = DEFAULT_ROOT) -> DocVersion:
    """Withdraw a sign-off (e.g. new evidence arrived); history stays in git/audit."""
    v = project.version(key)
    if v is None:
        raise KeyError(key)
    v.signoff, v.status = None, "in_review"
    save_project(project, root)
    return v


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
def _path(pid: str, root: Path) -> Path:
    return root / pid / "project.json"


def save_project(p: Project, root: Path = DEFAULT_ROOT) -> Path:
    path = _path(p.id, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(p.to_dict(), indent=2), encoding="utf-8")
    return path


def load_project(pid: str, root: Path = DEFAULT_ROOT) -> Optional[Project]:
    path = _path(pid, root)
    if not path.exists():
        return None
    return Project.from_dict(json.loads(path.read_text(encoding="utf-8")))


def list_projects(root: Path = DEFAULT_ROOT) -> List[Project]:
    if not root.exists():
        return []
    out = [load_project(d.name, root) for d in sorted(root.iterdir()) if d.is_dir()]
    return [p for p in out if p is not None]


def find_version(key: str, root: Path = DEFAULT_ROOT) -> Optional[DocVersion]:
    pid = key.split("/", 1)[0]
    p = load_project(pid, root)
    return p.version(key) if p else None
