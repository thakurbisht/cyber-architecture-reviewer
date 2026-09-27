"""System-model extraction - the LLM reads, Python judges.

Why this exists
---------------
Measured on the golden set, the section reviewer's findings are ~75% noise,
and most of the wrong ones quote the document correctly and then misread
it. Asking the model "what is wrong here?" invites interpretation. Asking it
"what components, zones and flows does this describe?" is a narrower,
checkable reading task.

So this module asks only for facts, each with a verbatim quote:

  components  name, kind, trust zone, exposure, sensitive data held
  flows       source -> target, protocol, authentication, encryption
  controls    a control the document says is present, absent or weakened

A fact whose quote is not found in the document is dropped - here grounding
does work, because a fact is a claim about the text, not a judgement.
Deterministic rules then run over the model (src/model_rules.py). The same
model gives the threat model and the architecture graph real zones instead
of section topics.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .models import Section

ZONES = ("internet", "partner", "dmz", "internal", "management", "restricted",
         "cloud", "unknown")
EXPOSURE = ("public", "partner", "internal", "unknown")
KINDS = ("service", "datastore", "network", "device", "user_group",
         "external_party", "identity", "pipeline", "other")
AUTH = ("none", "password", "shared_secret", "api_key", "token", "oauth",
        "mtls", "certificate", "kerberos", "sso", "unknown")
SENSITIVE = ("pii", "pci", "phi", "credentials", "financial", "regulated")

# Words that make a quote useless as evidence on its own.
MIN_QUOTE_WORDS = 5


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------
@dataclass
class Component:
    name: str
    kind: str = "other"
    zone: str = "unknown"
    exposure: str = "unknown"
    data: List[str] = field(default_factory=list)
    section: str = ""
    evidence: str = ""

    @property
    def key(self) -> str:
        return _key(self.name)

    @property
    def sensitive(self) -> bool:
        return any(d in SENSITIVE for d in self.data)


@dataclass
class Flow:
    source: str
    target: str
    protocol: str = ""
    auth: str = "unknown"
    encrypted: str = "unknown"      # yes / no / unknown
    section: str = ""
    evidence: str = ""


@dataclass
class Control:
    control: str
    target: str = ""
    status: str = "present"         # present / absent / weakened
    section: str = ""
    evidence: str = ""


@dataclass
class SystemModel:
    components: List[Component] = field(default_factory=list)
    flows: List[Flow] = field(default_factory=list)
    controls: List[Control] = field(default_factory=list)
    dropped_ungrounded: int = 0

    def component(self, name: str) -> Optional[Component]:
        k = _key(name)
        return next((c for c in self.components if c.key == k), None)

    def zone_of(self, name: str) -> str:
        c = self.component(name)
        return c.zone if c else "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "components": [asdict(c) for c in self.components],
            "flows": [asdict(f) for f in self.flows],
            "controls": [asdict(c) for c in self.controls],
            "dropped_ungrounded": self.dropped_ungrounded,
        }


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _norm(text: str) -> str:
    text = re.sub(r"[^\w\s]", " ", (text or "").lower())
    return re.sub(r"\s+", " ", text).strip()


def quote_grounded(quote: str, doc_norm: str) -> bool:
    words = _norm((quote or "").replace("...", " ").replace("…", " ")).split()
    if len(words) < MIN_QUOTE_WORDS:
        return False
    # A 6-word verbatim run: long enough not to match by chance, short
    # enough that a lightly trimmed quote still counts (8 dropped 49 facts
    # on gs-01, mostly quotes with a word or two altered at one end).
    n = min(len(words), 6)
    return any(" ".join(words[i:i + n]) in doc_norm
               for i in range(len(words) - n + 1))


def _pick(value: Any, allowed: Sequence[str], default: str) -> str:
    v = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    return v if v in allowed else default


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
EXTRACT_SYSTEM = f"""You extract facts from an architecture design document. You do NOT review it and you do NOT judge whether anything is secure.

Return ONLY a JSON object with three lists:

"components": things the design contains.
  {{"name": str, "kind": one of {list(KINDS)}, "zone": one of {list(ZONES)},
    "exposure": one of {list(EXPOSURE)}, "data": subset of {list(SENSITIVE)},
    "evidence": exact quote}}
"flows": connections between components or users.
  {{"source": component name, "target": component name, "protocol": str,
    "auth": one of {list(AUTH)}, "encrypted": "yes" | "no" | "unknown",
    "evidence": exact quote}}
"controls": security controls the text explicitly says are present, absent or weakened.
  {{"control": short name, "target": component name,
    "status": "present" | "absent" | "weakened", "evidence": exact quote}}

Rules:
- "evidence" MUST be copied word-for-word from the text (one sentence, at least 5 words). Facts without an exact quote are discarded.
- For every flow, read the surrounding sentences for HOW the caller authenticates and set auth to the stated mechanism: bearer/access/JWT tokens -> "token", OAuth/OIDC -> "oauth", client certificates/mutual TLS -> "mtls", username and password or a service account password -> "password", a shared key/community string/PSK -> "shared_secret", an API key -> "api_key".
- auth "none" when the text says no authentication, anonymous, unauthenticated, open, or "does not authenticate" - including "because it is internal/behind the firewall".
- encrypted "yes" when the text says TLS/HTTPS/SSH/IPsec/encrypted; "no" when it says plaintext, unencrypted, or names a cleartext protocol (HTTP, Telnet, FTP, LDAP on port 389, SNMP v1/v2c).
- Use "unknown" only when the text says nothing about it.
- exposure "public" only when the text says internet-facing, public, publicly accessible, or 0.0.0.0/0.
- Reuse the same component name every time you refer to the same thing.
- Empty lists are fine.
- Output compact JSON with no indentation or line breaks."""

EXTRACT_USER = """DOCUMENT: {document_name}

Components already identified in earlier parts (reuse these names):
{known}

TEXT:
{text}"""


def _batches(sections: Sequence[Section], max_words: int) -> List[List[Section]]:
    out: List[List[Section]] = []
    cur: List[Section] = []
    words = 0
    for s in sections:
        w = s.word_count + len(s.heading.split())
        if cur and words + w > max_words:
            out.append(cur)
            cur, words = [], 0
        cur.append(s)
        words += w
    if cur:
        out.append(cur)
    return out


def _salvage(text: str) -> Dict[str, Any]:
    """Recover every complete item from JSON cut off by the output cap.

    Measured: with a 2048-token cap, 8 of 12 golden documents came back
    truncated mid-list and a strict parse discarded everything.
    """
    decoder = json.JSONDecoder()
    out: Dict[str, Any] = {}
    for key in ("components", "flows", "controls"):
        m = re.search(r'"%s"\s*:\s*\[' % key, text)
        if not m:
            continue
        items, i = [], m.end()
        while True:
            j = text.find("{", i)
            if j < 0:
                break
            # stop at the end of this list
            close = text.find("]", i)
            if 0 <= close < j:
                break
            try:
                obj, end = decoder.raw_decode(text, j)
            except json.JSONDecodeError:
                break                       # truncated item: keep what we have
            if isinstance(obj, dict):
                items.append(obj)
            i = end
        out[key] = items
    return out


def _parse_json(text: str) -> Dict[str, Any]:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return _salvage(text or "")
    return data if isinstance(data, dict) else {}


def _message_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(p.get("text", "") if isinstance(p, dict) else str(p)
                       for p in content)
    return str(content or "")


def _section_for(quote: str, sections: Sequence[Section]) -> str:
    q = _norm(quote)[:60]
    for s in sections:
        if q and q in _norm(f"{s.heading}\n{s.body}"):
            return s.heading
    return sections[0].heading if sections else ""


def merge_extraction(model: SystemModel, data: Dict[str, Any],
                     sections: Sequence[Section], doc_norm: str) -> None:
    """Add one batch's extraction to the model, dropping ungrounded facts."""
    for raw in data.get("components") or []:
        if not isinstance(raw, dict) or not str(raw.get("name", "")).strip():
            continue
        ev = str(raw.get("evidence", ""))
        if not quote_grounded(ev, doc_norm):
            model.dropped_ungrounded += 1
            continue
        c = Component(
            name=str(raw["name"]).strip()[:80],
            kind=_pick(raw.get("kind"), KINDS, "other"),
            zone=_pick(raw.get("zone"), ZONES, "unknown"),
            exposure=_pick(raw.get("exposure"), EXPOSURE, "unknown"),
            data=sorted({_pick(d, SENSITIVE, "") for d in (raw.get("data") or [])
                         if isinstance(d, str)} - {""}),
            section=_section_for(ev, sections), evidence=ev.strip(),
        )
        existing = model.component(c.name)
        if existing is None:
            model.components.append(c)
            continue
        # Later mentions fill in what earlier ones left unknown; a stated
        # public exposure or sensitive data is never overwritten.
        if existing.zone == "unknown":
            existing.zone = c.zone
        if existing.exposure in ("unknown", "internal") and c.exposure in ("public", "partner"):
            existing.exposure, existing.evidence, existing.section = c.exposure, c.evidence, c.section
        if existing.kind == "other":
            existing.kind = c.kind
        existing.data = sorted(set(existing.data) | set(c.data))

    for raw in data.get("flows") or []:
        if not isinstance(raw, dict) or not raw.get("source") or not raw.get("target"):
            continue
        ev = str(raw.get("evidence", ""))
        if not quote_grounded(ev, doc_norm):
            model.dropped_ungrounded += 1
            continue
        model.flows.append(Flow(
            source=str(raw["source"]).strip()[:80], target=str(raw["target"]).strip()[:80],
            protocol=str(raw.get("protocol") or "")[:40],
            auth=_pick(raw.get("auth"), AUTH, "unknown"),
            encrypted=_pick(raw.get("encrypted"), ("yes", "no", "unknown"), "unknown"),
            section=_section_for(ev, sections), evidence=ev.strip(),
        ))

    for raw in data.get("controls") or []:
        if not isinstance(raw, dict) or not str(raw.get("control", "")).strip():
            continue
        ev = str(raw.get("evidence", ""))
        if not quote_grounded(ev, doc_norm):
            model.dropped_ungrounded += 1
            continue
        model.controls.append(Control(
            control=str(raw["control"]).strip()[:80],
            target=str(raw.get("target") or "")[:80],
            status=_pick(raw.get("status"), ("present", "absent", "weakened"), "present"),
            section=_section_for(ev, sections), evidence=ev.strip(),
        ))


def extract_system_model(sections: Sequence[Section], llm: Any, document_name: str,
                         max_words: int = 700,
                         record: Optional[Callable[..., None]] = None) -> SystemModel:
    """Build a SystemModel with one extraction call per batch of sections."""
    doc_norm = _norm("\n".join(f"{s.heading}\n{s.body}" for s in sections))
    model = SystemModel()
    for i, batch in enumerate(_batches(sections, max_words), start=1):
        known = ", ".join(c.name for c in model.components[:60]) or "(none yet)"
        text = "\n\n".join(f"## {s.heading}\n{s.body}" for s in batch)
        try:
            response = llm.invoke([
                ("system", EXTRACT_SYSTEM),
                ("human", EXTRACT_USER.format(document_name=document_name,
                                              known=known, text=text)),
            ])
            data = _parse_json(_message_text(response))
        except Exception as exc:  # noqa: BLE001
            if record:
                record("system_model_error", batch=i, error=str(exc)[:300])
            continue
        merge_extraction(model, data, batch, doc_norm)
        if record:
            record("system_model_batch", batch=i, sections=len(batch),
                   components=len(model.components), flows=len(model.flows))
    return model


def build_extractor_llm(config: Any) -> Any:
    """JSON-mode ChatOllama for models.system_model (default: models.llm)."""
    from langchain_ollama import ChatOllama
    name = str(config.models.get("system_model") or config.models["llm"])
    return ChatOllama(
        model=name,
        base_url=config.models["ollama_host"],
        temperature=0.0,
        num_ctx=int(config.models.get("num_ctx", 8192)),
        # Extraction output is long (every component and flow); the reviewer's
        # 2048 cap truncated 8 of 12 golden documents.
        num_predict=int(config.models.get("system_model_max_tokens", 6144)),
        format="json",
        client_kwargs={"timeout": float(config.models.get("request_timeout_s", 300))},
    )


def zone_for_sections(model: SystemModel, sections: Iterable[Section]) -> Dict[str, str]:
    """Most common known component zone per section heading (for the threat model)."""
    from collections import Counter
    votes: Dict[str, Counter] = {}
    for c in model.components:
        if c.zone != "unknown" and c.section:
            votes.setdefault(c.section, Counter())[c.zone] += 1
    return {s.heading: votes[s.heading].most_common(1)[0][0]
            for s in sections if s.heading in votes}
