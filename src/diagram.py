"""Diagrams as a second source for the DFD.

Why this exists
---------------
Half of an HLD is a picture. The text parser reads paragraphs and tables
and is blind to everything drawn: trust-zone bands, the arrow labelled
"no TLS", the note in the corner saying the admin portal needs no MFA.
A review that never sees those is reviewing half the design.

So images are pulled out of the document and read by a local vision model
into the same vocabulary the DFD already uses (``src/dfd.py``: zones,
component kinds, flow auth/encryption). The result is a *draft*, tagged
``source="diagram"``, that the engineer confirms in the DFD editor.

What this deliberately does NOT do
----------------------------------
Diagram-derived facts never become findings directly. Every other finding
in this tool is evidence-grounded - its quote must appear verbatim in the
document text (``triage.evidence_is_grounded``). A fact read off a picture
has no such text to check against, so it cannot pass that gate and must
not bypass it. The existing human gate is the DFD approval step, and that
is the only route a diagram fact takes into a review.

Measured on a synthetic 4-zone, 7-component diagram (gemma3:12b, 32s):
zones 4/4, components 7/7 with the right zone, flows 5/6, printed note
verbatim. The missed flow was a vertical connector with no arrowhead -
bent and unarrowed connectors are the known weak spot, which is the other
reason the engineer confirms the result rather than trusting it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .dfd import AUTH, DFD, DFDComponent, DFDFlow, ENCRYPTED, KINDS, ZONE_ORDER, slug

# A diagram worth reading is at least this big. Below it the image is a
# logo, an icon, a signature or a bullet glyph.
MIN_WIDTH = 320
MIN_HEIGHT = 220
# Banners and rules: very wide, very short. Not diagrams.
MAX_ASPECT = 6.0
MAX_IMAGES = 12           # one GPU, ~30s each: a 20-diagram HLD must not hang
# Visio and draw.io export to PDF as vector art, not as an embedded raster,
# so get_images() returns nothing for exactly the documents that matter.
# A page with this many drawing operations is treated as a diagram page and
# rendered instead.
VECTOR_MIN_OPS = 60
PAGE_ZOOM = 2.0           # render at 2x so 8pt arrow labels stay readable


@dataclass
class DiagramImage:
    """One candidate diagram pulled out of a document."""

    where: str                    # "page 4" / "image 2" - shown to the engineer
    data: bytes
    width: int
    height: int
    kind: str = "raster"          # raster (embedded) / page (rendered)

    @property
    def sha(self) -> str:
        return hashlib.sha256(self.data).hexdigest()[:12]


@dataclass
class DiagramExtraction:
    """What the vision model read off one image."""

    where: str
    image_sha: str
    model: str
    seconds: float = 0.0
    zones: List[str] = field(default_factory=list)
    components: List[Dict[str, Any]] = field(default_factory=list)
    flows: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.components)


# ==========================================================================
# Image extraction
# ==========================================================================
def _keep(width: int, height: int) -> bool:
    if width < MIN_WIDTH or height < MIN_HEIGHT:
        return False
    long_side, short_side = max(width, height), max(1, min(width, height))
    return long_side / short_side <= MAX_ASPECT


def _pdf_images(path: Path, limit: int) -> List[DiagramImage]:
    import pymupdf

    out: List[DiagramImage] = []
    doc = pymupdf.open(str(path))
    try:
        for page_no, page in enumerate(doc, start=1):
            if len(out) >= limit:
                break
            embedded = page.get_images(full=True)
            found_on_page = False
            for xref, *_ in embedded:
                if len(out) >= limit:
                    break
                try:
                    pix = pymupdf.Pixmap(doc, xref)
                    if pix.n - pix.alpha >= 4:          # CMYK -> RGB
                        pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                    if not _keep(pix.width, pix.height):
                        continue
                    out.append(DiagramImage(f"page {page_no}", pix.tobytes("png"),
                                            pix.width, pix.height))
                    found_on_page = True
                except Exception:  # noqa: BLE001 - a broken image is not fatal
                    continue
            # Vector drawing (Visio/draw.io export): nothing embedded to pull,
            # so render the page itself.
            if not found_on_page and len(page.get_drawings()) >= VECTOR_MIN_OPS:
                pix = page.get_pixmap(matrix=pymupdf.Matrix(PAGE_ZOOM, PAGE_ZOOM))
                if _keep(pix.width, pix.height):
                    out.append(DiagramImage(f"page {page_no}", pix.tobytes("png"),
                                            pix.width, pix.height, kind="page"))
    finally:
        doc.close()
    return out


def _docx_images(path: Path, limit: int) -> List[DiagramImage]:
    import docx
    from PIL import Image
    import io

    document = docx.Document(str(path))
    out: List[DiagramImage] = []
    for n, part in enumerate(document.part.related_parts.values(), start=1):
        if len(out) >= limit:
            break
        content_type = getattr(part, "content_type", "")
        if not content_type.startswith("image/"):
            continue
        blob = getattr(part, "blob", b"")
        try:
            with Image.open(io.BytesIO(blob)) as im:
                width, height = im.size
                if not _keep(width, height):
                    continue
                if im.format != "PNG":
                    buf = io.BytesIO()
                    im.convert("RGB").save(buf, format="PNG")
                    blob = buf.getvalue()
        except Exception:  # noqa: BLE001
            continue
        out.append(DiagramImage(f"image {n}", blob, width, height))
    return out


def extract_images(path: str | Path, limit: int = MAX_IMAGES) -> List[DiagramImage]:
    """Diagram-sized images from a .pdf or .docx, de-duplicated.

    The same diagram repeated in a header or on every page is read once.
    """
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".pdf":
        images = _pdf_images(p, limit)
    elif suffix == ".docx":
        images = _docx_images(p, limit)
    else:
        return []

    seen: set = set()
    unique: List[DiagramImage] = []
    for img in images:
        if img.sha in seen:
            continue
        seen.add(img.sha)
        unique.append(img)
    return unique[:limit]


# ==========================================================================
# Vision extraction
# ==========================================================================
# Ask the vision model for what only eyes can supply - boxes, bands, arrows
# and the text printed on them - and nothing else.
#
# Measured on the test diagram: asking for kind/auth/encrypted in the same
# call dropped flow accuracy from 5/6 to 3/6 and blanked the arrow labels
# the model had read correctly a moment earlier. Classification is cheap,
# deterministic and testable in Python (see classify_kind,
# _encryption_from_label), so it does not belong in the image call.
VISION_PROMPT = """You are reading an architecture or data flow diagram. Return ONLY JSON.

{
  "zones": ["the trust-zone bands, swimlanes or groupings drawn on the diagram"],
  "boxes": [
    {"name": "the box's main label, exactly as printed",
     "detail": "the smaller text inside the same box, or empty",
     "zone": "the name of the band this box sits inside, or empty"}
  ],
  "arrows": [
    {"from": "the label of the box the arrow starts at",
     "to": "the label of the box the arrow head points at",
     "label": "the text printed on or beside that arrow, exactly, or empty"}
  ],
  "notes": ["any other sentence printed on the diagram"]
}

Rules:
- Copy text exactly as printed. Do not expand abbreviations or correct spelling.
- Follow each arrow from its tail to the box its head touches. Vertical,
  bent and unarrowed connecting lines are arrows too.
- Every arrow label matters, especially ones like "HTTPS", "no TLS",
  "plain FTP" or "admin". Never leave a label out if text is printed there.
- Do not invent anything that is not drawn. An empty list is a correct answer.
"""


def build_prompt() -> str:
    return VISION_PROMPT


# --------------------------------------------------------------------------
# Deterministic classification of what the model read
# --------------------------------------------------------------------------
# Longest-match-first: "vector database" must beat "database".
_KIND_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"vector\s*(db|database|store)|pinecone|chroma|weaviate|qdrant|faiss", "vector_db"),
    (r"\b(llm|gpt|claude|gemini|llama|bedrock|openai|model\s+endpoint)\b", "llm"),
    (r"\bagent\b|orchestrat", "agent"),
    (r"pipeline|ci/?cd|jenkins|github\s*actions|gitlab|build\s+server|artifact", "pipeline"),
    (r"\b(db|database|postgres|mysql|oracle|sql|mongo|redis|cache|bucket|s3|blob|"
     r"storage|data\s*lake|warehouse|table|queue|kafka|topic)\b", "datastore"),
    (r"\b(idp|identity|directory|active\s*directory|entra|okta|ldap|iam|sso|"
     r"keycloak|auth\s*server|vault|hsm|kms)\b", "identity"),
    (r"\b(firewall|router|switch|vlan|vpn|waf|load\s*balanc|proxy|cdn|gateway\s*$|"
     r"nat|dns|subnet|vpc)\b", "network"),
    # "admin" is a person, but "Admin Portal" and "Admin API" are services.
    (r"\b(customer|user|staff|employee|analyst|operator|engineer|browser|"
     r"mobile\s*app|client)\b|"
     r"\badmin(istrator)?s?\b(?!\s*(portal|console|api|ui|dashboard|gateway|"
     r"interface|panel|plane))", "user_group"),
    (r"\b(partner|third[- ]party|external|supplier|vendor|bureau|msp|sftp)\b",
     "external_party"),
    (r"\b(device|sensor|plc|scada|rtu|iot|scooter|meter|camera|terminal|hmi)\b",
     "device"),
    (r"\b(api|service|gateway|server|app|portal|function|lambda|job|worker|"
     r"microservice|backend|frontend|jump\s*host|bastion|broker)\b", "service"),
)


def classify_kind(name: str, detail: str = "") -> str:
    """Component kind from its printed label. Deterministic and testable."""
    text = f"{name} {detail}".lower()
    for pattern, kind in _KIND_PATTERNS:
        if re.search(pattern, text):
            return kind
    return "other"


# Zone bands are drawn with whatever words the author likes; map them onto
# the DFD's fixed vocabulary.
_ZONE_SYNONYMS: Tuple[Tuple[str, str], ...] = (
    (r"internet|public|external\s*(network|zone)?|wan|untrusted", "internet"),
    (r"partner|third[- ]party|supplier|vendor|b2b|extranet", "partner"),
    (r"\bdmz\b|perimeter|edge|front[- ]?end\s*zone", "dmz"),
    (r"manage|\boob\b|out[- ]of[- ]band|admin\s*(zone|network|vlan)", "management"),
    (r"restricted|data\s*(zone|tier|layer)?$|secure\s*zone|crown|pci|cde|"
     r"card\s*holder", "restricted"),
    (r"cloud|aws|azure|gcp|saas|vpc|subscription|landing\s*zone", "cloud"),
    (r"internal|corporate|corp|trusted|on[- ]?prem|lan|back[- ]?end|private", "internal"),
)


def normalise_zone(raw: str) -> str:
    """Map a drawn band name onto the DFD zone vocabulary."""
    text = (raw or "").strip().lower()
    if not text:
        return "unknown"
    if text in ZONE_ORDER:
        return text
    for pattern, zone in _ZONE_SYNONYMS:
        if re.search(pattern, text):
            return zone
    return "unknown"


def _salvage(text: str) -> Dict[str, Any]:
    """Recover whole items from JSON cut short by the output cap."""
    decoder = json.JSONDecoder()
    out: Dict[str, Any] = {}
    for key in ("boxes", "arrows", "components", "flows"):
        m = re.search(r'"%s"\s*:\s*\[' % key, text)
        if not m:
            continue
        items, i = [], m.end()
        while True:
            j = text.find("{", i)
            if j < 0:
                break
            close = text.find("]", i)
            if 0 <= close < j:
                break
            try:
                obj, end = decoder.raw_decode(text, j)
            except json.JSONDecodeError:
                break
            if isinstance(obj, dict):
                items.append(obj)
            i = end
        out[key] = items
    for key in ("zones", "notes"):
        m = re.search(r'"%s"\s*:\s*(\[[^\]]*\])' % key, text)
        if m:
            try:
                out[key] = json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    return out


# A rendered page carries the prose around the diagram, so the model offers
# the section heading as a "note". The heading is already in the text review.
_HEADING = re.compile(r"^\d+(\.\d+)*\.?\s+\S|^(figure|fig\.|table|appendix|page)\b", re.I)


def _is_diagram_note(note: str) -> bool:
    """A sentence printed on the diagram, not the page furniture around it."""
    if len(note) < 12 or _HEADING.match(note):
        return False
    return bool(re.search(r"[a-z]", note))        # not an ALL-CAPS band label


def parse_response(text: str) -> Dict[str, Any]:
    body = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", body, re.S)
    if fence:
        body = fence.group(1).strip()
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        data = _salvage(body)
    return data if isinstance(data, dict) else {}


def build_vision_caller(model: str, host: str = "http://localhost:11434",
                        timeout_s: float = 600.0) -> Callable[[bytes, str], str]:
    """Return call(image_bytes, prompt) -> raw model text."""

    def call(image: bytes, prompt: str) -> str:
        import ollama

        client = ollama.Client(host=host, timeout=timeout_s)
        reply = client.generate(
            model=model, prompt=prompt,
            images=[base64.b64encode(image).decode()],
            format="json",
            options={"temperature": 0.1, "num_predict": 2048},
        )
        return reply.get("response", "") if isinstance(reply, dict) \
            else getattr(reply, "response", "")

    return call


def read_diagram(image: DiagramImage, call: Callable[[bytes, str], str],
                 model: str) -> DiagramExtraction:
    """Read one image into the DFD vocabulary. Never raises."""
    out = DiagramExtraction(where=image.where, image_sha=image.sha, model=model)
    started = time.time()
    try:
        data = parse_response(call(image.data, build_prompt()))
    except Exception as exc:  # noqa: BLE001 - one bad image must not stop the rest
        out.error = str(exc)[:200]
        out.seconds = round(time.time() - started, 1)
        return out
    out.seconds = round(time.time() - started, 1)
    out.zones = [str(z).strip() for z in data.get("zones", []) if str(z).strip()]
    out.notes = [n for n in (str(x).strip() for x in data.get("notes", []))
                 if _is_diagram_note(n)]

    # The model reports boxes and arrows; everything else is derived here.
    for box in data.get("boxes", data.get("components", [])):
        if not isinstance(box, dict):
            continue
        name = str(box.get("name", "")).strip()
        if not name:
            continue
        detail = str(box.get("detail", "")).strip()
        out.components.append({
            "name": name, "detail": detail,
            "kind": classify_kind(name, detail),
            "zone": normalise_zone(str(box.get("zone", ""))),
        })
    for arrow in data.get("arrows", data.get("flows", [])):
        if not isinstance(arrow, dict):
            continue
        src = str(arrow.get("from", arrow.get("source", ""))).strip()
        dst = str(arrow.get("to", arrow.get("target", ""))).strip()
        if not src or not dst:
            continue
        label = str(arrow.get("label", "")).strip()
        out.flows.append({
            "source": src, "target": dst, "label": label,
            "protocol": _protocol_from_label(label),
            "encrypted": _encryption_from_label(label, "unknown"),
            "auth": _auth_from_label(label),
        })
    if not out.components:
        out.error = out.error or "no components read from the image"
    return out


def read_document_diagrams(path: str | Path, call: Callable[[bytes, str], str],
                           model: str, limit: int = MAX_IMAGES,
                           progress: Optional[Callable[[str], None]] = None
                           ) -> Tuple[List[DiagramImage], List[DiagramExtraction]]:
    """Every diagram in a document, read one at a time (one GPU)."""
    images = extract_images(path, limit)
    out: List[DiagramExtraction] = []
    for n, img in enumerate(images, start=1):
        if progress:
            progress(f"Reading diagram {n} of {len(images)} ({img.where})…")
        out.append(read_diagram(img, call, model))
    return images, out


# ==========================================================================
# Merge into the DFD draft
# ==========================================================================
# An arrow label is the only encryption evidence a diagram offers, so read it.
_CLEAR = re.compile(r"\b(no\s+tls|plain|clear\s*text|cleartext|unencrypted|http(?!s)|"
                    r"ftp(?!s)|telnet|snmp\s*v?[12])\b", re.I)
_CRYPT = re.compile(r"\b(https|tls|ssl|mtls|ssh|sftp|ipsec|wireguard|encrypted)\b", re.I)


def _encryption_from_label(label: str, stated: str = "unknown") -> str:
    if stated in ENCRYPTED and stated != "unknown":
        return stated
    if _CLEAR.search(label or ""):
        return "no"
    if _CRYPT.search(label or ""):
        return "yes"
    return "unknown"


_PROTOCOL = re.compile(
    r"\b(https?|tls(?:\s*1\.[0-3])?|mtls|ssh|sftp|ftps?|telnet|smtp|amqp|mqtt|grpc|"
    r"odbc|jdbc|snmp\s*v?[123]c?|ipsec|wireguard|kafka|soap|rest|websocket)\b", re.I)
# A label can name how the caller authenticates; map those words onto AUTH.
_AUTH_WORDS: Tuple[Tuple[str, str], ...] = (
    (r"\bmtls\b|mutual\s*tls|client\s*cert", "mtls"),
    (r"\boauth\b|\bopenid\b|\boidc\b", "oauth"),
    (r"\bsaml\b|\bsso\b|federat", "sso"),
    (r"\bkerberos\b", "kerberos"),
    (r"\bapi\s*key\b", "api_key"),
    (r"\btoken\b|\bjwt\b|bearer", "token"),
    (r"\bcert(ificate)?\b", "certificate"),
    (r"shared\s*(secret|key)|pre[- ]?shared|\bpsk\b", "shared_secret"),
    (r"\bpassword\b|basic\s*auth", "password"),
    (r"\bno\s*auth\b|unauthenticated|anonymous|\bopen\b", "none"),
)


def _protocol_from_label(label: str) -> str:
    """The protocol the flow uses - not one the label says it lacks.

    "plain FTP" is FTP. "no TLS" is not TLS: the label names the missing
    control, and recording it as the protocol would read as the opposite
    of what the diagram says.
    """
    m = _PROTOCOL.search(label or "")
    if not m:
        return ""
    before = (label or "")[max(0, m.start() - 16):m.start()]
    if re.search(r"\b(no|not|without|lacks?|missing)\s*$", before, re.I):
        return ""
    return m.group(0)[:40]


def _auth_from_label(label: str) -> str:
    text = label or ""
    for pattern, auth in _AUTH_WORDS:
        if re.search(pattern, text, re.I):
            return auth
    return "unknown"


@dataclass
class Conflict:
    """The diagram and the text disagree about the same thing.

    This is not noise to resolve silently - a design whose picture and prose
    contradict each other is a defect in its own right, and the engineer is
    the one who decides which side is true.
    """

    kind: str                     # zone / encrypted / auth
    element: str                  # component or flow label
    text_says: str
    diagram_says: str
    where: str = ""               # which diagram


def merge_into(dfd: DFD, extractions: Sequence[DiagramExtraction]
               ) -> Tuple[int, int, List[Conflict]]:
    """Add what the diagrams show to an existing (text-derived) DFD.

    Returns (components added, flows added, conflicts). Existing elements
    keep their text-derived values; a disagreement is reported, never
    overwritten, because the engineer resolves it in the DFD editor.
    """
    by_name: Dict[str, DFDComponent] = {slug(c.name): c for c in dfd.components}
    taken = {c.id for c in dfd.components}
    added_c = added_f = 0
    conflicts: List[Conflict] = []

    def component_for(name: str, where: str, **kw) -> Optional[DFDComponent]:
        nonlocal added_c
        key = slug(name)
        if not key:
            return None
        existing = by_name.get(key)
        if existing is not None:
            zone = kw.get("zone", "unknown")
            if (zone != "unknown" and existing.zone != "unknown"
                    and zone != existing.zone):
                conflicts.append(Conflict("zone", existing.name, existing.zone,
                                          zone, where))
            elif existing.zone == "unknown" and zone != "unknown":
                existing.zone, existing.source = zone, "diagram"
            if existing.source == "text":
                existing.source = "text+diagram"
            return existing
        cid = key[:40] or "c"
        n = 2
        while cid in taken:
            cid, n = f"{key[:38]}{n}", n + 1
        taken.add(cid)
        comp = DFDComponent(id=cid, name=name.strip()[:60], source="diagram", **kw)
        dfd.components.append(comp)
        by_name[key] = comp
        added_c += 1
        return comp

    pairs = {(f.source, f.target) for f in dfd.flows}
    for ex in extractions:
        if not ex.ok:
            continue
        for c in ex.components:
            kind = str(c.get("kind", "other")).strip().lower()
            zone = str(c.get("zone", "unknown")).strip().lower()
            detail = str(c.get("detail", "")).strip()
            component_for(
                str(c["name"]), ex.where,
                kind=kind if kind in KINDS else "other",
                zone=zone if zone in ZONE_ORDER else "unknown",
                public=bool(c.get("public")),
                evidence=f"diagram ({ex.where}): {detail}" if detail
                         else f"diagram ({ex.where})")
        for f in ex.flows:
            src = component_for(str(f["source"]), ex.where)
            dst = component_for(str(f["target"]), ex.where)
            if src is None or dst is None or src.id == dst.id:
                continue
            label = str(f.get("label", "")).strip()
            encrypted = _encryption_from_label(label, str(f.get("encrypted", "unknown")))
            auth = str(f.get("auth", "unknown")).strip().lower()
            auth = auth if auth in AUTH else "unknown"
            existing = next((x for x in dfd.flows
                             if (x.source, x.target) == (src.id, dst.id)), None)
            if existing is not None:
                for field_name, diagram_value in (("encrypted", encrypted),
                                                  ("auth", auth)):
                    text_value = getattr(existing, field_name)
                    if diagram_value == "unknown":
                        continue
                    if text_value == "unknown":
                        setattr(existing, field_name, diagram_value)
                        existing.source_tag = "diagram"
                    elif text_value != diagram_value:
                        conflicts.append(Conflict(
                            field_name, f"{src.name} → {dst.name}",
                            text_value, diagram_value, ex.where))
                if existing.source_tag == "text":
                    existing.source_tag = "text+diagram"
                continue
            if (src.id, dst.id) in pairs:
                continue
            pairs.add((src.id, dst.id))
            dfd.flows.append(DFDFlow(
                id=f"f{len(dfd.flows) + 1}", source=src.id, target=dst.id,
                protocol=str(f.get("protocol", "")).strip()[:40] or label[:40],
                auth=auth, encrypted=encrypted, source_tag="diagram",
                evidence=f"diagram ({ex.where}): {label}" if label
                         else f"diagram ({ex.where})"))
            added_f += 1

    used = {c.zone for c in dfd.components}
    dfd.zones = [z for z in ZONE_ORDER
                 if z in used or z in ("internet", "internal", "unknown")]
    return added_c, added_f, conflicts


def diagram_notes(extractions: Sequence[DiagramExtraction]) -> List[Tuple[str, str]]:
    """(where, note) for every sentence printed on a diagram.

    These are the "reachable from the office VLAN without MFA" asides that
    carry real risk and appear nowhere in the prose.
    """
    return [(ex.where, note) for ex in extractions if ex.ok for note in ex.notes]
