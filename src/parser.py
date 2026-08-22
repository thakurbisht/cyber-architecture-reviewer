"""Document ingestion and section typing.

Supported inputs
----------------
  .md / .markdown / .txt   plain read
  .docx                    python-docx, headings preserved via style names
  .pdf                     PyMuPDF, headings inferred from font size
  .yaml / .yml / .json     OpenAPI / IaC specs, flattened into typed sections
  raw pasted text          via parse_text()

The output is always the same: a list of Section objects with a heading, a
body, and a domain/topic classification. Everything downstream - retrieval,
the rules engine, the agent - consumes Sections and nothing else, so adding
a new input format never touches the review logic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .domains import classify_section
from .models import Section

SUPPORTED_SUFFIXES = {
    ".md", ".markdown", ".txt", ".text",
    ".docx", ".pdf",
    ".yaml", ".yml", ".json",
}

MAX_SECTION_WORDS = 900       # split oversized sections so retrieval stays sharp
MIN_SECTION_WORDS = 8         # drop heading-only stubs


# ==========================================================================
# Format readers -> raw text
# ==========================================================================
def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _read_docx(path: Path) -> str:
    try:
        import docx  # python-docx
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "python-docx is required for .docx input. pip install python-docx"
        ) from exc

    document = docx.Document(str(path))
    lines: List[str] = []

    for para in document.paragraphs:
        text = para.text.strip()
        if not text:
            continue
        style = (para.style.name or "").lower()
        if style.startswith("heading"):
            m = re.search(r"(\d+)", style)
            level = int(m.group(1)) if m else 1
            lines.append(f"{'#' * min(level, 6)} {text}")
        elif style in {"title", "subtitle"}:
            lines.append(f"# {text}")
        else:
            lines.append(text)

    # Tables carry the real content in most LLDs (device tables, VLAN tables,
    # firewall rule tables). Flatten them as pipe rows so the model sees them.
    for t_index, table in enumerate(document.tables, start=1):
        lines.append(f"\n#### Table {t_index}")
        for row in table.rows:
            cells = [c.text.strip().replace("\n", " ") for c in row.cells]
            if any(cells):
                lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def _read_pdf(path: Path) -> str:
    try:
        import fitz  # PyMuPDF
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pymupdf is required for .pdf input. pip install pymupdf"
        ) from exc

    doc = fitz.open(str(path))
    try:
        # Collect span sizes first so heading detection is relative to this
        # document's own typography, not a hardcoded point size.
        sizes: List[float] = []
        pages: List[List[Tuple[str, float, bool]]] = []

        for page in doc:
            blocks = page.get_text("dict").get("blocks", [])
            page_lines: List[Tuple[str, float, bool]] = []
            for block in blocks:
                for line in block.get("lines", []):
                    text = "".join(s.get("text", "") for s in line.get("spans", []))
                    if not text.strip():
                        continue
                    spans = line.get("spans", [])
                    size = max((s.get("size", 0.0) for s in spans), default=0.0)
                    bold = any("bold" in (s.get("font", "").lower()) for s in spans)
                    sizes.append(size)
                    page_lines.append((text.strip(), size, bold))
            pages.append(page_lines)

        body_size = _median(sizes) if sizes else 10.0
        out: List[str] = []
        for page_lines in pages:
            for text, size, bold in page_lines:
                is_heading = (
                    size >= body_size * 1.15
                    or (bold and size >= body_size and len(text) < 90)
                    or bool(re.match(r"^\d+(\.\d+)*\s+\S", text)) and len(text) < 90
                )
                if is_heading:
                    level = 1 if size >= body_size * 1.4 else 2
                    out.append(f"{'#' * level} {text}")
                else:
                    out.append(text)
        return "\n".join(out)
    finally:
        doc.close()


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def _read_structured(path: Path) -> str:
    """Flatten an OpenAPI / IaC / JSON spec into reviewable markdown.

    Application reviews frequently arrive as an OpenAPI document rather than
    prose. Rather than embed raw YAML (which retrieves badly), we render the
    security-relevant structure into headed prose the reviewer can reason over.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            import yaml
            data = yaml.safe_load(text)
    except Exception:
        return text  # fall back to raw - better a rough review than none

    if not isinstance(data, dict):
        return text

    if "openapi" in data or "swagger" in data:
        return _render_openapi(data)

    return "# Specification\n\n" + _render_generic(data)


def _render_openapi(spec: Dict) -> str:
    lines: List[str] = []
    info = spec.get("info", {}) or {}
    lines.append(f"# API Specification: {info.get('title', 'Untitled API')}")
    lines.append(f"Version: {info.get('version', 'unspecified')}")
    if info.get("description"):
        lines.append(str(info["description"]))

    servers = spec.get("servers") or []
    lines.append("\n## API Servers and Transport")
    if servers:
        for s in servers:
            url = s.get("url", "")
            lines.append(f"- Server URL: {url} ({s.get('description', '')})")
            if url.startswith("http://"):
                lines.append(
                    "  Transport is plaintext HTTP for this server entry."
                )
    else:
        lines.append("No servers declared in the specification.")

    comps = spec.get("components", {}) or {}
    schemes = comps.get("securitySchemes", {}) or {}
    lines.append("\n## API Authentication and Authorisation")
    if schemes:
        for name, sch in schemes.items():
            stype = sch.get("type", "")
            detail = sch.get("scheme", "") or sch.get("in", "")
            lines.append(f"- Security scheme '{name}': type={stype} {detail}".strip())
    else:
        lines.append(
            "No securitySchemes are defined. The API declares no authentication."
        )
    global_sec = spec.get("security")
    lines.append(
        f"- Global security requirement: {global_sec}" if global_sec
        else "- No global security requirement is applied to the API."
    )

    lines.append("\n## API Endpoints and Integration Surface")
    paths = spec.get("paths", {}) or {}
    lines.append(f"The specification exposes {len(paths)} paths.")
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in {
                "get", "post", "put", "patch", "delete", "head", "options"
            }:
                continue
            op = op or {}
            sec = op.get("security", "inherited")
            summary = op.get("summary", "")
            lines.append(
                f"- {method.upper()} {path} - {summary} "
                f"[security: {sec}]"
            )
            if sec == [] or sec == [{}]:
                lines.append(
                    f"  Endpoint {method.upper()} {path} explicitly disables "
                    f"authentication with an empty security array."
                )

    lines.append("\n## API Data Handling and Schemas")
    schemas = comps.get("schemas", {}) or {}
    lines.append(f"The specification defines {len(schemas)} schemas.")
    for name, schema in list(schemas.items())[:60]:
        props = (schema or {}).get("properties", {}) or {}
        if props:
            lines.append(f"- Schema {name}: fields {', '.join(list(props)[:15])}")
    return "\n".join(lines)


def _render_generic(data, prefix: str = "", depth: int = 0) -> str:
    if depth > 4:
        return ""
    lines: List[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                nested = _render_generic(v, key, depth + 1)
                if nested:
                    lines.append(nested)
            else:
                lines.append(f"- {key}: {v}")
    elif isinstance(data, list):
        for i, item in enumerate(data[:40]):
            key = f"{prefix}[{i}]"
            if isinstance(item, (dict, list)):
                nested = _render_generic(item, key, depth + 1)
                if nested:
                    lines.append(nested)
            else:
                lines.append(f"- {key}: {item}")
    return "\n".join(lines)


def read_document(path: str | Path) -> str:
    """Read any supported document into a single markdown-ish string."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Document not found: {p}")
    suffix = p.suffix.lower()
    if suffix in {".md", ".markdown", ".txt", ".text", ""}:
        return _read_text_file(p)
    if suffix == ".docx":
        return _read_docx(p)
    if suffix == ".pdf":
        return _read_pdf(p)
    if suffix in {".yaml", ".yml", ".json"}:
        return _read_structured(p)
    raise ValueError(
        f"Unsupported file type '{suffix}'. Supported: "
        f"{', '.join(sorted(SUPPORTED_SUFFIXES))}"
    )


# ==========================================================================
# Section splitting
# ==========================================================================
_MD_HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_NUMBERED_HEADING = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+([A-Z][^\n]{2,80})$")
_UNDERLINE_HEADING = re.compile(r"^([=\-]{3,})\s*$")


def split_sections(text: str, source_file: str = "") -> List[Section]:
    """Split raw document text into headed sections.

    Recognises markdown ATX headings, setext underlines, and numbered
    headings ("3.2 Access Layer") which are ubiquitous in real HLD/LLD
    documents exported from Word.
    """
    lines = text.splitlines()
    raw: List[Tuple[str, int, List[str]]] = []
    # If the document turns out to have no headings at all, this stays as the
    # only section label - so name it for the common case (a pasted design)
    # rather than for the rare one (text before the first heading).
    current_heading = "Design Document"
    current_level = 1
    buffer: List[str] = []
    saw_heading = False

    def flush() -> None:
        label = current_heading
        if not saw_heading and label == "Design Document":
            label = "Design Document"
        elif not raw and label == "Design Document":
            label = "Document Preamble"
        raw.append((label, current_level, buffer.copy()))
        buffer.clear()

    i = 0
    while i < len(lines):
        line = lines[i]

        md = _MD_HEADING.match(line)
        if md:
            flush()
            saw_heading = True
            current_level = len(md.group(1))
            current_heading = md.group(2).strip()
            i += 1
            continue

        # Setext: a heading line followed by === or ---
        if i + 1 < len(lines) and _UNDERLINE_HEADING.match(lines[i + 1] or ""):
            candidate = line.strip()
            if candidate and len(candidate) < 100:
                flush()
                saw_heading = True
                current_level = 1 if lines[i + 1].startswith("=") else 2
                current_heading = candidate
                i += 2
                continue

        num = _NUMBERED_HEADING.match(line.strip())
        if num and len(line.strip()) < 90:
            flush()
            saw_heading = True
            current_level = min(num.group(1).count(".") + 1, 6)
            current_heading = line.strip()
            i += 1
            continue

        buffer.append(line)
        i += 1

    flush()

    sections: List[Section] = []
    index = 0
    for heading, level, body_lines in raw:
        body = "\n".join(body_lines).strip()
        if len(body.split()) < MIN_SECTION_WORDS:
            # Heading-only container (e.g. "## 3. Network Design" followed
            # immediately by "### 3.1"). Skip it; its children carry content.
            continue
        for part_heading, part_body in _split_oversized(heading, body):
            domain, topic, conf, secondary = classify_section(part_heading, part_body)
            sections.append(
                Section(
                    index=index,
                    heading=part_heading,
                    body=part_body,
                    level=level,
                    domain=domain,
                    topic=topic,
                    topic_confidence=conf,
                    secondary_topics=secondary,
                    source_file=source_file,
                )
            )
            index += 1

    if not sections and text.strip():
        # Unstructured paste with no headings at all - treat the whole blob
        # as one section rather than returning nothing.
        domain, topic, conf, secondary = classify_section("Design Document", text)
        sections.append(
            Section(0, "Design Document", text.strip(), 1, domain, topic,
                    conf, secondary, source_file)
        )

    return sections


def _split_oversized(heading: str, body: str) -> List[Tuple[str, str]]:
    """Break a very long section into paragraph-aligned parts.

    A 3000-word section produces one embedding that means nothing in
    particular. Splitting keeps each retrieval query focused.
    """
    words = body.split()
    if len(words) <= MAX_SECTION_WORDS:
        return [(heading, body)]

    paragraphs = [p for p in re.split(r"\n\s*\n", body) if p.strip()]
    parts: List[Tuple[str, str]] = []
    chunk: List[str] = []
    count = 0
    part_no = 1

    for para in paragraphs:
        pw = len(para.split())
        if count + pw > MAX_SECTION_WORDS and chunk:
            parts.append((f"{heading} (part {part_no})", "\n\n".join(chunk)))
            part_no += 1
            chunk, count = [], 0
        chunk.append(para)
        count += pw

    if chunk:
        label = f"{heading} (part {part_no})" if part_no > 1 else heading
        parts.append((label, "\n\n".join(chunk)))
    return parts


# ==========================================================================
# Public entry points
# ==========================================================================
def parse_document(path: str | Path) -> List[Section]:
    """Read a file from disk and return classified sections."""
    p = Path(path)
    return split_sections(read_document(p), source_file=p.name)


def parse_text(text: str, source_name: str = "pasted-input") -> List[Section]:
    """Classify sections from raw pasted text."""
    return split_sections(text, source_file=source_name)


def summarise_sections(sections: List[Section]) -> Dict[str, int]:
    """Count sections per domain - shown in the UI before a review starts."""
    counts: Dict[str, int] = {}
    for s in sections:
        counts[s.domain] = counts.get(s.domain, 0) + 1
    return counts


def filter_sections(sections: List[Section], enabled_domains: List[str],
                    include_general: bool = False) -> List[Section]:
    """Keep only sections belonging to the enabled review domains."""
    allowed = set(enabled_domains)
    if include_general:
        allowed.add("general")
    return [s for s in sections if s.domain in allowed]
