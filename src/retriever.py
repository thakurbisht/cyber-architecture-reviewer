"""Knowledge base: chunking, embedding, storage and retrieval.

Design decisions worth knowing about
------------------------------------
1. One ChromaDB collection per review domain. A network section never
   retrieves an OWASP clause by accident, and each domain's corpus can be
   re-seeded independently without rebuilding the whole index.

2. Clause-aware chunking. Standards are written as numbered clauses; a chunk
   that straddles §3.1 and §3.2 cites neither cleanly. The chunker splits on
   clause boundaries first and only falls back to word windows inside a long
   clause. Every chunk carries its clause id, so a finding can cite
   "Three-Tier LAN Standard §3.2" rather than "some document, somewhere".

3. The embedding model is fingerprinted into collection metadata at seed
   time and checked at query time. Mixing embedding models produces vectors
   in incompatible geometric spaces where similarity is meaningless - and it
   fails silently, returning plausible-looking garbage. This check turns a
   silent corruption into a loud error.

4. Embeddings are generated in small batches with retry and a per-batch
   timeout. Large corpora on CPU-only machines time out mid-batch and leave
   a corrupted index behind; batching plus verification prevents shipping a
   half-seeded KB.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .config import Config, load_config
from .models import RetrievedChunk

EMBED_BATCH = 16
EMBED_MAX_RETRIES = 3
EMBED_RETRY_SLEEP_S = 2.0


# ==========================================================================
# Chunking
# ==========================================================================
_CLAUSE_RE = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?P<clause>(?:§\s*)?\d+(?:\.\d+){0,3})\s*[.)\-:]?\s+(?P<title>\S.*)$"
)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")


@dataclass
class KBChunk:
    """One embeddable passage of a knowledge base document."""

    chunk_id: str
    text: str
    source: str
    domain: str
    clause: str
    heading: str
    ordinal: int

    def metadata(self) -> Dict[str, str | int]:
        return {
            "source": self.source,
            "domain": self.domain,
            "clause": self.clause,
            "heading": self.heading,
            "ordinal": self.ordinal,
        }


def _clause_label(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    raw = raw.lstrip("§").strip()
    return f"§{raw}" if raw else ""


def chunk_document(text: str, source: str, domain: str,
                   chunk_words: int = 220,
                   overlap_words: int = 40) -> List[KBChunk]:
    """Split a knowledge base document into clause-aligned chunks."""
    lines = text.splitlines()
    blocks: List[Tuple[str, str, List[str]]] = []   # (clause, heading, lines)
    clause, heading, buf = "", "Preamble", []

    for line in lines:
        h = _HEADING_RE.match(line)
        candidate = h.group(2).strip() if h else line.strip()
        c = _CLAUSE_RE.match(candidate) if (h or candidate) else None

        if h or (c and len(candidate) < 120):
            if buf:
                blocks.append((clause, heading, buf))
                buf = []
            if c:
                clause = _clause_label(c.group("clause"))
                heading = c.group("title").strip()
            else:
                clause = ""
                heading = candidate
            continue
        buf.append(line)

    if buf:
        blocks.append((clause, heading, buf))

    chunks: List[KBChunk] = []
    ordinal = 0
    for blk_clause, blk_heading, blk_lines in blocks:
        body = "\n".join(blk_lines).strip()
        if not body:
            continue
        for piece in _window(body, chunk_words, overlap_words):
            # Prefix every chunk with its own citation. This is deliberate:
            # the retrieved text the model reasons over then *contains* the
            # citation, which measurably reduces citation hallucination.
            header = f"[{source}{(' ' + blk_clause) if blk_clause else ''}] {blk_heading}"
            full = f"{header}\n{piece}"
            cid = hashlib.sha1(
                f"{domain}|{source}|{blk_clause}|{ordinal}|{piece[:80]}".encode()
            ).hexdigest()[:20]
            chunks.append(
                KBChunk(cid, full, source, domain, blk_clause, blk_heading, ordinal)
            )
            ordinal += 1
    return chunks


def _window(text: str, size: int, overlap: int) -> List[str]:
    words = text.split()
    if len(words) <= size:
        return [text.strip()] if text.strip() else []
    step = max(size - overlap, 1)
    out: List[str] = []
    for start in range(0, len(words), step):
        piece = " ".join(words[start:start + size])
        if piece.strip():
            out.append(piece)
        if start + size >= len(words):
            break
    return out


# ==========================================================================
# Embeddings
# ==========================================================================
class OllamaEmbedder:
    """Thin, retrying wrapper around Ollama's embedding endpoint."""

    def __init__(self, model: str, host: str, timeout_s: int = 300):
        self.model = model
        self.host = host
        self.timeout_s = timeout_s
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import ollama
            self._client = ollama.Client(host=self.host, timeout=self.timeout_s)
        return self._client

    def fingerprint(self) -> str:
        """Identity of this embedding space; stored with the collection."""
        return f"{self.model}"

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        """Embed a list of texts, batching and retrying on transient failure."""
        vectors: List[List[float]] = []
        for start in range(0, len(texts), EMBED_BATCH):
            batch = list(texts[start:start + EMBED_BATCH])
            vectors.extend(self._embed_batch(batch))
        return vectors

    def _embed_batch(self, batch: List[str]) -> List[List[float]]:
        last_error: Optional[Exception] = None
        for attempt in range(1, EMBED_MAX_RETRIES + 1):
            try:
                resp = self.client.embed(model=self.model, input=batch)
                embeddings = resp.get("embeddings") if isinstance(resp, dict) \
                    else getattr(resp, "embeddings", None)
                if not embeddings or len(embeddings) != len(batch):
                    raise RuntimeError(
                        f"Embedding response size mismatch: expected {len(batch)}, "
                        f"got {len(embeddings) if embeddings else 0}"
                    )
                return [list(e) for e in embeddings]
            except Exception as exc:  # noqa: BLE001 - retry any transport error
                last_error = exc
                if attempt < EMBED_MAX_RETRIES:
                    time.sleep(EMBED_RETRY_SLEEP_S * attempt)
        raise RuntimeError(
            f"Embedding failed after {EMBED_MAX_RETRIES} attempts using model "
            f"'{self.model}'. Is Ollama running at {self.host} and has the "
            f"model been pulled? Last error: {last_error}"
        )


# ==========================================================================
# Store
# ==========================================================================
class KnowledgeBase:
    """Per-domain ChromaDB collections with embedding-space safety checks."""

    def __init__(self, config: Optional[Config] = None,
                 embedder: Optional[OllamaEmbedder] = None):
        self.config = config or load_config()
        self.config.ensure_dirs()
        self.embedder = embedder or OllamaEmbedder(
            model=self.config.models["embedding"],
            host=self.config.models["ollama_host"],
            timeout_s=int(self.config.models.get("request_timeout_s", 300)),
        )
        self._client = None
        self._collections: Dict[str, object] = {}

    # -- chroma plumbing --------------------------------------------------
    @property
    def client(self):
        if self._client is None:
            import chromadb
            from chromadb.config import Settings
            self._client = chromadb.PersistentClient(
                path=str(self.config.chroma_dir),
                settings=Settings(anonymized_telemetry=False, allow_reset=True),
            )
        return self._client

    def collection_name(self, domain: str) -> str:
        prefix = self.config.retrieval.get("collection_prefix", "car")
        return f"{prefix}_{domain}"

    def collection(self, domain: str, create: bool = True):
        if domain in self._collections:
            return self._collections[domain]
        name = self.collection_name(domain)
        if create:
            col = self.client.get_or_create_collection(
                name=name,
                metadata={
                    "hnsw:space": "cosine",
                    "embedding_model": self.embedder.fingerprint(),
                    "domain": domain,
                },
            )
        else:
            col = self.client.get_collection(name=name)
        self._collections[domain] = col
        return col

    # -- integrity --------------------------------------------------------
    def verify_embedding_space(self, domain: str) -> Optional[str]:
        """Return an error string if the collection was seeded with another model."""
        try:
            col = self.collection(domain, create=False)
        except Exception:
            return None
        meta = col.metadata or {}
        seeded_with = meta.get("embedding_model")
        current = self.embedder.fingerprint()
        if seeded_with and seeded_with != current:
            return (
                f"Collection '{self.collection_name(domain)}' was seeded with "
                f"embedding model '{seeded_with}' but the current config uses "
                f"'{current}'. Vectors from different models are not comparable - "
                f"retrieval results would be meaningless. Re-seed this domain "
                f"or restore the original embedding model in config.yaml."
            )
        return None

    def chunk_counts(self) -> Dict[str, int]:
        """Chunks per domain. A zero here means a seed failed silently."""
        counts: Dict[str, int] = {}
        for domain in ("network", "application", "security", "cloud_data"):
            try:
                col = self.collection(domain, create=False)
                counts[domain] = col.count()
            except Exception:
                counts[domain] = 0
        return counts

    def total_chunks(self) -> int:
        return sum(self.chunk_counts().values())

    def status(self) -> Dict[str, object]:
        counts = self.chunk_counts()
        warnings: List[str] = []
        for domain in counts:
            err = self.verify_embedding_space(domain)
            if err:
                warnings.append(err)
        empty = [d for d, c in counts.items() if c == 0]
        if empty:
            warnings.append(
                "No knowledge base chunks for: " + ", ".join(empty) +
                ". Reviews in those domains will fall back to the model's "
                "parametric memory and produce generic, uncitable findings. "
                "Run: python scripts/seed_kb.py --domain <name>"
            )
        return {
            "counts": counts,
            "total": sum(counts.values()),
            "embedding_model": self.embedder.fingerprint(),
            "persist_dir": str(self.config.chroma_dir),
            "warnings": warnings,
        }

    # -- seeding ----------------------------------------------------------
    def reset_domain(self, domain: str) -> None:
        name = self.collection_name(domain)
        try:
            self.client.delete_collection(name)
        except Exception:
            pass
        self._collections.pop(domain, None)

    def add_chunks(self, domain: str, chunks: List[KBChunk],
                   progress=None) -> int:
        """Embed and store chunks. Returns the number actually written."""
        if not chunks:
            return 0
        col = self.collection(domain)
        written = 0
        for start in range(0, len(chunks), EMBED_BATCH):
            batch = chunks[start:start + EMBED_BATCH]
            vectors = self.embedder.embed([c.text for c in batch])
            col.add(
                ids=[c.chunk_id for c in batch],
                documents=[c.text for c in batch],
                embeddings=vectors,
                metadatas=[c.metadata() for c in batch],
            )
            written += len(batch)
            if progress:
                progress(written, len(chunks))
        return written

    def seed_file(self, path: Path, domain: str, progress=None) -> int:
        text = path.read_text(encoding="utf-8", errors="replace")
        chunks = chunk_document(
            text,
            source=path.name,
            domain=domain,
            chunk_words=int(self.config.retrieval["chunk_words"]),
            overlap_words=int(self.config.retrieval["chunk_overlap_words"]),
        )
        return self.add_chunks(domain, chunks, progress=progress)

    # -- retrieval --------------------------------------------------------
    def search(self, query: str, domain: str, top_k: Optional[int] = None,
               extra_domains: Optional[Sequence[str]] = None
               ) -> List[RetrievedChunk]:
        """Semantic search within a domain (optionally spanning others)."""
        k = top_k or int(self.config.retrieval["top_k"])
        floor = float(self.config.retrieval.get("min_similarity", 0.0))
        domains = [domain] + [d for d in (extra_domains or []) if d != domain]

        # CRITICAL: Verify embedding model matches before querying.
        # Mismatched models produce vectors in incompatible spaces where
        # similarity is meaningless and fails silently.
        for d in domains:
            error = self.verify_embedding_space(d)
            if error:
                raise RuntimeError(
                    f"EMBEDDING MODEL MISMATCH in domain '{d}': {error}\n"
                    f"This would produce meaningless retrieval results. "
                    f"Aborting search to prevent silent corruption."
                )

        try:
            qvec = self.embedder.embed([query])[0]
        except Exception as exc:
            raise RuntimeError(f"Query embedding failed: {exc}") from exc

        results: List[RetrievedChunk] = []
        for d in domains:
            try:
                col = self.collection(d, create=False)
            except Exception:
                continue
            if col.count() == 0:
                continue
            try:
                res = col.query(
                    query_embeddings=[qvec],
                    n_results=min(k, col.count()),
                    include=["documents", "metadatas", "distances"],
                )
            except Exception:
                continue

            docs = (res.get("documents") or [[]])[0]
            metas = (res.get("metadatas") or [[]])[0]
            dists = (res.get("distances") or [[]])[0]
            ids = (res.get("ids") or [[]])[0]

            for i, doc in enumerate(docs):
                meta = metas[i] if i < len(metas) else {}
                dist = dists[i] if i < len(dists) else 1.0
                similarity = max(0.0, 1.0 - float(dist))  # cosine distance
                if similarity < floor:
                    continue
                results.append(
                    RetrievedChunk(
                        chunk_id=ids[i] if i < len(ids) else f"{d}-{i}",
                        text=doc,
                        source=str(meta.get("source", "unknown")),
                        domain=str(meta.get("domain", d)),
                        clause=str(meta.get("clause", "")),
                        similarity=round(similarity, 4),
                    )
                )

        results.sort(key=lambda c: c.similarity, reverse=True)
        return results[:k]


# ==========================================================================
# Seeding driver
# ==========================================================================
def discover_kb_files(config: Config,
                      domains: Optional[Sequence[str]] = None
                      ) -> Dict[str, List[Path]]:
    """Map domain -> knowledge base files, skipping templates."""
    root = config.kb_root
    folder_map: Dict[str, str] = config.knowledge_base["folder_map"]
    wanted = set(domains) if domains else set(folder_map.values())
    out: Dict[str, List[Path]] = {}

    for folder, domain in folder_map.items():
        if domain not in wanted:
            continue
        d = root / folder
        if not d.exists():
            continue
        files = sorted(
            p for p in d.rglob("*")
            if p.is_file()
            and p.suffix.lower() in {".md", ".markdown", ".txt"}
            and "_templates" not in p.parts
            and not p.name.startswith("_")
        )
        if files:
            out[domain] = files
    return out


def seed_knowledge_base(config: Optional[Config] = None,
                        domains: Optional[Sequence[str]] = None,
                        reset: bool = False,
                        log=print) -> Dict[str, int]:
    """Seed the KB and verify the result.

    Seeds smallest files first. Large documents are the ones that time out on
    CPU-only machines, and a partial large-file failure should not prevent the
    small high-value standards from being available.
    """
    cfg = config or load_config()
    kb = KnowledgeBase(cfg)
    files_by_domain = discover_kb_files(cfg, domains)

    if not files_by_domain:
        log("No knowledge base files found. Check knowledge_base/ contents.")
        return {}

    written: Dict[str, int] = {}
    for domain, files in files_by_domain.items():
        if reset:
            log(f"[{domain}] resetting collection")
            kb.reset_domain(domain)
        files = sorted(files, key=lambda p: p.stat().st_size)
        total = 0
        for path in files:
            try:
                count = kb.seed_file(path, domain)
                total += count
                log(f"[{domain}] {path.name}: {count} chunks")
            except Exception as exc:  # noqa: BLE001
                log(f"[{domain}] {path.name}: FAILED - {exc}")
        written[domain] = total

    # Post-seed verification. The article's hardest bug was a silent seed
    # failure producing an empty index that only surfaced as bad reviews.
    log("\nVerifying...")
    for domain, count in kb.chunk_counts().items():
        if domain in files_by_domain:
            state = "OK" if count > 0 else "EMPTY - SEED FAILED"
            log(f"  {domain}: {count} chunks stored [{state}]")
    return written
