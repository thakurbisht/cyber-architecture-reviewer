# Archeo — Cyber Architecture Reviewer

An agentic AI assistant for security architects. It reviews **network,
application, cyber and cloud architecture designs** against your own
standards, drafts a **data flow diagram** that an engineer corrects and
approves, and runs a **STRIDE / MAESTRO threat model** on the approved DFD.
Every finding cites the text or standard clause it rests on.

Runs entirely on your machine (Ollama). No cloud services, no API keys, no
data leaving the machine.

```
Design doc ─▶ pre-check ─▶ text review (rules + standards + local LLM) ─┐
          └─▶ draft DFD ─▶ 👤 engineer edits & approves ─▶ threat model ─┴─▶ triage ─▶ 👤 accept/dispute ─▶ report, Jira CSV
```

> **Status: research prototype.** Useful as a second pair of eyes and a DFD /
> threat-model accelerator; not a substitute for an architect's review. See
> [Measured quality](#measured-quality) for honest numbers.

---

## Why

Manual design review does not scale, produces inconsistent findings, and
happens without opening the standards documents it is supposed to enforce.

This tool does not outsource the judgement. It encodes the standards that
govern the judgement, so they are retrieved, applied and cited the same way
every time — and leaves the judgement calls to the architect.

It **reads and flags**. It does not approve, reject, or change anything.

---

## What it reviews

| Domain | Lens |
|---|---|
| **Network** | Topology, redundancy and failure domains, routing protection, segmentation, management plane |
| **Application** | Trust boundaries, authN/authZ enforcement, input handling, secrets, API abuse, supply chain |
| **Cyber / Security** | Implicit trust, identity and privileged access, cryptography and keys, detection coverage, recoverability |
| **Cloud & Data** | Tenancy separation, guardrails, workload permissions, classification and residency, data exposure |

Plus a **cross-domain consistency pass** — the class of defect that only
appears when the domains are read together. The application relies on network
segmentation for isolation; the network design has one flat segment. Each
document looks fine alone.

**Inputs:** `.md` `.txt` `.docx` `.pdf` `.yaml` `.json` (OpenAPI specs and IaC
definitions are flattened into reviewable prose), or pasted text. Tables are read;
**the diagrams in a `.docx` or `.pdf` are read too**, by a local vision model, into
the DFD you confirm (see *Diagrams* below).

---

## Quick start

Needs Python 3.12+, [Ollama](https://ollama.com), and ideally a GPU with
12 GB VRAM (tested on an RTX 3060 12 GB; CPU works but is slow).

```bash
# 1. Models (one time, ~10 GB)
ollama pull qwen2.5:14b          # reviewer, DFD extraction, threat model
ollama pull nomic-embed-text     # embeddings for the standards library
ollama pull gemma3:12b           # reads diagrams (vision), and the eval judge
# optional: ollama pull phi4:14b (verifier)

# 2. Dependencies (a fresh virtual environment is recommended)
python -m venv .venv && .venv/Scripts/activate      # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

# 3. Seed the knowledge base - ALWAYS check the chunk count it prints
python scripts/seed_kb.py

# 4. Run
streamlit run app.py                                    # browser UI
python scripts/review_cli.py samples/sample-campus-lan-lld.md   # CLI
pytest                                                  # ~290 offline tests, no Ollama needed
```

Try the shipped samples, or the 12 golden-set designs in `golden/docs/` (all
fictional companies with planted issues; answer keys in `golden/answers/`).

### Using the app

| Page | What you do |
|---|---|
| **Review** | Pick a **project** and **stage** (prelim design / final as-built), upload, pre-check, then **Step 3: draft and approve the DFD first**, then run the AI review — the threat model runs right after it on the approved DFD |
| **Review queue** | Findings and threats in **one list**, duplicates merged, rule-based first; select many rows and **accept / dispute / mark mitigated** at once |
| **DFD editor** | Correct the AI-drafted data flow diagram: drag components between trust zones, draw/delete flows, set protocol / auth / encryption, choose STRIDE / MAESTRO / both, then **approve** a version. Each element shows where it came from — text, diagram, both, or your own edit |
| **Threats** | Run or replay the threat model on the approved DFD; export mitigations as Jira CSV |
| **Prelim report** | The Stage 1 register for stakeholders: **ID, Domain, Threat, Risk, Risk Rating, Cyber Recommendation, Acceptance Criteria** — built from confirmed items, AI-drafted, editable, **Excel for Archer** (column names in `config.yaml` → `archer_export`) |
| **Copilot** | Ask questions about the review |
| **Report** | Report, audit trail and **sign-off** — the status stays *provisional* until an architect signs off |

Every upload is a content-addressed **version** of a project (`data/projects/`), so a
revised design never reopens the previous version's DFD, threats or decisions.

**Diagrams.** Upload a `.pdf` or `.docx` and Step 3 offers to read its diagrams
(`src/diagram.py`): embedded images, plus a page render when the diagram is vector
art, which is what Visio and draw.io export. A local vision model
(`config.yaml` → `models.vision`, default `gemma3:12b`, ~15s per diagram) reads
boxes, trust-zone bands, arrows and their labels into the DFD draft; classification
is deterministic Python, not the model. Where the diagram and the text disagree —
the prose says TLS 1.3, the arrow says "no TLS" — both are shown and neither is
overwritten. **A diagram fact never becomes a finding by itself**: it has no text to
ground an evidence quote against, so it goes into the draft DFD and you confirm it.

Measured against generated diagrams with known ground truth (gemma3:12b, flows scored
as the source→target pairs actually drawn):

| Diagram | Boxes P / R | Arrows P / R | Zones |
|---|---|---|---|
| Clean, 6–8 boxes | 100% / 100% | 71–100% / 80–100% | 100% |
| Cloud icons instead of boxes | 100% / 100% | 83% / 83% | 100% |
| Bent, Visio-style connectors | 100% / 100% | 71% / 83% | 100% |
| Downscaled / low resolution | 100% / 100% | 50% / 60% | 100% |
| **14 boxes** | 100% / 100% | **43%** / 82% | 100% |
| **24 boxes** | 100% / 100% | **31%** / 64% | 100% |

**Boxes are dependable; dense arrows are not.** Past about ten boxes the model stops
reading arrows and starts inventing plausible ones, so those flows are labelled
*unverified* and the DFD step warns you to check them. Output is stable: three runs of
the same diagram were byte-identical. Roughly 12–40s per diagram.

**No Ollama yet?** The deterministic layer runs standalone:

```bash
python scripts/review_cli.py samples/sample-payments-app-hld.md --rules-only
```

---

## What a review produces

```
Status: 🔴 RED  |  Risk score: 99.9/100  |  Findings: 18  |  Sections: 13
```

- **Executive summary** in board language — no protocol names, no acronyms
- **Overall RAG status** with the scoring arithmetic shown so anyone can recheck it
- **Top 3 priority actions** that must close before implementation
- **Findings table per domain** — severity · section · issue · standard reference · recommendation
- **Evidence appendix** — the quoted design text behind each finding, its provenance, and its control mapping
- **Review coverage** — sections analysed per domain, so you can see what was *not* reviewed
- **Audit bundle (JSON)** — every retrieval, tool call and decision in the run

A finding looks like this:

> **[CRITICAL] Access Layer** — ACC-F4-01 has two uplinks but both terminate on
> DIST-SW-A.
> *Reference:* Three-Tier LAN Architecture Standard §3.2 — uplinks must
> terminate on two different upstream devices. Two uplinks to the same device
> satisfy quantity but not diversity.
> *Recommendation:* Reroute one uplink from ACC-F4-01 to DIST-SW-B.

Specific, citable, and reflecting *your* standard rather than public guidance —
which is the whole point. No generic model produces that finding, because the
standard it enforces is yours.

---

## The two-layer design

**Layer 1 — deterministic rules.** 57 pattern rules (incl. 18 "senior reviewer" patterns in `src/rules_expert.py`) with severity, citation
and control mapping. Same input, byte-identical output, every run. SNMPv2c with
community string `public` is a CRITICAL finding every time — it must not depend
on whether the model felt thorough on this pass.

**Layer 2 — agent reasoning.** LangGraph state machine over the retrieved
standards. Handles what a regex cannot: contradictions, implications, whether a
stated availability target is achievable with the described topology. Layer 1
findings are fed in as prior context so the model spends its budget on the
subtle rather than re-reporting the obvious.

Layer 1 guarantees the floor. Layer 2 provides the ceiling. Layer 1 still runs
if the model is down.

---

## Measured quality

Measured on the 12-document golden set (92 planted issues, 45 "must not flag"
traps) with a calibrated local judge (judge-v2, held-out agreement 95%,
κ 0.83). Caveat: the answer keys and judge calibration were produced with AI
assistance, not yet by independent human architects, and all tuning used the
same 12 documents — treat these as indicative, not proven.

| Pipeline | Precision | Recall | Traps flagged | False positives per clean doc |
|---|---|---|---|---|
| Deterministic rules only (57 rules) | 76% | 37% | 11% | 0 |
| Full pipeline, qwen2.5:14b | 33% | 62% | 56% | 21 |

What that means: when a rule fires it is usually right, but rules catch few
issues; the model catches most issues but about two in three of its findings
are noise. That is why only rule-matched or verifier/human-confirmed findings
can turn a design RED, model findings are shown as candidates, and the DFD +
threat model path relies on an engineer confirming the facts first.

### HLD → LLD consistency

A separate check answers a question neither document's own review asks: the HLD
committed to a control, so did the detailed design implement it?
(`src/consistency.py`.) Commitments are extracted from the HLD by deterministic
pattern, then each one is checked against the LLD sections that speak to it, and
the model's quote is verified against the LLD text before the verdict is kept.

Measured on `golden/pairs/cp-01`, a fictional HLD/LLD pair with 7 broken
commitments and 6 the LLD is silent on:

| | |
|---|---|
| Commitments extracted from the HLD | 26 |
| Planted defects that reached the review queue | **12 / 13** |
| …with the exact verdict (contradicted vs missing) | 11 / 13 |
| Contradictions flagged on a control with no planted defect | **0** |
| Time | 78s (≈3s per commitment) |

The one miss is a compound commitment — "secrets are never held in
configuration files, images **or pipeline variables**" — where the LLD satisfies
the first half and the model stopped reading. **Caveat, and it is the same one
as above:** this is a single pair that was written here and tuned against. It
shows the mechanism works; it is not an independent accuracy measurement.

---

## Making it yours

The starter knowledge base ships with structured standards derived from public
frameworks (NIST SP 800-207 / 800-53, CIS, OWASP ASVS, ISO 27001 Annex A,
TOGAF/SABSA-aligned patterns). **They are a scaffold, not the product.**

The value appears when you seed your own standards. Read
[`knowledge_base/_templates/AUTHORING_GUIDE.md`](knowledge_base/_templates/AUTHORING_GUIDE.md)
— it is the highest-leverage document here.

The core idea is the **finding trigger sentence**:

```
❌  Ensure redundant uplinks are provided.

✅  FINDING TRIGGER: If two uplinks from the same device terminate on the
    same upstream device, flag as CRITICAL even though two uplinks exist.
    State explicitly that quantity is satisfied but diversity is not.
```

The first is an aspiration. The second gives a pattern to match, a severity to
apply, and the reasoning to reproduce.

Priority order for seeding: your reference architectures first, then your
standards rewritten with trigger sentences, then post-incident findings from
past reviews, and public frameworks last and abridged — the model already knows
those; their value here is citation, not knowledge.

```bash
cp knowledge_base/_templates/STANDARD_TEMPLATE.md knowledge_base/network/my-standard.md
# edit, then:
python scripts/seed_kb.py --domain network
```

---

## CI/CD gating

```bash
python scripts/review_cli.py designs/platform.md --fail-on CRITICAL
```

Exit 1 on a breach. Attach it to a pull request that changes a design document
and the build fails on a new CRITICAL finding, the same way it fails on a
broken test.

Compare against a previous run — the diff is by finding fingerprint, so wording
drift between runs is ignored and only genuine change surfaces:

```bash
python scripts/review_cli.py designs/platform.md --compare last-review.json
```

---

## Configuration

Everything behavioural lives in `config.yaml`: models, chunk size, `top_k`,
similarity floor, agent loop caps, severity weights, RAG thresholds, enabled
domains.

```yaml
agent:
  max_tool_iterations: 6          # the agent WILL loop without this
  max_searches_per_section: 3
scoring:
  weights: {CRITICAL: 40, HIGH: 15, MEDIUM: 5, LOW: 1}
  rag: {red_at_score: 40, amber_at_score: 12, critical_forces_red: true}
```

The RAG verdict is computed in Python, never asked of the model. A board-facing
status has to be reproducible and recomputable by hand from the findings table.

---

## Project layout

```
config.yaml                 all tuning in one place
app.py                      Streamlit UI (Review, Findings, Copilot, Report)
dfd_page.py                 DFD editor page (streamlit-flow / React Flow)
threats_page.py             Threats page
src/
  parser.py                 md/docx/pdf/OpenAPI ingestion, section splitting
  diagram.py                diagrams -> DFD draft (vision model + Python classification)
  guardrail.py              "is this a design document?" pre-check
  domains.py                domain + topic taxonomy, retrieval query building
  rules.py                  deterministic rules engine (Layer 1)
  completeness.py           gaps -> questions for the author
  retriever.py              ChromaDB, clause-aware chunking, index integrity
  llm.py                    model handles + tool schemas
  prompts.py                domain-specialised prompts
  agent.py                  LangGraph review state machine (Layer 2)
  verifier.py               optional second-model check of findings (off by default)
  triage.py                 findings vs questions, cross-section dedup
  report.py                 evidence-gated scoring, RAG, markdown + JSON export
  system_model.py           LLM extraction of components / zones / flows (draft DFD)
  dfd.py                    DFD model, canvas sync, approved versions
  threat_agent.py           STRIDE / MAESTRO threat model agent (LangGraph)
  feedback.py               accept / dispute log
  audit.py                  immutable reasoning trail
  models.py                 Finding, Section, ReviewResult
knowledge_base/             your standards, per domain, + authoring templates
golden/                     12 fictional designs, answer keys, spec
samples/                    three designs with planted violations + answer key
scripts/seed_kb.py          seed and verify the vector store
scripts/review_cli.py       CLI / CI entry point
scripts/eval_golden.py      golden-set run / score / calibrate / verify
scripts/feedback_report.py  which rules reviewers dispute most
docs/ARCHITECTURE_BLUEPRINT.md   full design, threat model, operating model
tests/                      offline tests - no Ollama, no ChromaDB needed
```

---

## Tests

```bash
pytest
```

About 190 tests in a few seconds, no model download and no vector store. A scripted
stub LLM exercises the whole review graph and the threat model agent — routing, the tool loop, every loop cap,
citation verification, model-failure recovery, and the tool-free report node.

The structural failure modes are all covered:

| Test | Catches |
|---|---|
| `test_report_node_uses_unbound_model` | The report node emitting JSON instead of prose |
| `test_loop_cap_stops_a_runaway_agent` | An agent that never calls `section_complete` |
| `test_duplicate_search_is_suppressed` | Circular re-searching of the same topic |
| `test_hallucinated_citation_is_marked_unverified` | Fabricated standard references |
| `test_model_failure_does_not_abort_the_review` | A mid-review Ollama outage |
| `test_empty_knowledge_base_produces_warning` | A silently failed seed |
| `test_rules_are_deterministic` | Layer 1 drifting between runs |
| `test_recovers_tool_call_emitted_as_json_text` | Small models emitting tool calls as text |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Findings are generic and cite nothing | Empty knowledge base | `python scripts/seed_kb.py --status`; if a domain shows 0 the seed failed |
| "seeded with embedding model X but config uses Y" | Embedding model changed | `python scripts/seed_kb.py --reset` |
| Seeding times out on large documents | CPU embedding | Seed smaller files first; the seeder already batches and retries |
| Report is raw JSON | Report node given a tool-bound model | Use `writer`, not `reviewer` (see `llm.py`) |
| Review takes very long | Loop caps too high for CPU inference | Lower `max_tool_iterations` and `max_searches_per_section` |
| "Ollama unreachable" | Server not running | `ollama serve` |
| `pip install` fails on Windows with "No such file or directory" deep inside `site-packages\streamlit` | Windows 260-character path limit | Create the venv in a short path (e.g. `C:\archeo\.venv`) or enable long paths in Windows |
| DFD editor page is blank | `streamlit-flow-component` missing | `pip install -r requirements.txt` |

---

## Stack

LangGraph · ChromaDB · Ollama (qwen2.5:14b, nomic-embed-text) · Streamlit ·
streamlit-flow (React Flow) · Python 3.12+ · pytest

Everything local. Everything auditable.

---

## Read next

- [`docs/ARCHITECTURE_BLUEPRINT.md`](docs/ARCHITECTURE_BLUEPRINT.md) — full
  design, agent graph, scoring model, threat model of the reviewer itself,
  operating model and roadmap
- [`knowledge_base/_templates/AUTHORING_GUIDE.md`](knowledge_base/_templates/AUTHORING_GUIDE.md)
  — how to write standards that actually produce findings
- [`samples/EXPECTED_FINDINGS.md`](samples/EXPECTED_FINDINGS.md) — the
  regression answer key

---

> This is not AI replacing the architect. It is AI enforcing the architect's
> standards, so the architect can spend their time on the judgement calls that
> actually require twenty years of experience.
