# Option A (fully local) — Plan

Target: make the existing pipeline's findings accurate and measurable, with
everything running on one machine with a 12–16 GB GPU through Ollama.
Option B (system-model-first) comes after, reusing everything built here.

## 1. Local model lineup (three different families)

| Role | Ollama tag | Family | Approx. size | Why this one |
|---|---|---|---|---|
| Reviewer agent (tool calling) | `qwen3:14b` | Qwen (Alibaba) | ~9.3 GB | Supports tool calling in Ollama; much stronger reasoning and JSON than `llama3.1:8b` |
| Runtime verifier, 16 GB card | `gpt-oss:20b` | OpenAI open-weight | ~14 GB | Reasoning model, different family from the reviewer |
| Runtime verifier, 12 GB card | `phi4:14b` | Microsoft | ~9.1 GB | Fits 12 GB; different family from the reviewer |
| Offline eval judge | `gemma3:12b` | Google | ~8.1 GB | Third family, so the judge never grades its own family's work |
| Embeddings (dedup, doc search) | `nomic-embed-text` (current) vs `bge-m3` | — | 0.3 / 1.2 GB | Keep current; compare on the golden set |

Rules:
- Finders ≠ verifier ≠ eval judge (different families) — avoids correlated blind
  spots and self-preference when grading.
- The verifier and judge only return JSON (Ollama `format` with a JSON schema),
  so they don't need tool-calling support.
- These are starting picks, not final. After the baseline, run a small bake-off
  (e.g. reviewer `qwen3:14b` vs `gemma3:12b`, verifier `gpt-oss:20b` vs `phi4:14b`)
  on the golden set and keep the winners. Pin exact tags in config.

Pull (PowerShell):
```
ollama pull qwen3:14b
ollama pull gemma3:12b
ollama pull gpt-oss:20b      # 16 GB card
ollama pull phi4:14b         # 12 GB card (or both, for the bake-off)
ollama pull bge-m3           # optional, for the embedding comparison
```

Ollama settings for a 12–16 GB card (set as Windows user environment
variables, then restart Ollama):
```
OLLAMA_FLASH_ATTENTION=1       # less memory for long prompts
OLLAMA_KV_CACHE_TYPE=q8_0      # roughly halves context memory
OLLAMA_MAX_LOADED_MODELS=1     # one model in VRAM at a time
OLLAMA_NUM_PARALLEL=1
```
The pipeline will set `num_ctx` = 8192 per request and run stages grouped by
model (all reviewer calls, then all verifier calls) so Ollama isn't swapping
models on every call. Check the GPU/CPU split with `ollama ps` — anything not
"100% GPU" will be slow.

## 2. Work breakdown (measure after every step)

| Step | What changes | Done when |
|---|---|---|
| A0 Eval harness v2 | Reads `golden/answers/*.json`; local judge (`gemma3:12b`) matches predicted↔expected findings by meaning, after an embedding pre-filter; reports precision/recall per origin (rules/skills/agent/correlation), per severity and per type, trap-violation rate, evidence-validity rate, spread over 3 runs. Existing 3 samples converted to the new format. | Baseline numbers for the current pipeline (`llama3.1:8b`) on all 15 documents |
| A0b Leak check | Confirm the parser strips the HTML-comment answer keys in the 3 original samples. If it doesn't, the reviewer has been reading the answers and the old F1 of 0.48 is invalid. | Checked, fixed if needed |
| A1 Reviewer model | `llama3.1:8b` → `qwen3:14b` (bake-off vs `gemma3:12b`). | Measured |
| A2 Evidence | `Finding` gains `evidence_quote`, `evidence_section`, `finding_type` (defect/gap), `confidence`, `sources`, `model`, `prompt_version`. Prompts require a verbatim quote. Code checks the quote exists (normalised whitespace/quotes); findings without valid evidence are dropped or marked unverified. Rules/skills findings get their matched text as evidence. | 100% of reported findings carry a valid quote |
| A3 Semantic dedup | Embed domain + title + evidence; merge findings above a similarity threshold (tuned on the golden set); keep which sources agreed. | Duplicate rate measured and down |
| A4 Verifier | New stage after merge: for each finding, search the whole document for supporting or contradicting text, then the verifier model returns confirmed / refuted / needs_human, severity (rubric), defect/gap and a reason. HIGH/CRITICAL disagreements → needs_human. | Trap-violation rate and precision improve; recall drop ≤ 0.05 |
| A5 Risk score | From verified findings only; confidence-weighted; per-domain caps; RED/AMBER/GREEN thresholds calibrated on the golden set. | Clean docs no longer score 100/RED |
| A6 Judge calibration | Export ~150–200 predicted↔expected pairs to a labelling sheet; you label match / no match; compute agreement (Cohen's kappa). | kappa ≥ 0.7, otherwise fix the judge prompt/model before trusting metrics |

Option A targets (production targets need Option B too):
- Valid evidence quotes on 100% of findings.
- must_not_flag traps raised in < 15% of cases.
- At most 2 false positives per clean document.
- The injection document: findings not suppressed.
- Precision clearly above baseline, recall not more than 0.05 below it.

## 3. Test set

`golden/` holds batch 1: 12 synthetic documents (9 flawed, 2 clean, 1 prompt
injection), 92 expected findings (25 need cross-section reasoning), 45 traps.
They were written and independently audited by Claude models; please skim two
or three answer keys yourself. Batch 2 should add 3–5 real, anonymised documents
from your work, which I'll help label, plus more gap-type findings (currently
16 gap vs 76 defect).

## 4. First session on the linked computer

1. Read the repo; create branch `feat/option-a-accuracy` so every change is reversible.
2. Copy `golden/` into the repo (`eval/golden/`).
3. A0b leak check, then build A0 (eval harness v2 + judge).
4. You run the baseline in PowerShell (Ollama runs on Windows; the shell I use
   on your computer may not reach it) — I'll give the exact command.
