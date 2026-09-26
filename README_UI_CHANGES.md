# UI changes: Archeo redesign (26 Sep 2026)

The Streamlit UI was redesigned to look like a product rather than a prototype.
Only the presentation layer changed. `src/` is untouched, apart from the
earlier restore of `ReviewAgent.get_layer1_findings`.

## Files

| File | Change |
|---|---|
| `app.py` | New header, stepper, intake, progress panel and results dashboard |
| `assets/archeo.css` | New design system (light theme). The only stylesheet loaded |
| `.streamlit/config.toml` | Light theme, indigo `#4A5FD4`, 10 MB upload limit, minimal toolbar |
| `assets/theme.css`, `refine.css`, `enterprise.css` | Kept for reference, no longer loaded |

Revert: change `archeo.css` back to another file in `load_custom_css()`.

## Decisions on the brief's open questions

| Question | Choice |
|---|---|
| Product name | Archeo |
| Primary colour | Indigo `#4A5FD4` (one accent only) |
| Dark mode | Light is primary. The earlier dark theme is `assets/enterprise.css` if wanted later |
| Mobile | Responsive: cards stack, the stepper wraps to 2×2, bars shrink |
| Export | Markdown report, JSON bundle and findings CSV. PDF not yet |

## Screens

1. **Header**: Archeo mark, tagline, Ollama status (connected / models missing / offline), and a
   `Model · Verifier · Judge` line. Judge comes from the latest scored golden run.
2. **Stepper**: Intake → Pre-flight → AI review → Report. Completed steps are ticked.
3. **Intake**: upload or paste, with a document card showing section counts per domain.
4. **Pre-flight checkpoint**: KPI cards and rule findings with severity badges. Kept because it is a real trust-boundary step.
5. **Progress panel** (during a review): Parse → Rules → Standards retrieval and AI review
   (with the current section name) → Cross-domain → Verifier → Risk score and report. Shows the
   elapsed time per stage, an estimate of time remaining, and the model's share in GPU memory from `ollama ps`.
6. **Results dashboard**: 5 KPI cards, then Verification, Evidence and quality, and Risk score
   (overall score, RAG status, per-domain bars), then tabs: Findings, Report, Architecture flow,
   Audit trail, Section map, Export.
7. **Finding cards**: severity and verifier badges, confidence, issue, recommendation, a verbatim
   evidence quote in monospace, section and domain, source pills (origin and rule id), cited
   standard, and a Details expander (controls, standards source, model, fingerprint). Filter by
   severity, domain and verifier status, free-text search, and "Show more" (10 per page).

## Metrics the backend does not produce yet

Nothing on screen is invented. These panels are wired to real fields and show a
"not built yet" state until the backend step exists:

| UI element | Fills in when | Field it reads |
|---|---|---|
| Verification split, verifier badges and notes | A4 verifier sets it on each finding | `Finding.verifier_status`, `Finding.verifier_reason` |
| Semantic dedup count | A3 dedup reports it | (to add) |
| Judge agreement (kappa) | A6 calibration writes it to `scores.json` | `judge_kappa` |
| Per-finding model / prompt version | The agent records it | `Finding.model` (falls back to the configured LLM) |
| Multiple sources per finding | Merging keeps provenance | `Finding.sources` (falls back to `origin`) |
| Verifier model in header | Added to `config.yaml` | `models.verifier` |

## Items from the brief left out on purpose

- **Cancel button during a review.** Streamlit blocks while `agent.review()` runs, so a button
  can't interrupt it within the same run. It needs the review moved to a background thread.
- **GPU utilisation and temperature.** Ollama doesn't expose them. The panel shows the real
  VRAM share from `ollama ps` instead. `nvidia-smi` could be added later.
- **`enableXsrfProtection = false`.** Turning off a security protection isn't needed here.
- **`showErrorDetails = false`.** Kept on for a local tool, so crashes like the earlier
  `get_layer1_findings` one are visible.

## Also fixed

- Document- and model-derived text is HTML-escaped before rendering (`esc()`). This closes the
  HTML-injection issue from the design review.
- Emoji removed from headings, tabs and buttons.
