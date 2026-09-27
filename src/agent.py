"""The agentic core: a LangGraph state machine over the review.

Graph shape
-----------

        START
          |
      [triage]                 deterministic rules, section queue, KB health
          |
      [retrieve] <-------------------------------+
          |                                      |
      [review]  --- tool calls? --> [act] -------+   (bounded loop)
          |                            |
          | no tool calls / done       | section_complete
          v                            v
      [advance] ----- more sections? --+
          |
          | no more
          v
     [correlate]                cross-domain consistency pass
          |
       [report]                 TOOL-FREE model: prose only
          |
         END

Why the loop is bounded
-----------------------
The agent is thorough to the point of being circular: left alone it will
re-search the same topic until it feels satisfied, which on a CPU-only box
means a ten-minute section. Three limits are enforced, and each one is
recorded in the audit trail when it bites, so a truncated review is visible
rather than silent:

  max_tool_iterations      total model turns per section
  max_searches_per_section stops repeated retrieval on the same topic
  duplicate-query guard    an identical search string is answered from cache

Why report_node uses a different model handle
---------------------------------------------
report_node invokes the *unbound* model. Give it the tool-bound handle and
it sees a callable in context and emits a structured tool call - raw JSON -
instead of writing prose. The reasoning is done by the time report_node
runs. All it needs to do is write. See llm.py.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from typing_extensions import TypedDict

from .audit import AuditTrail
from .completeness import check_document_completeness, completeness_summary
from .triage import triage
from .config import Config, load_config
from .domains import DOMAIN_LABELS, build_retrieval_query
from .llm import build_models
from .models import (
    Finding,
    ORIGIN_AGENT,
    ORIGIN_CORRELATION,
    RetrievedChunk,
    ReviewResult,
    Section,
    dedupe_findings,
    normalise_severity,
    sort_findings,
)
from .parser import filter_sections
from .prompts import (
    CORRELATION_SYSTEM,
    build_correlation_user,
    build_reviewer_system,
    build_section_user,
)
from .retriever import KnowledgeBase
from .threat_model import build_threat_model

# TIER 1 Hardening: Skills integration
try:
    from .skill_index import SkillIndex, SkillRanking
    from .skill_executor_v2 import SkillExecutor, SkillFinding
    from .skill_cache import SkillMetadataCache
    SKILLS_ENABLED = True
except ImportError:
    SKILLS_ENABLED = False


# ==========================================================================
# State
# ==========================================================================
class ReviewState(TypedDict, total=False):
    document_name: str
    sections: List[Section]
    enabled_domains: List[str]

    cursor: int
    messages: List[Any]
    current_chunks: List[RetrievedChunk]
    section_searches: int
    tool_iterations: int
    section_done: bool
    seen_queries: List[str]

    findings: List[Finding]
    warnings: List[str]
    kb_chunk_count: int

    # TIER 1 Hardening: Skill execution state
    selected_skills: List[Any] = []      # SkillMetadata objects
    skill_rankings: List[SkillRanking] = []
    skill_findings: List[Any] = []       # SkillFinding objects

    executive_summary: str
    assurance_opinion: str


# ==========================================================================
# Agent
# ==========================================================================
@dataclass
class ReviewAgent:
    """Orchestrates a full multi-domain architecture review."""

    config: Config = None            # type: ignore[assignment]
    kb: Optional[KnowledgeBase] = None
    llm: Optional[Any] = None        # inject a stub in tests
    progress = None                  # callable(stage: str, pct: float)
    verifier_llm = None              # A4 verifier model; injectable in tests

    def __post_init__(self) -> None:
        self.config = self.config or load_config()
        self.kb = self.kb or KnowledgeBase(self.config)
        self.reviewer, self.writer = build_models(self.config, self.llm)
        self.audit = AuditTrail()
        self._graph = None

        # TIER 1 Hardening: Initialize skills if enabled
        self.skill_index = None
        self.skill_cache = None
        if SKILLS_ENABLED and self.config.agent.get("enable_skills", True):
            try:
                skills_dir = self.config.agent.get("skills_dir", "/tmp/work/skills")
                cache_dir = self.config.agent.get("cache_dir", "/tmp/work/cache")
                self.skill_cache = SkillMetadataCache(cache_dir)
                self.skill_index = SkillIndex(skills_dir)
                print(f"[Skills] Loaded {len(self.skill_index.skills)} skills")
            except Exception as e:
                print(f"[Skills] Error initializing: {e}")
                self.skill_index = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def get_layer1_findings(self, sections: List[Section],
                            enabled_domains: Optional[Sequence[str]] = None) -> Tuple[List[Finding], Dict[str, int]]:
        """Run deterministic rules (Layer 1) without the agent.

        Returns (findings, kb_counts) for the pre-flight checkpoint UI.
        """
        from .rules import run_rules

        domains = list(enabled_domains or self.config.enabled_domains)
        rule_findings: List[Finding] = []
        if self.config.agent.get("enable_rules_engine", True):
            rule_findings = run_rules(sections, domains)

        kb_counts = self.kb.status().get("counts", {})
        return rule_findings, kb_counts

    def review(self, sections: List[Section], document_name: str,
               enabled_domains: Optional[Sequence[str]] = None) -> ReviewResult:
        from .report import build_report

        started = time.time()
        domains = list(enabled_domains or self.config.enabled_domains)
        self.audit = AuditTrail()

        state: ReviewState = {
            "document_name": document_name,
            "sections": sections,
            "enabled_domains": domains,
            "cursor": 0,
            "messages": [],
            "current_chunks": [],
            "section_searches": 0,
            "tool_iterations": 0,
            "section_done": False,
            "seen_queries": [],
            "findings": [],
            "warnings": [],
            "kb_chunk_count": 0,
            "selected_skills": [],
            "skill_rankings": [],
            "skill_findings": [],
        }

        graph = self._compiled_graph()
        # Recursion limit sized to the worst case: every section running the
        # full tool loop, plus the correlation and report nodes.
        max_iters = int(self.config.agent["max_tool_iterations"])
        limit = max(50, len(sections) * (max_iters * 2 + 4) + 20)
        final: ReviewState = graph.invoke(state, {"recursion_limit": limit})

        # Merge findings from all sources (rules, skills, agent)
        all_findings = final.get("findings", [])
        skill_findings = final.get("skill_findings", [])
        if skill_findings:
            all_findings.extend(skill_findings)

        result = ReviewResult(
            document_name=document_name,
            findings=sort_findings(dedupe_findings(all_findings)),
            sections=final.get("sections", sections),
            audit=self.audit.events,
            domains_reviewed=domains,
            kb_chunk_count=final.get("kb_chunk_count", 0),
            warnings=final.get("warnings", []),
        )

        # Findings vs Questions (src/triage.py): gaps, document-level notes
        # and vague output leave the findings list before the verifier, the
        # threat model and scoring see it. Kept on result.questions.
        result.findings, result.questions = triage(result.findings,
                                                   result.sections)

        # A4 verifier: whole-document check of every candidate finding,
        # before threat modeling and scoring so REFUTED findings neither
        # drive the risk score (A5) nor the threat model. Refuted findings
        # are kept on result.refuted_findings for review, not deleted.
        self._run_verifier(result)

        # Threat modeling runs on the FINAL, merged, deduplicated finding
        # set - deliberately after the skill/rules/agent/correlation merge
        # above, not as a graph node, so it sees every finding regardless
        # of which stage produced it (skill_execution_node's raw
        # SkillFinding objects aren't converted to base Finding until the
        # merge just above runs). It needs no LLM call - see
        # src/threat_model.py's module docstring for why that's deliberate.
        if self.config.agent.get("enable_threat_modeling", True):
            try:
                result.threat_model = build_threat_model(
                    document_name=document_name,
                    sections=result.sections,
                    findings=result.findings,
                    domains=domains,
                ).to_dict()
            except Exception as exc:  # noqa: BLE001
                self.audit.record("threat_model_error", error=str(exc))
                result.warnings = result.warnings + [
                    f"Threat modeling failed: {exc}"
                ]

        build_report(
            result,
            self.config,
            executive_summary=final.get("executive_summary", ""),
            assurance_opinion=final.get("assurance_opinion", ""),
        )
        result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.audit.record("review_complete",
                          findings=len(result.findings),
                          rag=result.rag_status,
                          elapsed_s=round(time.time() - started, 1))
        result.audit = self.audit.events
        return result

    def _run_verifier(self, result: ReviewResult) -> None:
        from .verifier import Verifier, build_verifier_llm, split_by_verdict

        if not result.findings or not self.config.agent.get("enable_verifier", False):
            return
        if self.verifier_llm is None:
            try:
                self.verifier_llm = build_verifier_llm(self.config)
            except Exception as exc:  # noqa: BLE001
                self.audit.record("verifier_error", error=str(exc)[:300])
        if self.verifier_llm is None:
            result.warnings = result.warnings + [
                "Verifier enabled but no models.verifier is configured; "
                "findings are unverified."
            ]
            return

        self._emit("Verifying findings", 0.9)
        Verifier(
            self.verifier_llm,
            batch_size=int(self.config.agent.get("verifier_batch_size", 6)),
            record=self.audit.record,
        ).verify(result.findings, result.sections)
        kept, refuted = split_by_verdict(result.findings)
        result.findings, result.refuted_findings = kept, refuted
        self.audit.record("verifier_complete", kept=len(kept), refuted=len(refuted))

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------
    def _compiled_graph(self):
        if self._graph is not None:
            return self._graph

        from langgraph.graph import END, START, StateGraph

        g = StateGraph(ReviewState)
        g.add_node("triage", self.triage_node)

        # TIER 1 Hardening: Add skill nodes if enabled
        if self.skill_index is not None:
            g.add_node("skill_discovery", self.skill_discovery_node)
            g.add_node("skill_execution", self.skill_execution_node)

        g.add_node("retrieve", self.retrieve_node)
        g.add_node("review", self.review_node)
        g.add_node("act", self.act_node)
        g.add_node("advance", self.advance_node)
        g.add_node("correlate", self.correlate_node)
        g.add_node("report", self.report_node)

        g.add_edge(START, "triage")

        # TIER 1 Hardening: Route through skill nodes if enabled
        if self.skill_index is not None:
            g.add_edge("triage", "skill_discovery")
            g.add_edge("skill_discovery", "skill_execution")
            g.add_edge("skill_execution", "retrieve")
        else:
            g.add_conditional_edges("triage", self._route_after_triage,
                                    {"retrieve": "retrieve", "correlate": "correlate"})

        g.add_edge("retrieve", "review")
        g.add_conditional_edges("review", self._route_after_review,
                                {"act": "act", "advance": "advance"})
        g.add_conditional_edges("act", self._route_after_act,
                                {"review": "review", "advance": "advance"})
        g.add_conditional_edges("advance", self._route_after_advance,
                                {"retrieve": "retrieve", "correlate": "correlate"})
        g.add_edge("correlate", "report")
        g.add_edge("report", END)

        self._graph = g.compile()
        return self._graph

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------
    def triage_node(self, state: ReviewState) -> Dict[str, Any]:
        """Deterministic pass + knowledge base health check."""
        from .rules import run_rules

        domains = state["enabled_domains"]
        sections = filter_sections(state["sections"], domains, include_general=False)
        cap = int(self.config.agent.get("max_sections", 40))
        warnings: List[str] = []

        if len(sections) > cap:
            warnings.append(
                f"Document produced {len(sections)} in-scope sections; only the "
                f"first {cap} were reviewed by the agent (agent.max_sections). "
                f"The deterministic rules engine still scanned all of them."
            )

        kb_status = self.kb.status()
        warnings.extend([str(w) for w in kb_status.get("warnings", [])])

        # Completeness runs before the rules engine on purpose. On a design
        # that never mentions encryption, the rules engine finds no encryption
        # defects - and "no findings" would be read as a pass. This layer says
        # what the document never addressed, so silence is not mistaken for
        # assurance. See completeness.py.
        completeness_findings: List[Finding] = []
        completeness = None
        if self.config.agent.get("enable_completeness_checks", True):
            completeness = check_document_completeness(state["sections"], domains)
            completeness_findings = completeness.findings
            if not completeness.reviewable:
                warnings.append(completeness_summary(completeness))

        rule_findings: List[Finding] = []
        if self.config.agent.get("enable_rules_engine", True):
            rule_findings = run_rules(state["sections"], domains)

        self.audit.record(
            "triage",
            document=state["document_name"],
            domains=domains,
            sections_total=len(state["sections"]),
            sections_in_scope=len(sections),
            rule_findings=len(rule_findings),
            completeness_findings=len(completeness_findings),
            completeness_coverage=(round(completeness.coverage, 3)
                                   if completeness else None),
            completeness_missing=(sorted(completeness.missing)
                                  if completeness else []),
            reviewable=(completeness.reviewable if completeness else True),
            kb_chunks=kb_status.get("total", 0),
            kb_counts=kb_status.get("counts", {}),
        )
        for f in completeness_findings:
            self.audit.record("completeness_finding", rule=f.rule_id,
                              severity=f.severity, section=f.section)
        for f in rule_findings:
            self.audit.record("rule_finding", rule=f.rule_id,
                              severity=f.severity, section=f.section)

        self._emit("Deterministic rules pass complete", 0.1)

        return {
            "sections": sections[:cap],
            "findings": completeness_findings + rule_findings,
            "warnings": warnings,
            "kb_chunk_count": int(kb_status.get("total", 0)),
            "cursor": 0,
        }

    def skill_discovery_node(self, state: ReviewState) -> Dict[str, Any]:
        """
        Discover and rank relevant skills based on document context.

        LAYER 2: Triage context â†’ SkillIndex ranking â†’ Top 15 skills
        """
        if self.skill_index is None:
            return {"selected_skills": [], "skill_rankings": []}

        try:
            # Build context from triage output
            context = {
                'primary_domain': state.get("enabled_domains", ["general"])[0],
                'document_name': state.get("document_name", "unknown"),
                'sections': state.get("sections", []),
            }

            # Find and rank relevant skills
            relevant_skills = self.skill_index.find_relevant(context)

            # Store top skills in state (limit to 15)
            selected = [r.skill for r in relevant_skills[:15]]

            self.audit.record(
                "skill_discovery",
                skills_found=len(selected),
                top_skills=[s.name for s in selected[:3]],
            )

            return {
                "selected_skills": selected,
                "skill_rankings": relevant_skills[:15],
            }
        except Exception as e:
            self.audit.record("skill_discovery_error", error=str(e))
            return {"selected_skills": [], "skill_rankings": []}

    def skill_execution_node(self, state: ReviewState) -> Dict[str, Any]:
        """
        Execute selected skills against document sections.

        LAYER 2.5: For each skill â†’ run executor on sections â†’ generate findings
        Output bounded at MAX_TOTAL_FINDINGS=500 per TIER 1 hardening.
        """
        if self.skill_index is None:
            return {"skill_findings": []}

        all_findings: List[Any] = []
        max_total_findings = 500

        try:
            # Process each selected skill
            for skill in state.get("selected_skills", []):
                if len(all_findings) >= max_total_findings:
                    break

                try:
                    executor = SkillExecutor(skill)
                    skill_findings = []

                    # Execute against sections (limit scope to cursor-forward)
                    for section in state.get("sections", [state.get("sections", [None])[0]])[:10]:
                        if section is None:
                            continue
                        if len(all_findings) >= max_total_findings:
                            break

                        try:
                            # Run skill on this section's body
                            section_text = section.body if hasattr(section, 'body') else str(section)
                            section_name = section.heading if hasattr(section, 'heading') else "unknown"

                            findings = executor.execute(section_text, section_name)
                            skill_findings.extend(findings)

                            # Stop if we hit the limit
                            if len(all_findings) + len(findings) >= max_total_findings:
                                skill_findings = skill_findings[:max_total_findings - len(all_findings)]
                                break
                        except Exception as e:
                            self.audit.record(
                                "skill_execution_section_error",
                                skill=skill.name,
                                section=section_name if hasattr(section, 'heading') else "unknown",
                                error=str(e)
                            )

                    # Deduplicate findings from this skill
                    if skill_findings:
                        unique_findings = list({f.id: f for f in skill_findings}.values())
                        all_findings.extend(unique_findings)

                    self.audit.record(
                        "skill_executed",
                        skill=skill.name,
                        findings=len(skill_findings),
                        total_so_far=len(all_findings),
                    )
                except Exception as e:
                    self.audit.record(
                        "skill_execution_error",
                        skill=skill.name,
                        error=str(e)
                    )

            # Cap at max_total_findings
            all_findings = all_findings[:max_total_findings]

            self.audit.record(
                "skill_execution_complete",
                total_findings=len(all_findings),
            )

            return {"skill_findings": all_findings}
        except Exception as e:
            self.audit.record("skill_execution_complete_error", error=str(e))
            return {"skill_findings": []}

    def retrieve_node(self, state: ReviewState) -> Dict[str, Any]:
        """Targeted retrieval for the section at the cursor."""
        section = state["sections"][state["cursor"]]
        query = build_retrieval_query(section.heading, section.topic, section.body)

        # Secondary topics pull from their own domains too - this is how a
        # section that is 70% network and 30% security gets both lenses.
        extra_domains: List[str] = []
        from .domains import TOPIC_BY_KEY
        for key in section.secondary_topics:
            t = TOPIC_BY_KEY.get(key)
            if t and t.domain != section.domain and t.domain in state["enabled_domains"]:
                extra_domains.append(t.domain)

        chunks: List[RetrievedChunk] = []
        try:
            chunks = self.kb.search(query, section.domain,
                                    extra_domains=list(dict.fromkeys(extra_domains)))
        except Exception as exc:  # noqa: BLE001
            self.audit.record("retrieval_error", section=section.heading,
                              error=str(exc))

        self.audit.record(
            "retrieve",
            section=section.heading,
            domain=section.domain,
            topic=section.topic,
            topic_confidence=section.topic_confidence,
            query=query[:300],
            extra_domains=extra_domains,
            chunks=[{"id": c.chunk_id, "cite": c.citation(),
                     "sim": c.similarity} for c in chunks],
        )

        prior = [f for f in state["findings"] if f.section == section.heading]
        system = build_reviewer_system(
            section.domain,
            int(self.config.agent["max_searches_per_section"]),
        )
        user = build_section_user(state["document_name"], section, chunks, prior)

        total = max(len(state["sections"]), 1)
        self._emit(f"Reviewing: {section.heading}",
                   0.1 + 0.7 * (state["cursor"] / total))

        return {
            "current_chunks": chunks,
            "messages": [("system", system), ("human", user)],
            "section_searches": 0,
            "tool_iterations": 0,
            "section_done": False,
            "seen_queries": [],
        }

    def review_node(self, state: ReviewState) -> Dict[str, Any]:
        """One reasoning turn of the tool-bound model."""
        section = state["sections"][state["cursor"]]
        try:
            response = self.reviewer.invoke(state["messages"])
        except Exception as exc:  # noqa: BLE001
            self.audit.record("model_error", section=section.heading, error=str(exc))
            return {
                "section_done": True,
                "warnings": state["warnings"] + [
                    f"Model call failed on section '{section.heading}': {exc}"
                ],
            }

        calls = _extract_tool_calls(response)
        self.audit.record(
            "model_turn",
            section=section.heading,
            iteration=state["tool_iterations"] + 1,
            tool_calls=[c["name"] for c in calls],
            text_preview=_message_text(response)[:200],
        )
        return {
            "messages": state["messages"] + [response],
            "tool_iterations": state["tool_iterations"] + 1,
        }

    def act_node(self, state: ReviewState) -> Dict[str, Any]:
        """Execute the model's tool calls and feed results back."""
        section = state["sections"][state["cursor"]]
        last = state["messages"][-1]
        calls = _extract_tool_calls(last)

        updates = self._execute_tool_calls(
            calls,
            section=section,
            default_domain=section.domain,
            searches_used=state["section_searches"],
            seen_queries=list(state["seen_queries"]),
            origin=ORIGIN_AGENT,
            chunks=state["current_chunks"],
        )

        return {
            "messages": state["messages"] + updates["tool_messages"],
            "findings": state["findings"] + updates["findings"],
            "section_searches": updates["searches_used"],
            "seen_queries": updates["seen_queries"],
            "section_done": state["section_done"] or updates["done"],
            "current_chunks": state["current_chunks"] + updates["new_chunks"],
        }

    def advance_node(self, state: ReviewState) -> Dict[str, Any]:
        """Move to the next section."""
        section = state["sections"][state["cursor"]]
        section_findings = [
            f for f in state["findings"]
            if f.section == section.heading and f.origin == ORIGIN_AGENT
        ]
        self.audit.record("section_complete", section=section.heading,
                          agent_findings=len(section_findings),
                          tool_iterations=state["tool_iterations"])
        return {"cursor": state["cursor"] + 1}

    def correlate_node(self, state: ReviewState) -> Dict[str, Any]:
        """Cross-domain consistency pass.

        Runs its own bounded loop rather than reusing the graph loop, because
        it operates on the whole document rather than a section cursor. It
        shares the same tool executor, so tool semantics stay identical.
        """
        if not self.config.agent.get("enable_cross_domain_pass", True):
            return {}
        domains_present = {s.domain for s in state["sections"]}
        if len(domains_present) < 2:
            self.audit.record("correlation_skipped",
                              reason="fewer than two domains in scope")
            return {}

        self._emit("Cross-domain consistency pass", 0.85)

        messages: List[Any] = [
            ("system", CORRELATION_SYSTEM),
            ("human", build_correlation_user(state["document_name"],
                                             state["sections"],
                                             state["findings"])),
        ]
        findings: List[Finding] = []
        seen_queries: List[str] = []
        searches = 0
        max_iters = int(self.config.agent["max_tool_iterations"])

        for i in range(max_iters):
            try:
                response = self.reviewer.invoke(messages)
            except Exception as exc:  # noqa: BLE001
                self.audit.record("correlation_error", error=str(exc))
                break
            calls = _extract_tool_calls(response)
            self.audit.record("correlation_turn", iteration=i + 1,
                              tool_calls=[c["name"] for c in calls])
            messages.append(response)
            if not calls:
                break
            updates = self._execute_tool_calls(
                calls,
                section=None,
                default_domain="security",
                searches_used=searches,
                seen_queries=seen_queries,
                origin=ORIGIN_CORRELATION,
                chunks=[],
            )
            findings.extend(updates["findings"])
            messages.extend(updates["tool_messages"])
            searches = updates["searches_used"]
            seen_queries = updates["seen_queries"]
            if updates["done"]:
                break

        self.audit.record("correlation_complete", findings=len(findings))
        return {"findings": state["findings"] + findings}

    def report_node(self, state: ReviewState) -> Dict[str, Any]:
        """Narrative synthesis using the TOOL-FREE model handle."""
        from .prompts import REPORT_SYSTEM, REPORT_USER, findings_digest
        from .report import compute_risk

        self._emit("Writing report", 0.95)

        findings = sort_findings(dedupe_findings(state["findings"]))
        score, rag, counts = compute_risk(findings, self.config)

        user = REPORT_USER.format(
            document_name=state["document_name"],
            domains=", ".join(
                DOMAIN_LABELS.get(d, d) for d in state["enabled_domains"]),
            section_count=len(state["sections"]),
            kb_chunks=state.get("kb_chunk_count", 0),
            counts=", ".join(f"{k}={v}" for k, v in counts.items()),
            risk_score=score,
            rag_status=rag,
            findings_digest=findings_digest(findings),
        )

        text = ""
        try:
            # NOTE: self.writer, not self.reviewer. See module docstring.
            response = self.writer.invoke([("system", REPORT_SYSTEM),
                                           ("human", user)])
            text = _message_text(response)
        except Exception as exc:  # noqa: BLE001
            self.audit.record("report_error", error=str(exc))

        summary, opinion = _split_narrative(text)
        self.audit.record("report_written",
                          summary_chars=len(summary),
                          opinion_chars=len(opinion),
                          used_tool_free_model=True)
        self._emit("Complete", 1.0)
        return {"executive_summary": summary, "assurance_opinion": opinion}

    # ------------------------------------------------------------------
    # Shared tool executor
    # ------------------------------------------------------------------
    def _execute_tool_calls(self, calls: List[Dict[str, Any]],
                            section: Optional[Section],
                            default_domain: str,
                            searches_used: int,
                            seen_queries: List[str],
                            origin: str,
                            chunks: List[RetrievedChunk]) -> Dict[str, Any]:
        from langchain_core.messages import ToolMessage

        max_searches = int(self.config.agent["max_searches_per_section"])
        tool_messages: List[Any] = []
        new_findings: List[Finding] = []
        new_chunks: List[RetrievedChunk] = []
        done = False
        section_name = section.heading if section else "Cross-domain"

        for call in calls:
            name = call["name"]
            args = call.get("args") or {}
            call_id = call.get("id") or f"{name}-{len(tool_messages)}"

            if name == "search_architectural_standards":
                query = str(args.get("query", "")).strip()
                domain = str(args.get("domain") or default_domain)
                norm = re.sub(r"\W+", " ", query.lower()).strip()

                if not query:
                    content = "Empty query. Provide a specific question."
                elif norm in seen_queries:
                    content = (
                        "You already searched for this. The results are above. "
                        "Do not search again - either flag a finding or call "
                        "section_complete."
                    )
                    self.audit.record("search_suppressed_duplicate",
                                      section=section_name, query=query[:200])
                elif searches_used >= max_searches:
                    content = (
                        f"Search budget for this section is exhausted "
                        f"({max_searches} searches). Flag any remaining findings "
                        f"from what you already have, then call section_complete."
                    )
                    self.audit.record("search_budget_exhausted",
                                      section=section_name, query=query[:200])
                else:
                    searches_used += 1
                    seen_queries.append(norm)
                    try:
                        found = self.kb.search(query, domain)
                    except Exception as exc:  # noqa: BLE001
                        found = []
                        self.audit.record("search_error", query=query[:200],
                                          error=str(exc))
                    new_chunks.extend(found)
                    from .prompts import format_standards
                    content = format_standards(found)
                    self.audit.record(
                        "tool_search", section=section_name, query=query[:200],
                        domain=domain, results=len(found),
                        citations=[c.citation() for c in found])

                tool_messages.append(
                    ToolMessage(content=content, tool_call_id=call_id, name=name))

            elif name == "flag_finding":
                finding = self._finding_from_args(
                    args, section_name, default_domain, origin,
                    chunks + new_chunks)
                new_findings.append(finding)
                self.audit.record(
                    "tool_flag_finding",
                    section=section_name,
                    severity=finding.severity,
                    domain=finding.domain,
                    issue=finding.issue[:220],
                    reference=finding.standard_reference,
                    grounded=finding.is_grounded,
                    evidence_chunks=finding.evidence_chunk_ids,
                )
                tool_messages.append(ToolMessage(
                    content=(
                        f"Finding recorded: [{finding.severity}] "
                        f"{finding.issue[:120]}. Continue, or call "
                        f"section_complete if you have nothing further."
                    ),
                    tool_call_id=call_id, name=name))

            elif name == "section_complete":
                done = True
                self.audit.record("tool_section_complete",
                                  section=section_name,
                                  rationale=str(args.get("rationale", ""))[:300])
                tool_messages.append(ToolMessage(
                    content="Acknowledged. Section closed.",
                    tool_call_id=call_id, name=name))

            else:
                self.audit.record("unknown_tool_call", name=name,
                                  section=section_name)
                tool_messages.append(ToolMessage(
                    content=(
                        f"Unknown tool '{name}'. Available tools: "
                        f"search_architectural_standards, flag_finding, "
                        f"section_complete."
                    ),
                    tool_call_id=call_id, name=name))

        return {
            "tool_messages": tool_messages,
            "findings": new_findings,
            "new_chunks": new_chunks,
            "searches_used": searches_used,
            "seen_queries": seen_queries,
            "done": done,
        }

    def _finding_from_args(self, args: Dict[str, Any], section_name: str,
                           default_domain: str, origin: str,
                           chunks: List[RetrievedChunk]) -> Finding:
        reference = str(args.get("standard_reference", "") or "").strip()
        evidence = str(args.get("evidence", "") or "").strip()

        # Tie the citation back to a real retrieved chunk. If the model cited
        # something we never retrieved, the finding is downgraded to ungrounded
        # rather than being presented as standards-backed.
        kb_source = ""
        chunk_ids: List[str] = []
        confidence = 0.45
        if reference:
            match = _match_citation(reference, chunks)
            if match:
                kb_source = match.source
                chunk_ids = [match.chunk_id]
                confidence = round(min(0.95, 0.6 + match.similarity * 0.4), 2)
            else:
                self.audit.record("citation_unverified", section=section_name,
                                  reference=reference[:200])
                reference = f"{reference} (unverified)"
                confidence = 0.3

        return Finding(
            section=section_name,
            domain=str(args.get("domain") or default_domain),
            severity=normalise_severity(args.get("severity")),
            issue=str(args.get("issue", "")).strip() or "Unspecified issue.",
            recommendation=(
                str(args.get("recommendation", "")).strip()
                or "Remediation not specified by the reviewer; requires "
                   "architect input."
            ),
            standard_reference=reference,
            kb_source=kb_source,
            evidence_excerpt=evidence[:int(
                self.config.output.get("max_excerpt_chars", 400))],
            origin=origin,
            confidence=confidence,
            evidence_chunk_ids=chunk_ids,
        )

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def _route_after_triage(self, state: ReviewState) -> str:
        return "retrieve" if state["sections"] else "correlate"

    def _route_after_review(self, state: ReviewState) -> str:
        if state["section_done"]:
            return "advance"
        if state["tool_iterations"] >= int(self.config.agent["max_tool_iterations"]):
            self.audit.record(
                "loop_cap_reached",
                section=state["sections"][state["cursor"]].heading,
                iterations=state["tool_iterations"])
            return "advance"
        return "act" if _extract_tool_calls(state["messages"][-1]) else "advance"

    def _route_after_act(self, state: ReviewState) -> str:
        if state["section_done"]:
            return "advance"
        if state["tool_iterations"] >= int(self.config.agent["max_tool_iterations"]):
            self.audit.record(
                "loop_cap_reached",
                section=state["sections"][state["cursor"]].heading,
                iterations=state["tool_iterations"])
            return "advance"
        return "review"

    def _route_after_advance(self, state: ReviewState) -> str:
        return "retrieve" if state["cursor"] < len(state["sections"]) else "correlate"

    # ------------------------------------------------------------------
    def _emit(self, stage: str, pct: float) -> None:
        if callable(self.progress):
            try:
                self.progress(stage, max(0.0, min(1.0, pct)))
            except Exception:
                pass


# ==========================================================================
# Message helpers
# ==========================================================================
_JSON_TOOLCALL_RE = re.compile(
    r"\{[^{}]*\"(?:name|function)\"\s*:\s*\"(search_architectural_standards|"
    r"flag_finding|section_complete)\"[^{}]*(?:\{[^{}]*\}[^{}]*)?\}",
    re.DOTALL,
)


def _message_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(content)


def _extract_tool_calls(message: Any) -> List[Dict[str, Any]]:
    """Pull tool calls off a model response.

    Handles the well-behaved case (native `tool_calls`) and the common local
    small-model failure mode: emitting the tool call as JSON inside the text
    body. Without the fallback, a model that "almost" supports tool calling
    silently produces zero findings.
    """
    calls = getattr(message, "tool_calls", None)
    if calls:
        out: List[Dict[str, Any]] = []
        for c in calls:
            if isinstance(c, dict):
                name = c.get("name") or (c.get("function") or {}).get("name")
                args = c.get("args")
                if args is None:
                    raw = (c.get("function") or {}).get("arguments")
                    args = _loads(raw) if isinstance(raw, str) else (raw or {})
                out.append({"name": name, "args": args or {}, "id": c.get("id")})
            else:
                out.append({
                    "name": getattr(c, "name", None),
                    "args": getattr(c, "args", {}) or {},
                    "id": getattr(c, "id", None),
                })
        return [c for c in out if c["name"]]

    text = _message_text(message)
    if not text or '"' not in text:
        return []

    recovered: List[Dict[str, Any]] = []
    for match in _JSON_TOOLCALL_RE.finditer(text):
        data = _loads(match.group(0))
        if not isinstance(data, dict):
            continue
        name = data.get("name") or (data.get("function") or {}).get("name")
        args = data.get("arguments") or data.get("args") or data.get("parameters") or {}
        if isinstance(args, str):
            args = _loads(args) or {}
        if name:
            recovered.append({"name": name, "args": args,
                              "id": f"recovered-{len(recovered)}"})
    return recovered


def _loads(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


def _match_citation(reference: str, chunks: List[RetrievedChunk]
                    ) -> Optional[RetrievedChunk]:
    """Find the retrieved chunk a cited reference actually corresponds to."""
    if not chunks:
        return None
    ref = reference.lower()
    clause = ""
    m = re.search(r"Â§\s*(\d+(?:\.\d+)*)", reference)
    if m:
        clause = m.group(1)

    best: Optional[RetrievedChunk] = None
    best_score = 0.0
    for c in chunks:
        score = 0.0
        if clause and c.clause and clause == c.clause.lstrip("Â§"):
            score += 3.0
        stem = c.source.rsplit(".", 1)[0].replace("-", " ").replace("_", " ").lower()
        stem_words = [w for w in stem.split() if len(w) > 3]
        if stem_words:
            hits = sum(1 for w in stem_words if w in ref)
            score += 2.0 * (hits / len(stem_words))
        if score > best_score:
            best, best_score = c, score
    return best if best_score >= 1.0 else None


def _split_narrative(text: str) -> Tuple[str, str]:
    """Split the writer's output into summary and opinion."""
    if not text.strip():
        return "", ""
    cleaned = text.strip()
    parts = re.split(r"^\s*#{1,4}\s*Assurance Opinion\s*$", cleaned,
                     maxsplit=1, flags=re.IGNORECASE | re.MULTILINE)
    summary_block = parts[0]
    opinion = parts[1].strip() if len(parts) > 1 else ""
    summary = re.sub(r"^\s*#{1,4}\s*Executive Summary\s*$", "", summary_block,
                     flags=re.IGNORECASE | re.MULTILINE).strip()
    return summary, opinion

