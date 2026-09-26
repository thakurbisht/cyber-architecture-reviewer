# Skills Integration Guide

**Quick Start:** How to integrate SkillIndex and SkillExecutor into your agent.py

---

## Overview

The 4-layer architecture adds skill execution between agent triage and KB retrieval:

```
triage_node → skill_discovery_node → skill_execution_node → retrieve_node
```

---

## Step 1: Modify agent.py

### Import New Components

Add these imports at the top of `agent.py`:

```python
from src.skill_index import SkillIndex, SkillRanking
from src.skill_executor import SkillExecutor, SkillFinding
```

### Initialize SkillIndex in StateGraph Constructor

```python
def __init__(self, kb_path: str, rules_path: str, skills_dir: str = "/tmp/work/skills"):
    """Initialize agent with skills support"""
    self.rules_engine = RulesEngine(rules_path)
    self.kb = KnowledgeBase(kb_path)
    
    # NEW: Initialize skill index
    self.skill_index = SkillIndex(skills_dir)
    print(f"Loaded {len(self.skill_index.skills)} skills")
    
    # ... rest of initialization
```

### Create Skill Discovery Node

Add this method to your StateGraph class:

```python
def skill_discovery_node(self, state: ReviewState) -> ReviewState:
    """
    Discover relevant skills based on document context.
    
    LAYER 2: Triage context → SkillIndex → Top 15-20 skills
    """
    # Build context from triage output
    context = {
        'primary_domain': state.get('detected_domain', 'unknown'),
        'primary_topic': ', '.join(state.get('topics', [])),
        'detected_platforms': state.get('platforms', []),
        'frameworks': ['CSF', 'ATT&CK', 'D3FEND'],  # Your enabled frameworks
        'severity_filter': 'CRITICAL',
        'detected_attacks': state.get('mitre_attacks', []),
    }
    
    # Find relevant skills
    relevant_skills = self.skill_index.find_relevant(context)
    
    # Store top skills in state
    state['selected_skills'] = [r.skill for r in relevant_skills[:15]]
    state['skill_rankings'] = relevant_skills
    
    # Log for debugging
    print(f"[Skill Discovery] Found {len(state['selected_skills'])} relevant skills")
    for i, skill in enumerate(state['selected_skills'][:3], 1):
        print(f"  {i}. {skill.name} ({skill.domain})")
    
    return state
```

### Create Skill Execution Node

Add this method to your StateGraph class:

```python
def skill_execution_node(self, state: ReviewState) -> ReviewState:
    """
    Execute selected skills against document sections.
    
    LAYER 2.5: For each skill, run executor on each section → Generate findings
    """
    all_findings = []
    skill_findings_by_domain = {}
    
    # Process each selected skill
    for skill in state.get('selected_skills', []):
        print(f"\n[Skill Execution] Running: {skill.name}")
        executor = SkillExecutor(skill)
        
        # Execute against each section
        for section in state.get('sections', []):
            section_name = section.get('name', 'unknown')
            section_text = section.get('text', '')
            
            # Run skill on this section
            findings = executor.execute(section_text, section_name)
            
            # Add to collection
            all_findings.extend(findings)
            
            # Track by domain for later correlation
            if skill.domain not in skill_findings_by_domain:
                skill_findings_by_domain[skill.domain] = []
            skill_findings_by_domain[skill.domain].extend(findings)
            
            print(f"  Section '{section_name}': {len(findings)} findings")
    
    # Filter duplicates
    deduplicated = SkillExecutor.deduplicate_findings(all_findings)
    
    # Convert SkillFinding to Finding (add to state)
    for skill_finding in deduplicated:
        finding = Finding(
            id=skill_finding.id,
            origin='skill_executor',
            issue=skill_finding.issue,
            severity=skill_finding.severity,
            evidence_excerpt=skill_finding.evidence_excerpt,
            standard_reference=skill_finding.standard_reference,
            kb_source=f"skill:{skill_finding.skill_id}",
            # NEW: Skill provenance
            skill_id=skill_finding.skill_id,
            skill_name=skill_finding.skill_name,
            skill_domain=skill_finding.skill_domain,
            mitre_attack=skill_finding.mitre_attack,
            nist_csf=skill_finding.nist_csf,
            frameworks=skill_finding.frameworks,
        )
        state['findings'].append(finding)
    
    print(f"\n[Skill Execution] Total findings: {len(deduplicated)}")
    return state
```

### Update Graph Edges

Add these edges to your LangGraph state machine:

```python
# In your StateGraph.build() method:

workflow = StateGraph(ReviewState)

# Existing nodes
workflow.add_node("triage", self.triage_node)
workflow.add_node("retrieve", self.retrieve_node)
workflow.add_node("review", self.review_node)
workflow.add_node("correlate", self.correlate_node)
workflow.add_node("report", self.report_node)

# NEW: Skill nodes
workflow.add_node("skill_discovery", self.skill_discovery_node)
workflow.add_node("skill_execution", self.skill_execution_node)

# Update edges: triage → skill_discovery → skill_execution → retrieve
workflow.add_edge("triage", "skill_discovery")
workflow.add_edge("skill_discovery", "skill_execution")
workflow.add_edge("skill_execution", "retrieve")

# Rest of edges unchanged
workflow.add_edge("retrieve", "review")
workflow.add_edge("review", "correlate")
workflow.add_edge("correlate", "report")

workflow.set_entry_point("triage")
workflow.set_finish_point("report")

self.graph = workflow.compile()
```

---

## Step 2: Modify models.py

### Enhance Finding Dataclass

Update the Finding class to include skill provenance:

```python
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Finding:
    """Security finding from rules, agent, or skills"""
    id: str
    origin: str                      # "rules_engine" | "agent" | "skill_executor"
    issue: str
    severity: str                    # CRITICAL, HIGH, MEDIUM, LOW
    evidence_excerpt: str
    standard_reference: str
    kb_source: str
    
    # Existing fields
    # ...
    
    # NEW: Skill provenance fields
    skill_id: Optional[str] = None
    skill_name: Optional[str] = None
    skill_domain: Optional[str] = None
    mitre_attack: List[str] = field(default_factory=list)
    nist_csf: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for output"""
        return {
            'id': self.id,
            'origin': self.origin,
            'issue': self.issue,
            'severity': self.severity,
            'evidence_excerpt': self.evidence_excerpt,
            'standard_reference': self.standard_reference,
            'skill_id': self.skill_id,
            'skill_name': self.skill_name,
            'skill_domain': self.skill_domain,
            'mitre_attack': self.mitre_attack,
            'nist_csf': self.nist_csf,
            'frameworks': self.frameworks,
        }
```

---

## Step 3: Update Evaluation Harness

### Test Against Three Samples

```bash
# Test on cloud-landing-zone (target: improve from 16.7% to 50%+)
python scripts/eval.py \
  --input samples/cloud-landing-zone.md \
  --rules-only false \
  --skills-enabled true

# Test on campus-lan (target: maintain 85.7%, improve to 90%+)
python scripts/eval.py \
  --input samples/campus-lan.md \
  --rules-only false \
  --skills-enabled true

# Test on payments-app (target: improve from 33.3% to 55%+)
python scripts/eval.py \
  --input samples/payments-app.md \
  --rules-only false \
  --skills-enabled true
```

### Measure Improvement

Compare precision before/after:

```python
# In eval.py, add skill metrics:

results = {
    'phase1_precision': 45.2,  # Previous baseline
    'with_skills_precision': None,  # To be measured
    'improvement': None,
    
    'sample_results': {
        'cloud-landing-zone': {
            'before': 16.7,
            'after': None,  # To be measured
        },
        'campus-lan': {
            'before': 85.7,
            'after': None,
        },
        'payments-app': {
            'before': 33.3,
            'after': None,
        },
    }
}
```

---

## Step 4: Refine Skills Based on Results

### If Cloud Skill Needs Improvement

Add custom patterns to skill_executor.py:

```python
# In SkillExecutor.PATTERN_CHECKS, add:

'azure_owner_role_subscription': {
    'pattern': r'Owner\s+role.*subscription|roles/owner.*subscription',
    'issue': 'Owner role assigned at subscription level (should be scoped)',
    'severity': 'CRITICAL',
},

'gcp_workload_identity_missing': {
    'pattern': r'service.?account.*key|user.managed.*key',
    'issue': 'User-managed key on service account (should use workload identity)',
    'severity': 'HIGH',
},
```

### If Network Skill Needs Improvement

Add device-specific patterns:

```python
'cisco_default_credentials': {
    'pattern': r'username\s+cisco|password\s+cisco',
    'issue': 'Cisco default credentials not changed',
    'severity': 'CRITICAL',
},

'juniper_cleartext_snmp': {
    'pattern': r'snmp\s+community\s+(?:public|private)',
    'issue': 'Juniper SNMP using cleartext community string',
    'severity': 'HIGH',
},
```

### If Auth Skill Needs Improvement

Add API-specific patterns:

```python
'api_key_query_parameter': {
    'pattern': r'\?.*api.?key=|\.php\?.*key=|\.aspx\?.*token=',
    'issue': 'API key/token in query parameter (visible in logs)',
    'severity': 'HIGH',
},

'jwt_no_expiration': {
    'pattern': r'jwt|token.*no.*expir|indefinite.*session',
    'issue': 'JWT tokens without expiration or indefinite session',
    'severity': 'HIGH',
},
```

---

## Full Integration Example

### Before (2-Layer)

```python
async def review_architecture(doc: str) -> List[Finding]:
    state = {
        'input': doc,
        'findings': [],
    }
    
    # Layer 1: Rules
    state['findings'].extend(self.rules_engine.check(doc))
    
    # Layer 2: LLM + KB
    state['findings'].extend(self.agent.review(state))
    
    return state['findings']
```

### After (4-Layer)

```python
async def review_architecture(doc: str) -> List[Finding]:
    state = {
        'input': doc,
        'findings': [],
        'sections': self._parse_document(doc),
    }
    
    # Layer 1: Rules
    state = self.triage_node(state)  # Detect domain, platforms
    state['findings'].extend(self.rules_engine.check(doc))
    
    # Layer 2: Agent triage & Skill discovery
    state = self.skill_discovery_node(state)  # Find relevant skills
    
    # Layer 2.5: Skill execution (NEW)
    state = self.skill_execution_node(state)  # Run skills → findings
    
    # Layer 3: Fallback KB retrieval (if needed)
    state = self.retrieve_node(state)
    
    # Layer 4: Output
    state = self.correlate_node(state)
    state = self.report_node(state)
    
    return state['findings']
```

---

## Testing Checklist

- [ ] SkillIndex loads 3 skills successfully
- [ ] Skill discovery ranks cloud skill highest for cloud context
- [ ] Skill discovery ranks network skill highest for network context
- [ ] Skill discovery ranks auth skill highest for application context
- [ ] Skill executor finds AWS wildcard patterns
- [ ] Skill executor finds firewall over-permissive rules
- [ ] Skill executor deduplicates findings
- [ ] Finding includes skill_id and skill_name
- [ ] Finding includes MITRE ATT&CK mappings
- [ ] Precision on cloud-landing-zone improves from 16.7%
- [ ] Precision on campus-lan maintains or improves from 85.7%
- [ ] Precision on payments-app improves from 33.3%

---

## Performance Expectations

| Component | Load Time | Execution Time | Memory |
|-----------|-----------|----------------|--------|
| SkillIndex init | <2 sec | — | ~20 MB (3 skills) |
| Skill discovery | — | <0.5 sec | — |
| Skill execution (1 skill, 1 section) | — | <1 sec | ~5 MB |
| Total per document | — | <10 sec | ~50 MB |

---

## Rollback Plan

If skills cause precision to decrease:

1. **Disable skill execution:**
   ```python
   # In agent.py
   workflow.add_edge("skill_discovery", "retrieve")  # Skip execution
   ```

2. **Disable specific skill:**
   ```python
   # In skill_discovery_node
   exclude_skills = ['detecting-cloud-iam-misconfigurations']
   state['selected_skills'] = [
       s for s in state['selected_skills'] 
       if s.name not in exclude_skills
   ]
   ```

3. **Revert to rules-only:**
   ```python
   # In skill_execution_node
   if not skills_enabled:
       return state  # Skip skill execution
   ```

---

## Next: Create Additional Skills

Once 3 core skills are stable, create:

- **detecting-threat-hunting-indicators** (58 threat hunting patterns)
- **detecting-soc-operational-gaps** (35 SOC operations workflows)
- **detecting-incident-response-gaps** (26 IR procedure validations)

Each skill follows same structure:
- YAML frontmatter with frameworks
- 5-7 workflow steps
- Real-world examples
- Remediation guidance 
- 

---

## Summary

✅ **3 custom skills created** — Ready for integration  
✅ **SkillIndex component** — Ranks skills by relevance  
✅ **SkillExecutor component** — Runs workflows, generates findings  
✅ **Integration guide** — Shows exact code changes  

**Next:** Implement two new nodes in agent.py, test against three samples, measure precision improvement from 45.2% → 60%+.
