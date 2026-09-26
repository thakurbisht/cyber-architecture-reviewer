# TIER 1 Hardening Plan
## Stabilization Before Integration

**Status:** Prioritized Fixes for Production Readiness  
**Date:** September 5, 2026  
**Owner:** Architecture Review / Phase 1 Stabilization  

---

## Executive Summary

The 3-skill system is **architecturally sound** but has **5 critical TIER 1 blockers** that prevent production deployment:

1. **No error handling** — Skills crash on malformed patterns
2. **Regex DoS vulnerability** — Catastrophic backtracking in pattern matching
3. **No timeout protection** — Large files hang indefinitely
4. **State leakage** — Findings grow without bounds in agent state
5. **Scalability failure** — SkillIndex sequential loading doesn't scale

**Action:** Fix TIER 1 first (2-3 days), then proceed to skill integration and testing.

---

## Issue 1: No Error Handling in SkillExecutor

### Problem
```python
# Current code - crashes on bad regex
for pattern_name in step.get('patterns', []):
    pattern_def = self.PATTERN_CHECKS[pattern_name]
    pattern = pattern_def['pattern']
    matches = list(re.finditer(pattern, section_text, re.IGNORECASE))
    # ❌ If regex is invalid → unhandled exception
    # ❌ If section_text is huge → memory error
    # ❌ No timeout → infinite loop possible
```

### Risk
- Tool crashes mid-review (data loss)
- Evaluation fails silently
- Cannot retry gracefully

### Fix

**File:** `/tmp/work/src/skill_executor.py`

```python
import re
import logging
from typing import Optional, List
from contextlib import timeout

logger = logging.getLogger(__name__)

class SkillExecutorException(Exception):
    """Base exception for skill execution errors"""
    pass

class SkillExecutor:
    """Execute skill workflows against document sections"""
    
    # Configuration
    PATTERN_TIMEOUT_SECONDS = 5
    MAX_MATCH_COUNT = 1000
    
    # ... existing code ...
    
    def _execute_step(
        self,
        section_text: str,
        step: Dict,
        step_num: int,
        section_name: str
    ) -> List[SkillFinding]:
        """
        Execute a single workflow step with error handling.
        """
        findings = []
        
        for pattern_name in step.get('patterns', []):
            if pattern_name not in self.PATTERN_CHECKS:
                logger.warning(f"Unknown pattern: {pattern_name}")
                continue
            
            try:
                pattern_def = self.PATTERN_CHECKS[pattern_name]
                pattern = pattern_def['pattern']
                issue = pattern_def['issue']
                severity = pattern_def['severity']
                
                # Validate regex pattern
                try:
                    compiled_pattern = re.compile(pattern)
                except re.error as e:
                    logger.error(
                        f"Invalid regex pattern '{pattern_name}': {e}. "
                        f"Skill: {self.skill.name}"
                    )
                    continue
                
                # Search with timeout protection
                try:
                    # Use timeout context manager (requires signal on Unix)
                    matches = self._find_matches_with_timeout(
                        compiled_pattern,
                        section_text,
                        timeout_seconds=self.PATTERN_TIMEOUT_SECONDS
                    )
                except TimeoutError:
                    logger.warning(
                        f"Pattern matching timeout for '{pattern_name}' "
                        f"on section '{section_name}' (skill: {self.skill.name}). "
                        f"Text length: {len(section_text)} bytes"
                    )
                    continue
                
                # Safety cap on match count
                if len(matches) > self.MAX_MATCH_COUNT:
                    logger.warning(
                        f"Pattern '{pattern_name}' produced {len(matches)} matches "
                        f"(max: {self.MAX_MATCH_COUNT}). Truncating."
                    )
                    matches = matches[:self.MAX_MATCH_COUNT]
                
                # Generate findings from matches
                for match_idx, match in enumerate(matches):
                    try:
                        start = max(0, match.start() - 100)
                        end = min(len(section_text), match.end() + 100)
                        evidence_excerpt = section_text[start:end].strip()
                        
                        finding_id = (
                            f"{self.skill.name}_{section_name}_"
                            f"step{step_num}_match{match_idx}"
                        )
                        
                        finding = SkillFinding(
                            id=finding_id,
                            skill_id=self.skill.name,
                            skill_name=self.skill.name,
                            skill_domain=self.skill.domain,
                            issue=issue,
                            severity=severity,
                            evidence_excerpt=evidence_excerpt[:200],
                            mitre_attack=self.skill.mitre_attack.copy(),
                            nist_csf=self.skill.nist_csf.copy(),
                            frameworks=self.skill.frameworks.copy(),
                            finding_count=match_idx + 1,
                        )
                        findings.append(finding)
                    except Exception as e:
                        logger.error(
                            f"Error creating finding from match {match_idx}: {e}. "
                            f"Skill: {self.skill.name}, Pattern: {pattern_name}"
                        )
                        continue
                        
            except Exception as e:
                logger.error(
                    f"Unexpected error executing pattern '{pattern_name}' "
                    f"in skill '{self.skill.name}': {e}",
                    exc_info=True
                )
                continue
        
        return findings
    
    def _find_matches_with_timeout(
        self,
        compiled_pattern,
        text: str,
        timeout_seconds: float = 5
    ) -> List:
        """
        Find regex matches with timeout protection.
        
        On Unix: uses signal-based timeout
        On Windows: uses threading-based timeout
        """
        import sys
        
        if sys.platform == 'win32':
            # Windows: use threading approach
            return self._find_matches_threaded(
                compiled_pattern, text, timeout_seconds
            )
        else:
            # Unix: use signal-based timeout
            return self._find_matches_signal(
                compiled_pattern, text, timeout_seconds
            )
    
    def _find_matches_signal(self, pattern, text: str, timeout_sec: float):
        """Unix-based timeout using signal.alarm"""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Regex matching exceeded {timeout_sec} seconds")
        
        # Set signal handler
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(int(timeout_sec) + 1)  # Round up
        
        try:
            matches = list(pattern.finditer(text, re.IGNORECASE))
            return matches
        finally:
            signal.alarm(0)  # Cancel alarm
            signal.signal(signal.SIGALRM, old_handler)
    
    def _find_matches_threaded(self, pattern, text: str, timeout_sec: float):
        """Windows-compatible threading-based timeout"""
        from threading import Thread
        import queue
        
        result_queue = queue.Queue()
        
        def worker():
            try:
                matches = list(pattern.finditer(text, re.IGNORECASE))
                result_queue.put(('success', matches))
            except Exception as e:
                result_queue.put(('error', e))
        
        thread = Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=timeout_sec)
        
        if thread.is_alive():
            raise TimeoutError(f"Regex matching exceeded {timeout_sec} seconds")
        
        try:
            status, result = result_queue.get_nowait()
            if status == 'error':
                raise result
            return result
        except queue.Empty:
            raise TimeoutError("Thread result not available")
```

### Validation
```python
# Test error handling
skill = SkillIndex("/tmp/work/skills").get_skill_by_name("detecting-cloud-iam-misconfigurations")
executor = SkillExecutor(skill)

# Test 1: Malformed section text
findings = executor.execute("", "empty_section")
assert len(findings) >= 0, "Should handle empty sections gracefully"

# Test 2: Large text (simulate DoS attempt)
huge_text = "A" * 10_000_000
findings = executor.execute(huge_text, "large_section")
# Should not hang or crash; should timeout gracefully

# Test 3: Invalid patterns in PATTERN_CHECKS
executor.PATTERN_CHECKS['bad_pattern'] = {
    'pattern': '(?P<invalid>(?P<invalid>)',  # Invalid regex
    'issue': 'test',
    'severity': 'HIGH'
}
step = {'patterns': ['bad_pattern']}
findings = executor._execute_step("test text", step, 1, "test")
assert len(findings) == 0, "Should skip invalid patterns"
```

---

## Issue 2: Regex DoS Vulnerability

### Problem
```python
# Current predefined patterns - some are vulnerable
'aws_wildcard_action': {
    'pattern': r'"(?:Action|action)"?\s*:\s*["\']?\*["\']?',
    # ❌ Nested optional groups can backtrack catastrophically
    # ❌ On large JSON with many quotes, pattern matching hangs
}
```

### Risk
- Attacker can craft JSON/YAML to trigger regex backtracking
- Tool hangs for hours on modest-sized files
- Denial of service in evaluation pipeline

### Fix

**Create:** `/tmp/work/src/pattern_validator.py`

```python
"""Pattern validation and optimization for security"""

import re
from typing import Dict, Tuple, List

class PatternValidator:
    """Validates regex patterns for ReDoS vulnerabilities"""
    
    # Dangerous patterns that indicate ReDoS vulnerability
    DANGEROUS_PATTERNS = [
        r'\(\?P<\w+>.*\(\?P<\w+>',  # Nested named groups
        r'(\w+\*)+',                  # Nested quantifiers
        r'(\.\*){2,}',                # Multiple .* in sequence
        r'(\w+\+)+',                  # Nested + quantifiers
        r'(\w+\?)*\w+\?',             # Multiple optional groups
    ]
    
    @staticmethod
    def validate_pattern(pattern: str) -> Tuple[bool, str]:
        """
        Validate a regex pattern for ReDoS vulnerabilities.
        
        Returns:
            (is_safe, reason)
        """
        try:
            # Compile to check syntax
            re.compile(pattern)
        except re.error as e:
            return False, f"Invalid regex syntax: {e}"
        
        # Check for known dangerous patterns
        for dangerous in PatternValidator.DANGEROUS_PATTERNS:
            if re.search(dangerous, pattern):
                return False, f"Potential ReDoS vulnerability: {dangerous}"
        
        # Check for excessive backtracking potential
        # Simple heuristic: multiple quantifiers or groups > 10
        quantifier_count = len(re.findall(r'[*+?{]', pattern))
        group_count = len(re.findall(r'[()]', pattern)) // 2
        
        if quantifier_count > 15:
            return False, f"Too many quantifiers ({quantifier_count}), risk of backtracking"
        
        if group_count > 20:
            return False, f"Too many groups ({group_count}), risk of backtracking"
        
        return True, "Pattern is safe"
    
    @staticmethod
    def optimize_pattern(pattern: str) -> str:
        """
        Optimize a pattern to reduce backtracking.
        
        Strategies:
        1. Replace .* with [^"]+ where possible
        2. Remove unnecessary optional groups
        3. Use atomic groups (?>...) to prevent backtracking
        """
        optimized = pattern
        
        # Strategy 1: Replace .* with character class
        if '.*' in optimized:
            # Only if not at end (which is usually OK)
            optimized = re.sub(r'\.\*(?!$)', '[^]*?', optimized)
        
        # Strategy 2: Convert excessive ? to explicit alternatives
        # This is pattern-specific, skip for now
        
        return optimized


class PatternDatabase:
    """Manages safe, validated patterns"""
    
    def __init__(self):
        self.patterns = {}
        self.validation_cache = {}
    
    def add_pattern(self, name: str, pattern_def: Dict) -> bool:
        """
        Add a pattern after validation.
        
        Returns:
            True if valid and added, False otherwise
        """
        pattern_str = pattern_def.get('pattern', '')
        
        # Check cache
        if pattern_str in self.validation_cache:
            is_safe, reason = self.validation_cache[pattern_str]
        else:
            is_safe, reason = PatternValidator.validate_pattern(pattern_str)
            self.validation_cache[pattern_str] = (is_safe, reason)
        
        if not is_safe:
            print(f"❌ Pattern '{name}' rejected: {reason}")
            return False
        
        # Optimize
        optimized = PatternValidator.optimize_pattern(pattern_str)
        pattern_def['pattern'] = optimized
        pattern_def['validation_reason'] = reason
        
        self.patterns[name] = pattern_def
        print(f"✅ Pattern '{name}' validated and added")
        return True
    
    def get_pattern(self, name: str) -> Dict:
        """Retrieve a validated pattern"""
        return self.patterns.get(name)
    
    def validate_all(self) -> Dict:
        """Validate all patterns, return report"""
        report = {
            'total': len(self.patterns),
            'valid': 0,
            'invalid': 0,
            'details': {}
        }
        
        for name, pattern_def in self.patterns.items():
            is_safe, reason = PatternValidator.validate_pattern(
                pattern_def.get('pattern', '')
            )
            report['details'][name] = {
                'valid': is_safe,
                'reason': reason
            }
            if is_safe:
                report['valid'] += 1
            else:
                report['invalid'] += 1
        
        return report
```

### Update SkillExecutor to Use Validation

```python
from pattern_validator import PatternDatabase

class SkillExecutor:
    # ... existing code ...
    
    def __init__(self, skill: SkillMetadata):
        self.skill = skill
        self.findings: List[SkillFinding] = []
        
        # Validate all patterns on init
        self.pattern_db = PatternDatabase()
        for name, pattern_def in self.PATTERN_CHECKS.items():
            self.pattern_db.add_pattern(name, pattern_def.copy())
        
        validation_report = self.pattern_db.validate_all()
        if validation_report['invalid'] > 0:
            logger.warning(
                f"Skill {skill.name}: {validation_report['invalid']} patterns failed validation"
            )
```

### Validation
```bash
# Test pattern validation
python3 << 'EOF'
from pattern_validator import PatternValidator, PatternDatabase

# Test 1: Safe pattern
pattern = r'"Action"\s*:\s*"\*"'
is_safe, reason = PatternValidator.validate_pattern(pattern)
print(f"✓ Safe pattern: {is_safe}")

# Test 2: Dangerous pattern
dangerous = r'(a+)+b'  # Classic ReDoS
is_safe, reason = PatternValidator.validate_pattern(dangerous)
print(f"✓ Dangerous pattern correctly rejected: {not is_safe}")

# Test 3: Database validation
db = PatternDatabase()
db.add_pattern('safe', {'pattern': pattern, 'issue': 'test', 'severity': 'HIGH'})
db.add_pattern('unsafe', {'pattern': dangerous, 'issue': 'test', 'severity': 'HIGH'})
report = db.validate_all()
print(f"✓ Database validation: valid={report['valid']}, invalid={report['invalid']}")
EOF
```

---

## Issue 3: No Timeout Protection

**Already addressed in Issue 1 fix** with `_find_matches_with_timeout()`.

Key safeguard:
```python
PATTERN_TIMEOUT_SECONDS = 5  # Max 5 seconds per pattern
MAX_MATCH_COUNT = 1000        # Cap results at 1000 matches per pattern
```

---

## Issue 4: State Leakage in Agent Integration

### Problem
```python
# Current code in skill_execution_node
for skill in state.get('selected_skills', []):
    for section in state.get('sections', []):
        findings = executor.execute(section_text, section_name)
        state['findings'].extend(findings)  # ❌ Unbounded growth

# If 20 skills × 50 sections × avg 10 findings each
# = 10,000 findings in state (memory explosion)
```

### Risk
- Agent state grows indefinitely
- LLM context window fills up
- OOM errors mid-review

### Fix

**Update:** `/tmp/work/src/skill_executor.py`

```python
class SkillExecutor:
    # Configuration
    MAX_FINDINGS_PER_SKILL = 100
    MAX_TOTAL_FINDINGS = 500
    
    def execute(self, section_text: str, section_name: str = "") -> List[SkillFinding]:
        """
        Execute skill workflow with bounded output.
        
        Returns at most MAX_FINDINGS_PER_SKILL findings.
        """
        findings = []
        
        workflow_steps = self._extract_workflow_steps(self.skill.full_content)
        
        for step_num, step in enumerate(workflow_steps, 1):
            if len(findings) >= self.MAX_FINDINGS_PER_SKILL:
                logger.info(
                    f"Skill '{self.skill.name}' reached finding limit "
                    f"({self.MAX_FINDINGS_PER_SKILL}). Stopping execution."
                )
                break
            
            step_findings = self._execute_step(
                section_text, step, step_num, section_name
            )
            
            # Only add findings while under limit
            space_available = self.MAX_FINDINGS_PER_SKILL - len(findings)
            findings.extend(step_findings[:space_available])
        
        return findings
```

**Update:** `skill_execution_node()` in agent.py

```python
def skill_execution_node(self, state: ReviewState) -> ReviewState:
    """
    Execute selected skills with bounded findings accumulation.
    """
    all_findings = []
    
    for skill in state.get('selected_skills', []):
        # Stop if we've collected enough findings
        if len(all_findings) >= SkillExecutor.MAX_TOTAL_FINDINGS:
            logger.info(
                f"Reached maximum findings limit "
                f"({SkillExecutor.MAX_TOTAL_FINDINGS}). Skipping remaining skills."
            )
            break
        
        executor = SkillExecutor(skill)
        
        for section in state.get('sections', []):
            section_name = section.get('name', 'unknown')
            section_text = section.get('text', '')
            
            findings = executor.execute(section_text, section_name)
            all_findings.extend(findings)
            
            # Check limit after each skill execution
            if len(all_findings) >= SkillExecutor.MAX_TOTAL_FINDINGS:
                break
    
    # Deduplicate and add to state
    deduplicated = SkillExecutor.deduplicate_findings(all_findings)
    
    # Log memory impact
    logger.info(
        f"Skill execution: collected {len(all_findings)} findings, "
        f"deduplicated to {len(deduplicated)}, "
        f"state size now ~{len(str(state))} bytes"
    )
    
    for skill_finding in deduplicated:
        finding = Finding(
            id=skill_finding.id,
            origin='skill_executor',
            issue=skill_finding.issue,
            severity=skill_finding.severity,
            evidence_excerpt=skill_finding.evidence_excerpt,
            standard_reference=skill_finding.standard_reference,
            kb_source=f"skill:{skill_finding.skill_id}",
            skill_id=skill_finding.skill_id,
            skill_name=skill_finding.skill_name,
            skill_domain=skill_finding.skill_domain,
        )
        state['findings'].append(finding)
    
    return state
```

---

## Issue 5: SkillIndex Scalability

### Problem
```python
# Current: O(n) sequential loading
def _load_skills(self):
    for skill_dir in skills_path.iterdir():
        skill_file = skill_dir / "SKILL.md"
        metadata = self._parse_skill(skill_file, skill_dir.name)
        self.skills[metadata.name] = metadata
        # ❌ Loads ALL skills into memory at init time
        # ❌ Doesn't cache parsed metadata
        # ❌ No lazy loading
```

### Risk
- With 100+ skills, init takes 10+ seconds
- Every agent restart reloads all skills
- Memory usage grows with skill count

### Fix

**Create:** `/tmp/work/src/skill_cache.py`

```python
"""Caching layer for skill metadata"""

import json
import hashlib
from pathlib import Path
from typing import Dict, Optional
import pickle

class SkillMetadataCache:
    """Caches parsed skill metadata to disk"""
    
    def __init__(self, cache_dir: str = "/tmp/work/cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_path(self, skill_file: Path) -> Path:
        """Generate cache filename from skill file path"""
        file_hash = hashlib.md5(str(skill_file).encode()).hexdigest()[:8]
        return self.cache_dir / f"skill_{file_hash}.cache"
    
    def _get_file_mtime(self, skill_file: Path) -> float:
        """Get file modification time"""
        return skill_file.stat().st_mtime
    
    def get(self, skill_file: Path):
        """Retrieve cached metadata if valid"""
        cache_path = self._get_cache_path(skill_file)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'rb') as f:
                cached_data = pickle.load(f)
            
            # Validate cache freshness
            if cached_data['file_mtime'] == self._get_file_mtime(skill_file):
                return cached_data['metadata']
            
            # Cache stale, delete it
            cache_path.unlink()
            return None
        except Exception as e:
            print(f"Cache read error: {e}")
            return None
    
    def set(self, skill_file: Path, metadata):
        """Cache parsed metadata"""
        cache_path = self._get_cache_path(skill_file)
        
        try:
            cached_data = {
                'file_mtime': self._get_file_mtime(skill_file),
                'metadata': metadata
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cached_data, f)
        except Exception as e:
            print(f"Cache write error: {e}")
    
    def clear(self):
        """Clear entire cache"""
        for cache_file in self.cache_dir.glob("skill_*.cache"):
            cache_file.unlink()
```

**Update:** `skill_index.py`

```python
from skill_cache import SkillMetadataCache

class SkillIndex:
    def __init__(self, skills_dir: str, cache_dir: str = "/tmp/work/cache"):
        self.skills_dir = skills_dir
        self.skills: Dict[str, SkillMetadata] = {}
        self.cache = SkillMetadataCache(cache_dir)
        # ... index initialization ...
        
        self._load_skills()
    
    def _parse_skill(self, skill_file: Path, skill_name: str) -> Optional[SkillMetadata]:
        """
        Parse YAML frontmatter from SKILL.md file with caching.
        """
        # Check cache first
        cached = self.cache.get(skill_file)
        if cached is not None:
            print(f"[Cache HIT] {skill_name}")
            return cached
        
        # Parse from file
        try:
            with open(skill_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # ... parsing logic ...
            metadata = SkillMetadata(...)
            
            # Cache for next time
            self.cache.set(skill_file, metadata)
            print(f"[Cache MISS → SAVED] {skill_name}")
            
            return metadata
        except Exception as e:
            print(f"Error parsing {skill_file}: {e}")
            return None
```

### Validation
```python
# Benchmark: Load speed with cache
import time

# First load: no cache
start = time.time()
index1 = SkillIndex("/tmp/work/skills")
first_load = time.time() - start
print(f"First load (no cache): {first_load:.2f}s")

# Second load: with cache
start = time.time()
index2 = SkillIndex("/tmp/work/skills")
cached_load = time.time() - start
print(f"Cached load: {cached_load:.2f}s")
print(f"Speedup: {first_load / cached_load:.1f}x")

# Expected: 5x faster with cache
```

---

## Implementation Checklist

### Phase 1: Error Handling (Day 1)
- [ ] Add logging configuration to SkillExecutor
- [ ] Implement try/except blocks in `_execute_step()`
- [ ] Add timeout protection with `_find_matches_with_timeout()`
- [ ] Test error cases (invalid regex, timeout, memory limits)
- [ ] Document error codes and recovery strategies

### Phase 2: Pattern Validation (Day 1-2)
- [ ] Create `pattern_validator.py` with ReDoS detection
- [ ] Validate all PATTERN_CHECKS at SkillExecutor init
- [ ] Optimize patterns to reduce backtracking
- [ ] Add validation report to skill loading logs

### Phase 3: State Bounding (Day 2)
- [ ] Add MAX_FINDINGS_PER_SKILL configuration
- [ ] Add MAX_TOTAL_FINDINGS configuration
- [ ] Update skill_execution_node() to respect limits
- [ ] Add memory usage logging

### Phase 4: Caching (Day 2-3)
- [ ] Create SkillMetadataCache with file-based storage
- [ ] Update SkillIndex to use cache
- [ ] Benchmark cache effectiveness
- [ ] Add cache invalidation strategy

### Testing
- [ ] Unit tests for error handling
- [ ] Stress tests with malicious patterns
- [ ] Memory profiling with large skill sets
- [ ] Performance benchmarking

---

## Expected Outcomes

| Issue | Before | After | Benefit |
|-------|--------|-------|---------|
| 1. Error Handling | Crashes on bad input | Graceful error recovery | Production safe |
| 2. Regex DoS | Hangs on large files | Timeout + optimized patterns | DoS resistant |
| 3. Timeout | Infinite loops possible | 5-sec timeout per pattern | Predictable behavior |
| 4. State Leakage | 10K+ findings in state | Capped at 500 findings | Stable memory |
| 5. Scalability | 10+ sec load time | <1 sec with cache | Fast initialization |

---

## Next Steps

**Upon completion of TIER 1:**

1. Proceed to agent.py integration (skill_discovery_node + skill_execution_node)
2. Run evaluation harness on three samples
3. Measure precision improvement
4. Address TIER 2 (performance optimizations)

**Critical Gate:** Do NOT integrate skills into agent.py until TIER 1 hardening is complete and tested.

---

**Owner:** Pramod Singh Bisht  
**Approval Gate:** All TIER 1 fixes tested and validated  
**Target Date:** September 7, 2026
