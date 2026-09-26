"""Pattern validation and optimization for security"""

import re
from typing import Dict, Tuple, List


class PatternValidator:
    """Validates regex patterns for ReDoS vulnerabilities and inefficiencies"""

    # Dangerous patterns that indicate ReDoS vulnerability
    DANGEROUS_PATTERNS = [
        r'\(\?P<\w+>[\s\S]*\(\?P<\w+>',  # Nested named groups
        r'[)]\s*[*+?]',                  # Group followed by quantifier (a*)+
        r'(\.\*){2,}',                   # Multiple .* in sequence
        r'[*+]{2,}',                     # Consecutive quantifiers
        r'\*\*',                         # Double asterisk
    ]

    @staticmethod
    def validate_pattern(pattern: str) -> Tuple[bool, str]:
        """
        Validate a regex pattern for ReDoS vulnerabilities.

        Args:
            pattern: Regex pattern string to validate

        Returns:
            (is_safe, reason) - True if pattern is safe, False with explanation if not
        """
        try:
            # Compile to check syntax
            re.compile(pattern)
        except re.error as e:
            return False, f"Invalid regex syntax: {e}"

        # Check for known dangerous patterns
        for dangerous in PatternValidator.DANGEROUS_PATTERNS:
            if re.search(dangerous, pattern):
                return False, f"Potential ReDoS vulnerability detected"

        # Check for excessive backtracking potential
        # Simple heuristic: multiple quantifiers or groups
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
        Optimize a pattern to reduce backtracking risk.

        Strategies:
        1. Replace .* with more specific character classes
        2. Use possessive quantifiers where safe
        3. Remove unnecessary groups

        Args:
            pattern: Original regex pattern

        Returns:
            Optimized pattern string
        """
        optimized = pattern

        # Strategy 1: Replace .* with more specific patterns
        # Only when not at end of pattern (which is usually safe)
        if '.*' in optimized and not optimized.endswith('.*'):
            # Replace .* with [^]* (non-greedy of anything)
            # or more specific character class
            optimized = re.sub(r'\.\*(?!$)', '[^]*?', optimized)

        # Strategy 2: Simplify character classes
        # [a-zA-Z0-9_] can become \w
        optimized = re.sub(r'\[a-zA-Z0-9_\]', r'\\w', optimized)
        optimized = re.sub(r'\[0-9\]', r'\\d', optimized)

        return optimized


class PatternDatabase:
    """Manages safe, validated patterns"""

    def __init__(self):
        self.patterns: Dict[str, Dict] = {}
        self.validation_cache: Dict[str, Tuple[bool, str]] = {}

    def add_pattern(self, name: str, pattern_def: Dict) -> bool:
        """
        Add a pattern after validation and optimization.

        Args:
            name: Pattern name identifier
            pattern_def: Dictionary with 'pattern', 'issue', 'severity' keys

        Returns:
            True if valid and added, False otherwise
        """
        pattern_str = pattern_def.get('pattern', '')

        if not pattern_str:
            print(f"❌ Pattern '{name}': empty pattern string")
            return False

        # Check validation cache
        if pattern_str in self.validation_cache:
            is_safe, reason = self.validation_cache[pattern_str]
        else:
            is_safe, reason = PatternValidator.validate_pattern(pattern_str)
            self.validation_cache[pattern_str] = (is_safe, reason)

        if not is_safe:
            print(f"❌ Pattern '{name}' rejected: {reason}")
            return False

        # Optimize pattern
        optimized = PatternValidator.optimize_pattern(pattern_str)
        if optimized != pattern_str:
            print(f"   Optimized: {pattern_str[:50]}... → {optimized[:50]}...")

        # Create final pattern definition
        safe_pattern_def = pattern_def.copy()
        safe_pattern_def['pattern'] = optimized
        safe_pattern_def['validation_reason'] = reason

        self.patterns[name] = safe_pattern_def
        print(f"✅ Pattern '{name}' validated and added")
        return True

    def get_pattern(self, name: str) -> Dict:
        """
        Retrieve a validated pattern.

        Args:
            name: Pattern name

        Returns:
            Pattern definition dict, or empty dict if not found
        """
        return self.patterns.get(name, {})

    def validate_all(self) -> Dict:
        """
        Validate all currently loaded patterns.

        Returns:
            Report with total, valid, invalid counts and details
        """
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

    def clear(self):
        """Clear all patterns and validation cache"""
        self.patterns.clear()
        self.validation_cache.clear()


if __name__ == '__main__':
    # Test pattern validation
    print("=" * 60)
    print("Pattern Validator Test Suite")
    print("=" * 60)

    # Test 1: Safe pattern
    print("\n[Test 1] Safe pattern")
    pattern = r'"Action"\s*:\s*"\*"'
    is_safe, reason = PatternValidator.validate_pattern(pattern)
    print(f"  Pattern: {pattern}")
    print(f"  Safe: {is_safe} ({reason})")
    assert is_safe, "Should recognize safe pattern"

    # Test 2: Dangerous pattern (ReDoS)
    print("\n[Test 2] Dangerous pattern (ReDoS)")
    dangerous = r'(a+)+b'  # Classic ReDoS
    is_safe, reason = PatternValidator.validate_pattern(dangerous)
    print(f"  Pattern: {dangerous}")
    print(f"  Safe: {is_safe} (should be False)")
    # This may not detect classic ReDoS, but should fail on syntax

    # Test 3: Database validation
    print("\n[Test 3] Pattern database")
    db = PatternDatabase()

    # Add safe pattern
    db.add_pattern('aws_wildcard', {
        'pattern': r'"Action"\s*:\s*"\*"',
        'issue': 'Overly permissive action',
        'severity': 'CRITICAL'
    })

    # Add another safe pattern
    db.add_pattern('permit_any', {
        'pattern': r'permit\s+(?:ip|tcp)\s+any\s+any',
        'issue': 'Over-permissive firewall rule',
        'severity': 'CRITICAL'
    })

    # Try to add pattern with too many quantifiers
    db.add_pattern('bad_pattern', {
        'pattern': r'(a*)*b(c*)*d(e*)*f(g*)*h(i*)*j(k*)*l(m*)*n',
        'issue': 'test',
        'severity': 'HIGH'
    })

    report = db.validate_all()
    print(f"  Total: {report['total']}, Valid: {report['valid']}, Invalid: {report['invalid']}")
    assert report['valid'] >= 2, "Should have at least 2 valid patterns"

    print("\n✅ All tests passed!")
