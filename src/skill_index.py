"""
Skill Index and Discovery

Scans skill frontmatters to build an index of all available skills,
then discovers and ranks relevant skills for a given document context.
"""

import os
import re
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pathlib import Path


@dataclass
class SkillMetadata:
    """Parsed skill frontmatter metadata"""
    name: str
    domain: str
    subdomain: Optional[str] = None
    severity: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    nist_csf: List[str] = field(default_factory=list)
    nist_ai_rmf: List[str] = field(default_factory=list)
    mitre_d3fend: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    file_path: str = ""
    full_content: str = ""


@dataclass
class SkillRanking:
    """Ranked skill with relevance score"""
    skill: SkillMetadata
    score: float
    match_reasons: List[str] = field(default_factory=list)


class SkillIndex:
    """Index and discover skills for document review"""

    def __init__(self, skills_dir: str):
        """
        Initialize skill index by scanning all skills in directory.

        Args:
            skills_dir: Path to directory containing skill subdirectories
        """
        self.skills_dir = skills_dir
        self.skills: Dict[str, SkillMetadata] = {}
        self.index: Dict[str, Set[str]] = {
            'domains': set(),
            'subdomains': set(),
            'tags': set(),
            'mitre_attack': set(),
            'nist_csf': set(),
            'nist_ai_rmf': set(),
            'mitre_d3fend': set(),
            'frameworks': set(),
            'platforms': set(),
        }

        self._load_skills()

    def _load_skills(self):
        """Scan skills directory and load all frontmatters"""
        skills_path = Path(self.skills_dir)

        if not skills_path.exists():
            print(f"Warning: Skills directory not found: {self.skills_dir}")
            return

        # Find all SKILL.md files
        for skill_dir in skills_path.iterdir():
            if not skill_dir.is_dir():
                continue

            skill_file = skill_dir / "SKILL.md"
            if not skill_file.exists():
                continue

            try:
                metadata = self._parse_skill(skill_file, skill_dir.name)
                if metadata:
                    self.skills[metadata.name] = metadata
                    self._update_index(metadata)
            except Exception as e:
                print(f"Warning: Failed to parse {skill_file}: {e}")

    def _parse_skill(self, skill_file: Path, skill_name: str) -> Optional[SkillMetadata]:
        """
        Parse YAML frontmatter from SKILL.md file.

        Returns:
            SkillMetadata if successful, None otherwise
        """
        try:
            with open(skill_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract YAML frontmatter between --- delimiters
            match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
            if not match:
                return None

            yaml_content = match.group(1)
            metadata_dict = yaml.safe_load(yaml_content)

            if not metadata_dict:
                return None

            # Create SkillMetadata from YAML
            metadata = SkillMetadata(
                name=metadata_dict.get('name', skill_name),
                domain=metadata_dict.get('domain', 'unknown'),
                subdomain=metadata_dict.get('subdomain'),
                severity=metadata_dict.get('severity'),
                description=metadata_dict.get('description', ''),
                tags=[str(t).lower() for t in metadata_dict.get('tags', [])],
                mitre_attack=metadata_dict.get('mitre_attack', []),
                nist_csf=metadata_dict.get('nist_csf', []),
                nist_ai_rmf=metadata_dict.get('nist_ai_rmf', []),
                mitre_d3fend=metadata_dict.get('mitre_d3fend', []),
                frameworks=metadata_dict.get('frameworks', []),
                platforms=[str(p).lower() for p in metadata_dict.get('platforms', [])],
                file_path=str(skill_file),
                full_content=content
            )

            return metadata

        except Exception as e:
            print(f"Error parsing {skill_file}: {e}")
            return None

    def _update_index(self, metadata: SkillMetadata):
        """Update searchable index with skill metadata"""
        if metadata.domain:
            self.index['domains'].add(metadata.domain.lower())
        if metadata.subdomain:
            self.index['subdomains'].add(metadata.subdomain.lower())
        self.index['tags'].update(metadata.tags)
        self.index['mitre_attack'].update(metadata.mitre_attack)
        self.index['nist_csf'].update(metadata.nist_csf)
        self.index['nist_ai_rmf'].update(metadata.nist_ai_rmf)
        self.index['mitre_d3fend'].update(metadata.mitre_d3fend)
        self.index['frameworks'].update(metadata.frameworks)
        self.index['platforms'].update(metadata.platforms)

    def find_relevant(self, context: Dict) -> List[SkillRanking]:
        """
        Find and rank skills relevant to document context.

        Args:
            context: Dictionary with:
                - primary_domain: Main domain (e.g., 'Cloud Security')
                - primary_topic: Topic keywords (e.g., 'IAM, encryption')
                - detected_platforms: Platforms mentioned (e.g., ['AWS', 'Azure'])
                - frameworks: Required frameworks (e.g., ['CSF', 'ATT&CK'])
                - severity_filter: Min severity (e.g., 'CRITICAL', 'HIGH')
                - rules_triggered: Rule IDs that matched (e.g., ['NET-SEG-001'])

        Returns:
            List of SkillRanking sorted by relevance score (highest first)
        """
        rankings = []

        for skill_name, skill in self.skills.items():
            score = 0.0
            reasons = []

            # Domain match (highest weight)
            primary_domain = context.get('primary_domain', '').lower()
            if primary_domain and skill.domain.lower() == primary_domain:
                score += 50
                reasons.append(f"Domain: {skill.domain}")
            elif primary_domain and primary_domain in skill.domain.lower():
                score += 25
                reasons.append(f"Domain contains: {primary_domain}")

            # Topic/tag match
            topics = context.get('primary_topic', '').lower().split(',')
            topics = [t.strip() for t in topics if t.strip()]

            for topic in topics:
                matching_tags = [tag for tag in skill.tags if topic in tag]
                if matching_tags:
                    score += 5 * len(matching_tags)
                    reasons.append(f"Tags: {', '.join(matching_tags)}")

            # Platform match
            platforms = [p.lower() for p in context.get('detected_platforms', [])]
            if platforms:
                matching_platforms = [p for p in skill.platforms if p in platforms]
                if matching_platforms:
                    score += 10 * len(matching_platforms)
                    reasons.append(f"Platforms: {', '.join(matching_platforms)}")

            # Framework match
            frameworks = context.get('frameworks', [])
            if frameworks:
                matching_frameworks = [f for f in skill.frameworks if f in frameworks]
                if matching_frameworks:
                    score += 15 * len(matching_frameworks)
                    reasons.append(f"Frameworks: {', '.join(matching_frameworks)}")

            # Severity match
            severity_filter = context.get('severity_filter')
            if severity_filter and skill.severity:
                severity_order = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
                if severity_order.get(skill.severity, 0) >= severity_order.get(severity_filter, 0):
                    score += 5
                    reasons.append(f"Severity: {skill.severity}")

            # MITRE ATT&CK mapping
            detected_attacks = context.get('detected_attacks', [])
            if detected_attacks:
                matching_attacks = [a for a in skill.mitre_attack if a in detected_attacks]
                if matching_attacks:
                    score += 8 * len(matching_attacks)
                    reasons.append(f"MITRE ATT&CK: {', '.join(matching_attacks)}")

            # Only include skills with non-zero score
            if score > 0:
                rankings.append(SkillRanking(
                    skill=skill,
                    score=score,
                    match_reasons=reasons
                ))

        # Sort by score (descending)
        rankings.sort(key=lambda r: r.score, reverse=True)
        return rankings

    def get_skill_by_name(self, skill_name: str) -> Optional[SkillMetadata]:
        """Get a skill by exact name"""
        return self.skills.get(skill_name)

    def list_all_skills(self) -> List[SkillMetadata]:
        """Get all loaded skills"""
        return list(self.skills.values())

    def list_by_domain(self, domain: str) -> List[SkillMetadata]:
        """Get all skills in a domain"""
        domain_lower = domain.lower()
        return [s for s in self.skills.values() if s.domain.lower() == domain_lower]

    def list_by_tag(self, tag: str) -> List[SkillMetadata]:
        """Get all skills with a specific tag"""
        tag_lower = tag.lower()
        return [s for s in self.skills.values() if tag_lower in s.tags]

    def get_stats(self) -> Dict:
        """Get statistics about indexed skills"""
        return {
            'total_skills': len(self.skills),
            'domains': len(self.index['domains']),
            'subdomains': len(self.index['subdomains']),
            'tags': len(self.index['tags']),
            'frameworks': len(self.index['frameworks']),
            'platforms': len(self.index['platforms']),
            'domains_list': sorted(list(self.index['domains'])),
            'platforms_list': sorted(list(self.index['platforms'])),
        }


if __name__ == '__main__':
    # Example usage
    index = SkillIndex('/tmp/work/skills')

    print(f"Loaded {len(index.skills)} skills")
    print(f"Index stats: {index.get_stats()}\n")

    # Example discovery
    context = {
        'primary_domain': 'Cloud Security',
        'primary_topic': 'IAM, privileges, access control',
        'detected_platforms': ['AWS', 'Azure'],
        'frameworks': ['CSF', 'ATT&CK'],
        'severity_filter': 'CRITICAL',
        'detected_attacks': ['T1526', 'T1078']
    }

    results = index.find_relevant(context)
    print(f"Found {len(results)} relevant skills:")
    for ranking in results[:5]:
        print(f"\n{ranking.skill.name} (score: {ranking.score:.1f})")
        for reason in ranking.match_reasons:
            print(f"  - {reason}")
