"""Architecture flow extraction and diagram generation.

Automatically extracts components (services, databases, APIs, users, etc.)
from design document sections and generates an interactive data flow diagram.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Any
from enum import Enum

from .models import Section


class ComponentType(str, Enum):
    """Types of architecture components."""
    SERVICE = "service"          # Microservice, application
    DATABASE = "database"        # SQL, NoSQL databases
    CACHE = "cache"              # Redis, Memcached
    MESSAGE_QUEUE = "queue"      # RabbitMQ, Kafka, SQS
    API_GATEWAY = "api_gateway"  # API Gateway, load balancer
    EXTERNAL_API = "external"    # Third-party APIs
    USER = "user"                # Users, clients
    STORAGE = "storage"          # S3, blob storage
    OTHER = "other"              # Generic component


@dataclass
class Component:
    """An architecture component (service, database, etc.)."""
    id: str
    name: str
    component_type: ComponentType
    description: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"      # low, medium, high, critical
    section_reference: str = ""  # Which section it came from

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.component_type.value,
            "description": self.description,
            "properties": self.properties,
            "risk_level": self.risk_level,
            "section": self.section_reference,
        }


@dataclass
class Connection:
    """A data flow connection between components."""
    source_id: str
    target_id: str
    label: str = ""
    data_type: str = ""    # JSON, binary, text, etc.
    protocol: str = ""     # HTTP, TCP, AMQP, etc.
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "label": self.label,
            "data_type": self.data_type,
            "protocol": self.protocol,
            "properties": self.properties,
        }


@dataclass
class ArchitectureFlow:
    """Complete architecture diagram with components and flows."""
    components: Dict[str, Component] = field(default_factory=dict)
    connections: List[Connection] = field(default_factory=list)

    def add_component(self, component: Component) -> None:
        """Add a component to the diagram."""
        self.components[component.id] = component

    def add_connection(self, connection: Connection) -> None:
        """Add a connection between components."""
        self.connections.append(connection)

    def remove_component(self, component_id: str) -> None:
        """Remove a component and its connections."""
        if component_id in self.components:
            del self.components[component_id]
        self.connections = [
            c for c in self.connections
            if c.source_id != component_id and c.target_id != component_id
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "components": {
                cid: comp.to_dict()
                for cid, comp in self.components.items()
            },
            "connections": [c.to_dict() for c in self.connections],
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ArchitectureFlow:
        """Reconstruct from dictionary."""
        flow = ArchitectureFlow()
        for cid, comp_data in data.get("components", {}).items():
            component = Component(
                id=comp_data["id"],
                name=comp_data["name"],
                component_type=ComponentType(comp_data.get("type", "other")),
                description=comp_data.get("description", ""),
                properties=comp_data.get("properties", {}),
                risk_level=comp_data.get("risk_level", "low"),
                section_reference=comp_data.get("section", ""),
            )
            flow.add_component(component)

        for conn_data in data.get("connections", []):
            connection = Connection(
                source_id=conn_data["source"],
                target_id=conn_data["target"],
                label=conn_data.get("label", ""),
                data_type=conn_data.get("data_type", ""),
                protocol=conn_data.get("protocol", ""),
                properties=conn_data.get("properties", {}),
            )
            flow.add_connection(connection)

        return flow


# =============================================================================
# Component Extraction
# =============================================================================

COMPONENT_PATTERNS = {
    ComponentType.SERVICE: [
        r'\b(?:service|microservice|application|app|server|api|endpoint|backend)\b',
        r'\b(?:nodejs|python|java|go|rust|\.net|spring|django|fastapi)\s+(?:service|app)',
        r'\b(?:lambda|function|handler|worker)\b',
    ],
    ComponentType.DATABASE: [
        r'\b(?:database|db|sql|postgres|mysql|mongodb|dynamodb|cassandra|elasticsearch)\b',
        r'\b(?:oracle|mssql|mariadb|redis|memcached)\b',
    ],
    ComponentType.CACHE: [
        r'\b(?:cache|redis|memcached|varnish)\b',
    ],
    ComponentType.MESSAGE_QUEUE: [
        r'\b(?:queue|kafka|rabbitmq|sqs|sns|pubsub|message\s+broker)\b',
        r'\b(?:event\s+(?:bus|stream))\b',
    ],
    ComponentType.API_GATEWAY: [
        r'\b(?:api\s+gateway|load\s+balancer|reverse\s+proxy|ingress|alb|nlb)\b',
    ],
    ComponentType.EXTERNAL_API: [
        r'\b(?:external|third-party|saas|third\s+party)\s+(?:api|service|integration)\b',
        r'\b(?:oauth|saml|payment\s+gateway|sso)\b',
    ],
    ComponentType.STORAGE: [
        r'\b(?:s3|blob\s+storage|object\s+storage|gcs|azure\s+storage)\b',
        r'\b(?:file\s+storage|cdn|bucket)\b',
    ],
    ComponentType.USER: [
        r'\b(?:user|client|mobile|web\s+app|browser|frontend|consumer)\b',
    ],
}

CONNECTION_PATTERNS = [
    # Arrow notation (highest priority)
    (r'\w+\s*(?:->|→)\s*\w+', 'arrow'),
    # Verb patterns: explicit connections
    (r'(?:communicates?|calls?|invokes?|sends?|retrieves?|stores?|reads?|writes?)\s+(?:to|from|the|a)\s+', 'verb'),
    # Flow patterns
    (r'(?:flow|data|request)\s+(?:to|from|through)\s+', 'flow'),
    # Connection patterns
    (r'(?:connected?|linked?|integrated?)\s+with\s+', 'conn'),
]


def extract_components_from_sections(sections: List[Section]) -> ArchitectureFlow:
    """Auto-extract components from design document sections."""
    flow = ArchitectureFlow()
    seen_names: Set[str] = set()
    component_counter = {}

    for section in sections:
        text = (section.heading + " " + section.body).lower()

        # Extract components by type
        for comp_type, patterns in COMPONENT_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    # Try to extract component name from surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end]

                    # Extract meaningful name
                    words = re.findall(r'\b\w+\b', match.group(0))
                    if words:
                        base_name = words[-1].capitalize()

                        # Avoid duplicates
                        if base_name not in seen_names:
                            seen_names.add(base_name)

                            # Generate ID
                            comp_id = f"{comp_type.value}_{len(flow.components) + 1}"

                            component = Component(
                                id=comp_id,
                                name=base_name,
                                component_type=comp_type,
                                description=f"Extracted from {section.heading}",
                                section_reference=section.heading,
                            )
                            flow.add_component(component)

    # Extract connections between components using explicit patterns
    def find_nearest_component(text: str, position: int, seen_names: Set[str],
                             search_before: bool = True) -> Optional[str]:
        """Find the nearest component name in text relative to a position."""
        if search_before:
            # Search backwards from position
            search_text = text[:position].lower()
            best_match = None
            best_pos = -1
            for name in seen_names:
                pos = search_text.rfind(name.lower())
                if pos > best_pos:
                    best_pos = pos
                    best_match = name
            return best_match
        else:
            # Search forwards from position
            search_text = text[position:].lower()
            for name in seen_names:
                pos = search_text.find(name.lower())
                if pos >= 0:
                    return name
            return None

    for section in sections:
        text = section.body
        text_lower = text.lower()

        # Look for explicit connection patterns
        for pattern, pattern_type in CONNECTION_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                source_name = None
                target_name = None

                if pattern_type == 'arrow':
                    # For arrows, extract component names directly
                    arrow_match = re.search(r'(\w+)\s*(?:->|→)\s*(\w+)', match.group(0))
                    if arrow_match:
                        source_candidate = arrow_match.group(1).capitalize()
                        target_candidate = arrow_match.group(2).capitalize()
                        # Match against known component names (case-insensitive)
                        source_name = next(
                            (n for n in seen_names if n.lower() == source_candidate.lower()),
                            source_candidate
                        )
                        target_name = next(
                            (n for n in seen_names if n.lower() == target_candidate.lower()),
                            target_candidate
                        )
                else:
                    # For other patterns, find components from context
                    source_name = find_nearest_component(text, match.start(), seen_names, search_before=True)
                    target_name = find_nearest_component(text, match.end(), seen_names, search_before=False)

                if not source_name or not target_name:
                    continue

                # Find actual components by name (case-insensitive)
                source = next(
                    (c for c in flow.components.values()
                     if c.name.lower() == source_name.lower()),
                    None
                )
                target = next(
                    (c for c in flow.components.values()
                     if c.name.lower() == target_name.lower()),
                    None
                )

                if source and target and source.id != target.id:
                    # Avoid duplicate connections
                    exists = any(
                        c.source_id == source.id and c.target_id == target.id
                        for c in flow.connections
                    )
                    if not exists:
                        connection = Connection(
                            source_id=source.id,
                            target_id=target.id,
                            label="data flow",
                        )
                        flow.add_connection(connection)

    return flow


def enrich_flow_with_risks(flow: ArchitectureFlow, findings: List[Any]) -> ArchitectureFlow:
    """Mark components with risk levels based on findings."""
    for component in flow.components.values():
        risk_count = sum(
            1 for f in findings
            if component.name.lower() in f.section.lower()
        )

        if risk_count >= 3:
            component.risk_level = "critical"
        elif risk_count >= 2:
            component.risk_level = "high"
        elif risk_count >= 1:
            component.risk_level = "medium"
        else:
            component.risk_level = "low"

    return flow