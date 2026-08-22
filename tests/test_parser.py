"""Parser and domain classification tests."""

from __future__ import annotations

import json

from src.domains import APPLICATION, CLOUD_DATA, NETWORK, SECURITY
from src.parser import (
    filter_sections,
    parse_text,
    split_sections,
    summarise_sections,
)


def test_markdown_headings_split():
    text = """# Design

## 1. Access Layer

Each access switch has two uplinks to the distribution pair for redundancy
across the campus network topology described here.

## 2. Firewall Policy

The firewall enforces zone policy between the DMZ and the application zone
with explicit rules and a terminating deny.
"""
    sections = split_sections(text)
    headings = [s.heading for s in sections]
    assert "1. Access Layer" in headings
    assert "2. Firewall Policy" in headings


def test_numbered_word_style_headings():
    text = """3.1 Routing Design

OSPF is deployed in area zero across the distribution and core layers with
neighbour authentication enabled on every adjacency in the campus.

3.2 WAN Edge

Two circuits from two carriers terminate on the WAN edge routers with IPsec
encryption applied across both transports for confidentiality.
"""
    sections = split_sections(text)
    assert any("3.1" in s.heading for s in sections)
    assert any("3.2" in s.heading for s in sections)


def test_setext_headings():
    text = """Access Layer Design
===================

Two uplinks per access switch terminate on separate distribution switches so
no single chassis failure isolates a floor.
"""
    sections = split_sections(text)
    assert sections[0].heading == "Access Layer Design"


def test_heading_only_sections_dropped():
    text = """# Container

## 1. Network

### 1.1 Access

Access switches connect with dual uplinks to two separate distribution
switches across all nine floors of the building.
"""
    sections = split_sections(text)
    assert [s.heading for s in sections] == ["1.1 Access"]


def test_domain_classification_network():
    text = """## VLAN and Switching

The access switch uplinks terminate on the distribution switch pair and VLAN
trunking carries user traffic to the layer 3 boundary with spanning tree.
"""
    section = split_sections(text)[0]
    assert section.domain == NETWORK


def test_domain_classification_application():
    text = """## API Authentication

The REST API validates the OAuth 2.0 JWT access token on every request and
enforces authorisation in the service that owns the resource.
"""
    section = split_sections(text)[0]
    assert section.domain == APPLICATION


def test_domain_classification_security():
    text = """## Privileged Access

Administrative accounts require phishing resistant MFA brokered through the
privileged access management platform with full session recording enabled.
"""
    section = split_sections(text)[0]
    assert section.domain == SECURITY


def test_domain_classification_cloud():
    text = """## Landing Zone

Each workload occupies a separate AWS account under an organisational unit
with service control policy guardrails applied at the OU level.
"""
    section = split_sections(text)[0]
    assert section.domain == CLOUD_DATA


def test_classification_is_deterministic():
    text = """## Segmentation

Zones are enforced by the firewall pair with an explicit deny terminating
every policy set between the DMZ and the application zone.
"""
    first = split_sections(text)[0]
    second = split_sections(text)[0]
    assert (first.domain, first.topic, first.topic_confidence) == \
           (second.domain, second.topic, second.topic_confidence)


def test_heading_outweighs_body_mentions():
    text = """## Firewall Policy and Segmentation

The design references BGP once when describing the upstream router but the
section is about zone policy, rule specificity and the deny-all terminator.
"""
    section = split_sections(text)[0]
    assert section.topic == "segmentation"


def test_oversized_section_is_split():
    body = " ".join(["word"] * 400)
    text = f"## Big Section\n\n{body}\n\n{body}\n\n{body}\n"
    sections = split_sections(text)
    assert len(sections) > 1
    assert all("Big Section" in s.heading for s in sections)


def test_unstructured_text_still_parses():
    text = ("The firewall permits any any which defeats segmentation entirely "
            "and the switch has a single uplink to one distribution device.")
    sections = parse_text(text, "paste")
    assert len(sections) == 1
    assert sections[0].heading == "Design Document"


def test_filter_sections_by_domain():
    text = """## Access Layer

Two uplinks per access switch terminate on separate distribution switches
throughout the campus network described in this document.

## API Gateway

The API gateway validates OAuth tokens and forwards requests to the
downstream microservices over mutual TLS connections.
"""
    sections = split_sections(text)
    only_net = filter_sections(sections, ["network"])
    assert all(s.domain == "network" for s in only_net)
    assert len(only_net) < len(sections)


def test_summarise_sections_counts():
    text = """## Routing

OSPF area zero carries the campus prefixes between distribution and core with
authentication configured on every adjacency in the design.

## Secrets Management

Application secrets are injected at runtime from the enterprise vault using
workload identity so no long lived credential exists.
"""
    counts = summarise_sections(split_sections(text))
    assert sum(counts.values()) == 2


def test_openapi_flattening(tmp_path):
    from src.parser import read_document

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Payments", "version": "1"},
        "servers": [{"url": "http://api.example.com"}],
        "paths": {
            "/v1/pay": {"post": {"summary": "Create", "security": []}},
        },
        "components": {"schemas": {}},
    }
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf-8")

    text = read_document(p)
    assert "Transport is plaintext HTTP" in text
    assert "explicitly disables authentication" in text
    assert "No securitySchemes are defined" in text
