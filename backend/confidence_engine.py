"""
AndroAI Sandbox - Confidence Engine

This module assigns confidence levels to evidence-based findings.

Phase 24 scope:
- Assign confidence based on evidence type
- Keep confidence separate from severity
- Preserve original findings
"""

from typing import Any


def assign_confidence_to_findings(
    findings: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """
    Add confidence values to each finding.
    """

    confidence_by_evidence_type = {
        "permission": "high",
        "manifest_permission": "high",
        "manifest_component": "high",
        "manifest_intent_filter": "high",
        "native_library": "high",
        "native_architecture": "high",
        "dex": "high",
        "url": "medium",
        "ip_address": "medium",
        "certificate": "medium",
        "code_string": "medium",
        "yara_rule": "high",
        "api_usage": "medium",
    }

    enriched_findings: list[dict[str, Any]] = []

    for finding in findings:
        evidence_type = finding.get("evidence_type", "unknown")

        enriched_finding = finding.copy()
        enriched_finding["confidence"] = confidence_by_evidence_type.get(
            evidence_type,
            "low",
        )

        enriched_findings.append(enriched_finding)

    return enriched_findings