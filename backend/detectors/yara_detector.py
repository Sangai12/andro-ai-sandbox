"""
AndroAI Sandbox - YARA Detector

This module converts YARA rule matches into
evidence-based findings.

Phase 20.4 scope:
- Detect matched YARA rules
- Convert YARA matches into structured findings
"""

from typing import Any


def detect_yara_findings(
    yara_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Convert YARA rule matches into findings.
    """

    findings: list[dict[str, str]] = []

    matched_rules = yara_analysis.get("matched_rules", [])

    for rule_name in matched_rules:
        findings.append(
            {
                "id": "YARA_RULE_MATCH",
                "title": "YARA Rule Match Detected",
                "severity": "high",
                "evidence_type": "yara_rule",
                "evidence": rule_name,
            }
        )

    return findings