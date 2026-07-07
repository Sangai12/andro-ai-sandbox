"""
AndroAI Sandbox - DEX Detector

This module evaluates DEX metadata and returns
evidence-based findings.

Phase 13.2 scope:
- Detect multiple DEX files
- Detect DEX presence
"""

from typing import Any


def detect_dex_findings(
    dex_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Analyze DEX metadata and return findings.
    """

    findings: list[dict[str, str]] = []

    dex_files = dex_analysis.get("dex_files", [])

    if dex_files:
        findings.append(
            {
                "id": "DEX_FILES_PRESENT",
                "title": "DEX Files Present",
                "severity": "low",
                "evidence_type": "dex",
                "evidence": f"dex_file_count={len(dex_files)}",
            }
        )

    if len(dex_files) > 1:
        findings.append(
            {
                "id": "DEX_MULTIPLE_FILES",
                "title": "Multiple DEX Files Detected",
                "severity": "medium",
                "evidence_type": "dex",
                "evidence": ",".join(dex_files),
            }
        )

    return findings