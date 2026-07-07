"""
AndroAI Sandbox - Risk Summary

This module generates a deterministic human-readable
summary from evidence-based findings.

Phase 18.3 scope:
- Summarize risk level
- Highlight major evidence categories
- Avoid unsupported conclusions
"""

from typing import Any


def generate_risk_summary(
    risk_analysis: dict[str, Any],
    findings: list[dict[str, str]],
) -> str:
    """
    Generate a human-readable risk summary from findings.
    """

    risk_level = risk_analysis.get("risk_level", "unknown")
    evidence_types = {
        finding.get("evidence_type", "unknown")
        for finding in findings
    }

    reasons: list[str] = []

    if "permission" in evidence_types:
        reasons.append("sensitive permissions")

    if "manifest_component" in evidence_types:
        reasons.append("exported application components")

    if "manifest_intent_filter" in evidence_types:
        reasons.append("persistence-related manifest entries")

    if "native_library" in evidence_types:
        reasons.append("native libraries")

    if "url" in evidence_types or "ip_address" in evidence_types:
        reasons.append("network indicators")

    if "certificate" in evidence_types:
        reasons.append("certificate-related findings")

    if "code_string" in evidence_types:
        reasons.append("code or root-related indicators")

    if reasons:
        reason_text = ", ".join(reasons)
        return (
            f"Risk level is {risk_level} based on evidence including "
            f"{reason_text}. These findings do not prove malicious behavior "
            "by themselves, but they indicate areas requiring further analysis."
        )

    return (
        f"Risk level is {risk_level}. No major evidence categories were "
        "identified from the available static analysis findings."
    )