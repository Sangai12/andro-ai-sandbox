"""
AndroAI Sandbox - Risk Score Calculator

This module calculates an overall risk score from
evidence-based findings.

Phase 18.1 scope:
- Count findings by severity
- Calculate weighted risk score
- Assign risk level
"""

from typing import Any


def calculate_risk_score(
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    """
    Calculate overall risk score from findings.
    """

    severity_weights = {
        "low": 1,
        "medium": 3,
        "high": 6,
        "critical": 10,
    }

    severity_counts = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }

    raw_score = 0

    for finding in findings:
        severity = finding.get("severity", "low").lower()

        if severity not in severity_weights:
            severity = "low"

        severity_counts[severity] += 1
        raw_score += severity_weights[severity]

    risk_score = min(raw_score, 100)

    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
    }