"""
AndroAI Sandbox - Combined Risk Engine

This module combines static and dynamic risk results into
one overall risk assessment.

Phase 37 scope:
- Preserve static risk score
- Preserve dynamic risk score
- Calculate weighted overall risk score
- Produce overall risk level
"""

from typing import Any


def calculate_combined_risk(
    static_analysis: dict[str, Any],
    dynamic_risk: dict[str, Any],
) -> dict[str, Any]:
    """
    Combine static and dynamic risk results.
    """

    static_summary = static_analysis.get("summary", {})

    static_score = int(static_summary.get("risk_score", 0))
    static_level = static_summary.get("risk_level", "unknown")

    dynamic_score = int(dynamic_risk.get("dynamic_risk_score", 0))
    dynamic_level = dynamic_risk.get("dynamic_risk_level", "unknown")

    static_weight = 0.6
    dynamic_weight = 0.4

    overall_score = round(
        (static_score * static_weight)
        + (dynamic_score * dynamic_weight)
    )

    return {
        "static_risk_score": static_score,
        "static_risk_level": static_level,
        "dynamic_risk_score": dynamic_score,
        "dynamic_risk_level": dynamic_level,
        "overall_risk_score": overall_score,
        "overall_risk_level": _risk_level_from_score(overall_score),
        "weights": {
            "static_weight": static_weight,
            "dynamic_weight": dynamic_weight,
        },
        "message": "Combined risk calculated successfully.",
    }


def _risk_level_from_score(score: int) -> str:
    """
    Convert combined risk score into a risk level.
    """

    if score >= 80:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"