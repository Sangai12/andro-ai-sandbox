"""
AndroAI Sandbox - Dynamic Risk Score

This module calculates a dynamic risk score from runtime
behavior analysis results.

Phase 36 scope:
- Score runtime behavior flags
- Keep dynamic risk separate from static risk
- Produce dynamic risk level and severity counts
"""

from typing import Any


def calculate_dynamic_risk_score(
    runtime_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate dynamic risk score from runtime behavior summary.
    """

    behavior_summary = runtime_analysis.get("behavior_summary", {})

    scoring_rules = {
        "crash_detected": {
            "score": 10,
            "severity": "medium",
        },
        "exception_detected": {
            "score": 8,
            "severity": "low",
        },
        "permission_denial_detected": {
            "score": 15,
            "severity": "medium",
        },
        "network_activity_detected": {
            "score": 15,
            "severity": "medium",
        },
        "webview_activity_detected": {
            "score": 10,
            "severity": "low",
        },
        "security_event_detected": {
            "score": 20,
            "severity": "high",
        },
        "warning_detected": {
            "score": 5,
            "severity": "low",
        },
        "error_detected": {
            "score": 10,
            "severity": "medium",
        },
    }

    risk_score = 0

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    triggered_rules = []

    for behavior_flag, rule in scoring_rules.items():
        if not behavior_summary.get(behavior_flag, False):
            continue

        risk_score += rule["score"]
        severity_counts[rule["severity"]] += 1

        triggered_rules.append(
            {
                "behavior": behavior_flag,
                "score": rule["score"],
                "severity": rule["severity"],
            }
        )

    risk_score = min(risk_score, 100)

    return {
        "dynamic_risk_score": risk_score,
        "dynamic_risk_level": _risk_level_from_score(risk_score),
        "dynamic_severity_counts": severity_counts,
        "triggered_dynamic_rules": triggered_rules,
        "triggered_dynamic_rule_count": len(triggered_rules),
    }


def _risk_level_from_score(score: int) -> str:
    """
    Convert dynamic risk score into a risk level.
    """

    if score >= 80:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"