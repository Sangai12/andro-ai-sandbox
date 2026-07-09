"""
AndroAI Sandbox - Final AI Report Generator

This module creates a deterministic AI-style analyst report from
the final unified static and dynamic analysis report.

Phase 41 scope:
- Generate executive summary
- Summarize static findings
- Summarize dynamic behaviors
- Explain combined risk
- Recommend analyst next steps
- Avoid unsupported claims
"""

from typing import Any


def generate_final_ai_report(
    final_report: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate an evidence-based AI-style final analyst report.
    """

    apk = final_report.get("apk", {})
    static_analysis = final_report.get("static_analysis", {})
    dynamic_analysis = final_report.get("dynamic_analysis", {})
    dynamic_risk = final_report.get("dynamic_risk", {})
    combined_risk = final_report.get("combined_risk", {})

    package_name = apk.get("package_name", "unknown package")

    static_summary = static_analysis.get("summary", {})
    behavior_summary = dynamic_analysis.get("behavior_summary", {})

    executive_summary = _build_executive_summary(
        package_name=package_name,
        static_summary=static_summary,
        dynamic_risk=dynamic_risk,
        combined_risk=combined_risk,
    )

    static_findings_summary = _build_static_findings_summary(
        static_summary=static_summary,
        static_analysis=static_analysis,
    )

    dynamic_behavior_summary = _build_dynamic_behavior_summary(
        dynamic_analysis=dynamic_analysis,
        behavior_summary=behavior_summary,
    )

    risk_explanation = _build_risk_explanation(
        combined_risk=combined_risk,
    )

    recommended_next_steps = _build_recommended_next_steps(
        combined_risk=combined_risk,
        behavior_summary=behavior_summary,
    )

    return {
        "executive_summary": executive_summary,
        "static_findings_summary": static_findings_summary,
        "dynamic_behavior_summary": dynamic_behavior_summary,
        "risk_explanation": risk_explanation,
        "recommended_next_steps": recommended_next_steps,
        "disclaimer": (
            "This AI-style report is generated only from evidence already "
            "collected by AndroAI Sandbox. It does not introduce unsupported "
            "claims and should be reviewed by a human analyst."
        ),
    }


def _build_executive_summary(
    package_name: str,
    static_summary: dict[str, Any],
    dynamic_risk: dict[str, Any],
    combined_risk: dict[str, Any],
) -> str:
    """
    Build final executive summary.
    """

    static_level = static_summary.get("risk_level", "unknown")
    static_score = static_summary.get("risk_score", "unknown")

    dynamic_level = dynamic_risk.get("dynamic_risk_level", "unknown")
    dynamic_score = dynamic_risk.get("dynamic_risk_score", "unknown")

    overall_level = combined_risk.get("overall_risk_level", "unknown")
    overall_score = combined_risk.get("overall_risk_score", "unknown")

    return (
        f"The APK package {package_name} was analyzed using both static and "
        f"dynamic techniques. Static analysis produced a {static_level} risk "
        f"level with a score of {static_score}. Dynamic runtime analysis "
        f"produced a {dynamic_level} risk level with a score of "
        f"{dynamic_score}. After combining both sources of evidence, the "
        f"overall risk level is {overall_level} with an overall score of "
        f"{overall_score}. This assessment identifies security-relevant "
        "behaviors and indicators that require analyst review."
    )


def _build_static_findings_summary(
    static_summary: dict[str, Any],
    static_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Build static findings summary.
    """

    severity_counts = static_summary.get("severity_counts", {})

    return {
        "risk_level": static_summary.get("risk_level", "unknown"),
        "risk_score": static_summary.get("risk_score", 0),
        "total_findings": static_summary.get("total_findings", 0),
        "finding_count": static_analysis.get("finding_count", 0),
        "mitre_attack_count": static_analysis.get("mitre_attack_count", 0),
        "severity_counts": severity_counts,
        "summary": static_summary.get("risk_summary", ""),
    }


def _build_dynamic_behavior_summary(
    dynamic_analysis: dict[str, Any],
    behavior_summary: dict[str, Any],
) -> dict[str, Any]:
    """
    Build dynamic runtime behavior summary.
    """

    return {
        "detected_behaviors": behavior_summary.get(
            "detected_behaviors",
            [],
        ),
        "detected_behavior_count": behavior_summary.get(
            "detected_behavior_count",
            0,
        ),
        "crash_detected": behavior_summary.get("crash_detected", False),
        "exception_detected": behavior_summary.get(
            "exception_detected",
            False,
        ),
        "network_activity_detected": behavior_summary.get(
            "network_activity_detected",
            False,
        ),
        "webview_activity_detected": behavior_summary.get(
            "webview_activity_detected",
            False,
        ),
        "security_event_detected": behavior_summary.get(
            "security_event_detected",
            False,
        ),
        "warning_detected": behavior_summary.get("warning_detected", False),
        "error_detected": behavior_summary.get("error_detected", False),
        "counts": {
            "crashes": dynamic_analysis.get("crash_count", 0),
            "exceptions": dynamic_analysis.get("exception_count", 0),
            "permission_denials": dynamic_analysis.get(
                "permission_denial_count",
                0,
            ),
            "network_indicators": dynamic_analysis.get(
                "network_indicator_count",
                0,
            ),
            "webview_indicators": dynamic_analysis.get(
                "webview_indicator_count",
                0,
            ),
            "security_indicators": dynamic_analysis.get(
                "security_indicator_count",
                0,
            ),
            "warnings": dynamic_analysis.get("warning_count", 0),
            "errors": dynamic_analysis.get("error_count", 0),
        },
    }


def _build_risk_explanation(
    combined_risk: dict[str, Any],
) -> str:
    """
    Explain combined risk result.
    """

    static_score = combined_risk.get("static_risk_score", 0)
    static_level = combined_risk.get("static_risk_level", "unknown")

    dynamic_score = combined_risk.get("dynamic_risk_score", 0)
    dynamic_level = combined_risk.get("dynamic_risk_level", "unknown")

    overall_score = combined_risk.get("overall_risk_score", 0)
    overall_level = combined_risk.get("overall_risk_level", "unknown")

    weights = combined_risk.get("weights", {})
    static_weight = weights.get("static_weight", 0.6)
    dynamic_weight = weights.get("dynamic_weight", 0.4)

    return (
        f"The combined score was calculated using a weighted model with "
        f"static analysis weighted at {static_weight} and dynamic analysis "
        f"weighted at {dynamic_weight}. The static score was {static_score} "
        f"({static_level}), and the dynamic score was {dynamic_score} "
        f"({dynamic_level}). The resulting overall score is "
        f"{overall_score}, classified as {overall_level}."
    )


def _build_recommended_next_steps(
    combined_risk: dict[str, Any],
    behavior_summary: dict[str, Any],
) -> list[str]:
    """
    Build evidence-based analyst recommendations.
    """

    next_steps = [
        "Review high-severity static findings first.",
        "Validate whether sensitive permissions are required for expected app behavior.",
        "Review network indicators and confirm whether contacted destinations are expected.",
        "Compare runtime behavior against the application's stated purpose.",
        "Perform manual review before making a final malicious or benign conclusion.",
    ]

    if behavior_summary.get("exception_detected", False):
        next_steps.append(
            "Investigate runtime exceptions to determine whether they are benign environment issues or suspicious execution failures."
        )

    if behavior_summary.get("security_event_detected", False):
        next_steps.append(
            "Review security-related runtime events such as SELinux denials, hidden API access, or restricted system interactions."
        )

    if combined_risk.get("overall_risk_level") in ["high", "critical"]:
        next_steps.append(
            "Prioritize this sample for deeper manual analysis because the combined risk level is elevated."
        )

    return next_steps